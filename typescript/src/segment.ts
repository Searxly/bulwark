/**
 * Locate an injection inside a document instead of judging the whole thing.
 *
 * A page-level verdict forces a bad choice. "This 4,000-word article contains
 * an injection" leaves you blocking the article — and the attacker, who only
 * had to add one poisoned sentence to a page you wanted, has denied you the
 * content. Do that a few times and the operator turns the guard off, which is
 * the attack working perfectly.
 *
 * Segment analysis scores each passage on its own, so the answer becomes "the
 * injection is in paragraph 7, and paragraphs 1-6 and 8-40 are clean". From
 * there {@link neutralize} excises just the poisoned passages and hands the
 * model a document that is still worth summarizing. The attacker loses their
 * payload and keeps none of their leverage.
 *
 * The report also yields a **contamination ratio** — how much of the document
 * is hostile. A page that is 2% injection is a normal page someone poisoned; a
 * page that is 80% injection is an attack wearing a page as a costume, and
 * callers may reasonably treat the two differently.
 *
 * `start` and `end` are UTF-16 indexes, like every other offset in this
 * library, so `text.slice(segment.start, segment.end) === segment.text` always
 * holds. Lengths are a different matter: see {@link charCount}.
 */

import { detect } from "./detect.js";
import { foldDetection } from "./sanitize.js";
import type { Finding, Severity } from "./types.js";

/** A half-open `[start, end)` range of the source text. */
export type Span = [number, number];

// Segmentation budget. Detection is ~70 regexes per segment, so an unbounded
// split over a large document multiplies the scan cost by the segment count.
export const MAX_SEGMENTS = 250;
/** Runs shorter than this many *characters* merge into their neighbour. */
export const MIN_SEGMENT_CHARS = 40;
/** Paragraphs longer than this many *characters* are split into sentences. */
export const LONG_SEGMENT_CHARS = 1_200;

export const DEFAULT_PLACEHOLDER =
  "[removed: passage containing instructions addressed to the assistant]";

// The reference dialect's whitespace set, spelled out because JavaScript's
// `\s` is not quite the same: it omits U+001C–U+001F and U+0085, and adds
// U+FEFF. Segments are kept or dropped by whether they are blank, so the
// difference decides whether a stray U+0085 line survives as its own segment.
const SPACE_CHARS =
  "\\t\\n\\v\\f\\r \\u001c-\\u001f\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const BLANK_RE = new RegExp(`^[${SPACE_CHARS}]*$`, "u");
const TRIM_RE = new RegExp(`^[${SPACE_CHARS}]+|[${SPACE_CHARS}]+$`, "gu");

const PARAGRAPH_SPLIT_RE = /\n[ \t]*\n/gu;
// `[^\s]` in the lookahead is written out against the set above for the same
// reason. Both patterns are global so they can be walked with `lastIndex`,
// which is how the reference's `finditer(text, start, end)` is reproduced
// without slicing — a slice would put the lookbehind out of reach of the
// character just before the paragraph.
const SENTENCE_SPLIT_RE = new RegExp(
  `(?<=[.!?。！？])[ \\t]+(?=[^${SPACE_CHARS}])|\\n`,
  "gu",
);

/**
 * Count characters the way the reference does — code points, not UTF-16 units.
 *
 * Offsets stay in UTF-16 so slicing works, but both segmentation budgets and
 * the contamination ratio are counts of *characters*, and JavaScript weighs an
 * astral character twice. Measured in UTF-16 units a 25-character line stops
 * merging into its neighbour, a 960-character paragraph gets sentence-split
 * that the reference leaves whole, and a page of emoji reports a contamination
 * ratio that is simply the wrong number — which is the one figure a caller uses
 * to decide between "poisoned page" and "attack wearing a page as a costume".
 */
function charCount(text: string, start = 0, end = text.length): number {
  let n = 0;
  for (let i = start; i < end; i += 1, n += 1) {
    const unit = text.charCodeAt(i);
    // A surrogate pair is one character. A lone surrogate is also one, which is
    // why the low half is checked rather than assumed.
    if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < end) {
      const low = text.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) i += 1;
    }
  }
  return n;
}

/** One passage of the document, scored on its own. */
export class Segment {
  constructor(
    readonly text: string,
    readonly start: number,
    readonly end: number,
    readonly score: number,
    readonly risk: Severity,
    readonly injected: boolean,
    readonly findings: Finding[] = [],
  ) {}

  /**
   * Length in characters — code points, not UTF-16 units, so that the
   * contamination ratio built out of it means the same thing here as it does in
   * the reference. For text outside the astral planes this equals
   * `end - start`; for emoji and the like it is smaller.
   */
  get length(): number {
    return charCount(this.text);
  }
}

/** Where the injection is, and how much of the document it occupies. */
export class SegmentReport {
  constructor(
    readonly segments: Segment[],
    /** Share of characters inside injected segments. */
    readonly contamination: number,
    readonly injectedCount: number,
    readonly worst: Segment | undefined = undefined,
  ) {}

  get clean(): boolean {
    return this.injectedCount === 0;
  }

  injectedSegments(): Segment[] {
    return this.segments.filter((s) => s.injected);
  }

  summary(): string {
    if (this.clean) return `${this.segments.length} segment(s), none flagged`;
    return (
      `${this.injectedCount}/${this.segments.length} segment(s) flagged, ` +
      `${percent(this.contamination)} of the text by length`
    );
  }
}

/**
 * Split into paragraph spans, breaking overlong paragraphs into sentences and
 * merging runts, keeping every offset exact against the original text.
 */
function spansOf(text: string): Span[] {
  if (!text) return [];

  const raw: Span[] = [];
  let cursor = 0;
  PARAGRAPH_SPLIT_RE.lastIndex = 0;
  for (let m = PARAGRAPH_SPLIT_RE.exec(text); m !== null; m = PARAGRAPH_SPLIT_RE.exec(text)) {
    if (m.index > cursor) raw.push([cursor, m.index]);
    cursor = m.index + m[0].length;
  }
  if (cursor < text.length) raw.push([cursor, text.length]);
  if (raw.length === 0) raw.push([0, text.length]);

  // Break paragraphs that are long enough to hide a payload in a corner.
  const split: Span[] = [];
  for (const [start, end] of raw) {
    if (charCount(text, start, end) <= LONG_SEGMENT_CHARS) {
      split.push([start, end]);
      continue;
    }
    let pieceStart = start;
    SENTENCE_SPLIT_RE.lastIndex = start;
    for (let m = SENTENCE_SPLIT_RE.exec(text); m !== null; m = SENTENCE_SPLIT_RE.exec(text)) {
      const matchEnd = m.index + m[0].length;
      // Stop at the paragraph's end: the reference scans a bounded window, so
      // a separator that would straddle the boundary is not a separator here.
      if (matchEnd > end) break;
      if (matchEnd > pieceStart) {
        split.push([pieceStart, m.index]);
        pieceStart = matchEnd;
      }
    }
    if (pieceStart < end) split.push([pieceStart, end]);
  }

  // Merge runts forward so a one-word line doesn't become its own segment.
  const merged: Span[] = [];
  for (const [start, end] of split) {
    const last = merged[merged.length - 1];
    if (last !== undefined && charCount(text, start, end) < MIN_SEGMENT_CHARS) last[1] = end;
    else merged.push([start, end]);
  }

  // Enforce the budget by fusing neighbours evenly rather than dropping tail
  // segments — losing the end of a document is exactly where a payload hides.
  let budgeted = merged;
  while (budgeted.length > MAX_SEGMENTS) {
    const fused: Span[] = [];
    for (let i = 0; i < budgeted.length; i += 2) {
      const pair = budgeted.slice(i, i + 2);
      fused.push([pair[0]![0], pair[pair.length - 1]![1]]);
    }
    budgeted = fused;
  }

  return budgeted.filter(([s, e]) => !BLANK_RE.test(text.slice(s, e)));
}

export interface AnalyzeOptions {
  threshold?: number;
  /**
   * Defaults to false on purpose: the density heuristics measure a property of
   * a whole document (what fraction of its lines are imperative), and applying
   * them to a three-line segment turns any short instruction list into a hit.
   */
  useHeuristics?: boolean;
  /** Also scan a confusable-folded copy of each segment. Defaults to true. */
  fold?: boolean;
}

/** Score every passage of `text` independently. */
export function analyzeSegments(text: string, opts: AnalyzeOptions = {}): SegmentReport {
  const { threshold = 0.5, useHeuristics = false, fold = true } = opts;

  const segments: Segment[] = [];
  let contaminatedChars = 0;

  for (const [start, end] of spansOf(text)) {
    const piece = text.slice(start, end);
    const result = detect(piece, {
      threshold,
      useHeuristics,
      alsoScan: fold ? foldDetection(piece) : undefined,
    });
    const segment = new Segment(
      piece,
      start,
      end,
      result.score,
      result.risk,
      result.injected,
      result.findings,
    );
    segments.push(segment);
    if (segment.injected) contaminatedChars += segment.length;
  }

  const total = segments.reduce((sum, s) => sum + s.length, 0) || 1;
  const injectedCount = segments.filter((s) => s.injected).length;
  let worst: Segment | undefined;
  for (const segment of segments) {
    if (worst === undefined || segment.score > worst.score) worst = segment;
  }

  return new SegmentReport(segments, round4(contaminatedChars / total), injectedCount, worst);
}

/** Short alias, for use inside a pipeline that has already imported the module. */
export const analyze = analyzeSegments;

export interface NeutralizeOptions {
  threshold?: number;
  placeholder?: string;
  maxContamination?: number;
}

/**
 * Excise the flagged passages, keeping the rest of the document intact.
 *
 * When contamination exceeds `maxContamination` nothing is excised and the
 * text is returned unchanged: at that point the document *is* the attack, and
 * quietly handing back the 20% remainder would misrepresent it as a cleaned
 * version of something real. Callers should block instead — which they can see
 * from the report.
 */
export function neutralize(
  text: string,
  report?: SegmentReport,
  opts: NeutralizeOptions = {},
): { text: string; removed: number } {
  const {
    threshold = 0.5,
    placeholder = DEFAULT_PLACEHOLDER,
    maxContamination = 0.75,
  } = opts;

  const rep = report ?? analyzeSegments(text, { threshold });
  if (rep.clean || rep.contamination > maxContamination) return { text, removed: 0 };

  const out: string[] = [];
  let cursor = 0;
  let removed = 0;
  for (const segment of rep.segments) {
    if (!segment.injected) continue;
    out.push(text.slice(cursor, segment.start));
    out.push(placeholder);
    cursor = segment.end;
    removed += 1;
  }
  out.push(text.slice(cursor));

  // Collapse the blank space left behind by an excised paragraph.
  const joined = out.join("").replace(/\n{3,}/gu, "\n\n");
  return { text: joined.replace(TRIM_RE, ""), removed };
}

/**
 * Round to 4 decimal places exactly as the reference's `round(x, 4)` does.
 *
 * The subtlety is which values are actually ties. `round()` rounds the double's
 * *exact binary* value, and a decimal halfway case like 0.00025 is not
 * representable in binary — the nearest double sits a hair above it, so the
 * reference rounds it up and never consults its tie rule. Scaling by 10 000
 * first destroys exactly that information (0.00025 * 10000 lands on 0.5 on the
 * nose) and would round it down instead.
 *
 * A genuine tie needs `value * 10000` to be exactly k + 0.5, which for a binary
 * float happens only when `value` is an odd multiple of 1/32 — and there the
 * reference does apply banker's rounding. So: `toFixed` (correctly rounded from
 * the exact value, halfway away from zero) for everything, with the odd/32 case
 * pulled out and rounded to even by hand.
 */
function round4(value: number): number {
  // Scaling by a power of two is exact, so this detects odd/32 without error.
  const thirtySeconds = value * 32;
  if (Number.isInteger(thirtySeconds) && thirtySeconds % 2 !== 0) {
    const scaled = value * 10_000; // exact here: an odd j/32 gives j * 312.5
    const floor = Math.floor(scaled);
    return (floor % 2 === 0 ? floor : floor + 1) / 10_000;
  }
  return Number(value.toFixed(4));
}

/** Format a ratio as a whole percentage, matching the reference's `:.0%`. */
function percent(ratio: number): string {
  const scaled = ratio * 100;
  const floor = Math.floor(scaled);
  const rest = scaled - floor;
  let rounded: number;
  if (rest > 0.5) rounded = floor + 1;
  else if (rest < 0.5) rounded = floor;
  else rounded = floor % 2 === 0 ? floor : floor + 1;
  return `${rounded}%`;
}
