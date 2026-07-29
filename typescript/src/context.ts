/**
 * Tell a document that *performs* an attack from one that *discusses* one.
 *
 * The most common false positive in prompt-injection detection is a security
 * article. A page explaining how injection works quotes real payloads; an API
 * reference documenting chat templates prints real role tokens; a changelog
 * says "this release overrides the previous configuration". These are the exact
 * documents a security-conscious user is most likely to feed to a summarizer,
 * and flagging them is how a guard earns a reputation for crying wolf and gets
 * switched off.
 *
 * The difference between quoting an instruction and issuing one is *context*:
 *
 * - the payload sits in a code fence, a blockquote, or quotation marks; and
 * - the surrounding prose is talking *about* attacks — "an attacker embeds…",
 *   "for example…", "this payload demonstrates…"; and
 * - the document as a whole reads like security writing.
 *
 * Any one of those alone is weak evidence, and — critically — cheap for an
 * attacker to fake. Wrapping a payload in a code fence costs nothing. So a
 * single signal earns only a small discount, and the discount deepens only as
 * *independent* signals stack up. To reach the largest discount an attacker
 * must fence their payload, quote it, surround it with "this is a malicious
 * example" framing, and make the whole page read as a security write-up — at
 * which point they have spent the attack's own persuasive power telling the
 * model that the text is a quoted specimen. **The evasion weakens the payload.**
 * That property is the reason this is safe to do at all.
 *
 * The discount is also floored well above zero. Context can make a finding
 * quieter; it can never silence one, so this can never become a reliable
 * bypass. Everything downstream — spotlighting, the hardened prompt, output
 * validation — is unchanged.
 */

import type { Finding } from "./types.js";

/** A half-open `[start, end)` range of the source text. */
export type Span = [number, number];

// Discount by number of independent context signals. Never reaches zero: a
// discounted finding still contributes to the score and still appears in the
// report, so a "quoted" payload can never be silently dropped.
const DISCOUNT_BY_SIGNALS = [1.0, 0.78, 0.5, 0.34, 0.3] as const;
export const MIN_DISCOUNT = 0.3;

// Phrases that mark prose as *about* attacks rather than *being* one. Chosen to
// be the vocabulary of analysis, not of instruction.
const META_MARKERS = [
  "for example", "for instance", "e.g.", "such as", "consider the following",
  "the following text", "sample payload", "example payload", "attack string",
  "proof of concept", "demonstrat", "illustrat", "example of",
  "attacker", "adversar", "malicious", "payload", "exploit", "vulnerab",
  "prompt injection", "prompt-injection", "jailbreak", "injected", "injection",
  "red team", "red-team", "threat model", "mitigat", "guardrail", "sanitiz",
  "security research", "advisory", "cve-", "owasp", "write-up", "writeup",
  "in this lesson", "in this article", "this post", "we tested", "we found",
  "reported by", "disclosure", "verbatim", "quoted above", "quoted below",
  "would look like", "looks like this", "test case", "regression test",
  "do not run this", "harmless example", "defanged",
];
// Reaching this many *distinct* markers makes the whole document read as
// analysis. Set high enough that one passing mention of "attacker" is not enough.
const DOC_META_THRESHOLD = 4;

// Unicode-aware whitespace, spelled out because JavaScript's `\s` is not quite
// the reference dialect's set: it omits U+001C–U+001F and U+0085, and adds
// U+FEFF.
const SPACE =
  "[\\t\\n\\v\\f\\r \\u001c-\\u001f\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";

// Every pattern below carries `u` so that `{8,600}` counts code points the way
// the reference implementation does rather than UTF-16 units — otherwise a
// quotation full of astral characters would be measured at twice its length.
// None carry `m`: the leading `^` anchors to the start of the document only,
// and JavaScript's `m` would additionally treat \r, U+2028 and U+2029 as line
// starts, which the reference does not. Trailing `$` (no `m`) is the exact
// equivalent of the reference's absolute end-of-string anchor.
const FENCE_RE = /(?:^|\n)(```|~~~)[^\n]*\n.*?(?:\n\1|$)/gsu;
const INLINE_CODE_RE = /`[^`\n]{1,400}`/gu;
// The word boundary after the tag name is spelled out as a negative lookahead:
// JavaScript's `\b` is ASCII-only, so it would happily read "<codeé …>" as a
// <code> tag, where the Unicode-aware original does not.
const HTML_CODE_RE = new RegExp(
  `<(pre|code|samp|kbd)(?![\\p{L}\\p{N}_])[^>]*>.*?</\\1${SPACE}*>`,
  "gisu",
);
const INDENTED_BLOCK_RE = /(?:^|\n)(?:(?:[ ]{4}|\t)[^\n]*\n){2,}/gu;
const BLOCKQUOTE_RE = /(?:^|\n)(?:[ \t]*>[^\n]*\n?){1,}/gu;
// Paired quotation marks. Straight single quotes are excluded: apostrophes make
// them unpairable in ordinary English and the resulting spans are nonsense.
const QUOTE_RES = [
  /"[^"\n]{8,600}"/gu,
  /“[^”\n]{8,600}”/gu,
  /‘[^’\n]{8,600}’/gu,
  /«[^»\n]{8,600}»/gu,
  /「[^」\n]{8,600}」/gu,
];

// How far back to look for framing prose around a match.
const LOOKBEHIND_CHARS = 200;
const LOOKAHEAD_CHARS = 90;

export interface ContextProfileInit {
  codeSpans?: Span[];
  quoteSpans?: Span[];
  metaMarkers?: string[];
  textLength?: number;
}

/** Where the quoting constructs are, and how meta the document reads. */
export class ContextProfile {
  readonly codeSpans: Span[];
  readonly quoteSpans: Span[];
  readonly metaMarkers: string[];
  readonly textLength: number;

  constructor(init: ContextProfileInit = {}) {
    this.codeSpans = init.codeSpans ?? [];
    this.quoteSpans = init.quoteSpans ?? [];
    this.metaMarkers = init.metaMarkers ?? [];
    this.textLength = init.textLength ?? 0;
  }

  get documentIsMeta(): boolean {
    return this.metaMarkers.length >= DOC_META_THRESHOLD;
  }

  /** Share of the document inside code or quotes. A page that is mostly quoted
   * material is a specimen collection, not a message. Measured in UTF-16 units,
   * like every other offset in this library. */
  get quotedFraction(): number {
    if (!this.textLength) return 0.0;
    const covered = mergeSpans([...this.codeSpans, ...this.quoteSpans]);
    const total = covered.reduce((sum, [s, e]) => sum + (e - s), 0);
    return Math.min(1.0, total / this.textLength);
  }
}

function mergeSpans(spans: readonly Span[]): Span[] {
  if (spans.length === 0) return [];
  const ordered = [...spans].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const out: Span[] = [[ordered[0]![0], ordered[0]![1]]];
  for (const [start, end] of ordered.slice(1)) {
    const last = out[out.length - 1]!;
    if (start <= last[1]) last[1] = Math.max(last[1], end);
    else out.push([start, end]);
  }
  return out;
}

function spansOf(regexes: readonly RegExp[], text: string, limit = 400): Span[] {
  const spans: Span[] = [];
  for (const regex of regexes) {
    regex.lastIndex = 0;
    for (let m = regex.exec(text); m !== null; m = regex.exec(text)) {
      spans.push([m.index, m.index + m[0].length]);
      // Bail out early on pathological inputs, exactly as the reference does:
      // the remaining patterns are skipped, not merely truncated.
      if (spans.length >= limit) return mergeSpans(spans);
      // A zero-length match would spin forever; step past it.
      if (m[0].length === 0) regex.lastIndex += 1;
    }
  }
  return mergeSpans(spans);
}

/** Map the quoting constructs and meta-discourse in `text`. */
export function profile(text: string): ContextProfile {
  if (!text) return new ContextProfile();

  const code = spansOf([FENCE_RE, HTML_CODE_RE, INLINE_CODE_RE, INDENTED_BLOCK_RE], text);
  const quotes = spansOf([BLOCKQUOTE_RE, ...QUOTE_RES], text);

  const lowered = text.toLowerCase();
  const markers = META_MARKERS.filter((marker) => lowered.includes(marker));

  return new ContextProfile({
    codeSpans: code,
    quoteSpans: quotes,
    metaMarkers: markers,
    textLength: text.length,
  });
}

function inside(span: Span, spans: readonly Span[]): boolean {
  const midpoint = Math.floor((span[0] + span[1]) / 2);
  return spans.some(([s, e]) => s <= midpoint && midpoint < e);
}

/** Which independent context signals apply to a match at `span`. */
export function signalsFor(text: string, span: Span, prof: ContextProfile): string[] {
  const signals: string[] = [];
  if (inside(span, prof.codeSpans)) signals.push("in_code");
  if (inside(span, prof.quoteSpans)) signals.push("quoted");

  const [start, end] = span;
  const window = text
    .slice(Math.max(0, start - LOOKBEHIND_CHARS), Math.min(text.length, end + LOOKAHEAD_CHARS))
    .toLowerCase();
  if (META_MARKERS.some((marker) => window.includes(marker))) signals.push("meta_nearby");

  if (prof.documentIsMeta) signals.push("document_is_meta");
  return signals;
}

/** Weight multiplier for a finding at `span`, plus the signals behind it. */
export function discountFor(
  text: string,
  span: Span | undefined,
  prof: ContextProfile,
): { factor: number; signals: string[] } {
  if (span === undefined) return { factor: 1.0, signals: [] };
  const signals = signalsFor(text, span, prof);
  const factor = DISCOUNT_BY_SIGNALS[Math.min(signals.length, DISCOUNT_BY_SIGNALS.length - 1)]!;
  return { factor: Math.max(MIN_DISCOUNT, factor), signals };
}

/**
 * Round to 4 decimal places, so a re-weighted finding stays readable. Ties go
 * to the *even* digit, as the reference's `round()` does, where `toFixed`
 * rounds them up. The difference is real here because the discount factors are
 * multiplied into weights: 0.3125 discounted ×0.50 is exactly 0.15625, which
 * the reference reports as 0.1562 and `toFixed` as 0.1563. `toFixed(30)` is
 * correctly rounded and long enough to tell an exact tie from a value that
 * merely looks like one at four places. Only positive weights reach here —
 * {@link apply} passes the rest through untouched — so no sign handling.
 */
function round4(weight: number): number {
  const digits = weight.toFixed(30);
  const dot = digits.indexOf(".");
  const frac = digits.slice(dot + 1);
  let scaled = Number(digits.slice(0, dot) + frac.slice(0, 4));
  // Digit strings compare lexicographically the same way the fractions they
  // denote compare numerically, once trailing zeros are gone.
  const rest = frac.slice(4).replace(/0+$/, "");
  if (rest === "5" ? scaled % 2 !== 0 : rest > "5") scaled += 1;
  return scaled / 1e4;
}

/**
 * Return `findings` re-weighted for quoting context.
 *
 * Findings without a span (sanitization results, density heuristics) are
 * returned untouched: they describe the document as a whole, and "the document
 * as a whole" has no enclosing quotation to sit inside.
 */
export function apply(text: string, findings: readonly Finding[], prof?: ContextProfile): Finding[] {
  if (findings.length === 0) return [...findings];
  const p = prof ?? profile(text);
  if (!p.codeSpans.length && !p.quoteSpans.length && !p.documentIsMeta) return [...findings];

  const out: Finding[] = [];
  for (const finding of findings) {
    const { factor, signals } = discountFor(text, finding.span, p);
    if (factor >= 1.0 || finding.weight <= 0) {
      out.push(finding);
      continue;
    }
    out.push({
      ...finding,
      message: `${finding.message} (discounted ×${factor.toFixed(2)}: ${signals.join(", ")})`,
      weight: round4(finding.weight * factor),
    });
  }
  return out;
}
