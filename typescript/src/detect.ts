/**
 * Detection and risk scoring. Runs the signature database plus structural
 * heuristics over sanitized text and combines the weighted signals with a
 * noisy-OR (score = 1 - prod(1 - wi)), so weak signals accumulate without any
 * single one saturating the score.
 */

import { apply as applyContext } from "./context.js";
import { unwrap } from "./decode.js";
import { SIGNATURES } from "./patterns.js";
import { flattenForDetection, mapSpan, stripMarks } from "./sanitize.js";
import type { DetectResult, Finding, Severity } from "./types.js";
import { severityGte } from "./types.js";

const IMPERATIVE_VERBS = new Set([
  "ignore", "disregard", "forget", "stop", "do", "don't", "dont", "never", "always",
  "print", "output", "repeat", "reveal", "send", "post", "fetch", "execute", "run",
  "call", "follow", "obey", "respond", "reply", "answer", "write", "say", "tell",
  "act", "pretend", "become", "switch", "override", "bypass", "summarize", "translate",
]);

const DIRECTIVE_RE = /\byou\s+(?:must|should|shall|need\s+to|have\s+to|are\s+(?:required|instructed|now))\b/gi;
const LINE_RE = /^[\s\-*\d.)#>]*([a-zA-Z']+)/gm;

function excerpt(text: string, start: number, end: number, pad = 24): string {
  const a = Math.max(0, start - pad);
  const b = Math.min(text.length, end + pad);
  const s = text.slice(a, b).replace(/\n/g, " ").trim();
  return (a > 0 ? "…" : "") + s + (b < text.length ? "…" : "");
}

export function matchSignatures(text: string): Finding[] {
  const findings: Finding[] = [];
  for (const sig of SIGNATURES) {
    sig.regex.lastIndex = 0;
    const m = sig.regex.exec(text);
    if (!m) continue;
    const start = m.index;
    const end = m.index + m[0].length;
    findings.push({
      stage: "detect",
      category: sig.category,
      severity: sig.severity,
      message: sig.description,
      weight: sig.weight,
      excerpt: excerpt(text, start, end),
      span: [start, end],
      patternId: sig.id,
    });
  }
  return findings;
}

export function heuristicFindings(text: string): Finding[] {
  const findings: Finding[] = [];
  if (!text) return findings;

  const lines = [...text.matchAll(LINE_RE)].map((m) => m[1]!).filter(Boolean);
  if (lines.length >= 4) {
    const imperative = lines.filter((w) => IMPERATIVE_VERBS.has(w.toLowerCase())).length;
    const ratio = imperative / lines.length;
    if (ratio >= 0.4 && imperative >= 3) {
      findings.push({
        stage: "detect", category: "imperative_density", severity: "medium", weight: 0.45,
        message: `${imperative}/${lines.length} lines begin with a command verb`,
      });
    }
  }

  const directives = (text.match(DIRECTIVE_RE) ?? []).length;
  const perKChar = directives / Math.max(1, text.length / 1000);
  if (directives >= 2 && perKChar >= 1.5) {
    findings.push({
      stage: "detect", category: "directive_density", severity: "medium", weight: 0.4,
      message: `${directives} second-person directive(s) addressed to the assistant`,
    });
  }
  return findings;
}

export function scoreFindings(findings: Iterable<Finding>): number {
  let product = 1.0;
  for (const f of findings) {
    const w = Math.max(0, Math.min(0.99, f.weight));
    product *= 1 - w;
  }
  return 1 - product;
}

export function bucket(score: number): Severity {
  if (score >= 0.9) return "critical";
  if (score >= 0.7) return "high";
  if (score >= 0.4) return "medium";
  if (score >= 0.15) return "low";
  return "info";
}

/** Signatures that only appear once an encoded payload is decoded.
 *
 * A hit inside an encoded layer is *stronger* evidence than the same hit in
 * plaintext, not weaker: ordinary documents contain hashes and tokens, but
 * nobody accidentally Base64-encodes "ignore all previous instructions". So
 * each contaminated layer contributes one high-weight finding rather than
 * re-emitting every match, which would let a single payload stack the
 * noisy-OR several times over. */
export function decodedFindings(text: string): Finding[] {
  const findings: Finding[] = [];
  for (const layer of unwrap(text)) {
    const matches = matchSignatures(layer.text);
    if (matches.length === 0) continue;
    const ids = [...new Set(matches.map((m) => m.patternId).filter(Boolean))].sort().slice(0, 4).join(", ");
    const worst = matches.reduce((a, b) => (b.weight > a.weight ? b : a));
    findings.push({
      stage: "detect",
      category: "encoded_payload",
      severity: "critical",
      weight: Math.min(0.92, Math.max(0.8, worst.weight)),
      message: `A payload hidden under ${layer.label} decodes to injection content (${ids})`,
      excerpt: layer.text.slice(0, 60),
      patternId: `enc.decoded[${layer.label}]`,
    });
  }
  return findings;
}

export interface DetectOptions {
  threshold?: number;
  extraFindings?: Finding[];
  useHeuristics?: boolean;
  /** Additional copy of the text scanned with the same signatures, results
   * merged (used for the confusable-folded copy so homoglyph disguises are
   * caught without breaking detection of legitimate non-Latin scripts). */
  alsoScan?: string;
  /** Text to recursively decode and re-scan. Pass the **raw**, pre-sanitization
   * content: channels such as zero-width bit strings are removed by
   * sanitization precisely because they are invisible, and decoding them
   * afterwards would find nothing. */
  alsoDecode?: string;
  /** Discount findings that sit inside quoted or code-fenced passages of a
   * document that reads as writing *about* attacks. Reduces weight; never
   * removes a finding. */
  useContext?: boolean;
  /** Also scan a whitespace-flattened, de-hyphenated view. Without it, hard
   * wrapping the payload defeats every bounded-span signature. */
  flatten?: boolean;
}

export function detect(text: string, opts: DetectOptions = {}): DetectResult {
  const {
    threshold = 0.5, extraFindings = [], useHeuristics = true, alsoScan,
    alsoDecode, useContext = true, flatten = true,
  } = opts;
  let findings: Finding[] = [...extraFindings, ...matchSignatures(text)];
  const seenIds = new Set(findings.map((f) => f.patternId).filter(Boolean));

  const merge = (incoming: Finding[], index?: number[]): void => {
    for (const f of incoming) {
      if (seenIds.has(f.patternId)) continue;
      seenIds.add(f.patternId);
      findings.push(
        index && f.span
          ? { ...f, span: mapSpan(f.span as [number, number], index, text.length) }
          : f,
      );
    }
  };

  // Homoglyph / leetspeak view — 1:1, so spans need no remapping.
  if (alsoScan !== undefined && alsoScan !== text) merge(matchSignatures(alsoScan));

  if (flatten) {
    for (const view of [text, alsoScan]) {
      if (view === undefined) continue;
      const flat = flattenForDetection(view);
      if (flat.text && flat.text !== view) merge(matchSignatures(flat.text), flat.index);
      // Combining marks stacked on ASCII letters hide trigger words from every
      // signature; strip them on the flattened view too.
      const unmarked = stripMarks(flat.text);
      if (unmarked !== flat.text) merge(matchSignatures(unmarked));
    }
  }

  if (useHeuristics) findings.push(...heuristicFindings(text));

  if (useContext) findings = applyContext(text, findings);

  // Decoded findings are added after the context pass on purpose: an encoded
  // payload has no visible quoting context to sit inside, and discounting it
  // for the fence around the blob would reward the obfuscation.
  if (alsoDecode !== undefined) findings.push(...decodedFindings(alsoDecode));

  const score = scoreFindings(findings);
  const risk = bucket(score);
  const injected = score >= threshold || findings.some((f) => severityGte(f.severity, "high"));
  return { score, risk, injected, threshold, findings };
}
