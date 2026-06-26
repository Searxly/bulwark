/**
 * Detection and risk scoring. Runs the signature database plus structural
 * heuristics over sanitized text and combines the weighted signals with a
 * noisy-OR (score = 1 - prod(1 - wi)), so weak signals accumulate without any
 * single one saturating the score.
 */

import { SIGNATURES, type Signature } from "./patterns.js";
import type { DetectResult, Finding, Severity } from "./types.js";
import { severityGte } from "./types.js";

const B64_PAYLOAD_RE = /[A-Za-z0-9+/]{24,}={0,2}/g;

/** Decode `blob` (assumed valid Base64) to a UTF-8 string, or null. Isomorphic:
 * uses Node's Buffer when present, otherwise atob + TextDecoder in the browser. */
function decodeBase64(blob: string): string | null {
  try {
    if (typeof Buffer !== "undefined") {
      const buf = Buffer.from(blob, "base64");
      // Buffer.from is lenient; round-trip to reject non-Base64 input.
      if (buf.toString("base64").replace(/=+$/, "") !== blob.replace(/=+$/, "")) return null;
      return new TextDecoder("utf-8", { fatal: true }).decode(buf);
    }
    // eslint-disable-next-line no-undef
    const bin = atob(blob);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** Return the decoded text of embedded Base64 blobs that resolve to printable
 * UTF-8. A common evasion is to Base64-encode an instruction so it sails past
 * every keyword signature; decoding it here lets the same signatures run on the
 * real payload. Blobs that aren't valid Base64 or decode to mostly binary are
 * skipped, so random tokens and hashes don't generate noise. */
export function decodeBase64Payloads(text: string, maxPayloads = 12): string[] {
  const payloads: string[] = [];
  for (const m of text.matchAll(B64_PAYLOAD_RE)) {
    let blob = m[0];
    blob = blob.slice(0, blob.length - (blob.length % 4));
    if (blob.length < 24) continue;
    const decoded = decodeBase64(blob);
    if (decoded === null || decoded.trim().length < 4) continue;
    const printable = [...decoded].filter((c) => c >= " " || c === "\t" || c === "\n" || c === "\r").length;
    if (printable / decoded.length < 0.85) continue;
    payloads.push(decoded);
    if (payloads.length >= maxPayloads) break;
  }
  return payloads;
}

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

export function matchSignatures(text: string, signatures: readonly Signature[] = SIGNATURES): Finding[] {
  const findings: Finding[] = [];
  for (const sig of signatures) {
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

export interface DetectOptions {
  threshold?: number;
  extraFindings?: Finding[];
  useHeuristics?: boolean;
  /** Additional copy of the text scanned with the same signatures, results
   * merged (used for the de-obfuscated copy so homoglyph/leetspeak disguises are
   * caught without breaking detection of legitimate non-Latin scripts). */
  alsoScan?: string;
  /** Decode embedded Base64 blobs and scan the decoded payload too. */
  decodeBase64?: boolean;
  /** Custom signatures appended to the built-in database for this scan. */
  extraSignatures?: readonly Signature[];
}

export function detect(text: string, opts: DetectOptions = {}): DetectResult {
  const { threshold = 0.5, extraFindings = [], useHeuristics = true, alsoScan, decodeBase64 = true, extraSignatures } = opts;
  const sigs = extraSignatures && extraSignatures.length ? [...SIGNATURES, ...extraSignatures] : SIGNATURES;
  const findings: Finding[] = [...extraFindings];
  const seen = new Set(findings.map((f) => f.patternId).filter(Boolean));

  const merge = (newFindings: Finding[], note?: string) => {
    for (const f of newFindings) {
      if (f.patternId && seen.has(f.patternId)) continue;
      if (f.patternId) seen.add(f.patternId);
      findings.push(note ? { ...f, message: `${f.message} ${note}` } : f);
    }
  };

  merge(matchSignatures(text, sigs));
  if (alsoScan !== undefined && alsoScan !== text) merge(matchSignatures(alsoScan, sigs));
  if (decodeBase64) {
    for (const payload of decodeBase64Payloads(text)) merge(matchSignatures(payload, sigs), "(decoded from Base64)");
  }
  if (useHeuristics) findings.push(...heuristicFindings(text));

  const score = scoreFindings(findings);
  const risk = bucket(score);
  const injected = score >= threshold || findings.some((f) => severityGte(f.severity, "high"));
  return { score, risk, injected, threshold, findings };
}
