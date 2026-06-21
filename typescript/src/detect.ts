/**
 * Stage 2 — detection and risk scoring.
 *
 * Runs the signature database plus structural heuristics over sanitized text,
 * then combines weighted signals into a single risk score with a noisy-OR:
 *   score = 1 - ∏ (1 - wᵢ)
 */

import { SIGNATURES } from "./patterns.js";
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

export interface DetectOptions {
  threshold?: number;
  extraFindings?: Finding[];
  useHeuristics?: boolean;
  /** Additional copy of the text scanned with the same signatures, results
   * merged (used for the confusable-folded copy so homoglyph disguises are
   * caught without breaking detection of legitimate non-Latin scripts). */
  alsoScan?: string;
}

export function detect(text: string, opts: DetectOptions = {}): DetectResult {
  const { threshold = 0.5, extraFindings = [], useHeuristics = true, alsoScan } = opts;
  const findings: Finding[] = [...extraFindings, ...matchSignatures(text)];
  if (alsoScan !== undefined && alsoScan !== text) {
    const seen = new Set(findings.map((f) => f.patternId).filter(Boolean));
    for (const f of matchSignatures(alsoScan)) {
      if (!seen.has(f.patternId)) {
        findings.push(f);
        seen.add(f.patternId);
      }
    }
  }
  if (useHeuristics) findings.push(...heuristicFindings(text));

  const score = scoreFindings(findings);
  const risk = bucket(score);
  const injected = score >= threshold || findings.some((f) => severityGte(f.severity, "high"));
  return { score, risk, injected, threshold, findings };
}
