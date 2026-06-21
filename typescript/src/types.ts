/** Core data types shared across Bulwark's pipeline stages. */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** True if `a` is at least as severe as `b`. */
export function severityGte(a: Severity, b: Severity): boolean {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b];
}

export type Stage = "sanitize" | "detect" | "validate";

export interface Finding {
  stage: Stage;
  category: string;
  severity: Severity;
  message: string;
  weight: number;
  excerpt?: string;
  span?: [number, number];
  patternId?: string;
}

export interface SanitizeResult {
  text: string;
  originalLength: number;
  cleanedLength: number;
  removed: Record<string, number>;
  findings: Finding[];
}

export interface DetectResult {
  score: number;
  risk: Severity;
  injected: boolean;
  threshold: number;
  findings: Finding[];
}

export interface SpotlightResult {
  content: string;
  nonce: string;
  methods: string[];
  marker?: string;
  base64Encoded: boolean;
}

export interface PromptContext {
  canary: string;
  nonce: string;
  marker?: string;
  base64Encoded: boolean;
}

export interface ValidationResult {
  safe: boolean;
  summary: string;
  redacted: boolean;
  findings: Finding[];
}

export type Messages = { role: string; content: string }[];

export type LLM = (messages: Messages) => string | Promise<string>;

export interface GuardResult {
  safe: boolean;
  blocked: boolean;
  summary: string | null;
  riskScore: number;
  risk: Severity;
  findings: Finding[];
  sanitize?: SanitizeResult;
  detect?: DetectResult;
  validation?: ValidationResult | null;
  rawOutput?: string | null;
  /** Human-readable explanation of what happened. */
  report: string;
}

/** Render a short human-readable report for a guard result. */
export function formatReport(
  status: "BLOCKED" | "SAFE" | "FLAGGED",
  risk: Severity,
  score: number,
  findings: Finding[],
): string {
  const lines: string[] = [];
  lines.push(`Bulwark: ${status}  (risk=${risk}, score=${score.toFixed(2)})`);
  if (findings.length === 0) {
    lines.push("  No injection signals detected.");
  } else {
    lines.push(`  ${findings.length} finding(s):`);
    const sorted = [...findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    for (const f of sorted.slice(0, 12)) {
      const excerpt = f.excerpt ? ` — ${JSON.stringify(f.excerpt)}` : "";
      lines.push(`    [${f.severity.padStart(8)}] ${f.stage}/${f.category}: ${f.message}${excerpt}`);
    }
    if (sorted.length > 12) lines.push(`    … and ${sorted.length - 12} more`);
  }
  return lines.join("\n");
}
