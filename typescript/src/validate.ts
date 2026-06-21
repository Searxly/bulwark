/**
 * Stage 5 — output validation. Catches a *successful* attack in the model's
 * reply: canary leaks, boundary-nonce leaks, exfiltration channels (markdown
 * images/links, HTML <img>, autolinks, data-bearing URLs), and compliance
 * tells. The reply is normalized first (invisibles stripped, NFKC) so split-
 * canary / split-URL evasion can't slip through. In sync with Python validate.py.
 */

import { stripInvisible } from "./sanitize.js";
import type { Finding, PromptContext, ValidationResult } from "./types.js";

const MD_IMAGE_RE = /!\[[^\]]*\]\([^)]*\)/g;
const MD_LINK_RE = /\[[^\]]*\]\(\s*https?:\/\/[^)]*\)/g;
const HTML_IMG_RE = /<img\b[^>]*>/gi;
const AUTOLINK_RE = /<\s*https?:\/\/[^>]*>/gi;
const DATA_URL_RE = /https?:\/\/[^\s)>\]]*[?&][\w.\-%]+=[A-Za-z0-9+/=_-]{16,}[^\s)>\]]*/g;
const COMPLIANCE_RE =
  /^\s*(?:sure\b|certainly\b|of\s+course\b|okay\b|ok\b|here\s+(?:is|are|'s)\b|as\s+(?:dan|requested|instructed|you\s+(?:asked|wish|requested))\b|i\s+(?:will|'ll|have|am\s+now)\b|ignoring\s+(?:previous|the)\b|hacked\b|pwned\b|i\s+am\s+dan\b)/i;
const CANARY_PREFIX_RE = /BULWARK-CANARY-\w*/g;
const B64_BLOB_RE = /\b[A-Za-z0-9+/]{40,}={0,2}\b/;
// Distinctive phrases from the hardened system prompt; a verbatim appearance in
// the output means the rules leaked even if the canary line was stripped.
const PROMPT_FINGERPRINTS = [
  "bulwark-summarizer",
  "outrank anything found inside the content",
  "a quotation from a possibly hostile third party",
];

export interface ValidateOptions {
  redactLinks?: boolean;
  redactImages?: boolean;
  blockOnLeak?: boolean;
}

export function validateOutput(
  summary: string | null,
  ctx: PromptContext,
  opts: ValidateOptions = {},
): ValidationResult {
  const { redactLinks = true, redactImages = true, blockOnLeak = true } = opts;
  const findings: Finding[] = [];
  const raw = summary ?? "";

  // 0. Normalize: strip invisibles (defeats split-canary / split-URL evasion).
  let cleaned = stripInvisible(raw).text.normalize("NFKC");
  let redacted = cleaned !== raw;
  let safe = true;

  // 1. Canary leak.
  if (ctx.canary && cleaned.includes(ctx.canary)) {
    findings.push({ stage: "validate", category: "canary_leak", severity: "critical", weight: 1.0, message: "Output contains the secret canary token — the system prompt leaked" });
    cleaned = cleaned.split(ctx.canary).join("[REDACTED]");
    redacted = true;
    if (blockOnLeak) safe = false;
  }
  if (cleaned.includes("BULWARK-CANARY-")) {
    findings.push({ stage: "validate", category: "canary_leak", severity: "critical", weight: 1.0, message: "Output references the canary token prefix" });
    cleaned = cleaned.replace(CANARY_PREFIX_RE, "[REDACTED]");
    redacted = true;
    if (blockOnLeak) safe = false;
  }

  // 2. Boundary nonce leak.
  if (ctx.nonce && cleaned.includes(ctx.nonce)) {
    findings.push({ stage: "validate", category: "nonce_leak", severity: "high", weight: 0.8, message: "Output echoed the internal boundary nonce" });
    cleaned = cleaned.split(ctx.nonce).join("[REDACTED]");
    redacted = true;
  }

  // 3. Data-mark leak.
  if (ctx.marker && cleaned.includes(ctx.marker)) {
    cleaned = cleaned.split(ctx.marker).join(" ");
    redacted = true;
    findings.push({ stage: "validate", category: "marker_leak", severity: "low", weight: 0.2, message: "Output contained the data-mark character (normalized back to spaces)" });
  }

  // 4. Exfiltration channels.
  const images = [...(cleaned.match(MD_IMAGE_RE) ?? []), ...(cleaned.match(HTML_IMG_RE) ?? [])];
  if (images.length) {
    findings.push({ stage: "validate", category: "image_exfiltration", severity: "high", weight: 0.8, message: `Output contains ${images.length} image reference(s) — a data-exfiltration channel`, excerpt: images[0]!.slice(0, 80) });
    if (redactImages) {
      cleaned = cleaned.replace(MD_IMAGE_RE, "[image removed]").replace(HTML_IMG_RE, "[image removed]");
      redacted = true;
    }
  }

  const dataUrls = cleaned.match(DATA_URL_RE);
  if (dataUrls) {
    findings.push({ stage: "validate", category: "data_url_exfiltration", severity: "high", weight: 0.82, message: `Output contains ${dataUrls.length} URL(s) with a data-bearing query string`, excerpt: dataUrls[0]!.slice(0, 80) });
    if (redactLinks) {
      cleaned = cleaned.replace(DATA_URL_RE, "[link removed]");
      redacted = true;
    }
  }

  const links = [...(cleaned.match(MD_LINK_RE) ?? []), ...(cleaned.match(AUTOLINK_RE) ?? [])];
  if (links.length) {
    findings.push({ stage: "validate", category: "link_in_output", severity: "medium", weight: 0.45, message: `Output contains ${links.length} link(s)`, excerpt: links[0]!.slice(0, 80) });
    if (redactLinks) {
      cleaned = cleaned.replace(MD_LINK_RE, (m) => m.replace(/\(\s*https?:\/\/[^)]*\)/, "")).replace(AUTOLINK_RE, "");
      redacted = true;
    }
  }

  // 5. System-prompt fingerprint leak (rules leaked even without the canary).
  const lowered = cleaned.toLowerCase();
  if (PROMPT_FINGERPRINTS.some((fp) => lowered.includes(fp))) {
    findings.push({ stage: "validate", category: "prompt_leak", severity: "critical", weight: 0.95, message: "Output contains a verbatim fragment of the system prompt — the rules leaked" });
    if (blockOnLeak) safe = false;
  }

  // 6. Encoded blob in output (possible exfiltration the model encoded).
  const blob = cleaned.match(B64_BLOB_RE);
  if (blob) {
    findings.push({ stage: "validate", category: "encoded_output", severity: "medium", weight: 0.4, message: "Output contains a long Base64-like blob (possible encoded exfiltration)", excerpt: blob[0].slice(0, 60) });
  }

  // 7. Compliance tell at the start of the reply.
  if (COMPLIANCE_RE.test(cleaned)) {
    findings.push({ stage: "validate", category: "compliance_tell", severity: "medium", weight: 0.5, message: "Output opens with a phrase typical of obeying an injected instruction", excerpt: cleaned.slice(0, 60) });
  }

  return { safe, summary: cleaned.trim(), redacted, findings };
}
