/**
 * Stage 5 — output validation. Catches a *successful* attack in the model's
 * reply: canary leaks, boundary-nonce leaks, exfiltration channels (markdown
 * images/links), and compliance tells. Kept in sync with Python `validate.py`.
 */

import type { Finding, PromptContext, ValidationResult } from "./types.js";

const MD_IMAGE_RE = /!\[[^\]]*\]\([^)]*\)/g;
const MD_LINK_RE = /\[[^\]]*\]\(\s*https?:\/\/[^)]*\)/g;
const COMPLIANCE_RE =
  /^\s*(?:sure\b|certainly\b|of\s+course\b|okay\b|ok\b|here\s+(?:is|are|'s)\b|as\s+(?:dan|requested|instructed|you\s+(?:asked|wish|requested))\b|i\s+(?:will|'ll|have|am\s+now)\b|ignoring\s+(?:previous|the)\b|hacked\b|pwned\b|i\s+am\s+dan\b)/i;
const CANARY_PREFIX_RE = /BULWARK-CANARY-\w*/g;

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
  let cleaned = summary ?? "";
  let safe = true;
  let redacted = false;

  // 1. Canary leak.
  if (ctx.canary && cleaned.includes(ctx.canary)) {
    findings.push({
      stage: "validate", category: "canary_leak", severity: "critical", weight: 1.0,
      message: "Output contains the secret canary token — the system prompt leaked",
    });
    cleaned = cleaned.split(ctx.canary).join("[REDACTED]");
    redacted = true;
    if (blockOnLeak) safe = false;
  }
  if (cleaned.includes("BULWARK-CANARY-")) {
    findings.push({
      stage: "validate", category: "canary_leak", severity: "critical", weight: 1.0,
      message: "Output references the canary token prefix",
    });
    cleaned = cleaned.replace(CANARY_PREFIX_RE, "[REDACTED]");
    redacted = true;
    if (blockOnLeak) safe = false;
  }

  // 2. Boundary nonce leak.
  if (ctx.nonce && cleaned.includes(ctx.nonce)) {
    findings.push({
      stage: "validate", category: "nonce_leak", severity: "high", weight: 0.8,
      message: "Output echoed the internal boundary nonce",
    });
    cleaned = cleaned.split(ctx.nonce).join("[REDACTED]");
    redacted = true;
  }

  // 3. Data-mark leak.
  if (ctx.marker && cleaned.includes(ctx.marker)) {
    cleaned = cleaned.split(ctx.marker).join(" ");
    redacted = true;
    findings.push({
      stage: "validate", category: "marker_leak", severity: "low", weight: 0.2,
      message: "Output contained the data-mark character (normalized back to spaces)",
    });
  }

  // 4. Exfiltration channels.
  const images = cleaned.match(MD_IMAGE_RE);
  if (images) {
    findings.push({
      stage: "validate", category: "image_exfiltration", severity: "high", weight: 0.8,
      message: `Output contains ${images.length} markdown image(s) — a data-exfiltration channel`,
      excerpt: images[0]!.slice(0, 80),
    });
    if (redactImages) {
      cleaned = cleaned.replace(MD_IMAGE_RE, "[image removed]");
      redacted = true;
    }
  }

  const links = cleaned.match(MD_LINK_RE);
  if (links) {
    findings.push({
      stage: "validate", category: "link_in_output", severity: "medium", weight: 0.45,
      message: `Output contains ${links.length} markdown link(s)`,
      excerpt: links[0]!.slice(0, 80),
    });
    if (redactLinks) {
      cleaned = cleaned.replace(MD_LINK_RE, (m) => m.replace(/\(\s*https?:\/\/[^)]*\)/, ""));
      redacted = true;
    }
  }

  // 5. Compliance tell at the start of the reply.
  if (COMPLIANCE_RE.test(cleaned)) {
    findings.push({
      stage: "validate", category: "compliance_tell", severity: "medium", weight: 0.5,
      message: "Output opens with a phrase typical of obeying an injected instruction",
      excerpt: cleaned.slice(0, 60),
    });
  }

  return { safe, summary: cleaned.trim(), redacted, findings };
}
