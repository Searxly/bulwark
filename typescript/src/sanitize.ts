/**
 * Stage 1 — sanitization.
 *
 * Removes invisible/structural tricks attackers use to smuggle instructions:
 * Unicode Tag characters (ASCII smuggling), bidi controls (Trojan Source),
 * zero-width separators, variation-selector smuggling, control characters,
 * and HTML comments / scripts / CSS-hidden elements. Confusable evasion
 * (full-width text, etc.) is folded away with NFKC normalization.
 *
 * Kept behaviourally in sync with the Python `sanitize.py`.
 */

import type { Finding, SanitizeResult } from "./types.js";

const ZERO_WIDTH = new Set([
  0x200b, 0x200c, 0x200d, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff, 0x180e, 0x00ad,
]);
const BIDI = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200e, 0x200f, 0x061c]);

function isTag(cp: number): boolean {
  return cp >= 0xe0000 && cp <= 0xe007f;
}
function isVariationSelector(cp: number): boolean {
  return (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
}
function isControl(cp: number): boolean {
  return cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f);
}

const SCRIPT_STYLE_RE = /<(script|style|template|noscript)\b[^>]*>[\s\S]*?<\/\1\s*>/gi;
const COMMENT_RE = /<!--[\s\S]*?-->/g;
const HIDDEN_STYLE_RE = new RegExp(
  "<(?<tag>[a-zA-Z][\\w:-]*)\\b[^>]*?(?:" +
    "style\\s*=\\s*[\"'][^\"']*(?:display\\s*:\\s*none|visibility\\s*:\\s*hidden|opacity\\s*:\\s*0|font-size\\s*:\\s*0)" +
    "|aria-hidden\\s*=\\s*[\"']true[\"']|hidden(?=[\\s>]))" +
    "[^>]*>[\\s\\S]*?</\\k<tag>\\s*>",
  "gi",
);
const TAG_RE = /<[^>]+>/g;
const WS_RE = /[^\S\n]+/g;
const BLANKLINES_RE = /\n{3,}/g;
const HTMLISH_RE = /<(?:\/?[a-zA-Z][\w:-]*\b|!--)/;

const HTML_ENTITIES: Record<string, string> = {
  "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'", "&apos;": "'", "&nbsp;": " ",
};

function unescapeHtml(text: string): string {
  return text
    .replace(/&(amp|lt|gt|quot|apos|nbsp);|&#39;/gi, (m) => HTML_ENTITIES[m.toLowerCase()] ?? HTML_ENTITIES[m] ?? m)
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)));
}

export interface StripResult {
  text: string;
  counts: Record<string, number>;
  findings: Finding[];
}

export function stripInvisible(text: string, keepEmojiVariation = false): StripResult {
  const counts: Record<string, number> = {};
  const out: string[] = [];
  const bump = (k: string) => {
    counts[k] = (counts[k] ?? 0) + 1;
  };

  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (isTag(cp)) {
      bump("tag_chars");
      continue;
    }
    if (BIDI.has(cp)) {
      bump("bidi_controls");
      continue;
    }
    if (isVariationSelector(cp)) {
      if (keepEmojiVariation && cp >= 0xfe00 && cp <= 0xfe0f) {
        out.push(ch);
        continue;
      }
      bump("variation_selectors");
      continue;
    }
    if (ZERO_WIDTH.has(cp)) {
      bump("zero_width");
      continue;
    }
    if (ch === "\t" || ch === "\n" || ch === "\r") {
      out.push(ch);
      continue;
    }
    if (isControl(cp)) {
      bump("control_chars");
      continue;
    }
    out.push(ch);
  }

  const findings: Finding[] = [];
  if (counts.tag_chars) {
    findings.push({
      stage: "sanitize", category: "ascii_smuggling", severity: "critical", weight: 0.9,
      message: `Removed ${counts.tag_chars} Unicode Tag character(s) used to smuggle hidden text`,
    });
  }
  if (counts.bidi_controls) {
    findings.push({
      stage: "sanitize", category: "bidi_control", severity: "high", weight: 0.62,
      message: `Removed ${counts.bidi_controls} bidirectional control character(s) (Trojan Source)`,
    });
  }
  if (counts.variation_selectors) {
    findings.push({
      stage: "sanitize", category: "variation_smuggling", severity: "high", weight: 0.66,
      message: `Removed ${counts.variation_selectors} variation selector(s) (possible data smuggling)`,
    });
  }
  if (counts.zero_width) {
    findings.push({
      stage: "sanitize", category: "zero_width", severity: "low", weight: 0.24,
      message: `Removed ${counts.zero_width} zero-width character(s) (often used to split trigger words)`,
    });
  }
  if (counts.control_chars) {
    findings.push({
      stage: "sanitize", category: "control_chars", severity: "low", weight: 0.15,
      message: `Removed ${counts.control_chars} control character(s)`,
    });
  }
  return { text: out.join(""), counts, findings };
}

export function stripHtml(text: string): StripResult {
  const counts: Record<string, number> = {};
  const findings: Finding[] = [];

  const countAndStrip = (re: RegExp, s: string, key: string): string => {
    const matches = s.match(re);
    if (matches) counts[key] = (counts[key] ?? 0) + matches.length;
    return s.replace(re, " ");
  };

  let cleaned = countAndStrip(COMMENT_RE, text, "html_comments");
  cleaned = countAndStrip(SCRIPT_STYLE_RE, cleaned, "script_style");

  const hidden = cleaned.match(HIDDEN_STYLE_RE);
  if (hidden) {
    counts.hidden_elements = hidden.length;
    findings.push({
      stage: "sanitize", category: "hidden_html", severity: "medium", weight: 0.55,
      message: `Removed ${hidden.length} visually hidden HTML element(s) (text invisible to humans)`,
    });
  }
  cleaned = cleaned.replace(HIDDEN_STYLE_RE, " ");
  cleaned = cleaned.replace(TAG_RE, " ");
  cleaned = unescapeHtml(cleaned);
  return { text: cleaned, counts, findings };
}

export function normalize(text: string): string {
  let t = text.normalize("NFKC");
  t = t.replace(WS_RE, " ");
  t = t
    .split("\n")
    .map((line) => line.trim())
    .join("\n");
  t = t.replace(BLANKLINES_RE, "\n\n");
  return t.trim();
}

export function looksLikeHtml(text: string): boolean {
  return HTMLISH_RE.test(text);
}

export interface SanitizeOptions {
  stripHtmlContent?: boolean | "auto";
  normalizeUnicode?: boolean;
  keepEmojiVariation?: boolean;
}

export function sanitize(text: string, opts: SanitizeOptions = {}): SanitizeResult {
  const { stripHtmlContent = "auto", normalizeUnicode = true, keepEmojiVariation = false } = opts;
  const originalLength = text.length;
  const removed: Record<string, number> = {};
  const findings: Finding[] = [];

  const doHtml = stripHtmlContent === "auto" ? looksLikeHtml(text) : Boolean(stripHtmlContent);
  let working = text;
  if (doHtml) {
    const r = stripHtml(working);
    working = r.text;
    Object.assign(removed, r.counts);
    findings.push(...r.findings);
  }

  const inv = stripInvisible(working, keepEmojiVariation);
  working = inv.text;
  for (const [k, v] of Object.entries(inv.counts)) removed[k] = (removed[k] ?? 0) + v;
  findings.push(...inv.findings);

  working = normalizeUnicode ? normalize(working) : working.replace(WS_RE, " ").trim();

  return {
    text: working,
    originalLength,
    cleanedLength: working.length,
    removed,
    findings,
  };
}
