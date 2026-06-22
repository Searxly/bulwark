/**
 * Strip invisible and structural injection vectors from untrusted text: ASCII
 * smuggling (Unicode tag chars), bidi controls, zero-width and control chars,
 * and CSS-hidden HTML (stack-based extractor that handles nesting), then NFKC.
 * `foldConfusables` handles cross-script homoglyphs on the detection copy only.
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

// Cross-script homoglyphs → ASCII (1:1 so detection offsets stay aligned).
const CONFUSABLES: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
  "ӏ": "l", "ԁ": "d", "к": "k",
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
  "У": "Y", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
  "ο": "o", "α": "a", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "ς": "c",
  "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ρ": "P",
  "Τ": "T", "Υ": "Y", "Χ": "X", "Ζ": "Z",
  "ı": "i", "․": ".",
};

/** Map cross-script homoglyphs to ASCII. Detection-only — never send to a model. */
export function foldConfusables(text: string): string {
  let out = "";
  for (const ch of text) out += CONFUSABLES[ch] ?? ch;
  return out;
}

// Leetspeak / digit-substitution → ASCII letters (1:1, offsets stay aligned).
// Attackers swap letters for look-alike digits/symbols ("1gn0r3 pr3v10us") to
// dodge keyword filters while the model still reads the word. Detection-only.
const LEET: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
};

/** Map common leetspeak substitutions to ASCII letters. Detection-only. */
export function foldLeet(text: string): string {
  let out = "";
  for (const ch of text) out += LEET[ch] ?? ch;
  return out;
}

/** Detector's second-pass copy: fold leetspeak, then cross-script homoglyphs.
 * Both are 1:1 so detection offsets stay aligned. Detection-only. */
export function foldDetection(text: string): string {
  return foldConfusables(foldLeet(text));
}

const HIDDEN_STYLE_RE = /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px|em|rem|%)?\b/i;
const HIDDEN_ATTR_RE = /(?:^|\s)hidden(?=[\s=>]|$)/i;
const ARIA_HIDDEN_RE = /aria-hidden\s*=\s*["']?true/i;
const WS_RE = /[^\S\n]+/g;
const BLANKLINES_RE = /\n{3,}/g;
const HTMLISH_RE = /<(?:\/?[a-zA-Z][\w:-]*\b|!--)/;
const TAG_NAME_RE = /^([a-zA-Z][\w:-]*)/;

const RAWTEXT_TAGS = new Set(["script", "style", "noscript", "template", "svg", "math"]);
const BLOCK_TAGS = new Set([
  "p", "div", "br", "li", "ul", "ol", "tr", "table", "section", "article",
  "header", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "hr",
]);
const VOID_TAGS = new Set(["br", "img", "hr", "input", "meta", "link", "source", "area", "base", "col", "embed", "wbr"]);

const HTML_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ",
};

function unescapeHtml(text: string): string {
  return text
    .replace(/&(amp|lt|gt|quot|apos|nbsp);/gi, (_m, n: string) => HTML_ENTITIES[n.toLowerCase()] ?? _m)
    .replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_m, d: string) => String.fromCodePoint(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_m, h: string) => String.fromCodePoint(parseInt(h, 16)));
}

function attrsAreHidden(attrStr: string): boolean {
  return HIDDEN_ATTR_RE.test(attrStr) || ARIA_HIDDEN_RE.test(attrStr) || HIDDEN_STYLE_RE.test(attrStr);
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
    } else if (BIDI.has(cp)) {
      bump("bidi_controls");
    } else if (isVariationSelector(cp)) {
      if (keepEmojiVariation && cp >= 0xfe00 && cp <= 0xfe0f) out.push(ch);
      else bump("variation_selectors");
    } else if (ZERO_WIDTH.has(cp)) {
      bump("zero_width");
    } else if (ch === "\t" || ch === "\n" || ch === "\r") {
      out.push(ch);
    } else if (isControl(cp)) {
      bump("control_chars");
    } else {
      out.push(ch);
    }
  }

  const findings: Finding[] = [];
  if (counts.tag_chars)
    findings.push({ stage: "sanitize", category: "ascii_smuggling", severity: "critical", weight: 0.9, message: `Removed ${counts.tag_chars} Unicode Tag character(s) used to smuggle hidden text` });
  if (counts.bidi_controls)
    findings.push({ stage: "sanitize", category: "bidi_control", severity: "high", weight: 0.62, message: `Removed ${counts.bidi_controls} bidirectional control character(s) (Trojan Source)` });
  if (counts.variation_selectors)
    findings.push({ stage: "sanitize", category: "variation_smuggling", severity: "high", weight: 0.66, message: `Removed ${counts.variation_selectors} variation selector(s) (possible data smuggling)` });
  if (counts.zero_width)
    findings.push({ stage: "sanitize", category: "zero_width", severity: "low", weight: 0.24, message: `Removed ${counts.zero_width} zero-width character(s) (often used to split trigger words)` });
  if (counts.control_chars)
    findings.push({ stage: "sanitize", category: "control_chars", severity: "low", weight: 0.15, message: `Removed ${counts.control_chars} control character(s)` });
  return { text: out.join(""), counts, findings };
}

/** Stack-based HTML text extractor: emits only the text a human would see. */
export function stripHtml(text: string): StripResult {
  const counts: Record<string, number> = {};
  const findings: Finding[] = [];
  const out: string[] = [];
  const stack: { tag: string; hidden: boolean }[] = [];
  let skipDepth = 0;
  let comments = 0;
  let scriptStyle = 0;
  let hiddenElements = 0;
  const n = text.length;
  let i = 0;

  const emit = (s: string) => {
    if (skipDepth === 0) out.push(s);
  };

  while (i < n) {
    const lt = text.indexOf("<", i);
    if (lt === -1) {
      emit(text.slice(i));
      break;
    }
    if (lt > i) emit(text.slice(i, lt));

    if (text.startsWith("<!--", lt)) {
      const end = text.indexOf("-->", lt + 4);
      comments++;
      i = end === -1 ? n : end + 3;
      continue;
    }
    if (text.startsWith("<!", lt)) {
      const end = text.indexOf(">", lt + 2);
      i = end === -1 ? n : end + 1;
      continue;
    }

    const gt = text.indexOf(">", lt + 1);
    if (gt === -1) {
      emit(text.slice(lt));
      break;
    }
    let body = text.slice(lt + 1, gt);
    i = gt + 1;

    let isEnd = false;
    if (body.startsWith("/")) {
      isEnd = true;
      body = body.slice(1);
    }
    let selfClose = false;
    if (body.endsWith("/")) {
      selfClose = true;
      body = body.slice(0, -1);
    }
    const m = TAG_NAME_RE.exec(body);
    if (!m) continue;
    const tag = m[1]!.toLowerCase();
    const attrStr = body.slice(m[1]!.length);

    if (isEnd) {
      for (let s = stack.length - 1; s >= 0; s--) {
        if (stack[s]!.tag === tag) {
          if (stack[s]!.hidden && skipDepth > 0) skipDepth--;
          stack.length = s;
          break;
        }
      }
      if (BLOCK_TAGS.has(tag)) out.push("\n");
      continue;
    }

    if (RAWTEXT_TAGS.has(tag)) {
      scriptStyle++;
      const closeRe = new RegExp("</\\s*" + tag + "\\s*>", "i");
      const cm = closeRe.exec(text.slice(i));
      i = cm ? i + cm.index + cm[0].length : n;
      continue;
    }

    const hidden = attrsAreHidden(attrStr);
    if (!VOID_TAGS.has(tag) && !selfClose) {
      stack.push({ tag, hidden });
      if (hidden) {
        hiddenElements++;
        skipDepth++;
      }
    }
    if (BLOCK_TAGS.has(tag)) out.push("\n");
  }

  if (comments) counts.html_comments = comments;
  if (scriptStyle) counts.script_style = scriptStyle;
  if (hiddenElements) {
    counts.hidden_elements = hiddenElements;
    findings.push({
      stage: "sanitize", category: "hidden_html", severity: "medium", weight: 0.55,
      message: `Removed ${hiddenElements} visually hidden HTML element(s) (text invisible to humans)`,
    });
  }
  return { text: unescapeHtml(out.join("")), counts, findings };
}

export function normalize(text: string): string {
  let t = text.normalize("NFKC");
  t = t.replace(WS_RE, " ");
  t = t.split("\n").map((line) => line.trim()).join("\n");
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

  return { text: working, originalLength, cleanedLength: working.length, removed, findings };
}
