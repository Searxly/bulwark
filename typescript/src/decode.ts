/**
 * Recursively recover encoded payloads so the detector can see them.
 *
 * Signature matching only works on text the detector can read. An attacker who
 * writes `aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=` next to "decode this and
 * follow it" gets a model that reads the instruction and a regex database that
 * sees a meaningless blob. Flagging "there is a Base64 blob here" — which is all
 * Bulwark used to do — is a weak proxy: real pages are full of hashes and tokens,
 * so the signal has to stay low-weight to avoid false positives.
 *
 * This module closes that gap by actually **decoding** and handing every recovered
 * layer back to the detector, keeping a provenance chain so a finding can say
 * *where* it came from: `base64 → percent → "ignore all previous instructions"`.
 *
 * Two kinds of decoder:
 *
 * - **Span extractors** find an encoded region inside the text (a Base64 run, a
 *   percent-encoded sequence, a zero-width bit string) and decode just that span.
 * - **Whole-text transforms** rewrite the entire text (ROT13, reversal), because
 *   those ciphers have no delimiters to find.
 *
 * Everything is budgeted. Decoding is attacker-controlled work, so depth, layer
 * count and total decoded size are all hard-capped; the caps are chosen so a
 * pathological input costs a bounded, small multiple of one ordinary scan.
 */

// --- budgets ---------------------------------------------------------------
// Decoding is work an attacker asks us to do, so every dimension is capped.
/** base64(base64(rot13(payload))) is reachable; deeper is fantasy. */
export const MAX_DEPTH = 3;
/** Total decoded layers returned. */
export const MAX_LAYERS = 24;
/** Summed size of all decoded text. */
export const MAX_TOTAL_CHARS = 262_144;
/** Candidate spans one extractor may yield per layer. */
export const MAX_PER_EXTRACTOR = 6;
/** Shorter decodes carry no instruction worth acting on. */
export const MIN_PAYLOAD_CHARS = 12;
/** Do not even look at inputs larger than the pipeline cap. */
export const MAX_INPUT_CHARS = 200_000;

/** One recovered plaintext, plus how we got to it. */
export interface DecodedLayer {
  text: string;
  /** `["base64"]` or `["base64", "rot13"]`. */
  chain: readonly string[];
  /** Offsets in the immediate parent, `null` for whole-text transforms. */
  span: readonly [number, number] | null;
  /** Index into the layer list, -1 for the original input. */
  parent: number;
  /** The chain rendered for humans: `"base64 → rot13"`. */
  label: string;
}

// --- code-point arithmetic -------------------------------------------------
// Python indexes strings by code point, JavaScript by UTF-16 unit. Every length,
// budget and span offset below is therefore converted, so an astral character in
// the input cannot shift a reported offset or inflate a budget.

function codePointCount(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

/** Build a UTF-16 → code-point offset mapper for `text` (identity when it is
 * entirely BMP, which is the overwhelmingly common case). */
function makeIndexMapper(text: string): (i: number) => number {
  const pairs: number[] = [];
  for (let i = 0; i < text.length - 1; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = text.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        pairs.push(i);
        i++;
      }
    }
  }
  if (pairs.length === 0) return (i) => i;
  return (i) => {
    let lo = 0;
    let hi = pairs.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (pairs[mid]! < i) lo = mid + 1;
      else hi = mid;
    }
    return i - lo;
  };
}

// Python's `\s` (and the argument-less `str.split()`) cover ASCII whitespace plus
// the Unicode separators. JavaScript's `\s` disagrees at both ends: it omits
// U+001C-U+001F and U+0085, and it adds U+FEFF — which this module reads as a
// zero-width *bit*, not a separator. Spell the class out so runs split the same.
const PY_WS =
  "\\t\\n\\v\\f\\r \\u001c-\\u001f\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const PY_WS_RUN_RE = new RegExp(`[${PY_WS}]+`, "g");
const PY_WS_EDGE_RE = new RegExp(`^[${PY_WS}]+|[${PY_WS}]+$`, "g");

/** `" ".join(s.split())` — collapse whitespace runs and trim. */
function collapseWhitespace(s: string): string {
  return s.replace(PY_WS_EDGE_RE, "").replace(PY_WS_RUN_RE, " ");
}

/** `s.split()` — split on whitespace runs, dropping empties. */
function splitWhitespace(s: string): string[] {
  const trimmed = s.replace(PY_WS_EDGE_RE, "");
  return trimmed === "" ? [] : trimmed.split(PY_WS_RUN_RE);
}

// --- plausibility ----------------------------------------------------------

// Python asks `unicodedata.category(ch)`; TypeScript has no character database,
// so the same five top-level categories are expressed as property escapes. Runs
// are matched rather than single characters purely for speed on large inputs.
const PRINTABLE_RUN_RE = /[\p{L}\p{N}\p{P}\p{Z}\p{S}\n\r\t]+/gu;
const LETTER_RUN_RE = /\p{L}+/gu;

function countMatchedCodePoints(s: string, re: RegExp): number {
  re.lastIndex = 0;
  let total = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) total += codePointCount(m[0]);
  return total;
}

/**
 * Is this decode plausibly natural-language text rather than binary noise?
 *
 * Deliberately permissive: the cost of a false "yes" is one extra signature pass
 * over a short string, while a false "no" silently drops an attack.
 */
export function looksLikeText(s: string): boolean {
  const n = codePointCount(s);
  if (n < MIN_PAYLOAD_CHARS) return false;
  const printable = countMatchedCodePoints(s, PRINTABLE_RUN_RE);
  const letters = countMatchedCodePoints(s, LETTER_RUN_RE);
  return printable / n >= 0.85 && letters / n >= 0.25;
}

// --- span extractors -------------------------------------------------------

/** A decode candidate: where it was found (`null` for whole-text transforms),
 * what produced it, and the recovered text. Offsets are UTF-16 until `unwrap`
 * converts them. */
interface Candidate {
  span: [number, number] | null;
  name: string;
  text: string;
}

type Extractor = (text: string) => Candidate[];

// Contiguous runs, optionally wrapped at newlines (MIME style). The line-break
// group uses [ \t] and \n — disjoint character classes — so there is no
// alternation overlap for a backtracking engine to explode on.
const B64_RUN_RE = /[A-Za-z0-9+/]{24,}(?:[ \t]*\n[ \t]*[A-Za-z0-9+/]{4,})*={0,2}/g;
const B64URL_RUN_RE = /[A-Za-z0-9_-]{24,}={0,2}/g;
const HEX_RUN_RE = new RegExp(`(?:[0-9a-fA-F]{2}[${PY_WS}:,-]?){12,}`, "g");
const PERCENT_RUN_RE = /(?:%[0-9a-fA-F]{2}){6,}/g;
// Python's `\d` is every Unicode decimal digit, not just ASCII; `\p{Nd}` is the
// JavaScript spelling of the same set.
const NUMERIC_ENTITY_RE = /&#(?:\p{Nd}{1,7}|[xX][0-9a-fA-F]{1,6});/gu;
const ESCAPE_RUN_RE = /(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{3}){6,}/g;
const DECIMAL_RUN_RE = new RegExp(`(?:\\p{Nd}{2,3}[${PY_WS},;.]+){8,}\\p{Nd}{2,3}`, "gu");
const DECIMAL_NUMBER_RE = /\p{Nd}{2,3}/gu;
const SPACED_LETTERS_RE = /(?:[A-Za-z][ .\-_*|]{1,3}){8,}[A-Za-z]/g;
const MORSE_RE = /(?:[.\-]{1,6}[ /]+){6,}[.\-]{1,6}/g;
// Zero-width bits: U+200B/U+200C (or U+FEFF) used as 0/1. Runs are long by nature.
const ZW_BITS_RE = /[\u200b\u200c\u200d\ufeff]{16,}/g;

const MORSE_TABLE: Record<string, string> = {
  ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
  "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
  "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
  "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
  "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
  "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
  "---..": "8", "----.": "9",
};

// --- byte-level helpers ----------------------------------------------------

let utf8Decoder: TextDecoder | null = null;

/** Strict UTF-8, matching Python's `bytes.decode("utf-8")`: any malformed
 * sequence is a rejection, and a leading BOM is kept rather than swallowed. */
function utf8Decode(bytes: Uint8Array): string | null {
  if (utf8Decoder === null) utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    return null;
  }
}

const B64_VALUES = (() => {
  const table = new Int8Array(128).fill(-1);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (let i = 0; i < alphabet.length; i++) table[alphabet.charCodeAt(i)] = i;
  return table;
})();

/** Base64 → bytes, hand-rolled so the module stays isomorphic (no `atob`, no
 * `Buffer`). `data` must already be alphabet-only and unpadded. */
function base64ToBytes(data: string): Uint8Array | null {
  const n = data.length;
  // Python raises here ("number of data characters cannot be 1 more than a
  // multiple of 4"); the caller treats a raise and a null the same way.
  if (n % 4 === 1) return null;
  const rem = n % 4;
  const out = new Uint8Array(((n / 4) | 0) * 3 + (rem === 0 ? 0 : rem - 1));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < n; i++) {
    const code = data.charCodeAt(i);
    const v = code < 128 ? B64_VALUES[code]! : -1;
    if (v < 0) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

function b64Decode(blob: string, urlsafe = false): string | null {
  let compact = blob.replace(PY_WS_RUN_RE, "");
  if (compact.length < 24) return null;
  if (urlsafe) compact = compact.replace(/-/g, "+").replace(/_/g, "/");
  // Python re-pads to a multiple of four and then validates the result against
  // `[A-Za-z0-9+/]*={0,2}`, so a blob that already carried padding and still
  // needs more — "…cHQu==" re-padded to "…cHQu====" — is rejected outright
  // rather than decoded. Reproduce that before touching the payload.
  const padding = /=*$/.exec(compact)![0].length;
  if (padding + ((4 - (compact.length % 4)) % 4) > 2) return null;
  const data = compact.slice(0, compact.length - padding);
  const raw = base64ToBytes(data);
  if (raw === null) return null;
  return utf8Decode(raw);
}

function extractBase64(text: string): Candidate[] {
  const found: Candidate[] = [];
  const sources: Array<[RegExp, string, boolean]> = [
    [B64_RUN_RE, "base64", false],
    [B64URL_RUN_RE, "base64url", true],
  ];
  for (const [regex, name, urlsafe] of sources) {
    let count = 0;
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(text)) !== null) {
      if (count >= MAX_PER_EXTRACTOR) break;
      const blob = m[0];
      // The URL-safe alphabet is a superset match for standard Base64, so only
      // claim "base64url" when a URL-safe-only character is present.
      if (urlsafe && !blob.includes("-") && !blob.includes("_")) continue;
      const decoded = b64Decode(blob, urlsafe);
      if (decoded && looksLikeText(decoded)) {
        found.push({ span: [m.index, m.index + blob.length], name, text: decoded });
        count++;
      }
    }
  }
  return found;
}

function extractHex(text: string): Candidate[] {
  const found: Candidate[] = [];
  HEX_RUN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = HEX_RUN_RE.exec(text)) !== null) {
    if (found.length >= MAX_PER_EXTRACTOR) break;
    let digits = m[0].replace(/[^0-9a-fA-F]/g, "");
    if (digits.length % 2) digits = digits.slice(0, -1);
    const bytes = new Uint8Array(digits.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(digits.slice(i * 2, i * 2 + 2), 16);
    const decoded = utf8Decode(bytes);
    if (decoded !== null && looksLikeText(decoded)) {
      found.push({ span: [m.index, m.index + m[0].length], name: "hex", text: decoded });
    }
  }
  return found;
}

function extractPercent(text: string): Candidate[] {
  const found: Candidate[] = [];
  PERCENT_RUN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = PERCENT_RUN_RE.exec(text)) !== null) {
    if (found.length >= MAX_PER_EXTRACTOR) break;
    const run = m[0];
    const bytes = new Uint8Array(run.length / 3);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(run.slice(i * 3 + 1, i * 3 + 3), 16);
    const decoded = utf8Decode(bytes); // percent bytes that aren't UTF-8 text — not a payload
    if (decoded !== null && decoded !== run && looksLikeText(decoded)) {
      found.push({ span: [m.index, m.index + run.length], name: "percent", text: decoded });
    }
  }
  return found;
}

function extractEntities(text: string): Candidate[] {
  // Entities are scattered rather than contiguous, so unescape the whole text
  // once and treat the result as a single decoded layer. Gated on *numeric*
  // references: &amp; and friends are ordinary HTML, but spelling a word out
  // as &#105;&#103;&#110;… is only ever obfuscation.
  NUMERIC_ENTITY_RE.lastIndex = 0;
  let numeric = 0;
  while (NUMERIC_ENTITY_RE.exec(text) !== null) {
    if (++numeric >= 3) break;
  }
  if (numeric < 3) return [];
  const decoded = unescapeHtml(text);
  if (decoded === text || !looksLikeText(decoded)) return [];
  return [{ span: [0, text.length], name: "html_entities", text: decoded }];
}

function extractEscapes(text: string): Candidate[] {
  const found: Candidate[] = [];
  ESCAPE_RUN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ESCAPE_RUN_RE.exec(text)) !== null) {
    if (found.length >= MAX_PER_EXTRACTOR) break;
    const decoded = decodeUnicodeEscapes(m[0]);
    if (looksLikeText(decoded)) {
      found.push({ span: [m.index, m.index + m[0].length], name: "unicode_escape", text: decoded });
    }
  }
  return found;
}

/** Python's `codecs.unicode_escape` over a run the regex guarantees is made only
 * of `\\uXXXX`, `\\xXX` and `\\NNN`. Byte escapes decode as Latin-1, as they do
 * there. (A `\\uD83D\\uDE00` surrogate pair is one astral character in
 * JavaScript's UTF-16 string but two lone surrogates in Python; both are
 * rejected downstream unless they form real text.) */
function decodeUnicodeEscapes(blob: string): string {
  return blob.replace(
    /\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\([0-7]{3})/g,
    (_m, u?: string, x?: string, o?: string) =>
      String.fromCharCode(u !== undefined ? parseInt(u, 16) : x !== undefined ? parseInt(x, 16) : parseInt(o!, 8)),
  );
}

const ND_RE = /\p{Nd}/u;

/**
 * Decimal value of any Unicode decimal digit, the way Python's `int()` reads
 * one — JavaScript's `parseInt` only understands ASCII. There is no character
 * database to consult, so: NFKC first (which folds the fullwidth and
 * mathematical digit blocks onto ASCII), then walk back to the script block's
 * zero, which is the first digit whose predecessor is not itself a digit. Every
 * remaining Nd block is ten code points bounded by non-digits, so the walk is
 * exact; verified against `unicodedata` for all 650 Nd code points.
 */
function decimalValue(scalar: string): number | null {
  const cp = scalar.normalize("NFKC").codePointAt(0)!;
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30;
  if (!ND_RE.test(String.fromCodePoint(cp))) return null;
  for (let v = 0; v <= 9; v++) {
    if (!ND_RE.test(String.fromCodePoint(cp - v - 1))) return v;
  }
  return null;
}

function parseDigits(s: string): number | null {
  let n = 0;
  for (const ch of s) {
    const v = decimalValue(ch);
    if (v === null) return null;
    n = n * 10 + v;
  }
  return n;
}

function extractDecimal(text: string): Candidate[] {
  const found: Candidate[] = [];
  DECIMAL_RUN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = DECIMAL_RUN_RE.exec(text)) !== null) {
    if (found.length >= MAX_PER_EXTRACTOR) break;
    const numbers: number[] = [];
    DECIMAL_NUMBER_RE.lastIndex = 0;
    let d: RegExpExecArray | null;
    while ((d = DECIMAL_NUMBER_RE.exec(m[0])) !== null) {
      const v = parseDigits(d[0]);
      if (v !== null) numbers.push(v);
    }
    if (!numbers.length || numbers.some((n) => n > 126 || n < 32)) continue;
    const decoded = numbers.map((n) => String.fromCharCode(n)).join("");
    if (looksLikeText(decoded)) {
      found.push({ span: [m.index, m.index + m[0].length], name: "decimal_codes", text: decoded });
    }
  }
  return found;
}

function extractSpaced(text: string): Candidate[] {
  const found: Candidate[] = [];
  SPACED_LETTERS_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SPACED_LETTERS_RE.exec(text)) !== null) {
    if (found.length >= MAX_PER_EXTRACTOR) break;
    // A single separator joins letters within a word; a run of two or more is
    // the word break, so "i g n o r e  a l l" collapses to "ignore all". Park
    // the word breaks somewhere the letter-joining pass can't see them.
    let decoded = m[0].replace(/[ .\-_*|]{2,}/g, "\x00");
    // Python looks behind for the leading letter; consuming it and putting it
    // back through the capture keeps the same non-overlapping behaviour without
    // requiring lookbehind support.
    decoded = decoded.replace(/([A-Za-z])[ .\-_*|](?=[A-Za-z])/g, "$1");
    decoded = decoded.replace(/\x00/g, " ");
    if (looksLikeText(decoded)) {
      found.push({ span: [m.index, m.index + m[0].length], name: "letter_spacing", text: decoded });
    }
  }
  return found;
}

function extractMorse(text: string): Candidate[] {
  const found: Candidate[] = [];
  MORSE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MORSE_RE.exec(text)) !== null) {
    if (found.length >= MAX_PER_EXTRACTOR) break;
    const letters: string[] = [];
    for (const word of m[0].split("/")) {
      for (const symbol of splitWhitespace(word)) letters.push(MORSE_TABLE[symbol] ?? "");
      letters.push(" ");
    }
    const decoded = letters.join("").replace(PY_WS_EDGE_RE, "");
    if (looksLikeText(decoded)) {
      found.push({ span: [m.index, m.index + m[0].length], name: "morse", text: decoded });
    }
  }
  return found;
}

/** Zero-width characters used as binary. Only meaningful on *raw* text —
 * sanitization strips these, which is why `unwrap` runs before it. */
function extractZeroWidthBits(text: string): Candidate[] {
  const found: Candidate[] = [];
  ZW_BITS_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ZW_BITS_RE.exec(text)) !== null) {
    if (found.length >= MAX_PER_EXTRACTOR) break;
    const run = m[0];
    let bits = "";
    for (const ch of run) bits += ch === "\u200b" || ch === "\ufeff" ? "0" : "1";
    const usable = bits.length - (bits.length % 8);
    if (usable < 24) continue;
    const bytes = new Uint8Array(usable / 8);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
    const decoded = utf8Decode(bytes);
    if (decoded !== null && looksLikeText(decoded)) {
      found.push({ span: [m.index, m.index + run.length], name: "zero_width_bits", text: decoded });
    }
  }
  return found;
}

const SPAN_EXTRACTORS: readonly Extractor[] = [
  extractBase64,
  extractHex,
  extractPercent,
  extractEntities,
  extractEscapes,
  extractDecimal,
  extractSpaced,
  extractMorse,
  extractZeroWidthBits,
];

// --- HTML character references ---------------------------------------------

// Mirrors Python's `html.unescape`, including the WHATWG repairs for references
// that name a Windows-1252 byte or a non-character, and the same longest-prefix
// rule for named ones.
const CHARREF_RE = /&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)/gu;

const INVALID_CHARREFS: Record<number, string> = {
  0x00: "\ufffd", 0x0d: "\r", 0x80: "€", 0x81: "\u0081", 0x82: "‚",
  0x83: "ƒ", 0x84: "„", 0x85: "…", 0x86: "†", 0x87: "‡",
  0x88: "ˆ", 0x89: "‰", 0x8a: "Š", 0x8b: "‹", 0x8c: "Œ",
  0x8d: "\u008d", 0x8e: "Ž", 0x8f: "\u008f", 0x90: "\u0090", 0x91: "‘",
  0x92: "’", 0x93: "“", 0x94: "”", 0x95: "•", 0x96: "–",
  0x97: "—", 0x98: "˜", 0x99: "™", 0x9a: "š", 0x9b: "›",
  0x9c: "œ", 0x9d: "\u009d", 0x9e: "ž", 0x9f: "Ÿ",
};

function isInvalidCodepoint(cp: number): boolean {
  return (
    (cp >= 0x01 && cp <= 0x08) ||
    cp === 0x0b ||
    (cp >= 0x0e && cp <= 0x1f) ||
    (cp >= 0x7f && cp <= 0x9f) ||
    (cp >= 0xfdd0 && cp <= 0xfdef) ||
    (cp & 0xfffe) === 0xfffe // the xxFFFE / xxFFFF non-characters in every plane
  );
}

// The HTML5 named-reference table, all 2231 spellings, because `html.unescape` resolves every one of
// them and a payload hidden behind `&excl;` has to come out here exactly as it does there. Stored as
// text — `name:codepoint[.codepoint]`, with `!` marking the 106 legacy names an HTML parser resolves
// without their semicolon too — and expanded on first use, which for most texts is never. Spelled
// out as an object literal the same table would cost several times the source.
const HTML5_NAMED_REFERENCES = `
!AElig:C6 !AMP:26 !Aacute:C1 Abreve:102 !Acirc:C2 Acy:410 Afr:1D504 !Agrave:C0 Alpha:391 Amacr:100 And:2A53
Aogon:104 Aopf:1D538 ApplyFunction:2061 !Aring:C5 Ascr:1D49C Assign:2254 !Atilde:C3 !Auml:C4 Backslash:2216
Barv:2AE7 Barwed:2306 Bcy:411 Because:2235 Bernoullis:212C Beta:392 Bfr:1D505 Bopf:1D539 Breve:2D8 Bscr:212C
Bumpeq:224E CHcy:427 !COPY:A9 Cacute:106 Cap:22D2 CapitalDifferentialD:2145 Cayleys:212D Ccaron:10C
!Ccedil:C7 Ccirc:108 Cconint:2230 Cdot:10A Cedilla:B8 CenterDot:B7 Cfr:212D Chi:3A7 CircleDot:2299
CircleMinus:2296 CirclePlus:2295 CircleTimes:2297 ClockwiseContourIntegral:2232 CloseCurlyDoubleQuote:201D
CloseCurlyQuote:2019 Colon:2237 Colone:2A74 Congruent:2261 Conint:222F ContourIntegral:222E Copf:2102
Coproduct:2210 CounterClockwiseContourIntegral:2233 Cross:2A2F Cscr:1D49E Cup:22D3 CupCap:224D DD:2145
DDotrahd:2911 DJcy:402 DScy:405 DZcy:40F Dagger:2021 Darr:21A1 Dashv:2AE4 Dcaron:10E Dcy:414 Del:2207
Delta:394 Dfr:1D507 DiacriticalAcute:B4 DiacriticalDot:2D9 DiacriticalDoubleAcute:2DD DiacriticalGrave:60
DiacriticalTilde:2DC Diamond:22C4 DifferentialD:2146 Dopf:1D53B Dot:A8 DotDot:20DC DotEqual:2250
DoubleContourIntegral:222F DoubleDot:A8 DoubleDownArrow:21D3 DoubleLeftArrow:21D0 DoubleLeftRightArrow:21D4
DoubleLeftTee:2AE4 DoubleLongLeftArrow:27F8 DoubleLongLeftRightArrow:27FA DoubleLongRightArrow:27F9
DoubleRightArrow:21D2 DoubleRightTee:22A8 DoubleUpArrow:21D1 DoubleUpDownArrow:21D5 DoubleVerticalBar:2225
DownArrow:2193 DownArrowBar:2913 DownArrowUpArrow:21F5 DownBreve:311 DownLeftRightVector:2950
DownLeftTeeVector:295E DownLeftVector:21BD DownLeftVectorBar:2956 DownRightTeeVector:295F
DownRightVector:21C1 DownRightVectorBar:2957 DownTee:22A4 DownTeeArrow:21A7 Downarrow:21D3 Dscr:1D49F
Dstrok:110 ENG:14A !ETH:D0 !Eacute:C9 Ecaron:11A !Ecirc:CA Ecy:42D Edot:116 Efr:1D508 !Egrave:C8
Element:2208 Emacr:112 EmptySmallSquare:25FB EmptyVerySmallSquare:25AB Eogon:118 Eopf:1D53C Epsilon:395
Equal:2A75 EqualTilde:2242 Equilibrium:21CC Escr:2130 Esim:2A73 Eta:397 !Euml:CB Exists:2203
ExponentialE:2147 Fcy:424 Ffr:1D509 FilledSmallSquare:25FC FilledVerySmallSquare:25AA Fopf:1D53D ForAll:2200
Fouriertrf:2131 Fscr:2131 GJcy:403 !GT:3E Gamma:393 Gammad:3DC Gbreve:11E Gcedil:122 Gcirc:11C Gcy:413
Gdot:120 Gfr:1D50A Gg:22D9 Gopf:1D53E GreaterEqual:2265 GreaterEqualLess:22DB GreaterFullEqual:2267
GreaterGreater:2AA2 GreaterLess:2277 GreaterSlantEqual:2A7E GreaterTilde:2273 Gscr:1D4A2 Gt:226B HARDcy:42A
Hacek:2C7 Hat:5E Hcirc:124 Hfr:210C HilbertSpace:210B Hopf:210D HorizontalLine:2500 Hscr:210B Hstrok:126
HumpDownHump:224E HumpEqual:224F IEcy:415 IJlig:132 IOcy:401 !Iacute:CD !Icirc:CE Icy:418 Idot:130 Ifr:2111
!Igrave:CC Im:2111 Imacr:12A ImaginaryI:2148 Implies:21D2 Int:222C Integral:222B Intersection:22C2
InvisibleComma:2063 InvisibleTimes:2062 Iogon:12E Iopf:1D540 Iota:399 Iscr:2110 Itilde:128 Iukcy:406
!Iuml:CF Jcirc:134 Jcy:419 Jfr:1D50D Jopf:1D541 Jscr:1D4A5 Jsercy:408 Jukcy:404 KHcy:425 KJcy:40C Kappa:39A
Kcedil:136 Kcy:41A Kfr:1D50E Kopf:1D542 Kscr:1D4A6 LJcy:409 !LT:3C Lacute:139 Lambda:39B Lang:27EA
Laplacetrf:2112 Larr:219E Lcaron:13D Lcedil:13B Lcy:41B LeftAngleBracket:27E8 LeftArrow:2190
LeftArrowBar:21E4 LeftArrowRightArrow:21C6 LeftCeiling:2308 LeftDoubleBracket:27E6 LeftDownTeeVector:2961
LeftDownVector:21C3 LeftDownVectorBar:2959 LeftFloor:230A LeftRightArrow:2194 LeftRightVector:294E
LeftTee:22A3 LeftTeeArrow:21A4 LeftTeeVector:295A LeftTriangle:22B2 LeftTriangleBar:29CF
LeftTriangleEqual:22B4 LeftUpDownVector:2951 LeftUpTeeVector:2960 LeftUpVector:21BF LeftUpVectorBar:2958
LeftVector:21BC LeftVectorBar:2952 Leftarrow:21D0 Leftrightarrow:21D4 LessEqualGreater:22DA
LessFullEqual:2266 LessGreater:2276 LessLess:2AA1 LessSlantEqual:2A7D LessTilde:2272 Lfr:1D50F Ll:22D8
Lleftarrow:21DA Lmidot:13F LongLeftArrow:27F5 LongLeftRightArrow:27F7 LongRightArrow:27F6 Longleftarrow:27F8
Longleftrightarrow:27FA Longrightarrow:27F9 Lopf:1D543 LowerLeftArrow:2199 LowerRightArrow:2198 Lscr:2112
Lsh:21B0 Lstrok:141 Lt:226A Map:2905 Mcy:41C MediumSpace:205F Mellintrf:2133 Mfr:1D510 MinusPlus:2213
Mopf:1D544 Mscr:2133 Mu:39C NJcy:40A Nacute:143 Ncaron:147 Ncedil:145 Ncy:41D NegativeMediumSpace:200B
NegativeThickSpace:200B NegativeThinSpace:200B NegativeVeryThinSpace:200B NestedGreaterGreater:226B
NestedLessLess:226A NewLine:A Nfr:1D511 NoBreak:2060 NonBreakingSpace:A0 Nopf:2115 Not:2AEC
NotCongruent:2262 NotCupCap:226D NotDoubleVerticalBar:2226 NotElement:2209 NotEqual:2260
NotEqualTilde:2242.338 NotExists:2204 NotGreater:226F NotGreaterEqual:2271 NotGreaterFullEqual:2267.338
NotGreaterGreater:226B.338 NotGreaterLess:2279 NotGreaterSlantEqual:2A7E.338 NotGreaterTilde:2275
NotHumpDownHump:224E.338 NotHumpEqual:224F.338 NotLeftTriangle:22EA NotLeftTriangleBar:29CF.338
NotLeftTriangleEqual:22EC NotLess:226E NotLessEqual:2270 NotLessGreater:2278 NotLessLess:226A.338
NotLessSlantEqual:2A7D.338 NotLessTilde:2274 NotNestedGreaterGreater:2AA2.338 NotNestedLessLess:2AA1.338
NotPrecedes:2280 NotPrecedesEqual:2AAF.338 NotPrecedesSlantEqual:22E0 NotReverseElement:220C
NotRightTriangle:22EB NotRightTriangleBar:29D0.338 NotRightTriangleEqual:22ED NotSquareSubset:228F.338
NotSquareSubsetEqual:22E2 NotSquareSuperset:2290.338 NotSquareSupersetEqual:22E3 NotSubset:2282.20D2
NotSubsetEqual:2288 NotSucceeds:2281 NotSucceedsEqual:2AB0.338 NotSucceedsSlantEqual:22E1
NotSucceedsTilde:227F.338 NotSuperset:2283.20D2 NotSupersetEqual:2289 NotTilde:2241 NotTildeEqual:2244
NotTildeFullEqual:2247 NotTildeTilde:2249 NotVerticalBar:2224 Nscr:1D4A9 !Ntilde:D1 Nu:39D OElig:152
!Oacute:D3 !Ocirc:D4 Ocy:41E Odblac:150 Ofr:1D512 !Ograve:D2 Omacr:14C Omega:3A9 Omicron:39F Oopf:1D546
OpenCurlyDoubleQuote:201C OpenCurlyQuote:2018 Or:2A54 Oscr:1D4AA !Oslash:D8 !Otilde:D5 Otimes:2A37 !Ouml:D6
OverBar:203E OverBrace:23DE OverBracket:23B4 OverParenthesis:23DC PartialD:2202 Pcy:41F Pfr:1D513 Phi:3A6
Pi:3A0 PlusMinus:B1 Poincareplane:210C Popf:2119 Pr:2ABB Precedes:227A PrecedesEqual:2AAF
PrecedesSlantEqual:227C PrecedesTilde:227E Prime:2033 Product:220F Proportion:2237 Proportional:221D
Pscr:1D4AB Psi:3A8 !QUOT:22 Qfr:1D514 Qopf:211A Qscr:1D4AC RBarr:2910 !REG:AE Racute:154 Rang:27EB Rarr:21A0
Rarrtl:2916 Rcaron:158 Rcedil:156 Rcy:420 Re:211C ReverseElement:220B ReverseEquilibrium:21CB
ReverseUpEquilibrium:296F Rfr:211C Rho:3A1 RightAngleBracket:27E9 RightArrow:2192 RightArrowBar:21E5
RightArrowLeftArrow:21C4 RightCeiling:2309 RightDoubleBracket:27E7 RightDownTeeVector:295D
RightDownVector:21C2 RightDownVectorBar:2955 RightFloor:230B RightTee:22A2 RightTeeArrow:21A6
RightTeeVector:295B RightTriangle:22B3 RightTriangleBar:29D0 RightTriangleEqual:22B5 RightUpDownVector:294F
RightUpTeeVector:295C RightUpVector:21BE RightUpVectorBar:2954 RightVector:21C0 RightVectorBar:2953
Rightarrow:21D2 Ropf:211D RoundImplies:2970 Rrightarrow:21DB Rscr:211B Rsh:21B1 RuleDelayed:29F4 SHCHcy:429
SHcy:428 SOFTcy:42C Sacute:15A Sc:2ABC Scaron:160 Scedil:15E Scirc:15C Scy:421 Sfr:1D516 ShortDownArrow:2193
ShortLeftArrow:2190 ShortRightArrow:2192 ShortUpArrow:2191 Sigma:3A3 SmallCircle:2218 Sopf:1D54A Sqrt:221A
Square:25A1 SquareIntersection:2293 SquareSubset:228F SquareSubsetEqual:2291 SquareSuperset:2290
SquareSupersetEqual:2292 SquareUnion:2294 Sscr:1D4AE Star:22C6 Sub:22D0 Subset:22D0 SubsetEqual:2286
Succeeds:227B SucceedsEqual:2AB0 SucceedsSlantEqual:227D SucceedsTilde:227F SuchThat:220B Sum:2211 Sup:22D1
Superset:2283 SupersetEqual:2287 Supset:22D1 !THORN:DE TRADE:2122 TSHcy:40B TScy:426 Tab:9 Tau:3A4
Tcaron:164 Tcedil:162 Tcy:422 Tfr:1D517 Therefore:2234 Theta:398 ThickSpace:205F.200A ThinSpace:2009
Tilde:223C TildeEqual:2243 TildeFullEqual:2245 TildeTilde:2248 Topf:1D54B TripleDot:20DB Tscr:1D4AF
Tstrok:166 !Uacute:DA Uarr:219F Uarrocir:2949 Ubrcy:40E Ubreve:16C !Ucirc:DB Ucy:423 Udblac:170 Ufr:1D518
!Ugrave:D9 Umacr:16A UnderBar:5F UnderBrace:23DF UnderBracket:23B5 UnderParenthesis:23DD Union:22C3
UnionPlus:228E Uogon:172 Uopf:1D54C UpArrow:2191 UpArrowBar:2912 UpArrowDownArrow:21C5 UpDownArrow:2195
UpEquilibrium:296E UpTee:22A5 UpTeeArrow:21A5 Uparrow:21D1 Updownarrow:21D5 UpperLeftArrow:2196
UpperRightArrow:2197 Upsi:3D2 Upsilon:3A5 Uring:16E Uscr:1D4B0 Utilde:168 !Uuml:DC VDash:22AB Vbar:2AEB
Vcy:412 Vdash:22A9 Vdashl:2AE6 Vee:22C1 Verbar:2016 Vert:2016 VerticalBar:2223 VerticalLine:7C
VerticalSeparator:2758 VerticalTilde:2240 VeryThinSpace:200A Vfr:1D519 Vopf:1D54D Vscr:1D4B1 Vvdash:22AA
Wcirc:174 Wedge:22C0 Wfr:1D51A Wopf:1D54E Wscr:1D4B2 Xfr:1D51B Xi:39E Xopf:1D54F Xscr:1D4B3 YAcy:42F
YIcy:407 YUcy:42E !Yacute:DD Ycirc:176 Ycy:42B Yfr:1D51C Yopf:1D550 Yscr:1D4B4 Yuml:178 ZHcy:416 Zacute:179
Zcaron:17D Zcy:417 Zdot:17B ZeroWidthSpace:200B Zeta:396 Zfr:2128 Zopf:2124 Zscr:1D4B5 !aacute:E1 abreve:103
ac:223E acE:223E.333 acd:223F !acirc:E2 !acute:B4 acy:430 !aelig:E6 af:2061 afr:1D51E !agrave:E0
alefsym:2135 aleph:2135 alpha:3B1 amacr:101 amalg:2A3F !amp:26 and:2227 andand:2A55 andd:2A5C andslope:2A58
andv:2A5A ang:2220 ange:29A4 angle:2220 angmsd:2221 angmsdaa:29A8 angmsdab:29A9 angmsdac:29AA angmsdad:29AB
angmsdae:29AC angmsdaf:29AD angmsdag:29AE angmsdah:29AF angrt:221F angrtvb:22BE angrtvbd:299D angsph:2222
angst:C5 angzarr:237C aogon:105 aopf:1D552 ap:2248 apE:2A70 apacir:2A6F ape:224A apid:224B apos:27
approx:2248 approxeq:224A !aring:E5 ascr:1D4B6 ast:2A asymp:2248 asympeq:224D !atilde:E3 !auml:E4
awconint:2233 awint:2A11 bNot:2AED backcong:224C backepsilon:3F6 backprime:2035 backsim:223D backsimeq:22CD
barvee:22BD barwed:2305 barwedge:2305 bbrk:23B5 bbrktbrk:23B6 bcong:224C bcy:431 bdquo:201E becaus:2235
because:2235 bemptyv:29B0 bepsi:3F6 bernou:212C beta:3B2 beth:2136 between:226C bfr:1D51F bigcap:22C2
bigcirc:25EF bigcup:22C3 bigodot:2A00 bigoplus:2A01 bigotimes:2A02 bigsqcup:2A06 bigstar:2605
bigtriangledown:25BD bigtriangleup:25B3 biguplus:2A04 bigvee:22C1 bigwedge:22C0 bkarow:290D
blacklozenge:29EB blacksquare:25AA blacktriangle:25B4 blacktriangledown:25BE blacktriangleleft:25C2
blacktriangleright:25B8 blank:2423 blk12:2592 blk14:2591 blk34:2593 block:2588 bne:3D.20E5 bnequiv:2261.20E5
bnot:2310 bopf:1D553 bot:22A5 bottom:22A5 bowtie:22C8 boxDL:2557 boxDR:2554 boxDl:2556 boxDr:2553 boxH:2550
boxHD:2566 boxHU:2569 boxHd:2564 boxHu:2567 boxUL:255D boxUR:255A boxUl:255C boxUr:2559 boxV:2551 boxVH:256C
boxVL:2563 boxVR:2560 boxVh:256B boxVl:2562 boxVr:255F boxbox:29C9 boxdL:2555 boxdR:2552 boxdl:2510
boxdr:250C boxh:2500 boxhD:2565 boxhU:2568 boxhd:252C boxhu:2534 boxminus:229F boxplus:229E boxtimes:22A0
boxuL:255B boxuR:2558 boxul:2518 boxur:2514 boxv:2502 boxvH:256A boxvL:2561 boxvR:255E boxvh:253C boxvl:2524
boxvr:251C bprime:2035 breve:2D8 !brvbar:A6 bscr:1D4B7 bsemi:204F bsim:223D bsime:22CD bsol:5C bsolb:29C5
bsolhsub:27C8 bull:2022 bullet:2022 bump:224E bumpE:2AAE bumpe:224F bumpeq:224F cacute:107 cap:2229
capand:2A44 capbrcup:2A49 capcap:2A4B capcup:2A47 capdot:2A40 caps:2229.FE00 caret:2041 caron:2C7 ccaps:2A4D
ccaron:10D !ccedil:E7 ccirc:109 ccups:2A4C ccupssm:2A50 cdot:10B !cedil:B8 cemptyv:29B2 !cent:A2
centerdot:B7 cfr:1D520 chcy:447 check:2713 checkmark:2713 chi:3C7 cir:25CB cirE:29C3 circ:2C6 circeq:2257
circlearrowleft:21BA circlearrowright:21BB circledR:AE circledS:24C8 circledast:229B circledcirc:229A
circleddash:229D cire:2257 cirfnint:2A10 cirmid:2AEF cirscir:29C2 clubs:2663 clubsuit:2663 colon:3A
colone:2254 coloneq:2254 comma:2C commat:40 comp:2201 compfn:2218 complement:2201 complexes:2102 cong:2245
congdot:2A6D conint:222E copf:1D554 coprod:2210 !copy:A9 copysr:2117 crarr:21B5 cross:2717 cscr:1D4B8
csub:2ACF csube:2AD1 csup:2AD0 csupe:2AD2 ctdot:22EF cudarrl:2938 cudarrr:2935 cuepr:22DE cuesc:22DF
cularr:21B6 cularrp:293D cup:222A cupbrcap:2A48 cupcap:2A46 cupcup:2A4A cupdot:228D cupor:2A45
cups:222A.FE00 curarr:21B7 curarrm:293C curlyeqprec:22DE curlyeqsucc:22DF curlyvee:22CE curlywedge:22CF
!curren:A4 curvearrowleft:21B6 curvearrowright:21B7 cuvee:22CE cuwed:22CF cwconint:2232 cwint:2231
cylcty:232D dArr:21D3 dHar:2965 dagger:2020 daleth:2138 darr:2193 dash:2010 dashv:22A3 dbkarow:290F
dblac:2DD dcaron:10F dcy:434 dd:2146 ddagger:2021 ddarr:21CA ddotseq:2A77 !deg:B0 delta:3B4 demptyv:29B1
dfisht:297F dfr:1D521 dharl:21C3 dharr:21C2 diam:22C4 diamond:22C4 diamondsuit:2666 diams:2666 die:A8
digamma:3DD disin:22F2 div:F7 !divide:F7 divideontimes:22C7 divonx:22C7 djcy:452 dlcorn:231E dlcrop:230D
dollar:24 dopf:1D555 dot:2D9 doteq:2250 doteqdot:2251 dotminus:2238 dotplus:2214 dotsquare:22A1
doublebarwedge:2306 downarrow:2193 downdownarrows:21CA downharpoonleft:21C3 downharpoonright:21C2
drbkarow:2910 drcorn:231F drcrop:230C dscr:1D4B9 dscy:455 dsol:29F6 dstrok:111 dtdot:22F1 dtri:25BF
dtrif:25BE duarr:21F5 duhar:296F dwangle:29A6 dzcy:45F dzigrarr:27FF eDDot:2A77 eDot:2251 !eacute:E9
easter:2A6E ecaron:11B ecir:2256 !ecirc:EA ecolon:2255 ecy:44D edot:117 ee:2147 efDot:2252 efr:1D522 eg:2A9A
!egrave:E8 egs:2A96 egsdot:2A98 el:2A99 elinters:23E7 ell:2113 els:2A95 elsdot:2A97 emacr:113 empty:2205
emptyset:2205 emptyv:2205 emsp:2003 emsp13:2004 emsp14:2005 eng:14B ensp:2002 eogon:119 eopf:1D556 epar:22D5
eparsl:29E3 eplus:2A71 epsi:3B5 epsilon:3B5 epsiv:3F5 eqcirc:2256 eqcolon:2255 eqsim:2242 eqslantgtr:2A96
eqslantless:2A95 equals:3D equest:225F equiv:2261 equivDD:2A78 eqvparsl:29E5 erDot:2253 erarr:2971 escr:212F
esdot:2250 esim:2242 eta:3B7 !eth:F0 !euml:EB euro:20AC excl:21 exist:2203 expectation:2130
exponentiale:2147 fallingdotseq:2252 fcy:444 female:2640 ffilig:FB03 fflig:FB00 ffllig:FB04 ffr:1D523
filig:FB01 fjlig:66.6A flat:266D fllig:FB02 fltns:25B1 fnof:192 fopf:1D557 forall:2200 fork:22D4 forkv:2AD9
fpartint:2A0D !frac12:BD frac13:2153 !frac14:BC frac15:2155 frac16:2159 frac18:215B frac23:2154 frac25:2156
!frac34:BE frac35:2157 frac38:215C frac45:2158 frac56:215A frac58:215D frac78:215E frasl:2044 frown:2322
fscr:1D4BB gE:2267 gEl:2A8C gacute:1F5 gamma:3B3 gammad:3DD gap:2A86 gbreve:11F gcirc:11D gcy:433 gdot:121
ge:2265 gel:22DB geq:2265 geqq:2267 geqslant:2A7E ges:2A7E gescc:2AA9 gesdot:2A80 gesdoto:2A82 gesdotol:2A84
gesl:22DB.FE00 gesles:2A94 gfr:1D524 gg:226B ggg:22D9 gimel:2137 gjcy:453 gl:2277 glE:2A92 gla:2AA5 glj:2AA4
gnE:2269 gnap:2A8A gnapprox:2A8A gne:2A88 gneq:2A88 gneqq:2269 gnsim:22E7 gopf:1D558 grave:60 gscr:210A
gsim:2273 gsime:2A8E gsiml:2A90 !gt:3E gtcc:2AA7 gtcir:2A7A gtdot:22D7 gtlPar:2995 gtquest:2A7C
gtrapprox:2A86 gtrarr:2978 gtrdot:22D7 gtreqless:22DB gtreqqless:2A8C gtrless:2277 gtrsim:2273
gvertneqq:2269.FE00 gvnE:2269.FE00 hArr:21D4 hairsp:200A half:BD hamilt:210B hardcy:44A harr:2194
harrcir:2948 harrw:21AD hbar:210F hcirc:125 hearts:2665 heartsuit:2665 hellip:2026 hercon:22B9 hfr:1D525
hksearow:2925 hkswarow:2926 hoarr:21FF homtht:223B hookleftarrow:21A9 hookrightarrow:21AA hopf:1D559
horbar:2015 hscr:1D4BD hslash:210F hstrok:127 hybull:2043 hyphen:2010 !iacute:ED ic:2063 !icirc:EE icy:438
iecy:435 !iexcl:A1 iff:21D4 ifr:1D526 !igrave:EC ii:2148 iiiint:2A0C iiint:222D iinfin:29DC iiota:2129
ijlig:133 imacr:12B image:2111 imagline:2110 imagpart:2111 imath:131 imof:22B7 imped:1B5 in:2208 incare:2105
infin:221E infintie:29DD inodot:131 int:222B intcal:22BA integers:2124 intercal:22BA intlarhk:2A17
intprod:2A3C iocy:451 iogon:12F iopf:1D55A iota:3B9 iprod:2A3C !iquest:BF iscr:1D4BE isin:2208 isinE:22F9
isindot:22F5 isins:22F4 isinsv:22F3 isinv:2208 it:2062 itilde:129 iukcy:456 !iuml:EF jcirc:135 jcy:439
jfr:1D527 jmath:237 jopf:1D55B jscr:1D4BF jsercy:458 jukcy:454 kappa:3BA kappav:3F0 kcedil:137 kcy:43A
kfr:1D528 kgreen:138 khcy:445 kjcy:45C kopf:1D55C kscr:1D4C0 lAarr:21DA lArr:21D0 lAtail:291B lBarr:290E
lE:2266 lEg:2A8B lHar:2962 lacute:13A laemptyv:29B4 lagran:2112 lambda:3BB lang:27E8 langd:2991 langle:27E8
lap:2A85 !laquo:AB larr:2190 larrb:21E4 larrbfs:291F larrfs:291D larrhk:21A9 larrlp:21AB larrpl:2939
larrsim:2973 larrtl:21A2 lat:2AAB latail:2919 late:2AAD lates:2AAD.FE00 lbarr:290C lbbrk:2772 lbrace:7B
lbrack:5B lbrke:298B lbrksld:298F lbrkslu:298D lcaron:13E lcedil:13C lceil:2308 lcub:7B lcy:43B ldca:2936
ldquo:201C ldquor:201E ldrdhar:2967 ldrushar:294B ldsh:21B2 le:2264 leftarrow:2190 leftarrowtail:21A2
leftharpoondown:21BD leftharpoonup:21BC leftleftarrows:21C7 leftrightarrow:2194 leftrightarrows:21C6
leftrightharpoons:21CB leftrightsquigarrow:21AD leftthreetimes:22CB leg:22DA leq:2264 leqq:2266
leqslant:2A7D les:2A7D lescc:2AA8 lesdot:2A7F lesdoto:2A81 lesdotor:2A83 lesg:22DA.FE00 lesges:2A93
lessapprox:2A85 lessdot:22D6 lesseqgtr:22DA lesseqqgtr:2A8B lessgtr:2276 lesssim:2272 lfisht:297C
lfloor:230A lfr:1D529 lg:2276 lgE:2A91 lhard:21BD lharu:21BC lharul:296A lhblk:2584 ljcy:459 ll:226A
llarr:21C7 llcorner:231E llhard:296B lltri:25FA lmidot:140 lmoust:23B0 lmoustache:23B0 lnE:2268 lnap:2A89
lnapprox:2A89 lne:2A87 lneq:2A87 lneqq:2268 lnsim:22E6 loang:27EC loarr:21FD lobrk:27E6 longleftarrow:27F5
longleftrightarrow:27F7 longmapsto:27FC longrightarrow:27F6 looparrowleft:21AB looparrowright:21AC
lopar:2985 lopf:1D55D loplus:2A2D lotimes:2A34 lowast:2217 lowbar:5F loz:25CA lozenge:25CA lozf:29EB lpar:28
lparlt:2993 lrarr:21C6 lrcorner:231F lrhar:21CB lrhard:296D lrm:200E lrtri:22BF lsaquo:2039 lscr:1D4C1
lsh:21B0 lsim:2272 lsime:2A8D lsimg:2A8F lsqb:5B lsquo:2018 lsquor:201A lstrok:142 !lt:3C ltcc:2AA6
ltcir:2A79 ltdot:22D6 lthree:22CB ltimes:22C9 ltlarr:2976 ltquest:2A7B ltrPar:2996 ltri:25C3 ltrie:22B4
ltrif:25C2 lurdshar:294A luruhar:2966 lvertneqq:2268.FE00 lvnE:2268.FE00 mDDot:223A !macr:AF male:2642
malt:2720 maltese:2720 map:21A6 mapsto:21A6 mapstodown:21A7 mapstoleft:21A4 mapstoup:21A5 marker:25AE
mcomma:2A29 mcy:43C mdash:2014 measuredangle:2221 mfr:1D52A mho:2127 !micro:B5 mid:2223 midast:2A
midcir:2AF0 !middot:B7 minus:2212 minusb:229F minusd:2238 minusdu:2A2A mlcp:2ADB mldr:2026 mnplus:2213
models:22A7 mopf:1D55E mp:2213 mscr:1D4C2 mstpos:223E mu:3BC multimap:22B8 mumap:22B8 nGg:22D9.338
nGt:226B.20D2 nGtv:226B.338 nLeftarrow:21CD nLeftrightarrow:21CE nLl:22D8.338 nLt:226A.20D2 nLtv:226A.338
nRightarrow:21CF nVDash:22AF nVdash:22AE nabla:2207 nacute:144 nang:2220.20D2 nap:2249 napE:2A70.338
napid:224B.338 napos:149 napprox:2249 natur:266E natural:266E naturals:2115 !nbsp:A0 nbump:224E.338
nbumpe:224F.338 ncap:2A43 ncaron:148 ncedil:146 ncong:2247 ncongdot:2A6D.338 ncup:2A42 ncy:43D ndash:2013
ne:2260 neArr:21D7 nearhk:2924 nearr:2197 nearrow:2197 nedot:2250.338 nequiv:2262 nesear:2928 nesim:2242.338
nexist:2204 nexists:2204 nfr:1D52B ngE:2267.338 nge:2271 ngeq:2271 ngeqq:2267.338 ngeqslant:2A7E.338
nges:2A7E.338 ngsim:2275 ngt:226F ngtr:226F nhArr:21CE nharr:21AE nhpar:2AF2 ni:220B nis:22FC nisd:22FA
niv:220B njcy:45A nlArr:21CD nlE:2266.338 nlarr:219A nldr:2025 nle:2270 nleftarrow:219A nleftrightarrow:21AE
nleq:2270 nleqq:2266.338 nleqslant:2A7D.338 nles:2A7D.338 nless:226E nlsim:2274 nlt:226E nltri:22EA
nltrie:22EC nmid:2224 nopf:1D55F !not:AC notin:2209 notinE:22F9.338 notindot:22F5.338 notinva:2209
notinvb:22F7 notinvc:22F6 notni:220C notniva:220C notnivb:22FE notnivc:22FD npar:2226 nparallel:2226
nparsl:2AFD.20E5 npart:2202.338 npolint:2A14 npr:2280 nprcue:22E0 npre:2AAF.338 nprec:2280 npreceq:2AAF.338
nrArr:21CF nrarr:219B nrarrc:2933.338 nrarrw:219D.338 nrightarrow:219B nrtri:22EB nrtrie:22ED nsc:2281
nsccue:22E1 nsce:2AB0.338 nscr:1D4C3 nshortmid:2224 nshortparallel:2226 nsim:2241 nsime:2244 nsimeq:2244
nsmid:2224 nspar:2226 nsqsube:22E2 nsqsupe:22E3 nsub:2284 nsubE:2AC5.338 nsube:2288 nsubset:2282.20D2
nsubseteq:2288 nsubseteqq:2AC5.338 nsucc:2281 nsucceq:2AB0.338 nsup:2285 nsupE:2AC6.338 nsupe:2289
nsupset:2283.20D2 nsupseteq:2289 nsupseteqq:2AC6.338 ntgl:2279 !ntilde:F1 ntlg:2278 ntriangleleft:22EA
ntrianglelefteq:22EC ntriangleright:22EB ntrianglerighteq:22ED nu:3BD num:23 numero:2116 numsp:2007
nvDash:22AD nvHarr:2904 nvap:224D.20D2 nvdash:22AC nvge:2265.20D2 nvgt:3E.20D2 nvinfin:29DE nvlArr:2902
nvle:2264.20D2 nvlt:3C.20D2 nvltrie:22B4.20D2 nvrArr:2903 nvrtrie:22B5.20D2 nvsim:223C.20D2 nwArr:21D6
nwarhk:2923 nwarr:2196 nwarrow:2196 nwnear:2927 oS:24C8 !oacute:F3 oast:229B ocir:229A !ocirc:F4 ocy:43E
odash:229D odblac:151 odiv:2A38 odot:2299 odsold:29BC oelig:153 ofcir:29BF ofr:1D52C ogon:2DB !ograve:F2
ogt:29C1 ohbar:29B5 ohm:3A9 oint:222E olarr:21BA olcir:29BE olcross:29BB oline:203E olt:29C0 omacr:14D
omega:3C9 omicron:3BF omid:29B6 ominus:2296 oopf:1D560 opar:29B7 operp:29B9 oplus:2295 or:2228 orarr:21BB
ord:2A5D order:2134 orderof:2134 !ordf:AA !ordm:BA origof:22B6 oror:2A56 orslope:2A57 orv:2A5B oscr:2134
!oslash:F8 osol:2298 !otilde:F5 otimes:2297 otimesas:2A36 !ouml:F6 ovbar:233D par:2225 !para:B6
parallel:2225 parsim:2AF3 parsl:2AFD part:2202 pcy:43F percnt:25 period:2E permil:2030 perp:22A5
pertenk:2031 pfr:1D52D phi:3C6 phiv:3D5 phmmat:2133 phone:260E pi:3C0 pitchfork:22D4 piv:3D6 planck:210F
planckh:210E plankv:210F plus:2B plusacir:2A23 plusb:229E pluscir:2A22 plusdo:2214 plusdu:2A25 pluse:2A72
!plusmn:B1 plussim:2A26 plustwo:2A27 pm:B1 pointint:2A15 popf:1D561 !pound:A3 pr:227A prE:2AB3 prap:2AB7
prcue:227C pre:2AAF prec:227A precapprox:2AB7 preccurlyeq:227C preceq:2AAF precnapprox:2AB9 precneqq:2AB5
precnsim:22E8 precsim:227E prime:2032 primes:2119 prnE:2AB5 prnap:2AB9 prnsim:22E8 prod:220F profalar:232E
profline:2312 profsurf:2313 prop:221D propto:221D prsim:227E prurel:22B0 pscr:1D4C5 psi:3C8 puncsp:2008
qfr:1D52E qint:2A0C qopf:1D562 qprime:2057 qscr:1D4C6 quaternions:210D quatint:2A16 quest:3F questeq:225F
!quot:22 rAarr:21DB rArr:21D2 rAtail:291C rBarr:290F rHar:2964 race:223D.331 racute:155 radic:221A
raemptyv:29B3 rang:27E9 rangd:2992 range:29A5 rangle:27E9 !raquo:BB rarr:2192 rarrap:2975 rarrb:21E5
rarrbfs:2920 rarrc:2933 rarrfs:291E rarrhk:21AA rarrlp:21AC rarrpl:2945 rarrsim:2974 rarrtl:21A3 rarrw:219D
ratail:291A ratio:2236 rationals:211A rbarr:290D rbbrk:2773 rbrace:7D rbrack:5D rbrke:298C rbrksld:298E
rbrkslu:2990 rcaron:159 rcedil:157 rceil:2309 rcub:7D rcy:440 rdca:2937 rdldhar:2969 rdquo:201D rdquor:201D
rdsh:21B3 real:211C realine:211B realpart:211C reals:211D rect:25AD !reg:AE rfisht:297D rfloor:230B
rfr:1D52F rhard:21C1 rharu:21C0 rharul:296C rho:3C1 rhov:3F1 rightarrow:2192 rightarrowtail:21A3
rightharpoondown:21C1 rightharpoonup:21C0 rightleftarrows:21C4 rightleftharpoons:21CC rightrightarrows:21C9
rightsquigarrow:219D rightthreetimes:22CC ring:2DA risingdotseq:2253 rlarr:21C4 rlhar:21CC rlm:200F
rmoust:23B1 rmoustache:23B1 rnmid:2AEE roang:27ED roarr:21FE robrk:27E7 ropar:2986 ropf:1D563 roplus:2A2E
rotimes:2A35 rpar:29 rpargt:2994 rppolint:2A12 rrarr:21C9 rsaquo:203A rscr:1D4C7 rsh:21B1 rsqb:5D rsquo:2019
rsquor:2019 rthree:22CC rtimes:22CA rtri:25B9 rtrie:22B5 rtrif:25B8 rtriltri:29CE ruluhar:2968 rx:211E
sacute:15B sbquo:201A sc:227B scE:2AB4 scap:2AB8 scaron:161 sccue:227D sce:2AB0 scedil:15F scirc:15D
scnE:2AB6 scnap:2ABA scnsim:22E9 scpolint:2A13 scsim:227F scy:441 sdot:22C5 sdotb:22A1 sdote:2A66 seArr:21D8
searhk:2925 searr:2198 searrow:2198 !sect:A7 semi:3B seswar:2929 setminus:2216 setmn:2216 sext:2736
sfr:1D530 sfrown:2322 sharp:266F shchcy:449 shcy:448 shortmid:2223 shortparallel:2225 !shy:AD sigma:3C3
sigmaf:3C2 sigmav:3C2 sim:223C simdot:2A6A sime:2243 simeq:2243 simg:2A9E simgE:2AA0 siml:2A9D simlE:2A9F
simne:2246 simplus:2A24 simrarr:2972 slarr:2190 smallsetminus:2216 smashp:2A33 smeparsl:29E4 smid:2223
smile:2323 smt:2AAA smte:2AAC smtes:2AAC.FE00 softcy:44C sol:2F solb:29C4 solbar:233F sopf:1D564 spades:2660
spadesuit:2660 spar:2225 sqcap:2293 sqcaps:2293.FE00 sqcup:2294 sqcups:2294.FE00 sqsub:228F sqsube:2291
sqsubset:228F sqsubseteq:2291 sqsup:2290 sqsupe:2292 sqsupset:2290 sqsupseteq:2292 squ:25A1 square:25A1
squarf:25AA squf:25AA srarr:2192 sscr:1D4C8 ssetmn:2216 ssmile:2323 sstarf:22C6 star:2606 starf:2605
straightepsilon:3F5 straightphi:3D5 strns:AF sub:2282 subE:2AC5 subdot:2ABD sube:2286 subedot:2AC3
submult:2AC1 subnE:2ACB subne:228A subplus:2ABF subrarr:2979 subset:2282 subseteq:2286 subseteqq:2AC5
subsetneq:228A subsetneqq:2ACB subsim:2AC7 subsub:2AD5 subsup:2AD3 succ:227B succapprox:2AB8
succcurlyeq:227D succeq:2AB0 succnapprox:2ABA succneqq:2AB6 succnsim:22E9 succsim:227F sum:2211 sung:266A
sup:2283 !sup1:B9 !sup2:B2 !sup3:B3 supE:2AC6 supdot:2ABE supdsub:2AD8 supe:2287 supedot:2AC4 suphsol:27C9
suphsub:2AD7 suplarr:297B supmult:2AC2 supnE:2ACC supne:228B supplus:2AC0 supset:2283 supseteq:2287
supseteqq:2AC6 supsetneq:228B supsetneqq:2ACC supsim:2AC8 supsub:2AD4 supsup:2AD6 swArr:21D9 swarhk:2926
swarr:2199 swarrow:2199 swnwar:292A !szlig:DF target:2316 tau:3C4 tbrk:23B4 tcaron:165 tcedil:163 tcy:442
tdot:20DB telrec:2315 tfr:1D531 there4:2234 therefore:2234 theta:3B8 thetasym:3D1 thetav:3D1
thickapprox:2248 thicksim:223C thinsp:2009 thkap:2248 thksim:223C !thorn:FE tilde:2DC !times:D7 timesb:22A0
timesbar:2A31 timesd:2A30 tint:222D toea:2928 top:22A4 topbot:2336 topcir:2AF1 topf:1D565 topfork:2ADA
tosa:2929 tprime:2034 trade:2122 triangle:25B5 triangledown:25BF triangleleft:25C3 trianglelefteq:22B4
triangleq:225C triangleright:25B9 trianglerighteq:22B5 tridot:25EC trie:225C triminus:2A3A triplus:2A39
trisb:29CD tritime:2A3B trpezium:23E2 tscr:1D4C9 tscy:446 tshcy:45B tstrok:167 twixt:226C
twoheadleftarrow:219E twoheadrightarrow:21A0 uArr:21D1 uHar:2963 !uacute:FA uarr:2191 ubrcy:45E ubreve:16D
!ucirc:FB ucy:443 udarr:21C5 udblac:171 udhar:296E ufisht:297E ufr:1D532 !ugrave:F9 uharl:21BF uharr:21BE
uhblk:2580 ulcorn:231C ulcorner:231C ulcrop:230F ultri:25F8 umacr:16B !uml:A8 uogon:173 uopf:1D566
uparrow:2191 updownarrow:2195 upharpoonleft:21BF upharpoonright:21BE uplus:228E upsi:3C5 upsih:3D2
upsilon:3C5 upuparrows:21C8 urcorn:231D urcorner:231D urcrop:230E uring:16F urtri:25F9 uscr:1D4CA utdot:22F0
utilde:169 utri:25B5 utrif:25B4 uuarr:21C8 !uuml:FC uwangle:29A7 vArr:21D5 vBar:2AE8 vBarv:2AE9 vDash:22A8
vangrt:299C varepsilon:3F5 varkappa:3F0 varnothing:2205 varphi:3D5 varpi:3D6 varpropto:221D varr:2195
varrho:3F1 varsigma:3C2 varsubsetneq:228A.FE00 varsubsetneqq:2ACB.FE00 varsupsetneq:228B.FE00
varsupsetneqq:2ACC.FE00 vartheta:3D1 vartriangleleft:22B2 vartriangleright:22B3 vcy:432 vdash:22A2 vee:2228
veebar:22BB veeeq:225A vellip:22EE verbar:7C vert:7C vfr:1D533 vltri:22B2 vnsub:2282.20D2 vnsup:2283.20D2
vopf:1D567 vprop:221D vrtri:22B3 vscr:1D4CB vsubnE:2ACB.FE00 vsubne:228A.FE00 vsupnE:2ACC.FE00
vsupne:228B.FE00 vzigzag:299A wcirc:175 wedbar:2A5F wedge:2227 wedgeq:2259 weierp:2118 wfr:1D534 wopf:1D568
wp:2118 wr:2240 wreath:2240 wscr:1D4CC xcap:22C2 xcirc:25EF xcup:22C3 xdtri:25BD xfr:1D535 xhArr:27FA
xharr:27F7 xi:3BE xlArr:27F8 xlarr:27F5 xmap:27FC xnis:22FB xodot:2A00 xopf:1D569 xoplus:2A01 xotime:2A02
xrArr:27F9 xrarr:27F6 xscr:1D4CD xsqcup:2A06 xuplus:2A04 xutri:25B3 xvee:22C1 xwedge:22C0 !yacute:FD
yacy:44F ycirc:177 ycy:44B !yen:A5 yfr:1D536 yicy:457 yopf:1D56A yscr:1D4CE yucy:44E !yuml:FF zacute:17A
zcaron:17E zcy:437 zdot:17C zeetrf:2128 zeta:3B6 zfr:1D537 zhcy:436 zigrarr:21DD zopf:1D56B zscr:1D4CF
zwj:200D zwnj:200C
`;

let namedReferences: Map<string, string> | null = null;

/** What `&name;` (or, for the legacy spellings, `&name`) stands for. */
function namedReference(name: string): string | undefined {
  if (namedReferences === null) {
    namedReferences = new Map();
    for (const entry of HTML5_NAMED_REFERENCES.split(/\s+/)) {
      if (!entry) continue;
      const legacy = entry.startsWith("!");
      const colon = entry.indexOf(":");
      const bare = entry.slice(legacy ? 1 : 0, colon);
      const value = String.fromCodePoint(
        ...entry.slice(colon + 1).split(".").map((cp) => parseInt(cp, 16)),
      );
      namedReferences.set(`${bare};`, value);
      if (legacy) namedReferences.set(bare, value);
    }
  }
  return namedReferences.get(name);
}

function replaceCharref(ref: string): string {
  if (ref.startsWith("#")) {
    const body = ref.endsWith(";") ? ref.slice(0, -1) : ref;
    const hex = body[1] === "x" || body[1] === "X";
    const num = hex ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
    const repair = INVALID_CHARREFS[num];
    if (repair !== undefined) return repair;
    if ((num >= 0xd800 && num <= 0xdfff) || num > 0x10ffff) return "\ufffd";
    if (isInvalidCodepoint(num)) return "";
    return String.fromCodePoint(num);
  }
  const exact = namedReference(ref);
  if (exact !== undefined) return exact;
  // Longest matching name, as the standard defines it: "&notit" is "¬it".
  for (let x = ref.length - 1; x > 1; x--) {
    const prefix = namedReference(ref.slice(0, x));
    if (prefix !== undefined) return prefix + ref.slice(x);
  }
  return "&" + ref;
}

function unescapeHtml(text: string): string {
  if (!text.includes("&")) return text;
  return text.replace(CHARREF_RE, (_m, ref: string) => replaceCharref(ref));
}

// --- whole-text transforms -------------------------------------------------

export function rot13(text: string): string {
  return text.replace(/[A-Za-z]/g, (c) => {
    const cp = c.charCodeAt(0);
    const base = cp < 0x61 ? 0x41 : 0x61;
    return String.fromCharCode(((cp - base + 13) % 26) + base);
  });
}

export function reverse(text: string): string {
  // Python reverses a sequence of code points; spreading does the same, whereas
  // split("") would tear surrogate pairs in half.
  return [...text].reverse().join("");
}

// Whole-text ciphers have no delimiter to find, so they are simply tried.
const WHOLE_TRANSFORMS: ReadonlyArray<[string, (text: string) => string]> = [
  ["rot13", rot13],
  ["reversed", reverse],
];

// Function words that survive any topic. A ROT13'd or reversed English sentence
// scores near zero on these; its decoding scores high. Comparing the two is what
// keeps these transforms from emitting a useless second copy of every document.
const STOPWORDS = new Set(
  `the be to of and a in that have it for not on with as you do at this but his by
from they we say her she or an will my one all would there their what so up out
if about who get which go me when make can like time no just him know take people
into your some could them see other than then now look only come its over think
also back after use two how our work first well way even new want because any
these give day most us is are was were been has had please must should your you`.split(
    /\s+/,
  ),
);
const WORD_RE = /[A-Za-z']+/g;

/** Fraction of words that are common English function words, over the first 400
 * words. Cheap, allocation-light, and good enough to tell a decoding from its
 * ciphertext. (Python slices after scanning the whole text; stopping the scan at
 * 400 words gives the same number for a fraction of the work.) */
function englishScore(text: string): number {
  const lowered = text.toLowerCase();
  WORD_RE.lastIndex = 0;
  let words = 0;
  let hits = 0;
  let m: RegExpExecArray | null;
  while (words < 400 && (m = WORD_RE.exec(lowered)) !== null) {
    words++;
    if (STOPWORDS.has(m[0])) hits++;
  }
  if (words < 4) return 0;
  return hits / words;
}

// --- the unwrapper ---------------------------------------------------------

export interface UnwrapOptions {
  maxDepth?: number;
  maxLayers?: number;
  maxTotalChars?: number;
  wholeTextTransforms?: boolean;
}

interface FrontierItem {
  text: string;
  parent: number;
  chain: readonly string[];
  depth: number;
}

/**
 * Recover every plausible encoded payload in `text`, recursively.
 *
 * Returns the decoded layers only — never the original. Order is breadth-first,
 * so shallow (and usually more relevant) decodes come first. Deduplicated by
 * decoded text so `base64` and `base64url` matching the same run don't both
 * appear.
 */
export function unwrap(text: string, opts: UnwrapOptions = {}): DecodedLayer[] {
  const {
    maxDepth = MAX_DEPTH,
    maxLayers = MAX_LAYERS,
    maxTotalChars = MAX_TOTAL_CHARS,
    wholeTextTransforms = true,
  } = opts;

  if (!text) return [];
  // UTF-16 length is an upper bound on the code-point count, so the cheap test
  // rules out the common case before paying for the exact one.
  if (text.length > MAX_INPUT_CHARS && codePointCount(text) > MAX_INPUT_CHARS) return [];

  const layers: DecodedLayer[] = [];
  const seen = new Set<string>([collapseWhitespace(text)]);
  let totalChars = 0;

  const frontier: FrontierItem[] = [{ text, parent: -1, chain: [], depth: 0 }];
  let head = 0; // a moving head instead of shift(), so the queue stays O(1)

  while (head < frontier.length && layers.length < maxLayers && totalChars < maxTotalChars) {
    const { text: current, parent, chain, depth } = frontier[head++]!;
    if (depth >= maxDepth) continue;

    const candidates: Candidate[] = [];
    for (const extractor of SPAN_EXTRACTORS) candidates.push(...extractor(current));
    // Whole-text ciphers only at the top level: rot13(rot13(x)) == x, and
    // allowing them at depth turns the frontier into a treadmill. Keep a
    // transform only when it makes the text look MORE like English than it
    // already did — otherwise every ordinary document would emit two useless
    // gibberish layers for the detector to chew through.
    if (wholeTextTransforms && depth === 0) {
      const baseline = englishScore(current);
      for (const [name, fn] of WHOLE_TRANSFORMS) {
        const transformed = fn(current);
        if (transformed === current || !looksLikeText(transformed)) continue;
        if (englishScore(transformed) > Math.max(baseline, 0.04)) {
          candidates.push({ span: null, name, text: transformed });
        }
      }
    }

    const toCodePointIndex = makeIndexMapper(current);

    for (const candidate of candidates) {
      if (layers.length >= maxLayers || totalChars >= maxTotalChars) break;
      const key = collapseWhitespace(candidate.text);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      totalChars += codePointCount(candidate.text);
      const nextChain = [...chain, candidate.name];
      layers.push({
        text: candidate.text,
        chain: nextChain,
        span: candidate.span
          ? [toCodePointIndex(candidate.span[0]), toCodePointIndex(candidate.span[1])]
          : null,
        parent,
        label: nextChain.join(" → "),
      });
      frontier.push({ text: candidate.text, parent: layers.length - 1, chain: nextChain, depth: depth + 1 });
    }
  }

  return layers;
}

/** One-line human summary, e.g. `base64 (1), base64 → rot13 (1)`. */
export function describe(layers: readonly DecodedLayer[], limit = 5): string {
  if (!layers.length) return "";
  const counts = new Map<string, number>();
  for (const layer of layers) counts.set(layer.label, (counts.get(layer.label) ?? 0) + 1);
  const parts = [...counts.entries()].slice(0, limit).map(([label, n]) => `${label} (${n})`);
  if (counts.size > limit) parts.push(`and ${counts.size - limit} more`);
  return parts.join(", ");
}
