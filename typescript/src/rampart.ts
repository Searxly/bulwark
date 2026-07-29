/**
 * Rampart — replace sensitive values with typed placeholders before the model sees them.
 *
 * The rest of Bulwark stops a hostile page from steering your model. Rampart
 * handles the mirror-image risk: your model — or the provider behind it — seeing
 * data it never needed. A fetched page, an email body, a support ticket or a log
 * excerpt routinely carries a real person's email, card or national ID, and an
 * API key or private key besides. Rampart replaces each one with a typed,
 * reversible placeholder (`[EMAIL_1_7f3a]`) so the model reasons over structure
 * rather than secrets, and — when the model is remote — the raw value never
 * leaves the machine.
 *
 * This is the *deterministic* layer: regexes gated by checksum validators, zero
 * dependencies, no model to load. It matches structured identifiers exactly —
 * Luhn-valid cards, mod-97-valid IBANs, structurally-valid SSNs, validated IPv4
 * and IPv6, JWTs whose header really decodes to JSON. Names and street addresses
 * need a NER model and belong in the host application; this is the portable,
 * always-available floor beneath it.
 *
 * Approach inspired by National Design Studio's Rampart (CC BY 4.0); this is an
 * original, dependency-free reimplementation of the deterministic detectors.
 *
 * ## Placeholder nonces
 *
 * Every placeholder carries a short random suffix drawn per redaction, and
 * {@link rehydrate} restores only tokens bearing that redaction's nonce. Without
 * it there is a real exfiltration path: an attacker who knows the placeholder
 * format plants `[EMAIL_1]` in a page, the model echoes it, and a host that
 * rehydrates the reply substitutes a *real* address into text the attacker can
 * read. The nonce is unguessable, so a planted placeholder simply stays literal.
 *
 * ## Dialect note
 *
 * The reference implementation is Python, whose `\d`, `\w`, `\s`,
 * `str.isdigit()` and `str.isalpha()` are all Unicode-aware; JavaScript's
 * equivalents are ASCII-only. Every one of them is therefore spelled out below
 * as an explicit Unicode class, so that a run of Arabic-Indic digits is a card
 * number here exactly as it is there, and a word boundary falls in the same
 * places. The one deliberate divergence: where Python would raise on a
 * non-decimal "digit" character (`int("²")`), the validators here return false.
 * Offsets are UTF-16 indices rather than code points, which is the natural unit
 * for slicing a JavaScript string; they are used only against this same string,
 * so every span still covers the value it named.
 */

/** A class of sensitive value. The string is the placeholder prefix. */
export type Entity =
  | "EMAIL"
  | "PHONE"
  | "CREDIT_CARD"
  | "SSN"
  | "IP_ADDRESS"
  | "IBAN"
  | "MAC_ADDRESS"
  | "API_KEY"
  | "JWT"
  | "PRIVATE_KEY"
  | "CRYPTO_ADDRESS"
  | "NATIONAL_ID";

export const ENTITIES: readonly Entity[] = [
  "EMAIL", "PHONE", "CREDIT_CARD", "SSN", "IP_ADDRESS", "IBAN",
  "MAC_ADDRESS", "API_KEY", "JWT", "PRIVATE_KEY", "CRYPTO_ADDRESS", "NATIONAL_ID",
];

// Higher priority wins an overlap: a checksum-backed class beats a looser one on
// the same bytes, so a Luhn-valid 16-digit run is a card, not a phone number.
const PRIORITY: Record<Entity, number> = {
  PRIVATE_KEY: 9,
  JWT: 7,
  API_KEY: 6,
  CREDIT_CARD: 5,
  IBAN: 5,
  CRYPTO_ADDRESS: 5,
  SSN: 4,
  EMAIL: 4,
  NATIONAL_ID: 4,
  MAC_ADDRESS: 3,
  IP_ADDRESS: 3,
  PHONE: 2,
};

/** A detected sensitive value and where it sits, as a half-open `[start, end)`
 * range of UTF-16 offsets. */
export interface PIISpan {
  readonly start: number;
  readonly end: number;
  readonly entity: Entity;
  readonly value: string;
}

/** The result of a redaction pass. */
export interface Redaction {
  text: string;
  count: number;
  /** "EMAIL×2, SSN×1" — labels and counts only, never values, so it is safe to log. */
  summary: string;
  /** placeholder → original. */
  map: Record<string, string>;
  nonce: string;
  entities: Set<Entity>;
  redacted: boolean;
}

// --- Unicode character classes ---------------------------------------------

// Python's Unicode `\w`: alphanumeric in any script, plus underscore.
const W = "\\p{L}\\p{N}_";
// A faithful `\b`. JavaScript's own is ASCII-only, so "sk-…" inside "clé sk-…"
// would start a match here that it does not start there.
const WB = `(?:(?<![${W}])(?=[${W}])|(?<=[${W}])(?![${W}]))`;
// Python's Unicode `\d` is the decimal-number category, not just 0-9.
const D = "\\p{Nd}";
// Python's Unicode `\s`, spelled out: JavaScript's omits U+001C–U+001F and
// U+0085 and adds U+FEFF.
const SPACE =
  "\\t\\n\\v\\f\\r \\u001c-\\u001f\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";

const ND_RE = /^\p{Nd}$/u;
const ALPHA_RE = /^\p{L}$/u;
const SPACE_RUN_RE = new RegExp(`[${SPACE}]+`, "gu");
const IBAN_STRIP_RE = new RegExp(`[${SPACE}-]`, "gu");

/**
 * The value of a single decimal digit, in any script, or -1 if the character is
 * not one. JavaScript has no Unicode-aware `Number()` (`Number("٤")` is `NaN`)
 * where Python's `int()` handles every decimal script, so recover the value from
 * the code point: Unicode lays every decimal script out as ten consecutive code
 * points ascending from its own zero, so the distance down to that zero *is* the
 * digit.
 *
 * Walk all the way down to the start of the run of decimal digits rather than
 * stopping after nine steps, because several scripts sit immediately adjacent to
 * one another: U+1D7CE…U+1D7FF is five ten-digit runs back to back, so for every
 * block but the first the character below the block's zero is still a digit, and
 * a nine-step search never finds a floor. The run as a whole is always a whole
 * number of ten-digit blocks, so the offset modulo ten is the value — for the
 * double-struck zero U+1D7D8, ten code points above the bold zero, that is 0.
 */
function decimalValue(ch: string): number {
  const cp = ch.codePointAt(0);
  if (cp === undefined) return -1;
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30;
  if (!ND_RE.test(ch)) return -1;
  let start = cp;
  while (start > 0 && ND_RE.test(String.fromCodePoint(start - 1))) start--;
  return (cp - start) % 10;
}

function isAlpha(ch: string): boolean {
  return ALPHA_RE.test(ch);
}

// --- validators (useful on their own) --------------------------------------

/** Mod-10 checksum. Gates CREDIT_CARD so arbitrary digit runs don't match. */
export function luhnValid(digits: string): boolean {
  const values: number[] = [];
  for (const ch of digits) {
    const value = decimalValue(ch);
    if (value < 0) return false;
    values.push(value);
  }
  if (values.length === 0) return false;
  let total = 0;
  let double = false;
  for (let i = values.length - 1; i >= 0; i--) {
    let d = values[i]!;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
    double = !double;
  }
  return total % 10 === 0;
}

/** US SSN structural rules: area not 000/666/900-999, group not 00, serial not
 * 0000. Rejects the many nine-digit runs that are order numbers. */
export function validSSN(digits: string): boolean {
  const chars = [...digits];
  if (chars.length !== 9) return false;
  const values = chars.map(decimalValue);
  if (values.some((v) => v < 0)) return false;
  const area = chars.slice(0, 3).join("");
  const group = chars.slice(3, 5).join("");
  const serial = chars.slice(5).join("");
  const areaValue = values[0]! * 100 + values[1]! * 10 + values[2]!;
  if (area === "000" || area === "666" || areaValue >= 900) return false;
  return group !== "00" && serial !== "0000";
}

/** ISO 13616 mod-97 check. Without it, any `XX00` followed by alphanumerics
 * matches — which is most product codes. */
export function ibanValid(candidate: string): boolean {
  const compact = [...candidate.replace(IBAN_STRIP_RE, "").toUpperCase()];
  if (compact.length < 15 || compact.length > 34) return false;
  if (!isAlpha(compact[0]!) || !isAlpha(compact[1]!)) return false;
  if (decimalValue(compact[2]!) < 0 || decimalValue(compact[3]!) < 0) return false;
  const rearranged = [...compact.slice(4), ...compact.slice(0, 4)];
  let total = 0;
  for (const ch of rearranged) {
    const digit = decimalValue(ch);
    if (digit >= 0) total = (total * 10 + digit) % 97;
    else if (isAlpha(ch)) total = (total * 100 + (ch.codePointAt(0)! - 55)) % 97;
    else return false;
  }
  return total === 1;
}

let utf8Decoder: TextDecoder | null = null;

/** Strict UTF-8, matching Python's `bytes.decode("utf-8")`: a malformed sequence
 * is a rejection, and a leading BOM is kept rather than swallowed. */
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

/** base64url → bytes, hand-rolled so the module stays isomorphic (no `atob`, no
 * `Buffer`). Mirrors Python's non-strict decoder: characters outside the
 * alphabet are discarded, everything from the first `=` is ignored, and a length
 * one past a multiple of four — which Python raises on — is a rejection. */
function base64UrlToBytes(segment: string): Uint8Array | null {
  const data = segment
    .split("=")[0]!
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .replace(/[^A-Za-z0-9+/]/g, "");
  const n = data.length;
  if (n % 4 === 1) return null;
  const rem = n % 4;
  const out = new Uint8Array(((n / 4) | 0) * 3 + (rem === 0 ? 0 : rem - 1));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < n; i++) {
    acc = (acc << 6) | B64_VALUES[data.charCodeAt(i)]!;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/** Three base64url segments whose header decodes to JSON naming an algorithm. */
export function jwtValid(candidate: string): boolean {
  const parts = candidate.split(".");
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) return false;
  const raw = base64UrlToBytes(parts[0]!);
  if (raw === null) return false;
  const decoded = utf8Decode(raw);
  if (decoded === null) return false;
  let header: unknown;
  try {
    header = JSON.parse(decoded);
  } catch {
    // Any decode failure means "not a JWT".
    return false;
  }
  // A JSON array is an object to `typeof`, but it is not Python's `dict`.
  if (typeof header !== "object" || header === null || Array.isArray(header)) return false;
  return "alg" in header;
}

// --- detection -------------------------------------------------------------

// Provider-prefixed credentials only. A generic entropy heuristic would redact
// every commit hash and asset digest in the corpus; a known prefix does not.
const API_KEY_RE = new RegExp(
  `${WB}(?:` +
    "sk-[A-Za-z0-9_-]{16,}" +                      // OpenAI-style
    "|sk-ant-[A-Za-z0-9_-]{16,}" +                 // Anthropic
    "|gh[pousr]_[A-Za-z0-9]{16,}" +                // GitHub
    "|github_pat_[A-Za-z0-9_]{20,}" +
    "|AKIA[0-9A-Z]{16}" +                          // AWS access key id
    "|ASIA[0-9A-Z]{16}" +
    "|AIza[0-9A-Za-z_-]{35}" +                     // Google API key
    "|xox[baprs]-[A-Za-z0-9-]{10,}" +              // Slack
    "|glpat-[A-Za-z0-9_-]{16,}" +                  // GitLab
    "|npm_[A-Za-z0-9]{30,}" +
    "|dop_v1_[a-f0-9]{64}" +                       // DigitalOcean
    "|SG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}" + // SendGrid
    "|rk_live_[A-Za-z0-9]{16,}|sk_live_[A-Za-z0-9]{16,}|pk_live_[A-Za-z0-9]{16,}" +
    `)${WB}`,
  "gu",
);
const PRIVATE_KEY_RE =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/gsu;
const JWT_RE = new RegExp(
  `${WB}eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}${WB}`,
  "gu",
);
const EMAIL_RE = new RegExp(
  `${WB}[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\\.[A-Za-z]{2,}${WB}`,
  "gu",
);
// IBANs appear either contiguous ("DE89370400440532013000") or grouped in fours
// ("GB82 WEST 1234 5698 7654 32"). A single permissive pattern over "separator
// then alphanumerics" happily swallows the next word of the sentence, so the
// candidate match is trimmed back to its longest validating prefix below.
const IBAN_RE = new RegExp(
  `${WB}[A-Z]{2}${D}{2}(?:[A-Za-z0-9]{11,30}|(?:[ -][A-Za-z0-9]{2,4}){2,10})${WB}`,
  "gu",
);
const IPV4_RE = new RegExp(
  `${WB}(?:(?:25[0-5]|2[0-4]${D}|1${D}${D}|[1-9]?${D})\\.){3}(?:25[0-5]|2[0-4]${D}|1${D}${D}|[1-9]?${D})${WB}`,
  "gu",
);
const IPV6_RE = new RegExp(
  `(?<![:.${W}])(?:` +
    "(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}" +
    "|(?:[0-9A-Fa-f]{1,4}:){1,7}:" +
    "|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}" +
    "|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}" +
    "|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}" +
    "|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}" +
    "|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}" +
    "|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}" +
    "|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}" +
    `)(?![:.${W}])`,
  "gu",
);
const MAC_RE = new RegExp(`${WB}(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}${WB}`, "gu");
// Separators or a leading + are required, so bare digit runs (order numbers,
// prices, years) stay put.
const PHONE_RES = [
  new RegExp(
    `(?<![${W}.])(?:\\+?${D}{1,3}[ .-])?\\(?${D}{3}\\)?[ .-]${D}{3}[ .-]${D}{4}(?![${W}])`,
    "gu",
  ),
  new RegExp(`(?<![${W}.])\\+${D}[${D} .-]{6,}${D}(?![${W}])`, "gu"),
];
const ETH_RE = new RegExp(`${WB}0x[a-fA-F0-9]{40}${WB}`, "gu");
const BTC_RE = new RegExp(
  `${WB}(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})${WB}`,
  "gu",
);
// UK National Insurance number: two prefix letters, six digits, a suffix letter.
const NINO_RE = new RegExp(
  `${WB}[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z][${SPACE}]?${D}{2}[${SPACE}]?${D}{2}` +
    `[${SPACE}]?${D}{2}[${SPACE}]?[A-D]${WB}`,
  "gu",
);
const DIGIT_RUN_RE = new RegExp(`${D}(?:[ .-]?${D})*`, "gu");

// Dotted-quad version strings are indistinguishable from IPv4 addresses in
// isolation, so use the one cue that is actually present: what precedes them.
// The trailing `\n?$` is Python's `$`, which also matches before a final
// newline; JavaScript's `$` without `m` matches only at the very end.
const VERSION_CONTEXT_RE = new RegExp(
  `(?:${WB}v|${WB}version[${SPACE}]+|${WB}release[${SPACE}]+|${WB}build[${SPACE}]+)\\n?$`,
  "iu",
);

function regexSpans(
  text: string,
  regex: RegExp,
  entity: Entity,
  validator?: (value: string) => boolean,
): PIISpan[] {
  const spans: PIISpan[] = [];
  for (const match of text.matchAll(regex)) {
    const value = match[0]!;
    if (validator !== undefined && !validator(value)) continue;
    const start = match.index ?? 0;
    if (entity === "IP_ADDRESS" && VERSION_CONTEXT_RE.test(text.slice(0, start).slice(-12))) continue;
    spans.push({ start, end: start + value.length, entity, value });
  }
  return spans;
}

/**
 * IBAN spans, trimming a greedy candidate back to its longest valid prefix.
 *
 * Regex alone cannot know where an IBAN ends: "GB82 WEST 1234 5698 7654 32
 * please" is one uninterrupted run of separator-and-alphanumerics. The mod-97
 * checksum does know, so let it decide — drop trailing groups until the number
 * validates, and take the first prefix that does.
 */
function ibanSpans(text: string): PIISpan[] {
  const spans: PIISpan[] = [];
  for (const match of text.matchAll(IBAN_RE)) {
    const start = match.index ?? 0;
    let candidate = match[0]!;
    while (candidate.length >= 15) {
      if (ibanValid(candidate)) {
        spans.push({ start, end: start + candidate.length, entity: "IBAN", value: candidate });
        break;
      }
      const cut = Math.max(candidate.lastIndexOf(" "), candidate.lastIndexOf("-"));
      if (cut <= 4) break;
      candidate = candidate.slice(0, cut);
    }
  }
  return spans;
}

/** Card and SSN detection over digit runs, so every separator variant
 * ("888-88-8888", "888 88 8888", "888888888") collapses to one rule. */
function digitSpans(text: string): PIISpan[] {
  const spans: PIISpan[] = [];
  for (const match of text.matchAll(DIGIT_RUN_RE)) {
    const run = match[0]!;
    const runStart = match.index ?? 0;
    let digits = "";
    let start = -1;
    let end = -1;
    let offset = 0;
    // Iterate code points, not UTF-16 units: a digit outside the BMP (U+1D7D8
    // and friends are decimal digits too) would otherwise be split in half.
    for (const ch of run) {
      if (decimalValue(ch) >= 0) {
        digits += ch;
        if (start < 0) start = runStart + offset;
        end = runStart + offset + ch.length;
      }
      offset += ch.length;
    }
    if (start < 0) continue;
    const value = text.slice(start, end);
    const length = [...digits].length;
    if (length >= 13 && length <= 19 && luhnValid(digits)) {
      spans.push({ start, end, entity: "CREDIT_CARD", value });
    } else if (length === 9 && !run.includes(".") && validSSN(digits)) {
      // Dots disqualify: "192.168.1.42" has nine digits and satisfies every SSN
      // structural rule, and SSN outranks IP_ADDRESS on overlap — so without
      // this an ordinary private IP is redacted as a social security number.
      // No one writes an SSN with dots.
      spans.push({ start, end, entity: "SSN", value });
    }
  }
  return spans;
}

/** Every sensitive span in `text`, before overlap resolution. */
export function detectPII(text: string): PIISpan[] {
  const spans: PIISpan[] = [];
  spans.push(...regexSpans(text, PRIVATE_KEY_RE, "PRIVATE_KEY"));
  spans.push(...regexSpans(text, JWT_RE, "JWT", jwtValid));
  spans.push(...regexSpans(text, API_KEY_RE, "API_KEY"));
  spans.push(...regexSpans(text, EMAIL_RE, "EMAIL"));
  spans.push(...ibanSpans(text));
  spans.push(...regexSpans(text, IPV4_RE, "IP_ADDRESS"));
  spans.push(...regexSpans(text, IPV6_RE, "IP_ADDRESS"));
  spans.push(...regexSpans(text, MAC_RE, "MAC_ADDRESS"));
  spans.push(...regexSpans(text, ETH_RE, "CRYPTO_ADDRESS"));
  spans.push(...regexSpans(text, BTC_RE, "CRYPTO_ADDRESS"));
  spans.push(...regexSpans(text, NINO_RE, "NATIONAL_ID"));
  for (const regex of PHONE_RES) spans.push(...regexSpans(text, regex, "PHONE"));
  spans.push(...digitSpans(text));
  return spans;
}

/** Reduce overlapping spans to a disjoint set. Higher priority wins; ties go to
 * the longer span. Biased toward keeping a redaction: on any overlap the
 * survivor covers both ranges, so nothing sensitive is left exposed by a partial
 * match. */
function merge(spans: readonly PIISpan[]): PIISpan[] {
  if (spans.length < 2) return [...spans];
  const ordered = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const out: PIISpan[] = [];
  for (const span of ordered) {
    const prev = out[out.length - 1];
    if (prev === undefined || span.start >= prev.end) {
      out.push(span);
      continue;
    }
    const winner =
      PRIORITY[prev.entity] !== PRIORITY[span.entity]
        ? PRIORITY[prev.entity] > PRIORITY[span.entity]
          ? prev
          : span
        : prev.end - prev.start >= span.end - span.start
          ? prev
          : span;
    out[out.length - 1] = {
      start: Math.min(prev.start, span.start),
      end: Math.max(prev.end, span.end),
      entity: winner.entity,
      value: winner.value,
    };
  }
  return out;
}

function normalize(value: string): string {
  // Trim only spaces: every whitespace run has just become one, and JavaScript's
  // own `trim` would additionally strip U+FEFF, which Python's does not.
  return value.replace(SPACE_RUN_RE, " ").replace(/^ +| +$/g, "").toLowerCase();
}

/**
 * Four random hex digits, drawn once per redaction and embedded in every
 * placeholder it mints. No `Math.random` fallback: a guessable nonce is exactly
 * the hole the nonce exists to close, so a runtime without a CSPRNG must fail
 * loudly rather than quietly mint forgeable placeholders.
 */
function makeNonce(): string {
  if (typeof globalThis.crypto?.getRandomValues !== "function") {
    throw new Error("bulwark: rampart placeholders need crypto.getRandomValues, which this runtime does not provide");
  }
  const buf = new Uint8Array(2);
  globalThis.crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

// --- public API ------------------------------------------------------------

export interface RedactOptions {
  /** Fix the per-redaction nonce. For tests and golden files only — in
   * production let it be drawn randomly, which is the whole point of it. */
  nonce?: string;
}

function untouched(text: string): Redaction {
  return { text, count: 0, summary: "", map: {}, nonce: "", entities: new Set(), redacted: false };
}

/**
 * Replace sensitive values with typed placeholders.
 *
 * Entities in `keep` are detected but left in place — useful when downstream
 * logic genuinely needs the real value (keeping `IP_ADDRESS` in a log triage
 * flow, say). The same value always maps to the same placeholder within one
 * call, so a document mentioning an address twice still reads coherently.
 */
export function redact(
  text: string,
  keep: Iterable<Entity> = [],
  opts: RedactOptions = {},
): Redaction {
  const keepSet = new Set(keep);
  if (!text) return untouched(text);

  const spans = merge(detectPII(text)).filter((s) => !keepSet.has(s.entity));
  if (spans.length === 0) return untouched(text);

  const nonce = opts.nonce || makeNonce();
  const forward = new Map<string, string>();
  const reverse: Record<string, string> = {};
  const counters = new Map<string, number>();
  const labelCounts = new Map<string, number>();
  const labelOrder: string[] = [];

  const pieces: string[] = [];
  let cursor = 0;
  for (const span of spans) {
    // merge() returns them in order.
    const label = span.entity;
    const key = `${label}:${normalize(span.value)}`;
    let token = forward.get(key);
    if (token === undefined) {
      const n = (counters.get(label) ?? 0) + 1;
      counters.set(label, n);
      token = `[${label}_${n}_${nonce}]`;
      forward.set(key, token);
      reverse[token] = span.value;
    }
    pieces.push(text.slice(cursor, span.start), token);
    cursor = span.end;
    if (!labelCounts.has(label)) labelOrder.push(label);
    labelCounts.set(label, (labelCounts.get(label) ?? 0) + 1);
  }
  pieces.push(text.slice(cursor));

  return {
    text: pieces.join(""),
    count: spans.length,
    summary: labelOrder.map((label) => `${label}×${labelCounts.get(label)}`).join(", "),
    map: reverse,
    nonce,
    entities: new Set(spans.map((s) => s.entity)),
    redacted: true,
  };
}

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Restore original values from a {@link redact} map.
 *
 * Only tokens present in `mapping` are replaced, and because every token carries
 * that redaction's random nonce, a placeholder an attacker planted in the source
 * can never be rehydrated into a real value. Unknown placeholders are left
 * exactly as they are.
 */
export function rehydrate(text: string, mapping: Record<string, string>): string {
  const tokens = Object.keys(mapping);
  if (!text || tokens.length === 0) return text;
  // Longest first so [EMAIL_10_ab12] is not shadowed by [EMAIL_1_ab12].
  tokens.sort((a, b) => b.length - a.length);
  const pattern = new RegExp(tokens.map(escapeRegExp).join("|"), "g");
  return text.replace(pattern, (token) => mapping[token]!);
}
