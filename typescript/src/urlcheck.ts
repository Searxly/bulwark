/**
 * Decide whether a URL is a destination or a delivery mechanism.
 *
 * Wherever an LLM system touches a URL — a link a summarizer emitted, an
 * argument an agent wants to pass to `navigate` — the same two questions apply.
 * *Where does this actually point?* and *how much data is riding along?*
 *
 * Both are harder than they look, because a host is not a string. All of these
 * name 127.0.0.1, and a substring check for "127.0.0.1" catches none of them:
 *
 *     http://2130706433/     http://0177.0.0.1/    http://0x7f.0.0.1/
 *     http://127.1/          http://[::ffff:127.0.0.1]/
 *
 * And all of these look like they point at a domain you trust, but do not:
 *
 *     https://trusted.example.com@attacker.test/
 *     https://trusted.example.com.attacker.test/
 *     https://xn--trustd-9wa.example/            (homograph)
 *
 * So the host is *canonicalized* the way the network stack would canonicalize
 * it — the full `inet_aton` grammar, IPv6 forms, IPv4-mapped addresses — and
 * only then classified. The data-carrying checks are separate: an opaque blob
 * is exfiltration-shaped wherever it sits, and attackers move it from the query
 * string to the path, the fragment, or a subdomain precisely because guards
 * tend to only look at the query.
 *
 * **This is syntactic analysis only.** No DNS is resolved — Bulwark stays
 * deterministic and dependency-free — so a public hostname that resolves to
 * 169.254.169.254 passes here. Keep a resolver-level SSRF guard in the fetch
 * layer too; this is the check you can run before you have a socket, not a
 * replacement for the one you run when you do.
 */

import type { Finding, Severity } from "./types.js";

/** `ipv4` includes decimal/octal/hex/short forms once canonicalized. */
export type HostKind = "domain" | "ipv4" | "ipv6" | "empty" | "malformed";

// Cloud instance-metadata endpoints. Reaching one from a hijacked agent hands
// an attacker the machine's credentials, which makes them the highest-value
// target in the private ranges rather than just another internal address.
const METADATA_HOSTS = new Set([
  "169.254.169.254", // AWS / Azure / GCP / DigitalOcean IMDS
  "169.254.170.2", // AWS ECS task metadata
  "100.100.100.200", // Alibaba Cloud
  "192.0.0.192", // Oracle Cloud
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
]);
const METADATA_IPV6 = new Set(["fd00:ec2::254"]);

const LOCAL_SUFFIXES = [".local", ".internal", ".localhost", ".home.arpa", ".localdomain"];
const LOCAL_NAMES = new Set(["localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"]);

const SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.\-]*:/;
const OPAQUE_RUN_RE = /[A-Za-z0-9+/=_-]{8,}/g;
// Python's `$` also matches immediately before a single trailing newline, so the
// optional "\n" keeps a label like "com\n" a valid label here too.
const LABEL_RE = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\n?$/;
// Everything Python's str.isprintable() rejects, plus the ASCII space: the
// General_Category "Other" and "Separator" groups. Verified to be exactly the
// set `not ch.isprintable() or ch.isspace()` matches.
const UNPRINTABLE_RE = /[\p{C}\p{Z}]/gu;
const LETTER_RE = /\p{L}/u;
const DIGIT_RE = /\p{Nd}/u;
// Python's str.isspace(): bidirectional class WS/B/S, or category Zs. Not the
// same set as JavaScript's \s, which adds U+FEFF and drops U+001C–U+001F/U+0085.
const PY_SPACE = "\\t-\\r\\x1c-\\x1f \\x85\\p{Zs}\\u2028\\u2029";
const LEADING_SPACE_RE = new RegExp(`^[${PY_SPACE}]+`, "u");
const TRAILING_SPACE_RE = new RegExp(`[${PY_SPACE}]+$`, "u");

// Schemes that do something other than fetch a document, and are therefore
// never a legitimate "go here" target from untrusted content.
const ACTIVE_SCHEMES = new Set(["javascript", "data", "vbscript", "file", "jar", "blob", "about"]);

/** Everything syntactic analysis can tell you about one URL. */
export interface URLAssessment {
  raw: string;
  scheme: string;
  userinfo: string | null;
  host: string;
  canonicalHost: string;
  port: number | null;
  path: string;
  query: string;
  fragment: string;

  kind: HostKind;
  isPrivate: boolean;
  isMetadata: boolean;
  isPunycode: boolean;
  isMixedScript: boolean;
  hasCredentials: boolean;

  opaqueInQuery: number;
  opaqueInPath: number;
  opaqueInFragment: number;
  opaqueInSubdomain: number;
  /** The longest opaque run found anywhere in the URL. */
  maxOpaque: number;

  /** True when nothing was found — the URL is a plain destination. */
  safe: boolean;
  findings: Finding[];
}

/** The pieces of a URL, as `splitUrl` reads them. */
export interface SplitURL {
  scheme: string;
  userinfo: string | null;
  host: string;
  port: number | null;
  path: string;
  query: string;
  fragment: string;
}

// --- integer parsing -------------------------------------------------------

/** The value of one Unicode decimal digit, or null if `ch` is not one. */
function decimalValue(ch: string): number | null {
  const cp = ch.codePointAt(0);
  if (cp === undefined) return null;
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30;
  // Nd is the gate, and it has to come first: CPython's int() takes exactly the
  // characters that carry a decimal value, so a superscript or a circled digit
  // is not a digit to it — even though NFKC folds "²" to "2" and even though
  // str.isdigit() says yes. Testing the fold first would quietly turn "²" into
  // the address 0.0.0.2.
  if (!DIGIT_RE.test(ch)) return null;
  // Fullwidth and mathematical digits fold to ASCII under NFKC. They are also
  // the only decimal runs that sit back-to-back with another run, so folding
  // them first makes the walk below unambiguous.
  const folded = ch.normalize("NFKC");
  const foldedCp = folded.length <= 2 ? folded.codePointAt(0) : undefined;
  if (foldedCp !== undefined && foldedCp >= 0x30 && foldedCp <= 0x39) return foldedCp - 0x30;
  // Every other decimal digit belongs to a contiguous run of ten that starts at
  // its script's zero, so the distance back to the start of the run is the value.
  for (let value = 0; value < 10; value++) {
    if (!DIGIT_RE.test(String.fromCodePoint(cp - value - 1))) return value;
  }
  return null;
}

/**
 * Parse an integer the way CPython's `int(text, base)` does, because that is
 * what the reference implementation of `parseIpv4` relies on: surrounding
 * whitespace and a leading sign are allowed, `_` may separate digits, and any
 * Unicode decimal digit counts — `١٢٧.0.0.1` is 127.0.0.1. `parseInt` accepts a
 * different (looser at the end, tighter at the start) language entirely.
 */
function pyInt(text: string, base: 8 | 10 | 16): number | null {
  let body = text.replace(LEADING_SPACE_RE, "").replace(TRAILING_SPACE_RE, "");
  let sign = 1;
  if (body.startsWith("+") || body.startsWith("-")) {
    if (body.startsWith("-")) sign = -1;
    body = body.slice(1);
  }
  // The literal prefix for the base is allowed once the base is explicit, which
  // is why "0o17" is an octal component of an address and "0b11" is not one.
  const prefix = base === 16 ? "0x" : base === 8 ? "0o" : "";
  let afterPrefix = false;
  if (prefix && body.slice(0, 2).toLowerCase() === prefix) {
    body = body.slice(2);
    afterPrefix = true;
  }

  let result = 0;
  let sawDigit = false;
  let separatorAllowed = afterPrefix;
  for (const ch of body) {
    if (ch === "_") {
      // An underscore is only a separator: never leading, trailing or doubled.
      if (!separatorAllowed) return null;
      separatorAllowed = false;
      continue;
    }
    let digit = decimalValue(ch);
    if (digit === null && base === 16) {
      const lowered = ch.toLowerCase();
      if (lowered.length === 1 && lowered >= "a" && lowered <= "f") {
        digit = lowered.charCodeAt(0) - 0x61 + 10;
      }
    }
    if (digit === null || digit >= base) return null;
    result = result * base + digit;
    sawDigit = true;
    separatorAllowed = true;
  }
  if (!sawDigit || !separatorAllowed) return null;
  return sign * result;
}

// --- host canonicalization -------------------------------------------------

/** One component of an inet_aton-style address: 0x-hex, 0-octal, decimal. */
function parseIpv4Part(part: string): number | null {
  if (!part) return null;
  if (part.toLowerCase().startsWith("0x")) return part.length > 2 ? pyInt(part.slice(2), 16) : null;
  if (part.startsWith("0") && part.length > 1) return pyInt(part, 8);
  return pyInt(part, 10);
}

/**
 * Canonicalize any inet_aton-accepted IPv4 spelling to a 32-bit integer.
 *
 * Handles the four forms the C library accepts and browsers still honour:
 * `a.b.c.d`, `a.b.c` (c is 16-bit), `a.b` (b is 24-bit) and a bare 32-bit `a` —
 * each component independently decimal, octal or hex. Returns null when the
 * host is not an IPv4 literal in any of those spellings.
 */
export function parseIpv4(host: string): number | null {
  const parts = host.split(".");
  if (parts.length < 1 || parts.length > 4) return null;
  const values: number[] = [];
  for (const part of parts) {
    const value = parseIpv4Part(part);
    if (value === null || value < 0) return null;
    values.push(value);
  }

  // Every component but the last is one byte; the last absorbs the remainder.
  // Arithmetic, not shifts: JavaScript's bitwise operators are 32-bit *signed*,
  // so `192 << 24` would come out negative.
  const limit = 2 ** (8 * (5 - values.length));
  if (values[values.length - 1]! >= limit) return null;
  if (values.slice(0, -1).some((v) => v > 0xff)) return null;

  let result = values[values.length - 1]!;
  values.slice(0, -1).forEach((value, i) => {
    result += value * 2 ** (8 * (3 - i));
  });
  return result <= 0xffffffff ? result : null;
}

export function ipv4ToString(value: number): string {
  return [24, 16, 8, 0].map((shift) => Math.floor(value / 2 ** shift) % 256).join(".");
}

const PRIVATE_V4_RANGES: [number, number][] = (
  [
    [0x00000000, 8], //  0.0.0.0/8      this network
    [0x0a000000, 8], //  10/8           private
    [0x7f000000, 8], //  127/8          loopback
    [0xa9fe0000, 16], // 169.254/16     link-local (incl. cloud metadata)
    [0xac100000, 12], // 172.16/12      private
    [0xc0a80000, 16], // 192.168/16     private
    [0x64400000, 10], // 100.64/10      CGNAT
    [0xc0000000, 24], // 192.0.0/24     IETF protocol assignments
    [0xc0000200, 24], // 192.0.2/24     TEST-NET-1
    [0xc6120000, 15], // 198.18/15      benchmarking
    [0xc6336400, 24], // 198.51.100/24  TEST-NET-2
    [0xcb007100, 24], // 203.0.113/24   TEST-NET-3
    [0xe0000000, 4], //  224/4          multicast
    [0xf0000000, 4], //  240/4          reserved + broadcast
  ] as [number, number][]
).map(([base, bits]) => [base, base + 2 ** (32 - bits) - 1]);

function ipv4IsPrivate(value: number): boolean {
  return PRIVATE_V4_RANGES.some(([low, high]) => low <= value && value <= high);
}

function ipv6IsPrivate(host: string): boolean {
  const h = stripBrackets(host).toLowerCase().split("%")[0]!; // drop any zone id
  if (h === "::1" || h === "::" || h === "0:0:0:0:0:0:0:1") return true;
  if (/^fe[89ab]/.test(h) || h.startsWith("fe80:")) return true; // fe80::/10 link-local
  if (h.startsWith("fc") || h.startsWith("fd")) return true; // fc00::/7 unique-local
  if (h.startsWith("::")) {
    // IPv4-mapped and IPv4-compatible forms carry a v4 address inside.
    const tail = h.slice(h.lastIndexOf(":") + 1);
    const value = tail.includes(".") ? parseIpv4(tail) : null;
    if (value !== null) return ipv4IsPrivate(value);
  }
  return false;
}

/** Python's str.strip("[]"): remove every leading and trailing bracket. */
function stripBrackets(text: string): string {
  return text.replace(/^[[\]]+/, "").replace(/[[\]]+$/, "");
}

// Coarse script names, matching the first word of the Unicode character name
// the reference implementation reads ("CYRILLIC SMALL LETTER A" -> CYRILLIC).
// JavaScript has no character-name database, so the Script property stands in:
// every script whose letters Python names uniformly is listed here, spelled the
// way those names begin (Han is CJK, Canadian_Aboriginal is CANADIAN, and the
// several Old_* and Tai_* scripts collapse the way their names do). Scripts
// encoded after the reference's Unicode version have no letters there at all,
// so they are deliberately absent and fall to UNKNOWN.
const SCRIPTS: [RegExp, string][] = [
  [/\p{Script=Latin}/u, "LATIN"],
  [/\p{Script=Greek}/u, "GREEK"],
  [/\p{Script=Cyrillic}/u, "CYRILLIC"],
  [/\p{Script=Arabic}/u, "ARABIC"],
  [/\p{Script=Hebrew}/u, "HEBREW"],
  [/\p{Script=Han}/u, "CJK"],
  [/\p{Script=Hiragana}/u, "HIRAGANA"],
  [/\p{Script=Katakana}/u, "KATAKANA"],
  [/\p{Script=Hangul}/u, "HANGUL"],
  [/\p{Script=Devanagari}/u, "DEVANAGARI"],
  [/\p{Script=Thai}/u, "THAI"],
  [/\p{Script=Armenian}/u, "ARMENIAN"],
  [/\p{Script=Georgian}/u, "GEORGIAN"],
  [/\p{Script=Cherokee}/u, "CHEROKEE"],
  [/\p{Script=Ethiopic}/u, "ETHIOPIC"],
  [/\p{Script=Adlam}/u, "ADLAM"],
  [/\p{Script=Ahom}/u, "AHOM"],
  [/\p{Script=Anatolian_Hieroglyphs}/u, "ANATOLIAN"],
  [/\p{Script=Avestan}/u, "AVESTAN"],
  [/\p{Script=Balinese}/u, "BALINESE"],
  [/\p{Script=Bamum}/u, "BAMUM"],
  [/\p{Script=Bassa_Vah}/u, "BASSA"],
  [/\p{Script=Batak}/u, "BATAK"],
  [/\p{Script=Bengali}/u, "BENGALI"],
  [/\p{Script=Bhaiksuki}/u, "BHAIKSUKI"],
  [/\p{Script=Bopomofo}/u, "BOPOMOFO"],
  [/\p{Script=Brahmi}/u, "BRAHMI"],
  [/\p{Script=Buginese}/u, "BUGINESE"],
  [/\p{Script=Buhid}/u, "BUHID"],
  [/\p{Script=Canadian_Aboriginal}/u, "CANADIAN"],
  [/\p{Script=Carian}/u, "CARIAN"],
  [/\p{Script=Caucasian_Albanian}/u, "CAUCASIAN"],
  [/\p{Script=Chakma}/u, "CHAKMA"],
  [/\p{Script=Cham}/u, "CHAM"],
  [/\p{Script=Chorasmian}/u, "CHORASMIAN"],
  [/\p{Script=Coptic}/u, "COPTIC"],
  [/\p{Script=Cuneiform}/u, "CUNEIFORM"],
  [/\p{Script=Cypriot}/u, "CYPRIOT"],
  [/\p{Script=Deseret}/u, "DESERET"],
  [/\p{Script=Dives_Akuru}/u, "DIVES"],
  [/\p{Script=Dogra}/u, "DOGRA"],
  [/\p{Script=Duployan}/u, "DUPLOYAN"],
  [/\p{Script=Egyptian_Hieroglyphs}/u, "EGYPTIAN"],
  [/\p{Script=Elbasan}/u, "ELBASAN"],
  [/\p{Script=Elymaic}/u, "ELYMAIC"],
  [/\p{Script=Glagolitic}/u, "GLAGOLITIC"],
  [/\p{Script=Gothic}/u, "GOTHIC"],
  [/\p{Script=Grantha}/u, "GRANTHA"],
  [/\p{Script=Gujarati}/u, "GUJARATI"],
  [/\p{Script=Gunjala_Gondi}/u, "GUNJALA"],
  [/\p{Script=Gurmukhi}/u, "GURMUKHI"],
  [/\p{Script=Hanifi_Rohingya}/u, "HANIFI"],
  [/\p{Script=Hanunoo}/u, "HANUNOO"],
  [/\p{Script=Hatran}/u, "HATRAN"],
  [/\p{Script=Imperial_Aramaic}/u, "IMPERIAL"],
  [/\p{Script=Inscriptional_Pahlavi}/u, "INSCRIPTIONAL"],
  [/\p{Script=Inscriptional_Parthian}/u, "INSCRIPTIONAL"],
  [/\p{Script=Javanese}/u, "JAVANESE"],
  [/\p{Script=Kaithi}/u, "KAITHI"],
  [/\p{Script=Kannada}/u, "KANNADA"],
  [/\p{Script=Kayah_Li}/u, "KAYAH"],
  [/\p{Script=Kharoshthi}/u, "KHAROSHTHI"],
  [/\p{Script=Khitan_Small_Script}/u, "KHITAN"],
  [/\p{Script=Khmer}/u, "KHMER"],
  [/\p{Script=Khojki}/u, "KHOJKI"],
  [/\p{Script=Khudawadi}/u, "KHUDAWADI"],
  [/\p{Script=Lao}/u, "LAO"],
  [/\p{Script=Lepcha}/u, "LEPCHA"],
  [/\p{Script=Limbu}/u, "LIMBU"],
  [/\p{Script=Linear_A}/u, "LINEAR"],
  [/\p{Script=Linear_B}/u, "LINEAR"],
  [/\p{Script=Lisu}/u, "LISU"],
  [/\p{Script=Lycian}/u, "LYCIAN"],
  [/\p{Script=Lydian}/u, "LYDIAN"],
  [/\p{Script=Mahajani}/u, "MAHAJANI"],
  [/\p{Script=Makasar}/u, "MAKASAR"],
  [/\p{Script=Malayalam}/u, "MALAYALAM"],
  [/\p{Script=Mandaic}/u, "MANDAIC"],
  [/\p{Script=Manichaean}/u, "MANICHAEAN"],
  [/\p{Script=Marchen}/u, "MARCHEN"],
  [/\p{Script=Masaram_Gondi}/u, "MASARAM"],
  [/\p{Script=Medefaidrin}/u, "MEDEFAIDRIN"],
  [/\p{Script=Meetei_Mayek}/u, "MEETEI"],
  [/\p{Script=Mende_Kikakui}/u, "MENDE"],
  [/\p{Script=Meroitic_Cursive}/u, "MEROITIC"],
  [/\p{Script=Meroitic_Hieroglyphs}/u, "MEROITIC"],
  [/\p{Script=Miao}/u, "MIAO"],
  [/\p{Script=Modi}/u, "MODI"],
  [/\p{Script=Mongolian}/u, "MONGOLIAN"],
  [/\p{Script=Mro}/u, "MRO"],
  [/\p{Script=Multani}/u, "MULTANI"],
  [/\p{Script=Myanmar}/u, "MYANMAR"],
  [/\p{Script=Nabataean}/u, "NABATAEAN"],
  [/\p{Script=Nandinagari}/u, "NANDINAGARI"],
  [/\p{Script=New_Tai_Lue}/u, "NEW"],
  [/\p{Script=Newa}/u, "NEWA"],
  [/\p{Script=Nko}/u, "NKO"],
  [/\p{Script=Nushu}/u, "NUSHU"],
  [/\p{Script=Nyiakeng_Puachue_Hmong}/u, "NYIAKENG"],
  [/\p{Script=Ogham}/u, "OGHAM"],
  [/\p{Script=Ol_Chiki}/u, "OL"],
  [/\p{Script=Old_Hungarian}/u, "OLD"],
  [/\p{Script=Old_Italic}/u, "OLD"],
  [/\p{Script=Old_North_Arabian}/u, "OLD"],
  [/\p{Script=Old_Permic}/u, "OLD"],
  [/\p{Script=Old_Persian}/u, "OLD"],
  [/\p{Script=Old_Sogdian}/u, "OLD"],
  [/\p{Script=Old_South_Arabian}/u, "OLD"],
  [/\p{Script=Old_Turkic}/u, "OLD"],
  [/\p{Script=Oriya}/u, "ORIYA"],
  [/\p{Script=Osage}/u, "OSAGE"],
  [/\p{Script=Osmanya}/u, "OSMANYA"],
  [/\p{Script=Pahawh_Hmong}/u, "PAHAWH"],
  [/\p{Script=Palmyrene}/u, "PALMYRENE"],
  [/\p{Script=Pau_Cin_Hau}/u, "PAU"],
  [/\p{Script=Phags_Pa}/u, "PHAGS-PA"],
  [/\p{Script=Phoenician}/u, "PHOENICIAN"],
  [/\p{Script=Psalter_Pahlavi}/u, "PSALTER"],
  [/\p{Script=Rejang}/u, "REJANG"],
  [/\p{Script=Runic}/u, "RUNIC"],
  [/\p{Script=Samaritan}/u, "SAMARITAN"],
  [/\p{Script=Saurashtra}/u, "SAURASHTRA"],
  [/\p{Script=Sharada}/u, "SHARADA"],
  [/\p{Script=Shavian}/u, "SHAVIAN"],
  [/\p{Script=Siddham}/u, "SIDDHAM"],
  [/\p{Script=Sinhala}/u, "SINHALA"],
  [/\p{Script=Sogdian}/u, "SOGDIAN"],
  [/\p{Script=Sora_Sompeng}/u, "SORA"],
  [/\p{Script=Soyombo}/u, "SOYOMBO"],
  [/\p{Script=Sundanese}/u, "SUNDANESE"],
  [/\p{Script=Syloti_Nagri}/u, "SYLOTI"],
  [/\p{Script=Syriac}/u, "SYRIAC"],
  [/\p{Script=Tagalog}/u, "TAGALOG"],
  [/\p{Script=Tagbanwa}/u, "TAGBANWA"],
  [/\p{Script=Tai_Le}/u, "TAI"],
  [/\p{Script=Tai_Tham}/u, "TAI"],
  [/\p{Script=Tai_Viet}/u, "TAI"],
  [/\p{Script=Takri}/u, "TAKRI"],
  [/\p{Script=Tamil}/u, "TAMIL"],
  [/\p{Script=Tangut}/u, "TANGUT"],
  [/\p{Script=Telugu}/u, "TELUGU"],
  [/\p{Script=Thaana}/u, "THAANA"],
  [/\p{Script=Tibetan}/u, "TIBETAN"],
  [/\p{Script=Tifinagh}/u, "TIFINAGH"],
  [/\p{Script=Tirhuta}/u, "TIRHUTA"],
  [/\p{Script=Ugaritic}/u, "UGARITIC"],
  [/\p{Script=Vai}/u, "VAI"],
  [/\p{Script=Wancho}/u, "WANCHO"],
  [/\p{Script=Warang_Citi}/u, "WARANG"],
  [/\p{Script=Yezidi}/u, "YEZIDI"],
  [/\p{Script=Yi}/u, "YI"],
  [/\p{Script=Zanabazar_Square}/u, "ZANABAZAR"],
];

// Letters named for what they are rather than for the script they belong to:
// U+1D400 is "MATHEMATICAL BOLD CAPITAL A", not "LATIN …", and U+0640 ARABIC
// TATWEEL is script Common. They bucket by name, which is the point — a
// modifier letter or a fullwidth form sitting in an otherwise ASCII label is a
// homograph in its own right. Checked before SCRIPTS, so a range wins over the
// script its characters belong to.
const NAMED_RANGES: [number, number, string][] = [
  [0x00aa, 0x00aa, "FEMININE"],
  [0x00b5, 0x00b5, "MICRO"],
  [0x00ba, 0x00ba, "MASCULINE"],
  [0x02b0, 0x02c6, "MODIFIER"],
  [0x02c7, 0x02c7, "CARON"],
  [0x02c8, 0x02d1, "MODIFIER"],
  [0x02e0, 0x02ee, "MODIFIER"],
  [0x0374, 0x0374, "GREEK"],
  [0x0640, 0x0640, "ARABIC"],
  [0x10fc, 0x10fc, "MODIFIER"],
  [0x1ce9, 0x1cfa, "VEDIC"],
  [0x1d2c, 0x1d61, "MODIFIER"],
  [0x1d78, 0x1d78, "MODIFIER"],
  [0x1d9b, 0x1dbf, "MODIFIER"],
  [0x2071, 0x2071, "SUPERSCRIPT"],
  [0x207f, 0x207f, "SUPERSCRIPT"],
  [0x2102, 0x2102, "DOUBLE-STRUCK"],
  [0x2107, 0x2107, "EULER"],
  [0x210a, 0x210b, "SCRIPT"],
  [0x210c, 0x210c, "BLACK-LETTER"],
  [0x210d, 0x210d, "DOUBLE-STRUCK"],
  [0x210e, 0x210f, "PLANCK"],
  [0x2110, 0x2110, "SCRIPT"],
  [0x2111, 0x2111, "BLACK-LETTER"],
  [0x2112, 0x2113, "SCRIPT"],
  [0x2115, 0x2115, "DOUBLE-STRUCK"],
  [0x2119, 0x211a, "DOUBLE-STRUCK"],
  [0x211b, 0x211b, "SCRIPT"],
  [0x211c, 0x211c, "BLACK-LETTER"],
  [0x211d, 0x211d, "DOUBLE-STRUCK"],
  [0x2124, 0x2124, "DOUBLE-STRUCK"],
  [0x2126, 0x2126, "OHM"],
  [0x2128, 0x2128, "BLACK-LETTER"],
  [0x212a, 0x212a, "KELVIN"],
  [0x212b, 0x212b, "ANGSTROM"],
  [0x212c, 0x212c, "SCRIPT"],
  [0x212d, 0x212d, "BLACK-LETTER"],
  [0x212f, 0x2131, "SCRIPT"],
  [0x2132, 0x2132, "TURNED"],
  [0x2133, 0x2134, "SCRIPT"],
  [0x2135, 0x2135, "ALEF"],
  [0x2136, 0x2136, "BET"],
  [0x2137, 0x2137, "GIMEL"],
  [0x2138, 0x2138, "DALET"],
  [0x2139, 0x2139, "INFORMATION"],
  [0x213c, 0x213f, "DOUBLE-STRUCK"],
  [0x2145, 0x2149, "DOUBLE-STRUCK"],
  [0x214e, 0x214e, "TURNED"],
  [0x2183, 0x2183, "ROMAN"],
  [0x2c7d, 0x2c7d, "MODIFIER"],
  [0x2e2f, 0x2e2f, "VERTICAL"],
  [0x3005, 0x3006, "IDEOGRAPHIC"],
  [0x3031, 0x3035, "VERTICAL"],
  [0x303b, 0x303b, "VERTICAL"],
  [0x303c, 0x303c, "MASU"],
  [0x30fc, 0x30fc, "KATAKANA-HIRAGANA"],
  [0xa69c, 0xa69d, "MODIFIER"],
  [0xa717, 0xa71f, "MODIFIER"],
  [0xa770, 0xa770, "MODIFIER"],
  [0xa788, 0xa788, "MODIFIER"],
  [0xa7f8, 0xa7f9, "MODIFIER"],
  [0xa9cf, 0xa9cf, "JAVANESE"],
  [0xab5c, 0xab5f, "MODIFIER"],
  [0xab69, 0xab69, "MODIFIER"],
  [0xff21, 0xff5a, "FULLWIDTH"],
  [0xff66, 0xffdc, "HALFWIDTH"],
  [0x16fe3, 0x16fe3, "OLD"],
  [0x1b002, 0x1b11e, "HENTAIGANA"],
  [0x1d400, 0x1d7cb, "MATHEMATICAL"],
];

// Tangut ideographs are the one block of letters Python cannot name: their
// names are algorithmic and CPython's unicodedata does not synthesize them, so
// unicodedata.name() raises and the reference drops the character entirely.
// Bucketing them instead would invent a second script in an otherwise Latin
// label and report a homograph the reference does not.
const UNNAMED_RANGES: [number, number][] = [
  [0x17000, 0x187f7], // Tangut
  [0x18d00, 0x18d08], // Tangut Supplement
];

/**
 * Coarse script names for the letters in `text` — enough to notice a label
 * mixing Latin with Cyrillic, which is what a homograph does. A letter the
 * reference cannot name is skipped, exactly as it is there; a letter in a script
 * too new for the reference to know at all lands in one shared UNKNOWN bucket.
 */
function scriptsOf(text: string): Set<string> {
  const scripts = new Set<string>();
  for (const ch of text) {
    if (!LETTER_RE.test(ch)) continue;
    const cp = ch.codePointAt(0)!;
    if (UNNAMED_RANGES.some(([low, high]) => cp >= low && cp <= high)) continue;
    const named = NAMED_RANGES.find(([low, high]) => cp >= low && cp <= high);
    if (named) {
      scripts.add(named[2]);
      continue;
    }
    const entry = SCRIPTS.find(([re]) => re.test(ch));
    scripts.add(entry ? entry[1] : "UNKNOWN");
  }
  return scripts;
}

// --- parsing ---------------------------------------------------------------

/**
 * Split a URL without the leniency `new URL()` applies.
 *
 * A value with no scheme is treated as a bare host, matching how a model or a
 * user would read `evil.example/path` — the platform parser would either throw
 * or invent a scheme. The pieces are returned unparsed and unescaped.
 */
export function splitUrl(raw: string): SplitURL {
  // Control and whitespace characters inside a URL are how parsers get split
  // against each other; strip them but remember the string was odd. (Removing
  // them subsumes the surrounding trim the reference does first.)
  let text = raw.replace(UNPRINTABLE_RE, "");

  let scheme = "";
  const match = SCHEME_RE.exec(text);
  if (match) {
    scheme = match[0].slice(0, -1).toLowerCase();
    text = text.slice(match[0].length);
    if (text.startsWith("//")) text = text.slice(2);
  } else if (text.startsWith("//")) {
    text = text.slice(2); // scheme-relative
  }

  let fragment = "";
  const hash = text.indexOf("#");
  if (hash !== -1) {
    fragment = text.slice(hash + 1);
    text = text.slice(0, hash);
  }
  let query = "";
  const question = text.indexOf("?");
  if (question !== -1) {
    query = text.slice(question + 1);
    text = text.slice(0, question);
  }
  let path = "";
  const slash = text.indexOf("/");
  if (slash !== -1) {
    path = text.slice(slash);
    text = text.slice(0, slash);
  }

  let userinfo: string | null = null;
  const at = text.lastIndexOf("@");
  if (at !== -1) {
    // Last '@' wins: https://a@b@evil.test authenticates to evil.test.
    userinfo = text.slice(0, at);
    text = text.slice(at + 1);
  }

  let port: number | null = null;
  let host = text;
  if (host.startsWith("[")) {
    // IPv6 literal
    const close = host.indexOf("]");
    if (close !== -1) {
      const rest = host.slice(close + 1);
      host = host.slice(0, close + 1);
      if (rest.startsWith(":")) port = parsePort(rest.slice(1));
    }
  } else if (host.includes(":")) {
    const colon = host.lastIndexOf(":");
    const parsed = parsePort(host.slice(colon + 1));
    if (parsed !== null) {
      host = host.slice(0, colon);
      port = parsed;
    }
  }

  return { scheme, userinfo, host: host.replace(/\.+$/, ""), port, path, query, fragment };
}

/**
 * A port is any run of Unicode decimal digits, not just ASCII ones, so
 * `example.com:٨٤٤٣` is a host with a port and not a malformed IPv6 literal.
 * (CPython's `isdigit()` also admits superscripts, where its `int()` then
 * raises; those read as "not a port" here rather than as an exception.)
 */
function parsePort(text: string): number | null {
  if (!text) return null;
  let value = 0;
  for (const ch of text) {
    const digit = decimalValue(ch);
    if (digit === null) return null;
    value = value * 10 + digit;
  }
  return value;
}

/** A host's kind and its canonical spelling. */
export function classifyHost(host: string): { kind: HostKind; canonical: string } {
  if (!host) return { kind: "empty", canonical: "" };
  // A fully-qualified name may carry a trailing root dot. Resolvers treat
  // "localhost." and "localhost" as the same name, so anything comparing
  // hostnames must too — otherwise one dot walks straight past a host check.
  const lowered = host.toLowerCase().replace(/\.+$/, "");
  if (!lowered) return { kind: "empty", canonical: "" };
  if (lowered.startsWith("[") && lowered.endsWith("]")) return { kind: "ipv6", canonical: lowered };
  if (lowered.includes(":")) return { kind: "ipv6", canonical: lowered };
  const value = parseIpv4(lowered);
  if (value !== null) return { kind: "ipv4", canonical: ipv4ToString(value) };
  const labels = lowered.split(".");
  const wellFormed = labels
    .filter((label) => label !== "")
    .every((label) => LABEL_RE.test(label) || [...label].some((c) => c.codePointAt(0)! > 127));
  return { kind: wellFormed ? "domain" : "malformed", canonical: lowered };
}

/** Syntactic private/local check across every IPv4 and IPv6 spelling. */
export function isPrivateHost(host: string): boolean {
  const { kind, canonical } = classifyHost(host);
  if (kind === "ipv4") return ipv4IsPrivate(parseIpv4(host.toLowerCase()) ?? 0);
  if (kind === "ipv6") return ipv6IsPrivate(canonical);
  if (kind === "empty" || kind === "malformed") return false;
  if (LOCAL_NAMES.has(canonical) || LOCAL_SUFFIXES.some((s) => canonical.endsWith(s))) return true;
  // A single-label host resolves through the local search domain.
  return !canonical.includes(".");
}

export function isMetadataHost(host: string): boolean {
  const { kind, canonical } = classifyHost(host);
  if (METADATA_HOSTS.has(canonical)) return true;
  if (kind === "ipv6" && METADATA_IPV6.has(stripBrackets(canonical))) return true;
  return false;
}

function longestOpaque(text: string): number {
  let longest = 0;
  for (const match of text.matchAll(OPAQUE_RUN_RE)) longest = Math.max(longest, match[0].length);
  return longest;
}

/** Code-point length, so an astral character counts once as it does in Python. */
function codePoints(text: string): string[] {
  return [...text];
}

// --- the check -------------------------------------------------------------

export interface AnalyzeOptions {
  allowedSchemes?: readonly string[];
  maxLength?: number;
  /**
   * The longest opaque run tolerated in a query, path or fragment before it
   * reads as smuggled data.
   */
  maxOpaque?: number;
  /**
   * Subdomains get a tighter limit: DNS labels are chosen by humans and are
   * short, so a 30-character random label is already anomalous where the same
   * run in a query string might be a legitimate session token.
   */
  maxOpaqueSubdomain?: number;
  allowPrivate?: boolean;
}

/** Assess one URL. */
export function analyze(raw: string, opts: AnalyzeOptions = {}): URLAssessment {
  const {
    allowedSchemes = ["http", "https"],
    maxLength = 2048,
    maxOpaque = 48,
    maxOpaqueSubdomain = 24,
    allowPrivate = false,
  } = opts;

  const { scheme, userinfo, host, port, path, query, fragment } = splitUrl(raw);
  const { kind, canonical } = classifyHost(host);

  const findings: Finding[] = [];
  const excerpt = codePoints(raw).slice(0, 100).join("");
  const add = (category: string, severity: Severity, message: string, weight: number): void => {
    findings.push({ stage: "validate", category, severity, message, weight, excerpt });
  };

  // Scheme. An active scheme is not a destination at all; it is code.
  const activeScheme = scheme !== "" && ACTIVE_SCHEMES.has(scheme);
  if (activeScheme) {
    add("url_active_scheme", "critical", `URL uses the '${scheme}:' scheme, which executes rather than fetches`, 0.95);
  } else if (scheme && allowedSchemes.length && !allowedSchemes.includes(scheme)) {
    add("url_scheme", "high", `URL scheme '${scheme}' is not in the allowed set`, 0.8);
  }

  const hasCredentials = Boolean(userinfo);
  if (userinfo) {
    add(
      "url_credentials",
      "high",
      `URL embeds userinfo before the host — the real destination is '${canonical}', ` +
        `not '${userinfo.split(":")[0]}'`,
      0.82,
    );
  }

  // An active-scheme URL has no host in any meaningful sense, so reporting the
  // leftovers as a malformed hostname would just be noise beside the real
  // (critical) finding.
  if (kind === "malformed" && !activeScheme) {
    add("url_malformed", "medium", `URL host '${host}' is not a valid hostname`, 0.5);
  }

  const isMetadata = isMetadataHost(host);
  const isPrivate = isPrivateHost(host);
  if (isMetadata) {
    add("url_metadata_endpoint", "critical", `URL targets a cloud instance-metadata endpoint (${canonical})`, 0.96);
  } else if (isPrivate && !allowPrivate) {
    add("url_private_host", "high", `URL targets a private or local host (${canonical || host})`, 0.8);
  }

  // The canonical form differing from what was written is itself the tell: an
  // honest link to 10.0.0.1 says "10.0.0.1", not "167772161".
  if (kind === "ipv4" && canonical !== host.toLowerCase()) {
    add("url_obfuscated_ip", "high", `URL host '${host}' is an obfuscated spelling of ${canonical}`, 0.82);
  }

  const labels = kind === "domain" ? canonical.split(".") : [];
  let isPunycode = false;
  let isMixedScript = false;
  if (labels.some((label) => label.startsWith("xn--"))) {
    isPunycode = true;
    add("url_punycode", "medium", `URL host '${canonical}' uses punycode — it may not read as it renders`, 0.55);
  }
  for (const label of labels) {
    const scripts = scriptsOf(label);
    if (scripts.size > 1) {
      isMixedScript = true;
      add(
        "url_mixed_script",
        "high",
        `URL host label '${label}' mixes ${[...scripts].sort().join(", ")} scripts — homograph`,
        0.78,
      );
      break;
    }
  }

  const length = codePoints(raw).length;
  if (maxLength && length > maxLength) {
    add("url_length", "high", `URL is ${length} characters — long enough to be carrying a payload`, 0.78);
  }

  const opaqueInQuery = longestOpaque(query);
  const opaqueInPath = longestOpaque(path);
  const opaqueInFragment = longestOpaque(fragment);
  const opaqueInSubdomain = labels.slice(0, -2).reduce((best, label) => Math.max(best, longestOpaque(label)), 0);
  const channels: [string, number, number][] = [
    ["query string", opaqueInQuery, maxOpaque],
    ["path", opaqueInPath, maxOpaque],
    ["fragment", opaqueInFragment, maxOpaque],
    ["subdomain", opaqueInSubdomain, maxOpaqueSubdomain],
  ];
  for (const [where, runLength, limit] of channels) {
    if (limit && runLength > limit) {
      add(
        "url_opaque_payload",
        "high",
        `URL ${where} carries a ${runLength}-character opaque run — possible encoded exfiltration`,
        0.8,
      );
      break;
    }
  }

  return {
    raw,
    scheme,
    userinfo,
    host,
    canonicalHost: canonical,
    port,
    path,
    query,
    fragment,
    kind,
    isPrivate,
    isMetadata,
    isPunycode,
    isMixedScript,
    hasCredentials,
    opaqueInQuery,
    opaqueInPath,
    opaqueInFragment,
    opaqueInSubdomain,
    maxOpaque: Math.max(opaqueInQuery, opaqueInPath, opaqueInFragment, opaqueInSubdomain),
    safe: findings.length === 0,
    findings,
  };
}
