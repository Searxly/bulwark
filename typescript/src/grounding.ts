/**
 * Check that the model's answer actually came from the source.
 *
 * Every other output check asks "does this reply look dangerous?". This one asks
 * a sharper question: **is this reply derived from the document we gave it?**
 *
 * The distinction matters because the strongest evidence that a summarizer was
 * steered is not a scary phrase — an attacker can phrase a payload innocuously —
 * it is a summary containing something that was never in the source. A domain, an
 * email address, a URL that the document does not mention cannot have come from
 * summarizing the document. It came from an instruction the model obeyed.
 *
 * This is a cheap, deterministic approximation of provenance:
 *
 * - **Reference grounding** (strong, language-independent) — every host, URL and
 *   email address in the output must occur in the source. A novel one is a
 *   `critical`/`high` finding, because an exfiltration channel that survived
 *   every other layer is exactly what it looks like.
 * - **Lexical grounding** (weak, language-dependent) — what fraction of the
 *   output's content words occur in the source. A faithful summary reuses the
 *   source's vocabulary; a hijacked reply talks about something else. Skipped
 *   when the summary was requested in a different language than the source,
 *   where the measure is meaningless.
 *
 * Both are advisory signals feeding the same noisy-OR as everything else. Neither
 * can be trusted alone: a paraphrase-heavy summary scores low on lexical grounding
 * without being an attack, which is why that signal is weighted well below the
 * reference check.
 */

import type { Finding } from "./types.js";

// Hosts that carry no exfiltration value on their own: an attacker cannot
// receive data at a domain they do not control, and these are the ones a model
// is most likely to mention from its own knowledge rather than from the source.
const UBIQUITOUS_HOSTS = new Set([
  "example.com", "example.org", "example.net", "localhost",
  "w3.org", "schema.org", "iana.org", "ietf.org",
]);

// JavaScript's `\w` and `\b` are ASCII-only; Python's are Unicode-aware. Every
// word-boundary assertion below is therefore spelled out against this class,
// which is Python's Unicode `\w` (alphanumeric, in any script, plus underscore).
const W = "\\p{L}\\p{N}_";
// The generic Unicode word boundary, for the positions where the character on
// the pattern side may itself be either a word character or not.
const WB = `(?:(?<![${W}])(?=[${W}])|(?<=[${W}])(?![${W}]))`;

// Python's `\s` (and `str.strip()`) is not JavaScript's: Python also treats the
// four ASCII separators U+001C..U+001F and NEL U+0085 as space, and does *not*
// treat the byte-order mark U+FEFF as space. Both halves of that difference are
// observable here — `evil.examplemore` is one host to JavaScript and two
// tokens to Python — so the whitespace set is spelled out rather than left to
// `\s`.
const PY_SPACE =
  "\\t\\n\\v\\f\\r\\u001c-\\u001f \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const PY_BLANK_RE = new RegExp(`^[${PY_SPACE}]*$`, "u");
const PY_TRIM_RE = new RegExp(`^[${PY_SPACE}]+|[${PY_SPACE}]+$`, "gu");

// `\b` before `https?://` / `www.` only ever sits in front of a word character,
// so it collapses to "the preceding character is not a word character".
const URL_RE = new RegExp(`(?<![${W}])(?:https?://|www\\.)[^${PY_SPACE}<>"'\\)\\]\\}]+`, "giu");

// Python's `[a-z]` under re.IGNORECASE also matches the four non-ASCII letters
// that fold onto ASCII: İ, ı, ſ and K. JavaScript's simple case folding covers
// ſ→s and K→k but not the two Turkish dotted-i forms, so they are spelled out —
// without them a homoglyph host like "İnfo.com" would not register as a host at
// all, and an ungrounded reference would go unreported.
const DOTTED_I = "[i\\u0130\\u0131]";
const LABEL_CHAR = "[a-z0-9\\u0130\\u0131]";
const TLDS = [
  "com", "org", "net", "io", "dev", "app", "co", "ai", "me", "xyz", "info", "biz",
  "ru", "cn", "uk", "de", "fr", "jp", "top", "site", "online", "link", "click",
];

// The lookbehind excludes '-' as well as word characters so that
// "mailbox-relay.io" yields one host, not a phantom "relay.io" too.
const BARE_HOST_RE = new RegExp(
  `(?<![@.${W}-])((?:${LABEL_CHAR}(?:[a-z0-9\\u0130\\u0131-]{0,61}${LABEL_CHAR})?\\.)+` +
    `(?:${TLDS.map((t) => t.replace(/i/g, DOTTED_I)).join("|")}))` +
    `(?![${W}.-])`,
  "giu",
);

const EMAIL_RE = new RegExp(
  `${WB}[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})(?![${W}])`,
  "gu",
);

// Python uses `[^\W\d_]{4,}` with re.UNICODE — a word character that is neither a
// decimal digit nor an underscore. That is *not* just `\p{L}`: Python's `\w` also
// covers the non-decimal numerics (letterlike and other numbers, `\p{Nl}` and
// `\p{No}`) while its `\d` covers only `\p{Nd}`, so those survive the exclusion.
// Most of them — Ⅷ, ①, ½ — are folded away to ASCII by the NFKC pass first, but
// the ones NFKC leaves alone, such as the Tibetan half digits, are content words
// to Python and must be here too. `{4,}` counts code points under the `u` flag,
// as Python counts characters.
const WORD_RE = /[\p{L}\p{Nl}\p{No}]{4,}/gu;

// Small, deliberately English-centric list. Its only job is to stop function
// words from inflating the grounding ratio; unknown-language text simply keeps
// more words, which makes the measure more conservative, not less.
const STOPWORDS = new Set(
  `about above after again against because been before being below between both
   during each further have here into itself more most only other over same some
   such than that their them then there these they this those through under until
   very were what when where which while with your`.split(/\s+/),
);

/** How much of the output can be traced back to the source. */
export interface GroundingReport {
  /** 0..1 lexical overlap, 1.0 when skipped. */
  ratio: number;
  lexicalChecked: boolean;
  novelHosts: string[];
  novelEmails: string[];
  findings: Finding[];
  /** True when nothing in the output was left unaccounted for. */
  grounded: boolean;
}

export interface GroundingOptions {
  /**
   * Set to false when the summary was requested in a different language than the
   * source, or when the caller's task is not summarization — the vocabulary
   * measure means nothing there. Defaults to true.
   */
  checkLexical?: boolean;
  minWordsForLexical?: number;
  lexicalFloor?: number;
}

function fold(text: string): string {
  return text.normalize("NFKC").toLowerCase();
}

function normalizeHost(host: string): string {
  // `String.prototype.trim` is not `str.strip()` — it would eat a trailing BOM
  // that Python keeps as part of the host. See PY_SPACE.
  let h = host.replace(PY_TRIM_RE, "").replace(/\.+$/, "").toLowerCase();
  if (h.startsWith("www.")) h = h.slice(4);
  return h;
}

/** Every host referenced by a URL or a bare domain in `text`. */
export function extractHosts(text: string): Set<string> {
  const hosts = new Set<string>();
  for (const match of text.matchAll(URL_RE)) {
    let raw = match[0].replace(/^https?:\/\//i, "");
    // Drop userinfo before the host — https://good.com@evil.example is evil.
    const at = raw.lastIndexOf("@");
    if (at !== -1) raw = raw.slice(at + 1);
    const cut = raw.search(/[/?#:]/);
    const host = cut === -1 ? raw : raw.slice(0, cut);
    if (host) hosts.add(normalizeHost(host));
  }
  for (const match of text.matchAll(BARE_HOST_RE)) {
    hosts.add(normalizeHost(match[1]!));
  }
  const out = new Set<string>();
  for (const h of hosts) if (h && !UBIQUITOUS_HOSTS.has(h)) out.add(h);
  return out;
}

export function extractEmails(text: string): Set<string> {
  const emails = new Set<string>();
  for (const match of text.matchAll(EMAIL_RE)) emails.add(match[0].toLowerCase());
  return emails;
}

export function contentWords(text: string): string[] {
  return (fold(text).match(WORD_RE) ?? []).filter((w) => !STOPWORDS.has(w));
}

/**
 * Code-point ordering, matching Python's `sorted()` on strings.
 *
 * `<` on strings compares UTF-16 code units, which sorts every astral character
 * ahead of U+E000..U+FFFF because its lead surrogate is only 0xD800. Walking the
 * strings by code point — what `for...of` yields — restores Python's order, so a
 * host like `😀.io` lands where the reference puts it.
 */
function sortedStrings(values: Iterable<string>): string[] {
  return [...values].sort((a, b) => {
    const left = a[Symbol.iterator]();
    const right = b[Symbol.iterator]();
    for (;;) {
      const x = left.next();
      const y = right.next();
      if (x.done) return y.done ? 0 : -1;
      if (y.done) return 1;
      if (x.value !== y.value) return x.value.codePointAt(0)! - y.value.codePointAt(0)!;
    }
  });
}

/** Python's `format(x, ".0%")`: scale by 100, then round half to even. */
function formatPercent(ratio: number): string {
  const scaled = ratio * 100;
  const floor = Math.floor(scaled);
  const rest = scaled - floor;
  let n: number;
  if (rest > 0.5) n = floor + 1;
  else if (rest < 0.5) n = floor;
  else n = floor % 2 === 0 ? floor : floor + 1;
  return `${n}%`;
}

/**
 * Python's `round(x, 4)` — half to *even*, where `toFixed` rounds half *up*.
 * The difference is visible for the dyadic ratios counting produces: 1/32 is
 * exactly 0.03125, which Python reports as 0.0312 and `toFixed` as 0.0313.
 * `toFixed(30)` is correctly rounded and long enough to tell an exact tie from a
 * value that merely looks like one at four places.
 */
function roundTo4(x: number): number {
  const s = x.toFixed(30);
  const dot = s.indexOf(".");
  const frac = s.slice(dot + 1);
  let scaled = Number(s.slice(0, dot) + frac.slice(0, 4));
  // Digit strings compare lexicographically the same way the fractions they
  // denote compare numerically, once trailing zeros are gone.
  const rest = frac.slice(4).replace(/0+$/, "");
  if (rest === "5" ? scaled % 2 !== 0 : rest > "5") scaled += 1;
  return scaled / 1e4;
}

/**
 * Compare a model reply against the source it was supposed to summarize.
 *
 * `checkLexical` should be false when the summary was requested in a different
 * language than the source, or when the caller's task is not summarization — the
 * vocabulary measure means nothing there. The reference checks always run; they
 * do not depend on language.
 */
/** First `n` code points, matching Python's `s[:n]`.
 *
 * `String.prototype.slice` counts UTF-16 code units, so an astral character
 * costs two and the excerpt comes out short. Python slices code points. */
function head(text: string, n: number): string {
  return [...text].slice(0, n).join("");
}

export function checkGrounding(
  output: string,
  source: string,
  opts: GroundingOptions = {},
): GroundingReport {
  const { checkLexical = true, minWordsForLexical = 25, lexicalFloor = 0.3 } = opts;
  const findings: Finding[] = [];
  if (!output || PY_BLANK_RE.test(output)) {
    return { ratio: 1.0, lexicalChecked: false, novelHosts: [], novelEmails: [], findings, grounded: true };
  }

  const sourceFolded = fold(source);

  // --- reference grounding (strong) ---------------------------------------
  const sourceHosts = extractHosts(source);
  const novelHosts = sortedStrings(
    [...extractHosts(output)].filter(
      (h) =>
        // A host is grounded if the source names it, or names it as a suffix
        // (the source may show "docs.example.com" and the summary "example.com").
        !sourceHosts.has(h) &&
        ![...sourceHosts].some((s) => h === s || s.endsWith("." + h) || h.endsWith("." + s)) &&
        !sourceFolded.includes(h),
    ),
  );
  if (novelHosts.length) {
    findings.push({
      stage: "validate",
      category: "ungrounded_host",
      severity: "critical",
      message:
        `Output references ${novelHosts.length} host(s) absent from the source: ` +
        novelHosts.slice(0, 4).join(", "),
      weight: 0.92,
      excerpt: head(novelHosts[0]!, 80),
    });
  }

  const sourceEmails = extractEmails(source);
  const novelEmails = sortedStrings([...extractEmails(output)].filter((e) => !sourceEmails.has(e)));
  if (novelEmails.length) {
    findings.push({
      stage: "validate",
      category: "ungrounded_email",
      severity: "high",
      message: `Output contains ${novelEmails.length} email address(es) absent from the source`,
      weight: 0.8,
      excerpt: head(novelEmails[0]!, 80),
    });
  }

  // --- lexical grounding (weak) -------------------------------------------
  let ratio = 1.0;
  let checked = false;
  if (checkLexical) {
    const outWords = contentWords(output);
    if (outWords.length >= minWordsForLexical) {
      checked = true;
      const sourceWords = new Set(contentWords(source));
      if (sourceWords.size) {
        const hits = outWords.reduce((n, w) => n + (sourceWords.has(w) ? 1 : 0), 0);
        ratio = hits / outWords.length;
        if (ratio < lexicalFloor) {
          findings.push({
            stage: "validate",
            category: "low_grounding",
            severity: "medium",
            message:
              `Only ${formatPercent(ratio)} of the summary's content words appear in the source ` +
              "— the reply may not be derived from it",
            weight: 0.45,
          });
        }
      }
    }
  }

  return {
    ratio: roundTo4(ratio),
    lexicalChecked: checked,
    novelHosts,
    novelEmails,
    findings,
    grounded: novelHosts.length === 0 && novelEmails.length === 0 && findings.length === 0,
  };
}
