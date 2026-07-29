// Tell a document that *performs* an attack from one that *discusses* one.
//
// The most common false positive in prompt-injection detection is a security article. A page
// explaining how injection works quotes real payloads; an API reference documenting chat templates
// prints real role tokens; a changelog says "this release overrides the previous configuration".
// These are the exact documents a security-conscious user is most likely to feed to a summarizer,
// and flagging them is how a guard earns a reputation for crying wolf and gets switched off.
//
// The difference between quoting an instruction and issuing one is *context*:
//
//   * the payload sits in a code fence, a blockquote, or quotation marks; and
//   * the surrounding prose is talking *about* attacks — "an attacker embeds…", "for example…",
//     "this payload demonstrates…"; and
//   * the document as a whole reads like security writing.
//
// Any one of those alone is weak evidence, and — critically — cheap for an attacker to fake.
// Wrapping a payload in a code fence costs nothing. So a single signal earns only a small discount,
// and the discount deepens only as *independent* signals stack up. To reach the largest discount an
// attacker must fence their payload, quote it, surround it with "this is a malicious example"
// framing, and make the whole page read as a security write-up — at which point they have spent the
// attack's own persuasive power telling the model that the text is a quoted specimen. **The evasion
// weakens the payload.** That property is the reason this is safe to do at all.
//
// The discount is also floored well above zero. Context can make a finding quieter; it can never
// silence one, so this can never become a reliable bypass. Everything downstream — spotlighting,
// the hardened prompt, output validation — is unchanged.

import Foundation

// MARK: - Tuning

/// Discount by number of independent context signals. Never reaches zero: a discounted finding
/// still contributes to the score and still appears in the report, so a "quoted" payload can never
/// be silently dropped.
private let discountBySignals: [Double] = [1.00, 0.78, 0.50, 0.34, 0.30]

/// The floor no stack of context signals can dig below. Context makes a finding quieter; it never
/// silences one.
public let minContextDiscount = 0.30

/// Phrases that mark prose as *about* attacks rather than *being* one. Chosen to be the vocabulary
/// of analysis, not of instruction.
private let metaMarkerPhrases: [String] = [
    "for example", "for instance", "e.g.", "such as", "consider the following",
    "the following text", "sample payload", "example payload", "attack string",
    "proof of concept", "demonstrat", "illustrat", "example of",
    "attacker", "adversar", "malicious", "payload", "exploit", "vulnerab",
    "prompt injection", "prompt-injection", "jailbreak", "injected", "injection",
    "red team", "red-team", "threat model", "mitigat", "guardrail", "sanitiz",
    "security research", "advisory", "cve-", "owasp", "write-up", "writeup",
    "in this lesson", "in this article", "this post", "we tested", "we found",
    "reported by", "disclosure", "verbatim", "quoted above", "quoted below",
    "would look like", "looks like this", "test case", "regression test",
    "do not run this", "harmless example", "defanged",
]

/// Reaching this many *distinct* markers makes the whole document read as analysis. Set high enough
/// that one passing mention of "attacker" is not enough.
private let docMetaThreshold = 4

/// How far back and forward to look for framing prose around a match, in code points.
private let lookbehindChars = 200
private let lookaheadChars = 90

/// Cap on how many construct matches are collected before giving up. A page that is nothing but
/// backticks must not make profiling the slowest thing in the pipeline.
private let spanLimit = 400

// MARK: - Quoting constructs
//
// These patterns are deliberately not a mechanical transliteration; ICU and Python's `re` disagree
// in four places that would change which spans are found:
//
//   * The reference compiles every pattern here *without* MULTILINE, so a leading `^` anchors to
//     the start of the input. `CompiledRegex` enables `.anchorsMatchLines` by default, which would
//     make `^` match at every line start and widen the fence and indented-block spans — so all of
//     them pass their options explicitly.
//   * Python's `\Z` is the absolute end of input. ICU spells that `\z`; ICU's own `\Z` would also
//     match *before* a trailing newline, clipping the span of an unterminated fence.
//   * `re.DOTALL` becomes `.dotMatchesLineSeparators`. Only the two patterns containing `.` need
//     it; everywhere else the reference writes `[^\n]`, and a negated class means the same thing in
//     both dialects — a bare ICU `.` would additionally exclude \r, NEL, LS and PS, but a class
//     does not.
//   * The reference is case-sensitive except on the HTML pattern, so `.caseInsensitive` is set only
//     there.

// `[\s\S]` rather than `.` with `.dotMatchesLineSeparators`. ICU's DOTALL dot
// treats a CRLF pair as one unit, so a lazy `.*?` cannot stop between the CR and
// the LF — which makes the closing-fence alternative fail on CRLF input and the
// span run on to end-of-text. Verified against the Python reference: with `.`
// the span was two characters longer on every CRLF-terminated fence.
private let fenceRegex = CompiledRegex(
    #"(?:^|\n)(```|~~~)[^\n]*\n[\s\S]*?(?:\n\1|\z)"#,
    options: []
)

private let inlineCodeRegex = CompiledRegex(#"`[^`\n]{1,400}`"#, options: [])

/// Python's `\w` — and therefore its `\b` — counts Nl and No as word characters, while ICU's counts
/// combining marks and drops No. `<code½ …>` would open a code span under ICU but not under the
/// reference, and erring wide is the wrong direction here: a code span an attacker did not earn is
/// a discount they did not earn. So the boundary is spelled out as "not followed by a Python word
/// character".
private let pythonWordLookahead = #"(?![\p{L}\p{Nd}\p{Nl}\p{No}_])"#

/// Likewise `\s`: Python's also matches the four information separators, U+001C–U+001F, and ICU's
/// does not — so `</pre` + U+001C + `>` closes a code span for the reference but would not here.
/// Spelled out as Python's exact whitespace set.
private let pythonSpaceClass = #"[\u0009-\u000D\u001C-\u001F\u0020\u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]"#

private let htmlCodeRegex = CompiledRegex(
    #"<(pre|code|samp|kbd)\#(pythonWordLookahead)[^>]*>[\s\S]*?</\1\#(pythonSpaceClass)*>"#,
    options: [.caseInsensitive]
)

private let indentedBlockRegex = CompiledRegex(#"(?:^|\n)(?:(?:[ ]{4}|\t)[^\n]*\n){2,}"#, options: [])

private let blockquoteRegex = CompiledRegex(#"(?:^|\n)(?:[ \t]*>[^\n]*\n?){1,}"#, options: [])

/// Paired quotation marks. Straight single quotes are excluded: apostrophes make them unpairable in
/// ordinary English and the resulting spans are nonsense.
private let quoteRegexes: [CompiledRegex] = [
    CompiledRegex(#""[^"\n]{8,600}""#, options: []),
    CompiledRegex(#"“[^”\n]{8,600}”"#, options: []),
    CompiledRegex(#"‘[^’\n]{8,600}’"#, options: []),
    CompiledRegex(#"«[^»\n]{8,600}»"#, options: []),
    CompiledRegex(#"「[^」\n]{8,600}」"#, options: []),
]

// MARK: - Profile

/// Where the quoting constructs are, and how meta the document reads.
///
/// Spans are half-open `(start, end)` UTF-16 offsets — the same coordinate system `Finding.span`
/// uses, so a finding can be tested against them directly. `textLength` and `quotedFraction` are
/// the exception: the reference measures both in code points, so they are counted that way here
/// too. Mixing the units would make the fraction disagree with the reference over astral text —
/// an emoji is two UTF-16 units but one code point, so a quoted run of them would look like a
/// larger share of the page than it is.
public struct ContextProfile: Sendable {
    public let codeSpans: [(Int, Int)]
    public let quoteSpans: [(Int, Int)]
    public let metaMarkers: [String]
    /// Length of the profiled text in code points.
    public let textLength: Int
    /// Share of the document inside code or quotes, in code points. A page that is mostly quoted
    /// material is a specimen collection, not a message.
    public let quotedFraction: Double

    /// Assembles a profile from spans alone, for callers that already know where the constructs
    /// are. With no text to measure against, `quotedFraction` reads the spans in whatever unit
    /// `textLength` is given in; `contextProfile(_:)` measures the real thing.
    public init(
        codeSpans: [(Int, Int)] = [],
        quoteSpans: [(Int, Int)] = [],
        metaMarkers: [String] = [],
        textLength: Int = 0
    ) {
        let covered = mergeSpans(codeSpans + quoteSpans).reduce(0) { $0 + ($1.1 - $1.0) }
        self.init(codeSpans: codeSpans, quoteSpans: quoteSpans, metaMarkers: metaMarkers,
                  textLength: textLength, coveredCodePoints: covered)
    }

    init(
        codeSpans: [(Int, Int)],
        quoteSpans: [(Int, Int)],
        metaMarkers: [String],
        textLength: Int,
        coveredCodePoints: Int
    ) {
        self.codeSpans = codeSpans
        self.quoteSpans = quoteSpans
        self.metaMarkers = metaMarkers
        self.textLength = textLength
        self.quotedFraction = textLength > 0
            ? min(1.0, Double(coveredCodePoints) / Double(textLength))
            : 0.0
    }

    public var documentIsMeta: Bool { metaMarkers.count >= docMetaThreshold }
}

/// Map the quoting constructs and meta-discourse in `text`.
public func contextProfile(_ text: String) -> ContextProfile {
    if text.isEmpty { return ContextProfile() }

    let code = spans(of: [fenceRegex, htmlCodeRegex, inlineCodeRegex, indentedBlockRegex], in: text)
    let quotes = spans(of: [blockquoteRegex] + quoteRegexes, in: text)

    let lowered = text.lowercased()
    let markers = metaMarkerPhrases.filter { containsLiteral(lowered, $0) }

    return ContextProfile(
        codeSpans: code,
        quoteSpans: quotes,
        metaMarkers: markers,
        textLength: text.unicodeScalars.count,
        coveredCodePoints: codePointsCovered(mergeSpans(code + quotes), in: text)
    )
}

// MARK: - Signals and discount

/// Which independent context signals apply to a match at `span`.
public func contextSignals(_ text: String, span: (Int, Int), profile: ContextProfile) -> [String] {
    var signals: [String] = []
    if encloses(profile.codeSpans, span) { signals.append("in_code") }
    if encloses(profile.quoteSpans, span) { signals.append("quoted") }

    let window = framingWindow(text, around: span).lowercased()
    if metaMarkerPhrases.contains(where: { containsLiteral(window, $0) }) { signals.append("meta_nearby") }

    if profile.documentIsMeta { signals.append("document_is_meta") }
    return signals
}

/// Weight multiplier for a finding at `span`, plus the signals behind it.
public func contextDiscount(
    _ text: String,
    span: (Int, Int)?,
    profile: ContextProfile
) -> (factor: Double, signals: [String]) {
    guard let span else { return (1.0, []) }
    let signals = contextSignals(text, span: span, profile: profile)
    let factor = discountBySignals[min(signals.count, discountBySignals.count - 1)]
    return (max(minContextDiscount, factor), signals)
}

/// Return `findings` re-weighted for quoting context.
///
/// Findings without a span (sanitization results, density heuristics) are returned untouched: they
/// describe the document as a whole, and "the document as a whole" has no enclosing quotation to
/// sit inside.
public func applyContext(
    _ text: String,
    _ findings: [Finding],
    _ profile: ContextProfile? = nil
) -> [Finding] {
    if findings.isEmpty { return findings }
    let prof = profile ?? contextProfile(text)
    if prof.codeSpans.isEmpty && prof.quoteSpans.isEmpty && !prof.documentIsMeta { return findings }

    return findings.map { finding in
        let (factor, signals) = contextDiscount(text, span: finding.span, profile: prof)
        if factor >= 1.0 || finding.weight <= 0 { return finding }
        let note = "(discounted ×\(String(format: "%.2f", factor)): \(signals.joined(separator: ", ")))"
        return Finding(
            stage: finding.stage,
            category: finding.category,
            severity: finding.severity,
            weight: roundedTo4(finding.weight * factor),
            message: "\(finding.message) \(note)",
            excerpt: finding.excerpt,
            span: finding.span,
            patternId: finding.patternId
        )
    }
}

// MARK: - Span algebra

private func mergeSpans(_ spans: [(Int, Int)]) -> [(Int, Int)] {
    guard !spans.isEmpty else { return [] }
    let ordered = spans.sorted { $0.0 != $1.0 ? $0.0 < $1.0 : $0.1 < $1.1 }
    var out: [(Int, Int)] = [ordered[0]]
    for next in ordered.dropFirst() {
        if next.0 <= out[out.count - 1].1 {
            out[out.count - 1].1 = max(out[out.count - 1].1, next.1)
        } else {
            out.append(next)
        }
    }
    return out
}

private func spans(of regexes: [CompiledRegex], in text: String) -> [(Int, Int)] {
    var found: [(Int, Int)] = []
    for regex in regexes {
        for match in regex.allMatches(text) {
            found.append((match.range.location, match.range.location + match.range.length))
            if found.count >= spanLimit { return mergeSpans(found) }
        }
    }
    return mergeSpans(found)
}

/// How many code points `spans` cover, given merged (sorted, disjoint) UTF-16 ranges. A regex
/// offset never splits a surrogate pair, so a scalar belongs to a span exactly when the scalar's
/// own UTF-16 offset falls inside it.
private func codePointsCovered(_ spans: [(Int, Int)], in text: String) -> Int {
    guard !spans.isEmpty else { return 0 }
    var covered = 0
    var index = 0
    var offset = 0
    for scalar in text.unicodeScalars {
        while index < spans.count && offset >= spans[index].1 { index += 1 }
        if index == spans.count { break }
        if offset >= spans[index].0 { covered += 1 }
        offset += UTF16.width(scalar)
    }
    return covered
}

/// The midpoint, not the edges: a match that merely brushes a fence is not inside it.
private func encloses(_ spans: [(Int, Int)], _ span: (Int, Int)) -> Bool {
    let midpoint = (span.0 + span.1) / 2
    return spans.contains { $0.0 <= midpoint && midpoint < $0.1 }
}

// MARK: - Helpers

/// The prose around `span` that could be framing it.
///
/// The reference measures this window in code points. Spans here are UTF-16 offsets, so the bounds
/// are translated before slicing: measuring 200 UTF-16 units instead would halve the window over
/// emoji or other astral text and miss framing prose the reference sees. Slicing by scalar rather
/// than by `Character` also keeps the window from swallowing or dropping a whole grapheme cluster
/// when a regex offset lands between a base letter and its combining mark.
private func framingWindow(_ text: String, around span: (Int, Int)) -> String {
    let view = text.unicodeScalars
    let from = max(0, scalarOffset(ofUTF16: span.0, in: text) - lookbehindChars)
    let to = scalarOffset(ofUTF16: span.1, in: text) + lookaheadChars
    guard to > from,
          let lower = view.index(view.startIndex, offsetBy: from, limitedBy: view.endIndex)
    else { return "" }
    let upper = view.index(lower, offsetBy: to - from, limitedBy: view.endIndex) ?? view.endIndex
    return String(String.UnicodeScalarView(view[lower..<upper]))
}

private func scalarOffset(ofUTF16 offset: Int, in text: String) -> Int {
    var units = 0
    var scalars = 0
    for value in text.unicodeScalars {
        if units >= offset { break }
        units += UTF16.width(value)
        scalars += 1
    }
    return scalars
}

/// The reference tests markers with Python's `in`, a code-point substring search. Swift's
/// `String.contains` compares grapheme clusters under canonical equivalence: it would miss
/// "attacker" inside a decomposed "attackér" and would find a composed needle inside a decomposed
/// haystack. `.literal` restores exact code-unit matching, which is what the reference does.
private func containsLiteral(_ haystack: String, _ needle: String) -> Bool {
    (haystack as NSString).range(of: needle, options: .literal).location != NSNotFound
}

/// Python's `round(x, 4)` rounds the *decimal* expansion of the exact binary value, half to even.
/// Scaling by 10_000 and rounding does not: the multiply introduces its own error and lands on the
/// wrong side of the tie — `0.06255 * 10_000` is 625.5000000000001, which rounds up, while the
/// reference sees 0.06254999… and rounds down. Formatting to four places is the same
/// correctly-rounded decimal conversion the reference performs, so the two always agree.
private func roundedTo4(_ value: Double) -> Double {
    Double(String(format: "%.4f", value)) ?? value
}
