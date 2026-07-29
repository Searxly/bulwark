// Check that the model's answer actually came from the source.
//
// Every other output check asks "does this reply look dangerous?". This one asks a sharper
// question: **is this reply derived from the document we gave it?**
//
// The distinction matters because the strongest evidence that a summarizer was steered is not a
// scary phrase — an attacker can phrase a payload innocuously — it is a summary containing
// something that was never in the source. A domain, an email address, a URL that the document does
// not mention cannot have come from summarizing the document. It came from an instruction the
// model obeyed.
//
// This is a cheap, deterministic approximation of provenance:
//
// * **Reference grounding** (strong, language-independent) — every host, URL and email address in
//   the output must occur in the source. A novel one is a `critical`/`high` finding, because an
//   exfiltration channel that survived every other layer is exactly what it looks like.
// * **Lexical grounding** (weak, language-dependent) — what fraction of the output's content words
//   occur in the source. A faithful summary reuses the source's vocabulary; a hijacked reply talks
//   about something else. Skipped when the summary was requested in a different language than the
//   source, where the measure is meaningless.
//
// Both are advisory signals feeding the same noisy-OR as everything else. Neither can be trusted
// alone: a paraphrase-heavy summary scores low on lexical grounding without being an attack, which
// is why that signal is weighted well below the reference check.

import Foundation

/// Hosts that carry no exfiltration value on their own: an attacker cannot receive data at a domain
/// they do not control, and these are the ones a model is most likely to mention from its own
/// knowledge rather than from the source.
private let ubiquitousHosts: Set<String> = [
    "example.com", "example.org", "example.net", "localhost",
    "w3.org", "schema.org", "iana.org", "ietf.org",
]

// Python's `\w` is "alphanumeric or underscore" — categories L* and N* plus '_'. ICU's `\w` is a
// different set: it drops \p{No} and it *adds* combining marks, \p{Pc} and the ZWJ/ZWNJ joiners.
// The difference is not cosmetic. With marks inside `\w`, ICU's `\b` stops firing after a decomposed
// accent, so "áb@x.io" written in NFD yields no email at all where Python finds "b@x.io". Every
// `\b` and `\w` below is therefore spelled out as `[\p{L}\p{N}_]`, Python's definition.

// ICU's `\s` is `[\t\n\v\f\r\p{Z}]`; Python's also covers U+000B, U+001C–U+001F and U+0085 (NEL),
// so those are named explicitly to make the URL run stop on exactly the same characters in both.
private let urlRegex = CompiledRegex(
    #"(?<![\p{L}\p{N}_])(?:https?://|www\.)[^\s\u000B\u001C-\u001F\u0085<>"'\)\]\}]+"#,
    options: [.caseInsensitive]
)

// Python's `re.IGNORECASE` folds four non-ASCII letters into this pattern's ASCII ranges: ſ U+017F
// and K U+212A (which ICU's case folding also covers) and İ U+0130 and ı U+0131 (which it does
// not — neither has a simple case fold onto 'i'). Left alone, "İexample.com" is a host to Python
// and nothing at all here, so the two Turkish forms are spliced in by hand: into the label classes,
// and into every 'i' of the TLD list.
private let dottedI = #"[iİı]"#
private let hostLabelEdge = #"[a-z0-9İı]"#
private let hostLabelInner = #"[a-z0-9İı-]"#

private let bareHostRegex: CompiledRegex = {
    let tlds = ["com", "org", "net", "io", "dev", "app", "co", "ai", "me", "xyz", "info", "biz",
                "ru", "cn", "uk", "de", "fr", "jp", "top", "site", "online", "link", "click"]
        .map { $0.replacingOccurrences(of: "i", with: dottedI) }
    return CompiledRegex(
        // The lookbehind excludes '-' as well as word characters so that "mailbox-relay.io" yields
        // one host, not a phantom "relay.io" too. It also subsumes the `\b` Python spells here:
        // both demand a non-word character before the host, and this rules out '@', '.' and '-'
        // on top.
        #"(?<![@.\p{L}\p{N}_-])((?:"# + hostLabelEdge
        + "(?:" + hostLabelInner + "{0,61}" + hostLabelEdge + #")?\.)+"#
        + "(?:" + tlds.joined(separator: "|") + "))"
        + #"(?![.\p{L}\p{N}_-])"#,
        options: [.caseInsensitive]
    )
}()

private let emailRegex = CompiledRegex(
    // The leading `\b` expands to two cases because the local part may open with punctuation:
    // a word character needs a non-word char before it, '.'/'%'/'+'/'-' needs a word char.
    #"(?:(?<![\p{L}\p{N}_])(?=[A-Za-z0-9_])|(?<=[\p{L}\p{N}_])(?=[.%+-]))"#
    + #"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\p{L}\p{N}_])"#,
    options: []
)

// Python spells this `[^\W\d_]` under re.UNICODE — a word character that is neither a digit nor an
// underscore, i.e. letters plus the non-decimal numerals. ICU's `\w` additionally covers combining
// marks, which would glue Devanagari matras onto their consonants and turn "हिन्दी" into a match
// where Python finds none. Naming the categories keeps the two dialects on the same words.
private let wordRegex = CompiledRegex(#"[\p{L}\p{Nl}\p{No}]{4,}"#, options: [])

/// Small, deliberately English-centric list. Its only job is to stop function words from inflating
/// the grounding ratio; unknown-language text simply keeps more words, which makes the measure more
/// conservative, not less.
private let stopwords: Set<String> = Set("""
about above after again against because been before being below between both
during each further have here into itself more most only other over same some
such than that their them then there these they this those through under until
very were what when where which while with your
""".split(whereSeparator: { $0.isWhitespace }).map(String.init))

/// How much of the output can be traced back to the source.
public struct GroundingReport: Sendable {
    /// 0..1 lexical overlap; 1.0 when the check was skipped.
    public let ratio: Double
    public let lexicalChecked: Bool
    public let novelHosts: [String]
    public let novelEmails: [String]
    public let findings: [Finding]

    public var grounded: Bool { novelHosts.isEmpty && novelEmails.isEmpty && findings.isEmpty }
}

public struct GroundingOptions: Sendable {
    /// Set to false when the summary was requested in a different language than the source, or when
    /// the caller's task is not summarization — the vocabulary measure means nothing there.
    public var checkLexical: Bool
    public var minWordsForLexical: Int
    public var lexicalFloor: Double

    public init(checkLexical: Bool = true, minWordsForLexical: Int = 25, lexicalFloor: Double = 0.30) {
        self.checkLexical = checkLexical
        self.minWordsForLexical = minWordsForLexical
        self.lexicalFloor = lexicalFloor
    }
}

// MARK: - Helpers

private func fold(_ text: String) -> String {
    text.precomposedStringWithCompatibilityMapping.lowercased()
}

/// Exactly what Python's `str.strip()` removes. Foundation's `.whitespacesAndNewlines` is a
/// different set: it counts U+200B as space, where Python does not — so a host of "\u{200B}" would
/// be trimmed away to nothing here and survive there — and it omits U+001C–U+001F, which Python
/// does strip.
private let pythonWhitespace: CharacterSet = {
    var set = CharacterSet(charactersIn: Unicode.Scalar(0x09)!...Unicode.Scalar(0x0D)!)
    set.insert(charactersIn: Unicode.Scalar(0x1C)!...Unicode.Scalar(0x20)!)
    set.insert(charactersIn: Unicode.Scalar(0x2000)!...Unicode.Scalar(0x200A)!)
    set.insert(charactersIn: "\u{0085}\u{00A0}\u{1680}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}")
    return set
}()

/// Python indexes a host by code point; `hasPrefix`/`hasSuffix`/`removeFirst` index by grapheme
/// cluster under canonical equivalence. In "www.\u{0301}foo.io" the dot and the following combining
/// acute form one cluster ".\u{0301}", so `hasPrefix("www.")` is false and the "www." would survive
/// where Python strips it. Scalars keep the two on the same answer.
private func normalizeHost(_ host: String) -> String {
    var scalars = host.trimmingCharacters(in: pythonWhitespace).lowercased().unicodeScalars
    while scalars.last == "." { scalars.removeLast() }
    if scalars.starts(with: "www.".unicodeScalars) { scalars.removeFirst(4) }
    return String(scalars)
}

/// Python's `round(x, 4)` rounds the *decimal* expansion of the double, breaking ties to even.
/// Scaling by 10 000 and calling `rounded()` gets this wrong twice over: it rounds ties away from
/// zero (1/32 would report 0.0313, not 0.0312), and the multiplication perturbs values that were
/// already near a tie (1/160 would report 0.0062, not 0.0063). Formatting to four places and
/// reading the value back performs exactly the correctly-rounded, ties-to-even decimal conversion
/// CPython does.
private func roundedToFourPlaces(_ value: Double) -> Double {
    Double(String(format: "%.4f", value)) ?? value
}

/// Python sorts strings by code point; Swift's `<` compares by Unicode collation, which would order
/// non-ASCII hosts differently. Sorting on scalars keeps the reported order identical.
private func codePointSorted(_ values: some Sequence<String>) -> [String] {
    values.sorted { a, b in
        var lhs = a.unicodeScalars.makeIterator(), rhs = b.unicodeScalars.makeIterator()
        while true {
            switch (lhs.next(), rhs.next()) {
            case (nil, nil): return false
            case (nil, _):   return true
            case (_, nil):   return false
            case let (x?, y?): if x.value != y.value { return x.value < y.value }
            }
        }
    }
}

// MARK: - Extraction

/// Everything Python's `re.split(r"[/?#:]", raw, 1)` cuts the authority at.
private let hostDelimiters: Set<Unicode.Scalar> = ["/", "?", "#", ":"]

/// Every host referenced by a URL or a bare domain in `text`.
public func extractHosts(_ text: String) -> Set<String> {
    var hosts: Set<String> = []

    for match in urlRegex.allMatches(text) {
        var raw = match.string(in: text)
        if let scheme = raw.range(of: #"^https?://"#, options: [.regularExpression, .caseInsensitive]) {
            raw.removeSubrange(scheme)
        }
        // Drop userinfo before the host — https://good.com@evil.example is evil.
        if let at = raw.range(of: "@", options: [.backwards, .literal]) {
            raw = String(raw[at.upperBound...])
        }
        // Scalars, not Characters: a delimiter followed by a combining mark forms one grapheme
        // cluster, and a per-Character scan would sail straight past it where Python splits.
        let host = String(String.UnicodeScalarView(raw.unicodeScalars.prefix(while: { !hostDelimiters.contains($0) })))
        if !host.isEmpty { hosts.insert(normalizeHost(host)) }
    }

    for match in bareHostRegex.allMatches(text) {
        if let host = match.group(1, in: text) { hosts.insert(normalizeHost(host)) }
    }

    return hosts.filter { !$0.isEmpty && !ubiquitousHosts.contains($0) }
}

public func extractEmails(_ text: String) -> Set<String> {
    Set(emailRegex.allMatches(text).map { $0.string(in: text).lowercased() })
}

public func contentWords(_ text: String) -> [String] {
    let folded = fold(text)
    return wordRegex.allMatches(folded).map { $0.string(in: folded) }.filter { !stopwords.contains($0) }
}

// MARK: - Check

/// Compare a model reply against the source it was supposed to summarize.
///
/// `options.checkLexical` should be false when the summary was requested in a different language
/// than the source, or when the caller's task is not summarization — the vocabulary measure means
/// nothing there. The reference checks always run; they do not depend on language.
/// First `n` code points, matching Python's `s[:n]`.
///
/// `String.prefix` counts grapheme clusters, so a base letter plus a combining
/// mark costs one where Python counts two, and an emoji ZWJ sequence costs one
/// where Python counts several. Slice unicode scalars instead.
private func headCodePoints(_ text: String, _ n: Int) -> String {
    String(String.UnicodeScalarView(text.unicodeScalars.prefix(n)))
}

public func checkGrounding(
    _ output: String,
    source: String,
    options: GroundingOptions = GroundingOptions()
) -> GroundingReport {
    var findings: [Finding] = []
    if output.trimmingCharacters(in: pythonWhitespace).isEmpty {
        return GroundingReport(ratio: 1.0, lexicalChecked: false, novelHosts: [], novelEmails: [], findings: [])
    }

    let sourceFolded = fold(source)

    // --- reference grounding (strong) -------------------------------------
    let sourceHosts = extractHosts(source)
    let novelHosts = codePointSorted(extractHosts(output).filter { host in
        // A host is grounded if the source names it, or names it as a suffix (the source may show
        // "docs.example.com" and the summary "example.com").
        guard !sourceHosts.contains(host) else { return false }
        guard !sourceHosts.contains(where: { host == $0 || $0.hasSuffix("." + host) || host.hasSuffix("." + $0) })
        else { return false }
        // `.literal` so this is a code-point substring test, as in Python — not Swift's default
        // canonical-equivalence search.
        return sourceFolded.range(of: host, options: .literal) == nil
    })
    if !novelHosts.isEmpty {
        findings.append(Finding(
            stage: .validate, category: "ungrounded_host", severity: .critical, weight: 0.92,
            message: "Output references \(novelHosts.count) host(s) absent from the source: "
                + novelHosts.prefix(4).joined(separator: ", "),
            excerpt: headCodePoints(novelHosts[0], 80)
        ))
    }

    let sourceEmails = extractEmails(source)
    let novelEmails = codePointSorted(extractEmails(output).filter { !sourceEmails.contains($0) })
    if !novelEmails.isEmpty {
        findings.append(Finding(
            stage: .validate, category: "ungrounded_email", severity: .high, weight: 0.80,
            message: "Output contains \(novelEmails.count) email address(es) absent from the source",
            excerpt: headCodePoints(novelEmails[0], 80)
        ))
    }

    // --- lexical grounding (weak) -----------------------------------------
    var ratio = 1.0
    var checked = false
    if options.checkLexical {
        let outWords = contentWords(output)
        if outWords.count >= options.minWordsForLexical {
            checked = true
            let sourceWords = Set(contentWords(source))
            if !sourceWords.isEmpty {
                let hits = outWords.reduce(0) { $0 + (sourceWords.contains($1) ? 1 : 0) }
                ratio = Double(hits) / Double(outWords.count)
                if ratio < options.lexicalFloor {
                    findings.append(Finding(
                        stage: .validate, category: "low_grounding", severity: .medium, weight: 0.45,
                        message: "Only \(String(format: "%.0f", ratio * 100))% of the summary's content words "
                            + "appear in the source — the reply may not be derived from it"
                    ))
                }
            }
        }
    }

    return GroundingReport(
        ratio: roundedToFourPlaces(ratio),
        lexicalChecked: checked,
        novelHosts: novelHosts,
        novelEmails: novelEmails,
        findings: findings
    )
}
