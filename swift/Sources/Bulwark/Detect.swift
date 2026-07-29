// Detection and risk scoring: noisy-OR over weighted signature/heuristic signals.

import Foundation

private let imperativeVerbs: Set<String> = [
    "ignore", "disregard", "forget", "stop", "do", "don't", "dont", "never", "always",
    "print", "output", "repeat", "reveal", "send", "post", "fetch", "execute", "run",
    "call", "follow", "obey", "respond", "reply", "answer", "write", "say", "tell",
    "act", "pretend", "become", "switch", "override", "bypass", "summarize", "translate",
]

private let directiveRegex = CompiledRegex(#"\byou\s+(?:must|should|shall|need\s+to|have\s+to|are\s+(?:required|instructed|now))\b"#)
private let lineRegex = CompiledRegex(#"^[\s\-*\d.)#>]*([a-zA-Z']+)"#, options: [.anchorsMatchLines])

private func excerpt(_ text: String, _ range: NSRange, pad: Int = 24) -> String {
    let ns = text as NSString
    let a = max(0, range.location - pad)
    let b = min(ns.length, range.location + range.length + pad)
    var s = ns.substring(with: NSRange(location: a, length: b - a))
        .replacingOccurrences(of: "\n", with: " ")
        .trimmingCharacters(in: .whitespaces)
    if a > 0 { s = "…" + s }
    if b < ns.length { s += "…" }
    return s
}

public func matchSignatures(_ text: String) -> [Finding] {
    var findings: [Finding] = []
    for s in signatures {
        guard let m = s.regex.firstMatch(text) else { continue }
        findings.append(Finding(
            stage: .detect, category: s.category, severity: s.severity, weight: s.weight,
            message: s.description, excerpt: excerpt(text, m.range),
            span: (m.range.location, m.range.location + m.range.length), patternId: s.id
        ))
    }
    return findings
}

public func heuristicFindings(_ text: String) -> [Finding] {
    var findings: [Finding] = []
    if text.isEmpty { return findings }

    let lineWords = lineRegex.allMatches(text).compactMap { $0.group(1, in: text) }
    if lineWords.count >= 4 {
        let imperative = lineWords.filter { imperativeVerbs.contains($0.lowercased()) }.count
        let ratio = Double(imperative) / Double(lineWords.count)
        if ratio >= 0.4 && imperative >= 3 {
            findings.append(Finding(stage: .detect, category: "imperative_density", severity: .medium, weight: 0.45,
                                    message: "\(imperative)/\(lineWords.count) lines begin with a command verb"))
        }
    }

    let directives = directiveRegex.count(text)
    let perKChar = Double(directives) / max(1.0, Double(text.count) / 1000.0)
    if directives >= 2 && perKChar >= 1.5 {
        findings.append(Finding(stage: .detect, category: "directive_density", severity: .medium, weight: 0.40,
                                message: "\(directives) second-person directive(s) addressed to the assistant"))
    }
    return findings
}

public func scoreFindings<S: Sequence>(_ findings: S) -> Double where S.Element == Finding {
    var product = 1.0
    for f in findings {
        let w = max(0.0, min(0.99, f.weight))
        product *= (1.0 - w)
    }
    return 1.0 - product
}

public func bucket(_ score: Double) -> Severity {
    if score >= 0.90 { return .critical }
    if score >= 0.70 { return .high }
    if score >= 0.40 { return .medium }
    if score >= 0.15 { return .low }
    return .info
}

/// Signatures that only appear once an encoded payload is decoded.
///
/// A hit inside an encoded layer is *stronger* evidence than the same hit in
/// plaintext, not weaker: ordinary documents contain hashes and tokens, but
/// nobody accidentally Base64-encodes "ignore all previous instructions". So
/// each contaminated layer contributes one high-weight finding rather than
/// re-emitting every match, which would let a single payload stack the noisy-OR
/// several times over.
public func decodedFindings(_ text: String) -> [Finding] {
    var findings: [Finding] = []
    for layer in unwrap(text) {
        let matches = matchSignatures(layer.text)
        guard !matches.isEmpty else { continue }
        let ids = Array(Set(matches.compactMap { $0.patternId })).sorted().prefix(4).joined(separator: ", ")
        let worst = matches.max(by: { $0.weight < $1.weight })!
        findings.append(Finding(
            stage: .detect, category: "encoded_payload", severity: .critical,
            weight: Swift.min(0.92, Swift.max(0.80, worst.weight)),
            message: "A payload hidden under \(layer.label) decodes to injection content (\(ids))",
            excerpt: String(layer.text.prefix(60)),
            patternId: "enc.decoded[\(layer.label)]"
        ))
    }
    return findings
}

public struct DetectOptions {
    public var threshold: Double
    public var extraFindings: [Finding]
    public var useHeuristics: Bool
    /// Additional copy of the text scanned with the same signatures, merged
    /// (used for the confusable-folded copy so homoglyph disguises are caught
    /// without breaking detection of legitimate non-Latin scripts).
    public var alsoScan: String?
    /// Text to recursively decode and re-scan. Pass the **raw**,
    /// pre-sanitization content: channels such as zero-width bit strings are
    /// removed by sanitization precisely because they are invisible, and
    /// decoding them afterwards would find nothing.
    public var alsoDecode: String?
    /// Discount findings inside quoted or code-fenced passages of a document
    /// that reads as writing *about* attacks. Reduces weight, never removes.
    public var useContext: Bool
    /// Also scan a whitespace-flattened, de-hyphenated view. Without it, hard
    /// wrapping the payload defeats every bounded-span signature.
    public var flatten: Bool

    public init(threshold: Double = 0.5, extraFindings: [Finding] = [], useHeuristics: Bool = true,
                alsoScan: String? = nil, alsoDecode: String? = nil,
                useContext: Bool = true, flatten: Bool = true) {
        self.threshold = threshold
        self.extraFindings = extraFindings
        self.useHeuristics = useHeuristics
        self.alsoScan = alsoScan
        self.alsoDecode = alsoDecode
        self.useContext = useContext
        self.flatten = flatten
    }
}

public func detect(_ text: String, options: DetectOptions = DetectOptions()) -> DetectResult {
    var findings = options.extraFindings
    findings.append(contentsOf: matchSignatures(text))
    var seen = Set(findings.compactMap { $0.patternId })
    let textLength = (text as NSString).length

    func merge(_ incoming: [Finding], index: [Int]? = nil) {
        for f in incoming {
            if let pid = f.patternId, seen.contains(pid) { continue }
            if let pid = f.patternId { seen.insert(pid) }
            if let index, let span = f.span {
                let mapped = mapSpan(span, index: index, originalLength: textLength)
                findings.append(Finding(
                    stage: f.stage, category: f.category, severity: f.severity, weight: f.weight,
                    message: f.message, excerpt: f.excerpt, span: mapped, patternId: f.patternId
                ))
            } else {
                findings.append(f)
            }
        }
    }

    // Homoglyph / leetspeak view — 1:1, so spans need no remapping.
    if let also = options.alsoScan, also != text { merge(matchSignatures(also)) }

    if options.flatten {
        for view in [text, options.alsoScan].compactMap({ $0 }) {
            let flat = flattenForDetection(view)
            if !flat.text.isEmpty, flat.text != view {
                merge(matchSignatures(flat.text), index: flat.index)
            }
            // Combining marks stacked on ASCII letters hide trigger words from
            // every signature; strip them on the flattened view too.
            let unmarked = stripMarks(flat.text)
            if unmarked != flat.text { merge(matchSignatures(unmarked)) }
        }
    }

    if options.useHeuristics { findings.append(contentsOf: heuristicFindings(text)) }

    if options.useContext { findings = applyContext(text, findings) }

    // Decoded findings are added after the context pass on purpose: an encoded
    // payload has no visible quoting context to sit inside, and discounting it
    // for the fence around the blob would reward the obfuscation.
    if let raw = options.alsoDecode { findings.append(contentsOf: decodedFindings(raw)) }

    let score = scoreFindings(findings)
    let risk = bucket(score)
    let injected = score >= options.threshold || findings.contains { $0.severity >= .high }
    return DetectResult(score: score, risk: risk, injected: injected, threshold: options.threshold, findings: findings)
}
