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

public func matchSignatures(_ text: String, using sigs: [Signature]? = nil) -> [Finding] {
    var findings: [Finding] = []
    for s in sigs ?? signatures {
        guard let m = s.regex.firstMatch(text) else { continue }
        findings.append(Finding(
            stage: .detect, category: s.category, severity: s.severity, weight: s.weight,
            message: s.description, excerpt: excerpt(text, m.range), patternId: s.id
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

private let b64PayloadRegex = CompiledRegex(#"[A-Za-z0-9+/]{24,}={0,2}"#, options: [])

/// Return the decoded text of embedded Base64 blobs that resolve to printable
/// UTF-8. A common evasion is to Base64-encode an instruction so it sails past
/// every keyword signature; decoding it here lets the same signatures run on the
/// real payload. Blobs that aren't valid Base64 or decode to mostly binary are
/// skipped, so random tokens and hashes don't generate noise.
public func decodeBase64Payloads(_ text: String, maxPayloads: Int = 12) -> [String] {
    var payloads: [String] = []
    for m in b64PayloadRegex.allMatches(text) {
        let blob0 = m.string(in: text)
        let usable = blob0.count - (blob0.count % 4)
        if usable < 24 { continue }
        let blob = String(blob0.prefix(usable))
        guard let data = Data(base64Encoded: blob), let decoded = String(data: data, encoding: .utf8) else { continue }
        if decoded.trimmingCharacters(in: .whitespacesAndNewlines).count < 4 { continue }
        let scalars = decoded.unicodeScalars
        let printable = scalars.filter { $0.value >= 0x20 || $0 == "\t" || $0 == "\n" || $0 == "\r" }.count
        if Double(printable) / Double(scalars.count) < 0.85 { continue }
        payloads.append(decoded)
        if payloads.count >= maxPayloads { break }
    }
    return payloads
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

public struct DetectOptions {
    public var threshold: Double
    public var extraFindings: [Finding]
    public var useHeuristics: Bool
    /// Additional copy of the text scanned with the same signatures, merged
    /// (used for the de-obfuscated copy so homoglyph/leetspeak disguises are
    /// caught without breaking detection of legitimate non-Latin scripts).
    public var alsoScan: String?
    /// Decode embedded Base64 blobs and scan the decoded payload too.
    public var decodeBase64: Bool
    /// Custom signatures appended to the built-in database for this scan.
    public var extraSignatures: [Signature]

    public init(threshold: Double = 0.5, extraFindings: [Finding] = [], useHeuristics: Bool = true, alsoScan: String? = nil, decodeBase64: Bool = true, extraSignatures: [Signature] = []) {
        self.threshold = threshold
        self.extraFindings = extraFindings
        self.useHeuristics = useHeuristics
        self.alsoScan = alsoScan
        self.decodeBase64 = decodeBase64
        self.extraSignatures = extraSignatures
    }
}

public func detect(_ text: String, options: DetectOptions = DetectOptions()) -> DetectResult {
    let sigs = options.extraSignatures.isEmpty ? signatures : signatures + options.extraSignatures
    var findings = options.extraFindings
    var seen = Set(findings.compactMap { $0.patternId })

    func merge(_ newFindings: [Finding], note: String? = nil) {
        for f in newFindings {
            if let pid = f.patternId, seen.contains(pid) { continue }
            if let pid = f.patternId { seen.insert(pid) }
            if let note = note {
                findings.append(Finding(stage: f.stage, category: f.category, severity: f.severity,
                                        weight: f.weight, message: "\(f.message) \(note)",
                                        excerpt: f.excerpt, patternId: f.patternId))
            } else {
                findings.append(f)
            }
        }
    }

    merge(matchSignatures(text, using: sigs))
    if let also = options.alsoScan, also != text { merge(matchSignatures(also, using: sigs)) }
    if options.decodeBase64 {
        for payload in decodeBase64Payloads(text) { merge(matchSignatures(payload, using: sigs), note: "(decoded from Base64)") }
    }
    if options.useHeuristics { findings.append(contentsOf: heuristicFindings(text)) }

    let score = scoreFindings(findings)
    let risk = bucket(score)
    let injected = score >= options.threshold || findings.contains { $0.severity >= .high }
    return DetectResult(score: score, risk: risk, injected: injected, threshold: options.threshold, findings: findings)
}
