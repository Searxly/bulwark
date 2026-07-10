// Rampart: redact PII before the model ever sees it.
//
// The other Bulwark layers stop a hostile page from steering your model. Rampart handles the
// mirror-image risk: your model — or the provider behind it — seeing personal data it never
// needed. When a tool returns a page, an email, or a search result, that text can carry a real
// person's email, phone, card, or national ID. Rampart replaces each one with a typed,
// reversible placeholder (`[EMAIL_1]`) so the model reasons over structure, not secrets — and if
// the model is a remote one, the raw value never leaves the machine.
//
// This is the deterministic layer: regex + checksum validators, zero dependencies, no model to
// load. It catches structured identifiers exactly (Luhn-valid cards, structurally-valid US SSNs,
// validated IPv4/IPv6, emails, phones, IBANs). Names and street addresses need a NER model and
// live in the host app (Searxly ships one); this layer is the portable, always-available floor.
//
// Placeholders are stable within a redaction: the same value always maps to the same token, so a
// document that mentions one email twice reads consistently to the model. `rehydrate` restores
// the originals from the returned map when you control the model's reply channel (redact outbound,
// rehydrate inbound). For a one-way scrub (tool output → model, no reply to us), just drop the map.
//
// Approach inspired by National Design Studio's Rampart (CC BY 4.0); this is an original,
// dependency-free reimplementation of the deterministic detectors.

import Foundation

/// Structured PII classes this deterministic layer can detect. The raw value is the placeholder
/// prefix (`.email` → `[EMAIL_1]`).
public enum RampartEntity: String, Sendable, CaseIterable {
    case email       = "EMAIL"
    case phone       = "PHONE"
    case creditCard  = "CREDIT_CARD"
    case ssn         = "SSN"
    case ipAddress   = "IP_ADDRESS"
    case iban        = "IBAN"
}

/// The result of a redaction.
public struct RampartRedaction: Sendable {
    /// The text with each PII span replaced by its placeholder.
    public let text: String
    /// How many spans were replaced.
    public let count: Int
    /// PII-safe summary of what was hidden, e.g. "EMAIL×2, SSN×1" — labels and counts only,
    /// never the values, so it's safe to log or show.
    public let summary: String
    /// placeholder → original value, for `rehydrate` when you control the reply channel.
    public let map: [String: String]
}

/// Deterministic PII redaction. Stateless; call `redact` per piece of text.
public enum Rampart {

    /// Regex that finds every placeholder this layer mints, for `rehydrate`.
    static let placeholderPattern = try! NSRegularExpression(pattern: #"\[[A-Z][A-Z_]*_\d+\]"#)

    // MARK: - Public API

    /// Replace structured PII in `text` with typed placeholders. Entities in `keep` are detected
    /// but left in place (e.g. keep `.ipAddress` when logs need real IPs). Returns the redacted
    /// text plus a reverse map for optional `rehydrate`.
    public static func redact(_ text: String, keep: Set<RampartEntity> = []) -> RampartRedaction {
        guard !text.isEmpty else { return RampartRedaction(text: text, count: 0, summary: "", map: [:]) }

        let spans = merge(detect(text)).filter { !keep.contains($0.entity) }
        guard !spans.isEmpty else { return RampartRedaction(text: text, count: 0, summary: "", map: [:]) }

        // Splice right-to-left so earlier UTF-16 offsets stay valid.
        let ordered = spans.sorted { $0.start > $1.start }
        let mutable = NSMutableString(string: text)
        var forward: [String: String] = [:]     // "LABEL:normalized" → token
        var reverse: [String: String] = [:]      // token → original value
        var counters: [String: Int] = [:]
        var labelCounts: [String: Int] = [:]
        var labelOrder: [String] = []

        for span in ordered {
            let label = span.entity.rawValue
            let key = "\(label):\(normalize(span.value))"
            let token: String
            if let existing = forward[key] {
                token = existing
            } else {
                let next = (counters[label] ?? 0) + 1
                counters[label] = next
                token = "[\(label)_\(next)]"
                forward[key] = token
                reverse[token] = span.value
            }
            mutable.replaceCharacters(in: NSRange(location: span.start, length: span.end - span.start), with: token)
            if labelCounts[label] == nil { labelOrder.append(label) }
            labelCounts[label, default: 0] += 1
        }

        let summary = labelOrder.map { "\($0)×\(labelCounts[$0]!)" }.joined(separator: ", ")
        return RampartRedaction(text: mutable as String, count: ordered.count, summary: summary, map: reverse)
    }

    /// Restore original values from a `redact` map. Unknown placeholders are left intact.
    public static func rehydrate(_ text: String, map: [String: String]) -> String {
        let ns = text as NSString
        let matches = placeholderPattern.matches(in: text, range: NSRange(location: 0, length: ns.length))
        guard !matches.isEmpty else { return text }
        let result = NSMutableString(string: text)
        for match in matches.reversed() {
            let token = ns.substring(with: match.range)
            if let value = map[token] { result.replaceCharacters(in: match.range, with: value) }
        }
        return result as String
    }

    // MARK: - Validators (public — useful on their own)

    /// Luhn (mod-10) checksum — gates CREDIT_CARD so arbitrary digit runs don't match.
    public static func luhnValid(_ digits: String) -> Bool {
        guard !digits.isEmpty else { return false }
        var sum = 0, double = false
        for ch in digits.reversed() {
            guard let d = ch.wholeNumberValue, (0...9).contains(d) else { return false }
            let v = double ? (d * 2 > 9 ? d * 2 - 9 : d * 2) : d
            sum += v
            double.toggle()
        }
        return sum % 10 == 0
    }

    /// US SSN structural rules: area ≠ 000/666/900-999, group ≠ 00, serial ≠ 0000. Rejects the
    /// many 9-digit runs (padded phone numbers, IDs) that aren't SSNs.
    public static func validSSN(_ digits: String) -> Bool {
        guard digits.count == 9 else { return false }
        let area = String(digits.prefix(3)), group = String(digits.dropFirst(3).prefix(2)), serial = String(digits.suffix(4))
        if area == "000" || area == "666" || (Int(area) ?? 0) >= 900 { return false }
        return group != "00" && serial != "0000"
    }

    // MARK: - Detection

    struct Span { let start: Int; let end: Int; let entity: RampartEntity; let priority: Int; let value: String }

    private static func detect(_ text: String) -> [Span] {
        digitSpans(text) + textSpans(text)
    }

    /// Priority resolves overlaps: a stricter, checksum-backed class beats a looser one on the
    /// same bytes (a Luhn-valid 16-digit card is a card, not a phone).
    private static func priority(_ e: RampartEntity) -> Int {
        switch e {
        case .creditCard: return 5
        case .iban:       return 5
        case .ssn:        return 4
        case .email:      return 4
        case .ipAddress:  return 3
        case .phone:      return 2
        }
    }

    // Text-shaped entities: matched on the raw string where structure lives in the punctuation.
    private static let textRules: [(RampartEntity, NSRegularExpression)] = [
        (.email, re(#"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"#)),
        (.iban,  re(#"\b[A-Z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,30}\b"#)),
        (.ipAddress, re(#"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"#)),
        (.ipAddress, re(#"(?<![:.\w])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})(?![:.\w])"#)),
        // Phone: require separators or a leading + so bare digit runs (IDs, prices) don't match.
        // NANP-style, optional country code: "(555) 123-4567", "555-123-4567", "+1 555 123 4567".
        (.phone, re(#"(?<![\w.])(?:\+?\d{1,3}[ .-])?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\w])"#)),
        // International: a leading + then a separated run, e.g. "+44 20 7946 0958".
        (.phone, re(#"(?<![\w.])\+\d[\d .-]{6,}\d(?![\w])"#)),
    ]

    private static func textSpans(_ text: String) -> [Span] {
        let ns = text as NSString
        let full = NSRange(location: 0, length: ns.length)
        var spans: [Span] = []
        for (entity, regex) in textRules {
            for m in regex.matches(in: text, range: full) where m.range.length > 0 {
                spans.append(Span(start: m.range.location, end: m.range.location + m.range.length,
                                  entity: entity, priority: priority(entity), value: ns.substring(with: m.range)))
            }
        }
        return spans
    }

    // Digit-run entities (card, SSN): found over digit runs so every separator variant collapses
    // to one rule — "888-88-8888", "888 88 8888", "888888888" all match.
    private static let digitRun = try! NSRegularExpression(pattern: #"\d(?:[ .-]?\d)*"#)

    private static func digitSpans(_ text: String) -> [Span] {
        let ns = text as NSString
        var spans: [Span] = []
        for m in digitRun.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            var digits = ""
            var idx: [Int] = []
            for i in 0..<m.range.length {
                let cu = ns.character(at: m.range.location + i)
                if cu >= 0x30 && cu <= 0x39 { digits.append(Character(UnicodeScalar(cu)!)); idx.append(m.range.location + i) }
            }
            guard let first = idx.first, let last = idx.last else { continue }
            let (start, end) = (first, last + 1)
            let value = ns.substring(with: NSRange(location: start, length: end - start))
            if [14, 15, 16].contains(digits.count), luhnValid(digits) {
                spans.append(Span(start: start, end: end, entity: .creditCard, priority: priority(.creditCard), value: value))
            } else if digits.count == 9, validSSN(digits) {
                spans.append(Span(start: start, end: end, entity: .ssn, priority: priority(.ssn), value: value))
            }
        }
        return spans
    }

    /// Reduce overlapping spans to a disjoint set: higher priority wins, ties break to the longer
    /// span. Biased to keep a redaction — on any overlap the survivor covers both byte ranges.
    private static func merge(_ spans: [Span]) -> [Span] {
        guard spans.count > 1 else { return spans }
        let sorted = spans.sorted { $0.start != $1.start ? $0.start < $1.start : $0.end > $1.end }
        var out: [Span] = []
        for span in sorted {
            guard let prev = out.last, span.start < prev.end else { out.append(span); continue }
            let winner = (prev.priority != span.priority) ? (prev.priority > span.priority ? prev : span)
                                                          : ((prev.end - prev.start) >= (span.end - span.start) ? prev : span)
            let start = Swift.min(prev.start, span.start), end = Swift.max(prev.end, span.end)
            out[out.count - 1] = Span(start: start, end: end, entity: winner.entity, priority: winner.priority, value: winner.value)
        }
        return out
    }

    // MARK: - Helpers

    private static func normalize(_ value: String) -> String {
        value.lowercased()
            .replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespaces)
    }

    private static func re(_ pattern: String) -> NSRegularExpression { try! NSRegularExpression(pattern: pattern) }
}
