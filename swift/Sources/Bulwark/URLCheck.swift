// Decide whether a URL is a destination or a delivery mechanism.
//
// Wherever an LLM system touches a URL — a link a summarizer emitted, an argument
// an agent wants to pass to `navigate` — the same two questions apply. *Where does
// this actually point?* and *how much data is riding along?*
//
// Both are harder than they look, because a host is not a string. All of these name
// 127.0.0.1, and a substring check for "127.0.0.1" catches none of them:
//
//     http://2130706433/     http://0177.0.0.1/    http://0x7f.0.0.1/
//     http://127.1/          http://[::ffff:127.0.0.1]/
//
// And all of these look like they point at a domain you trust, but do not:
//
//     https://trusted.example.com@attacker.test/
//     https://trusted.example.com.attacker.test/
//     https://xn--trustd-9wa.example/            (homograph)
//
// So the host is CANONICALIZED the way the network stack would canonicalize it —
// the full `inet_aton` grammar, IPv6 forms, IPv4-mapped addresses — and only then
// classified. The data-carrying checks are separate: an opaque blob is
// exfiltration-shaped wherever it sits, and attackers move it from the query string
// to the path, the fragment, or a subdomain precisely because guards tend to only
// look at the query.
//
// This is SYNTACTIC analysis only. No DNS is resolved — Bulwark stays deterministic
// and dependency-free — so a public hostname that resolves to 169.254.169.254 passes
// here. Keep a resolver-level SSRF guard in the fetch layer too; this is the check
// you can run before you have a socket, not a replacement for the one you run when
// you do.

import Foundation

// MARK: - Public types

public enum HostKind: String, Sendable {
    case domain
    case ipv4      // includes decimal/octal/hex/short forms once canonicalized
    case ipv6
    case empty
    case malformed
}

/// The pieces of a URL, as `splitURL` reads them.
public struct URLParts: Sendable {
    public let scheme: String
    public let userinfo: String?
    public let host: String
    public let port: Int?
    public let path: String
    public let query: String
    public let fragment: String
}

/// Everything syntactic analysis can tell you about one URL.
public struct URLAssessment: Sendable {
    public let raw: String
    public let scheme: String
    public let userinfo: String?
    public let host: String
    public let canonicalHost: String
    public let port: Int?
    public let path: String
    public let query: String
    public let fragment: String

    public let kind: HostKind
    public var isPrivate = false
    public var isMetadata = false
    public var isPunycode = false
    public var isMixedScript = false
    public var hasCredentials = false

    public var opaqueInQuery = 0
    public var opaqueInPath = 0
    public var opaqueInFragment = 0
    public var opaqueInSubdomain = 0

    public var findings: [Finding] = []

    public var maxOpaque: Int {
        max(opaqueInQuery, opaqueInPath, opaqueInFragment, opaqueInSubdomain)
    }

    public var safe: Bool { findings.isEmpty }
}

public struct URLCheckOptions: Sendable {
    /// Schemes that may fetch a document. Empty disables the check.
    public var allowedSchemes: Set<String>
    public var maxLength: Int
    /// Longest opaque run tolerated in a query, path or fragment. 0 disables.
    public var maxOpaque: Int
    /// Subdomains get a tighter limit: DNS labels are chosen by humans and are
    /// short, so a 30-character random label is already anomalous where the same
    /// run in a query string might be a legitimate session token.
    public var maxOpaqueSubdomain: Int
    public var allowPrivate: Bool

    public init(
        allowedSchemes: Set<String> = ["http", "https"],
        maxLength: Int = 2_048,
        maxOpaque: Int = 48,
        maxOpaqueSubdomain: Int = 24,
        allowPrivate: Bool = false
    ) {
        self.allowedSchemes = allowedSchemes
        self.maxLength = maxLength
        self.maxOpaque = maxOpaque
        self.maxOpaqueSubdomain = maxOpaqueSubdomain
        self.allowPrivate = allowPrivate
    }
}

// MARK: - Constants

/// Cloud instance-metadata endpoints. Reaching one from a hijacked agent hands an
/// attacker the machine's credentials, which makes them the highest-value target in
/// the private ranges rather than just another internal address.
private let metadataHosts: Set<String> = [
    "169.254.169.254",          // AWS / Azure / GCP / DigitalOcean IMDS
    "169.254.170.2",            // AWS ECS task metadata
    "100.100.100.200",          // Alibaba Cloud
    "192.0.0.192",              // Oracle Cloud
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
]
private let metadataIPv6: Set<String> = ["fd00:ec2::254"]

private let localSuffixes = [".local", ".internal", ".localhost", ".home.arpa", ".localdomain"]
private let localNames: Set<String> = ["localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"]

// `\A`/`\z` rather than `^`/`$`: ICU anchors are line-oriented, so `^`/`$` would
// match at every embedded newline and let "evil.test\nlocalhost" pass as one valid
// label. The trailing `\n?` is deliberate — the reference implementation's `$` also
// matches just before a single newline at the very end of the string, so
// `classify_host("mybox\n")` reads as a domain there and must here too.
private let schemeRegex = CompiledRegex(#"\A([a-zA-Z][a-zA-Z0-9+.\-]*):"#, options: [])
private let opaqueRunRegex = CompiledRegex(#"[A-Za-z0-9+/=_-]{8,}"#, options: [])
private let labelRegex = CompiledRegex(#"\A[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\n?\z"#, options: [])

/// Schemes that do something other than fetch a document, and are therefore never a
/// legitimate "go here" target from untrusted content.
private let activeSchemes: Set<String> = ["javascript", "data", "vbscript", "file", "jar", "blob", "about"]

// MARK: - Code-point string operations

/// A host is attacker-controlled text, and Swift's `String` methods work on grapheme
/// clusters where the reference implementation works on code points. A `.` followed
/// by a combining acute is *one* `Character`, so `"a.\u{0301}b".split(separator: ".")`
/// does not split and `contains(".")` is false — which would hand an attacker
/// `evil.\u{0301}attacker.test`, read as a single label, classified as a local
/// single-label host, with the real registrable domain never examined. Every
/// operation below therefore mirrors Python's `split`, `in`, `startswith`,
/// `endswith` and `strip` over `unicodeScalars`.
private extension String {
    /// `text.split(sep)` — empty pieces preserved, as Python's does.
    func splitOnScalar(_ separator: Unicode.Scalar) -> [String] {
        unicodeScalars.split(separator: separator, omittingEmptySubsequences: false)
            .map { String(String.UnicodeScalarView($0)) }
    }

    /// `sep in text`
    func containsScalar(_ scalar: Unicode.Scalar) -> Bool { unicodeScalars.contains(scalar) }

    /// `text.startswith(prefix)`
    func hasScalarPrefix(_ prefix: String) -> Bool {
        unicodeScalars.starts(with: prefix.unicodeScalars)
    }

    /// `text.endswith(suffix)`
    func hasScalarSuffix(_ suffix: String) -> Bool {
        unicodeScalars.reversed().starts(with: suffix.unicodeScalars.reversed())
    }

    /// `text.rstrip(chars)`
    func trimmingTrailingScalars(in scalars: Set<Unicode.Scalar>) -> String {
        var view = unicodeScalars[...]
        while let last = view.last, scalars.contains(last) { view = view.dropLast() }
        return String(String.UnicodeScalarView(view))
    }

    /// `text.strip(chars)`
    func trimmingScalars(in scalars: Set<Unicode.Scalar>) -> String {
        var view = unicodeScalars[...]
        while let first = view.first, scalars.contains(first) { view = view.dropFirst() }
        while let last = view.last, scalars.contains(last) { view = view.dropLast() }
        return String(String.UnicodeScalarView(view))
    }

    /// `text.split(sep)[0]`
    func prefixBeforeScalar(_ scalar: Unicode.Scalar) -> String {
        String(String.UnicodeScalarView(unicodeScalars.prefix { $0 != scalar }))
    }
}

// MARK: - Host canonicalization

/// The digit value of a scalar, or nil when it is not a digit in `radix`.
///
/// Unicode decimal digits count, not just ASCII: a browser NFKC-maps `١٢٧.0.0.1`
/// and `０x７f.0.0.1` onto the loopback address, so a guard that only knows ASCII
/// digits reads them as ordinary domain names and waves them through.
private func digitValue(_ scalar: Unicode.Scalar, radix: UInt64) -> UInt64? {
    let value: UInt64
    switch scalar {
    case "0"..."9": value = UInt64(scalar.value - 0x30)
    case "a"..."z": value = UInt64(scalar.value - 0x61) + 10
    case "A"..."Z": value = UInt64(scalar.value - 0x41) + 10
    default:
        guard scalar.properties.generalCategory == .decimalNumber,
              let decimal = Character(scalar).wholeNumberValue else { return nil }
        value = UInt64(decimal)
    }
    return value < radix ? value : nil
}

/// One component of an inet_aton-style address, parsed the way the reference
/// implementation's `int(text, radix)` parses it: optional surrounding whitespace,
/// an optional sign, `_` separators between digits, and a redundant `0x`/`0o`
/// prefix are all accepted, because every one of those spellings still reaches the
/// same address through the C library. Returns nil for anything else, and for
/// values too large to be part of an address (they are rejected downstream anyway).
private func parseIntComponent(_ scalars: ArraySlice<Unicode.Scalar>, radix: UInt64) -> UInt64? {
    var s = scalars
    while let first = s.first, first.properties.isWhitespace { s = s.dropFirst() }
    while let last = s.last, last.properties.isWhitespace { s = s.dropLast() }

    var negative = false
    if s.first == "+" { s = s.dropFirst() } else if s.first == "-" { negative = true; s = s.dropFirst() }

    var consumedPrefix = false
    if radix == 16 || radix == 8 {
        let lower: Unicode.Scalar = radix == 16 ? "x" : "o"
        let upper: Unicode.Scalar = radix == 16 ? "X" : "O"
        if s.first == "0", let second = s.dropFirst().first, second == lower || second == upper {
            s = s.dropFirst(2)
            consumedPrefix = true
        }
    }

    var result: UInt64 = 0
    var digits = 0
    // A leading underscore is not allowed, but one directly after a base prefix is.
    var previousWasUnderscore = !consumedPrefix
    for scalar in s {
        if scalar == "_" {
            if previousWasUnderscore { return nil }
            previousWasUnderscore = true
            continue
        }
        guard let value = digitValue(scalar, radix: radix) else { return nil }
        let (shifted, overflow1) = result.multipliedReportingOverflow(by: radix)
        guard !overflow1 else { return nil }
        let (sum, overflow2) = shifted.addingReportingOverflow(value)
        guard !overflow2 else { return nil }
        result = sum
        digits += 1
        previousWasUnderscore = false
    }
    guard digits > 0, !previousWasUnderscore else { return nil }
    // "-0" is zero and survives; any other negative is not an address component.
    return negative && result != 0 ? nil : result
}

private func parseIPv4Part(_ part: ArraySlice<Unicode.Scalar>) -> UInt64? {
    guard !part.isEmpty else { return nil }
    if part.count >= 2, part.first == "0",
       let second = part.dropFirst().first, second == "x" || second == "X" {
        return part.count > 2 ? parseIntComponent(part.dropFirst(2), radix: 16) : nil
    }
    if part.first == "0", part.count > 1 {
        return parseIntComponent(part, radix: 8)
    }
    return parseIntComponent(part, radix: 10)
}

/// Canonicalize any `inet_aton`-accepted IPv4 spelling to a 32-bit integer.
///
/// Handles the four forms the C library accepts and browsers still honour:
/// `a.b.c.d`, `a.b.c` (c is 16-bit), `a.b` (b is 24-bit) and a bare 32-bit `a` —
/// each component independently decimal, octal or hex. Returns nil when the host is
/// not an IPv4 literal in any of those spellings.
public func parseIPv4(_ host: String) -> UInt32? {
    let scalars = Array(host.unicodeScalars)
    let parts = scalars.split(separator: ".", omittingEmptySubsequences: false)
    guard (1...4).contains(parts.count) else { return nil }

    var values: [UInt64] = []
    for part in parts {
        guard let value = parseIPv4Part(part) else { return nil }
        values.append(value)
    }

    // Every component but the last is one byte; the last absorbs the remainder.
    let limit = UInt64(1) << (8 * UInt64(5 - values.count))
    guard let last = values.last, last < limit else { return nil }
    guard values.dropLast().allSatisfy({ $0 <= 0xFF }) else { return nil }

    var result = last
    for (i, value) in values.dropLast().enumerated() {
        result |= value << (8 * UInt64(3 - i))
    }
    return result <= 0xFFFF_FFFF ? UInt32(result) : nil
}

public func ipv4ToString(_ value: UInt32) -> String {
    [24, 16, 8, 0].map { String((value >> UInt32($0)) & 0xFF) }.joined(separator: ".")
}

private let privateV4Ranges: [(low: UInt32, high: UInt32)] = [
    (0x0000_0000, 8),   // 0.0.0.0/8      this network
    (0x0A00_0000, 8),   // 10/8           private
    (0x7F00_0000, 8),   // 127/8          loopback
    (0xA9FE_0000, 16),  // 169.254/16     link-local (incl. cloud metadata)
    (0xAC10_0000, 12),  // 172.16/12      private
    (0xC0A8_0000, 16),  // 192.168/16     private
    (0x6440_0000, 10),  // 100.64/10      CGNAT
    (0xC000_0000, 24),  // 192.0.0/24     IETF protocol assignments
    (0xC000_0200, 24),  // 192.0.2/24     TEST-NET-1
    (0xC612_0000, 15),  // 198.18/15      benchmarking
    (0xC633_6400, 24),  // 198.51.100/24  TEST-NET-2
    (0xCB00_7100, 24),  // 203.0.113/24   TEST-NET-3
    (0xE000_0000, 4),   // 224/4          multicast
    (0xF000_0000, 4),   // 240/4          reserved + broadcast
].map { base, bits in (base, base + UInt32((UInt64(1) << (32 - UInt64(bits))) - 1)) }

private func ipv4IsPrivate(_ value: UInt32) -> Bool {
    privateV4Ranges.contains { value >= $0.low && value <= $0.high }
}

private func ipv6IsPrivate(_ host: String) -> Bool {
    var h = host.lowercased().trimmingScalars(in: ["[", "]"])
    h = h.prefixBeforeScalar("%")                    // drop any zone id

    if h == "::1" || h == "::" || h == "0:0:0:0:0:0:0:1" { return true }
    if h.hasScalarPrefix("fe80:") || h.hasScalarPrefix("fe8") || h.hasScalarPrefix("fe9")
        || h.hasScalarPrefix("fea") || h.hasScalarPrefix("feb") { return true }  // fe80::/10 link-local
    if h.hasScalarPrefix("fc") || h.hasScalarPrefix("fd") { return true }        // fc00::/7 unique-local
    if h.hasScalarPrefix("::ffff:") || h.hasScalarPrefix("::") {
        // IPv4-mapped and IPv4-compatible forms carry a v4 address inside.
        if let tail = h.splitOnScalar(":").last,
           tail.containsScalar("."), let value = parseIPv4(tail) {
            return ipv4IsPrivate(value)
        }
    }
    return false
}

/// Coarse script names for the letters in `text` — enough to notice a label mixing
/// Latin with Cyrillic, which is what a homograph does.
///
/// Iterates scalars rather than Characters: a base letter plus a combining mark is
/// one Character but two scalars, and only the base letter names a script.
private func scriptsOf(_ text: String) -> Set<String> {
    var scripts: Set<String> = []
    for scalar in text.unicodeScalars {
        guard scalar.properties.generalCategory.isLetter, let name = scalar.properties.name else { continue }
        scripts.insert(String(name.prefix { $0 != " " }))
    }
    return scripts
}

private extension Unicode.GeneralCategory {
    /// Matches the reference implementation's `str.isalpha()` — Unicode category L*.
    var isLetter: Bool {
        switch self {
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter: return true
        default: return false
        }
    }

    /// A character a URL may contain: anything that is neither "Other" nor
    /// "Separator". Mirrors `ch.isprintable() and not ch.isspace()`.
    var isURLPrintable: Bool {
        switch self {
        case .control, .format, .surrogate, .privateUse, .unassigned,
             .spaceSeparator, .lineSeparator, .paragraphSeparator: return false
        default: return true
        }
    }
}

// MARK: - Parsing

private extension Array where Element == Unicode.Scalar {
    var string: String { String(String.UnicodeScalarView(self)) }
}

/// Split a URL without the leniency `URLComponents` applies.
///
/// A value with no scheme is treated as a bare host, matching how a model or a user
/// would read `evil.example/path`. `URLComponents` and `URL` return nil or a nil
/// host for several of the shapes that matter here, and a guard that cannot see the
/// host of a hostile URL is a guard that passes it.
public func splitURL(_ raw: String) -> URLParts {
    // Control and whitespace characters inside a URL are how parsers get split
    // against each other; strip them before anything reads the string.
    var text = Array(raw.unicodeScalars.filter { $0.properties.generalCategory.isURLPrintable })

    var scheme = ""
    let flat = text.string
    if let match = schemeRegex.firstMatch(flat), let name = match.group(1, in: flat) {
        scheme = name.lowercased()
        // The match is ASCII, so its UTF-16 length is also its scalar count.
        text.removeFirst(match.range.length)
        if text.starts(with: ["/", "/"]) { text.removeFirst(2) }
    } else if text.starts(with: ["/", "/"]) {
        text.removeFirst(2)                  // scheme-relative
    }

    var fragment: [Unicode.Scalar] = []
    if let i = text.firstIndex(of: "#") {
        fragment = Array(text[(i + 1)...])
        text = Array(text[..<i])
    }
    var query: [Unicode.Scalar] = []
    if let i = text.firstIndex(of: "?") {
        query = Array(text[(i + 1)...])
        text = Array(text[..<i])
    }
    var path: [Unicode.Scalar] = []
    if let i = text.firstIndex(of: "/") {
        path = Array(text[i...])
        text = Array(text[..<i])
    }

    var userinfo: [Unicode.Scalar]?
    if let i = text.lastIndex(of: "@") {
        // Last '@' wins: https://a@b@evil.test authenticates to evil.test.
        userinfo = Array(text[..<i])
        text = Array(text[(i + 1)...])
    }

    var port: Int?
    if text.first == "[" {                                   // IPv6 literal
        if let close = text.firstIndex(of: "]") {
            let rest = Array(text[(close + 1)...])
            text = Array(text[...close])
            if rest.first == ":", let value = parsePort(Array(rest.dropFirst())) { port = value }
        }
    } else if let colon = text.lastIndex(of: ":") {
        if let value = parsePort(Array(text[(colon + 1)...])) {
            port = value
            text = Array(text[..<colon])
        }
    }

    while text.last == "." { text.removeLast() }
    return URLParts(scheme: scheme, userinfo: userinfo?.string, host: text.string,
                    port: port, path: path.string, query: query.string, fragment: fragment.string)
}

/// A port is one or more decimal digits. Unicode decimal digits are accepted for the
/// same reason they are in an address component; anything else (including the
/// superscripts `str.isdigit()` would accept) leaves the colon in the host, where
/// `classifyHost` can see it.
private func parsePort(_ scalars: [Unicode.Scalar]) -> Int? {
    guard !scalars.isEmpty else { return nil }
    var value = 0
    for scalar in scalars {
        guard let digit = digitValue(scalar, radix: 10) else { return nil }
        // A port past Int.max is nonsense but still splits the host; saturate
        // rather than lose the split.
        value = value > (Int.max - 9) / 10 ? Int.max : value * 10 + Int(digit)
    }
    return value
}

/// Return the host's kind and its canonical spelling.
public func classifyHost(_ host: String) -> (kind: HostKind, canonical: String) {
    guard !host.isEmpty else { return (.empty, "") }
    // A fully-qualified name may carry a trailing root dot. Resolvers treat
    // "localhost." and "localhost" as the same name, so anything comparing
    // hostnames must too — otherwise one dot walks straight past a host check.
    let lowered = host.lowercased().trimmingTrailingScalars(in: ["."])
    guard !lowered.isEmpty else { return (.empty, "") }

    if lowered.hasScalarPrefix("[") && lowered.hasScalarSuffix("]") { return (.ipv6, lowered) }
    if lowered.containsScalar(":") { return (.ipv6, lowered) }
    if let value = parseIPv4(lowered) { return (.ipv4, ipv4ToString(value)) }

    let labels = lowered.splitOnScalar(".")
    let valid = labels.allSatisfy { label in
        label.isEmpty || labelRegex.test(label) || label.unicodeScalars.contains { $0.value > 127 }
    }
    return valid ? (.domain, lowered) : (.malformed, lowered)
}

/// Syntactic private/local check across every IPv4 and IPv6 spelling.
/// No DNS is resolved — keep a resolver-level SSRF guard in the fetch layer too.
public func isPrivateHost(_ host: String) -> Bool {
    let (kind, canonical) = classifyHost(host)
    switch kind {
    case .ipv4:
        // A trailing root dot defeats `parseIPv4` but not `classifyHost`; treating
        // the unparseable remainder as 0.0.0.0 keeps "127.0.0.1." private.
        return ipv4IsPrivate(parseIPv4(host.lowercased()) ?? 0)
    case .ipv6:
        return ipv6IsPrivate(canonical)
    case .empty, .malformed:
        return false
    case .domain:
        if localNames.contains(canonical) { return true }
        if localSuffixes.contains(where: { canonical.hasScalarSuffix($0) }) { return true }
        // A single-label host resolves through the local search domain.
        return !canonical.containsScalar(".")
    }
}

public func isMetadataHost(_ host: String) -> Bool {
    let (kind, canonical) = classifyHost(host)
    if metadataHosts.contains(canonical) { return true }
    if kind == .ipv6 {
        return metadataIPv6.contains(canonical.trimmingScalars(in: ["[", "]"]))
    }
    return false
}

private func longestOpaqueRun(_ text: String) -> Int {
    // The run is ASCII, so its UTF-16 length is also its character count.
    opaqueRunRegex.allMatches(text).reduce(0) { max($0, $1.range.length) }
}

// MARK: - The check

/// Assess one URL.
public func analyzeURL(_ raw: String, options: URLCheckOptions = URLCheckOptions()) -> URLAssessment {
    let parts = splitURL(raw)
    let (kind, canonical) = classifyHost(parts.host)

    var assessment = URLAssessment(
        raw: raw, scheme: parts.scheme, userinfo: parts.userinfo, host: parts.host,
        canonicalHost: canonical, port: parts.port, path: parts.path,
        query: parts.query, fragment: parts.fragment, kind: kind
    )
    let excerpt = String(String.UnicodeScalarView(raw.unicodeScalars.prefix(100)))

    func add(_ category: String, _ severity: Severity, _ message: String, _ weight: Double) {
        assessment.findings.append(Finding(stage: .validate, category: category, severity: severity,
                                           weight: weight, message: message, excerpt: excerpt))
    }

    // Scheme. An active scheme is not a destination at all; it is code.
    let activeScheme = !parts.scheme.isEmpty && activeSchemes.contains(parts.scheme)
    if activeScheme {
        add("url_active_scheme", .critical,
            "URL uses the '\(parts.scheme):' scheme, which executes rather than fetches", 0.95)
    } else if !parts.scheme.isEmpty, !options.allowedSchemes.isEmpty,
              !options.allowedSchemes.contains(parts.scheme) {
        add("url_scheme", .high, "URL scheme '\(parts.scheme)' is not in the allowed set", 0.80)
    }

    if let userinfo = parts.userinfo, !userinfo.isEmpty {
        assessment.hasCredentials = true
        let user = userinfo.prefixBeforeScalar(":")
        add("url_credentials", .high,
            "URL embeds userinfo before the host — the real destination is '\(canonical)', not '\(user)'", 0.82)
    }

    // An active-scheme URL has no host in any meaningful sense, so reporting the
    // leftovers as a malformed hostname would just be noise beside the real
    // (critical) finding.
    if kind == .malformed, !activeScheme {
        add("url_malformed", .medium, "URL host '\(parts.host)' is not a valid hostname", 0.50)
    }

    assessment.isMetadata = isMetadataHost(parts.host)
    assessment.isPrivate = isPrivateHost(parts.host)
    if assessment.isMetadata {
        add("url_metadata_endpoint", .critical,
            "URL targets a cloud instance-metadata endpoint (\(canonical))", 0.96)
    } else if assessment.isPrivate, !options.allowPrivate {
        add("url_private_host", .high,
            "URL targets a private or local host (\(canonical.isEmpty ? parts.host : canonical))", 0.80)
    }

    // The canonical form differing from what was written is itself the tell: an
    // honest link to 10.0.0.1 says "10.0.0.1", not "167772161".
    if kind == .ipv4, canonical != parts.host.lowercased() {
        add("url_obfuscated_ip", .high,
            "URL host '\(parts.host)' is an obfuscated spelling of \(canonical)", 0.82)
    }

    let labels = kind == .domain ? canonical.splitOnScalar(".") : []
    if labels.contains(where: { $0.hasScalarPrefix("xn--") }) {
        assessment.isPunycode = true
        add("url_punycode", .medium,
            "URL host '\(canonical)' uses punycode — it may not read as it renders", 0.55)
    }
    for label in labels {
        let scripts = scriptsOf(label)
        if scripts.count > 1 {
            assessment.isMixedScript = true
            add("url_mixed_script", .high,
                "URL host label '\(label)' mixes \(scripts.sorted().joined(separator: ", ")) scripts — homograph", 0.78)
            break
        }
    }

    // Length is counted in code points, as the reference implementation counts it.
    let length = raw.unicodeScalars.count
    if options.maxLength > 0, length > options.maxLength {
        add("url_length", .high, "URL is \(length) characters — long enough to be carrying a payload", 0.78)
    }

    assessment.opaqueInQuery = longestOpaqueRun(parts.query)
    assessment.opaqueInPath = longestOpaqueRun(parts.path)
    assessment.opaqueInFragment = longestOpaqueRun(parts.fragment)
    assessment.opaqueInSubdomain = labels.dropLast(2).map(longestOpaqueRun).max() ?? 0
    for (place, run, limit) in [
        ("query string", assessment.opaqueInQuery, options.maxOpaque),
        ("path", assessment.opaqueInPath, options.maxOpaque),
        ("fragment", assessment.opaqueInFragment, options.maxOpaque),
        ("subdomain", assessment.opaqueInSubdomain, options.maxOpaqueSubdomain),
    ] {
        if limit > 0, run > limit {
            add("url_opaque_payload", .high,
                "URL \(place) carries a \(run)-character opaque run — possible encoded exfiltration", 0.80)
            break
        }
    }

    return assessment
}
