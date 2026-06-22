// Strip invisible and structural injection vectors from untrusted text: ASCII
// smuggling (Unicode tag chars), bidi, zero-width, variation selectors, control
// chars, and CSS-hidden HTML (stack-based, handles nesting), then NFKC.
// foldConfusables handles cross-script homoglyphs on the detection copy only.

import Foundation

private let zeroWidth: Set<UInt32> = [
    0x200b, 0x200c, 0x200d, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff, 0x180e, 0x00ad,
]
private let bidiControls: Set<UInt32> = [
    0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200e, 0x200f, 0x061c,
]

private func isTag(_ cp: UInt32) -> Bool { cp >= 0xE0000 && cp <= 0xE007F }
private func isVariationSelector(_ cp: UInt32) -> Bool {
    (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF)
}
private func isControl(_ cp: UInt32) -> Bool { cp < 0x20 || cp == 0x7F || (cp >= 0x80 && cp <= 0x9F) }

// Cross-script homoglyphs → ASCII (1:1). Detection-only — never sent to a model.
private let confusables: [Character: Character] = [
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ӏ": "l", "ԁ": "d", "к": "k",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "У": "Y", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "ο": "o", "α": "a", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "ς": "c",
    "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X", "Ζ": "Z",
    "ı": "i", "․": ".",
]

/// Map cross-script homoglyphs to ASCII. Detection-only — never send to a model.
public func foldConfusables(_ text: String) -> String {
    String(text.map { confusables[$0] ?? $0 })
}

// Leetspeak / digit-substitution → ASCII letters (1:1, offsets stay aligned).
// Attackers swap letters for look-alike digits/symbols ("1gn0r3 pr3v10us") to
// dodge keyword filters while the model still reads the word. Detection-only.
private let leet: [Character: Character] = [
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
]

/// Map common leetspeak substitutions to ASCII letters. Detection-only.
public func foldLeet(_ text: String) -> String {
    String(text.map { leet[$0] ?? $0 })
}

/// Detector's second-pass copy: fold leetspeak, then cross-script homoglyphs.
/// Both are 1:1 so detection offsets stay aligned. Detection-only.
public func foldDetection(_ text: String) -> String {
    foldConfusables(foldLeet(text))
}

private let wsRegex = CompiledRegex(#"[^\S\n]+"#, options: [])
private let blanklinesRegex = CompiledRegex(#"\n{3,}"#, options: [])
private let htmlishRegex = CompiledRegex(#"<(?:/?[a-zA-Z][\w:-]*\b|!--)"#, options: [.caseInsensitive])
private let hiddenStyleRegex = CompiledRegex(#"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px|em|rem|%)?\b"#)
private let hiddenAttrRegex = CompiledRegex(#"(?:^|\s)hidden(?=[\s=>]|$)"#)
private let ariaHiddenRegex = CompiledRegex(#"aria-hidden\s*=\s*["']?true"#)

private let rawtextTags: Set<String> = ["script", "style", "noscript", "template", "svg", "math"]
private let blockTags: Set<String> = [
    "p", "div", "br", "li", "ul", "ol", "tr", "table", "section", "article",
    "header", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "hr",
]
private let voidTags: Set<String> = ["br", "img", "hr", "input", "meta", "link", "source", "area", "base", "col", "embed", "wbr"]

public func looksLikeHtml(_ text: String) -> Bool { htmlishRegex.test(text) }

struct StripResult {
    var text: String
    var counts: [String: Int]
    var findings: [Finding]
}

public func stripInvisible(_ text: String, keepEmojiVariation: Bool = false) -> (text: String, counts: [String: Int], findings: [Finding]) {
    var counts: [String: Int] = [:]
    var out = ""
    func bump(_ k: String) { counts[k, default: 0] += 1 }

    for s in text.unicodeScalars {
        let cp = s.value
        if isTag(cp) { bump("tag_chars") }
        else if bidiControls.contains(cp) { bump("bidi_controls") }
        else if isVariationSelector(cp) {
            if keepEmojiVariation && cp >= 0xFE00 && cp <= 0xFE0F { out.unicodeScalars.append(s) }
            else { bump("variation_selectors") }
        }
        else if zeroWidth.contains(cp) { bump("zero_width") }
        else if s == "\t" || s == "\n" || s == "\r" { out.unicodeScalars.append(s) }
        else if isControl(cp) { bump("control_chars") }
        else { out.unicodeScalars.append(s) }
    }

    var findings: [Finding] = []
    if let n = counts["tag_chars"] {
        findings.append(Finding(stage: .sanitize, category: "ascii_smuggling", severity: .critical, weight: 0.90,
                                message: "Removed \(n) Unicode Tag character(s) used to smuggle hidden text"))
    }
    if let n = counts["bidi_controls"] {
        findings.append(Finding(stage: .sanitize, category: "bidi_control", severity: .high, weight: 0.62,
                                message: "Removed \(n) bidirectional control character(s) (Trojan Source)"))
    }
    if let n = counts["variation_selectors"] {
        findings.append(Finding(stage: .sanitize, category: "variation_smuggling", severity: .high, weight: 0.66,
                                message: "Removed \(n) variation selector(s) (possible data smuggling)"))
    }
    if let n = counts["zero_width"] {
        findings.append(Finding(stage: .sanitize, category: "zero_width", severity: .low, weight: 0.24,
                                message: "Removed \(n) zero-width character(s) (often used to split trigger words)"))
    }
    if let n = counts["control_chars"] {
        findings.append(Finding(stage: .sanitize, category: "control_chars", severity: .low, weight: 0.15,
                                message: "Removed \(n) control character(s)"))
    }
    return (out, counts, findings)
}

private func attrsAreHidden(_ attrStr: String) -> Bool {
    hiddenAttrRegex.test(attrStr) || ariaHiddenRegex.test(attrStr) || hiddenStyleRegex.test(attrStr)
}

private func indexOf(_ hay: [Character], _ needle: [Character], _ start: Int) -> Int {
    if needle.isEmpty { return start }
    let last = hay.count - needle.count
    if last < start { return -1 }
    var i = start
    while i <= last {
        var k = 0
        while k < needle.count && hay[i + k] == needle[k] { k += 1 }
        if k == needle.count { return i }
        i += 1
    }
    return -1
}

private func tagName(_ body: String) -> String? {
    var name = ""
    for ch in body {
        if name.isEmpty {
            if ch.isASCII && ch.isLetter { name.append(ch) } else { return nil }
        } else if (ch.isASCII && (ch.isLetter || ch.isNumber)) || ch == "_" || ch == ":" || ch == "-" {
            name.append(ch)
        } else { break }
    }
    return name.isEmpty ? nil : name
}

private func findRawClose(_ chars: [Character], _ tag: String, _ from: Int) -> Int {
    let lowerTag = Array(tag.lowercased())
    let n = chars.count
    var j = from
    while j < n {
        if chars[j] == "<" {
            var k = j + 1
            if k < n && chars[k] == "/" {
                k += 1
                var t = 0
                while t < lowerTag.count && k < n && String(chars[k]).lowercased() == String(lowerTag[t]) {
                    k += 1; t += 1
                }
                if t == lowerTag.count {
                    while k < n && chars[k] == " " { k += 1 }
                    if k < n && chars[k] == ">" { return k + 1 }
                }
            }
        }
        j += 1
    }
    return n
}

public func stripHtml(_ text: String) -> (text: String, counts: [String: Int], findings: [Finding]) {
    let chars = Array(text)
    let n = chars.count
    var i = 0
    var out = ""
    var stack: [(tag: String, hidden: Bool)] = []
    var skipDepth = 0
    var comments = 0
    var scriptStyle = 0
    var hiddenElements = 0

    func emit(_ s: String) { if skipDepth == 0 { out += s } }
    func matchesAt(_ needle: [Character], _ at: Int) -> Bool {
        if at + needle.count > n { return false }
        for k in 0..<needle.count where chars[at + k] != needle[k] { return false }
        return true
    }

    while i < n {
        let lt = indexOf(chars, ["<"], i)
        if lt == -1 { emit(String(chars[i...])); break }
        if lt > i { emit(String(chars[i..<lt])) }

        if matchesAt(["<", "!", "-", "-"], lt) {
            let end = indexOf(chars, ["-", "-", ">"], lt + 4)
            comments += 1
            i = end == -1 ? n : end + 3
            continue
        }
        if matchesAt(["<", "!"], lt) {
            let end = indexOf(chars, [">"], lt + 2)
            i = end == -1 ? n : end + 1
            continue
        }

        let gt = indexOf(chars, [">"], lt + 1)
        if gt == -1 { emit(String(chars[lt...])); break }
        var body = String(chars[(lt + 1)..<gt])
        i = gt + 1

        var isEnd = false
        if body.hasPrefix("/") { isEnd = true; body.removeFirst() }
        var selfClose = false
        if body.hasSuffix("/") { selfClose = true; body.removeLast() }

        guard let name = tagName(body) else { continue }
        let tag = name.lowercased()
        let attrStr = String(body.dropFirst(name.count))

        if isEnd {
            var s = stack.count - 1
            while s >= 0 {
                if stack[s].tag == tag {
                    if stack[s].hidden && skipDepth > 0 { skipDepth -= 1 }
                    stack.removeLast(stack.count - s)
                    break
                }
                s -= 1
            }
            if blockTags.contains(tag) { out += "\n" }
            continue
        }

        if rawtextTags.contains(tag) {
            scriptStyle += 1
            i = findRawClose(chars, tag, i)
            continue
        }

        let hidden = attrsAreHidden(attrStr)
        if !voidTags.contains(tag) && !selfClose {
            stack.append((tag, hidden))
            if hidden { hiddenElements += 1; skipDepth += 1 }
        }
        if blockTags.contains(tag) { out += "\n" }
    }

    var counts: [String: Int] = [:]
    var findings: [Finding] = []
    if comments > 0 { counts["html_comments"] = comments }
    if scriptStyle > 0 { counts["script_style"] = scriptStyle }
    if hiddenElements > 0 {
        counts["hidden_elements"] = hiddenElements
        findings.append(Finding(stage: .sanitize, category: "hidden_html", severity: .medium, weight: 0.55,
                                message: "Removed \(hiddenElements) visually hidden HTML element(s) (text invisible to humans)"))
    }
    return (unescapeHtml(out), counts, findings)
}

public func normalize(_ text: String) -> String {
    var t = text.precomposedStringWithCompatibilityMapping  // NFKC
    t = wsRegex.replaceAll(t, with: " ")
    t = t.split(separator: "\n", omittingEmptySubsequences: false)
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .joined(separator: "\n")
    t = blanklinesRegex.replaceAll(t, with: "\n\n")
    return t.trimmingCharacters(in: .whitespacesAndNewlines)
}

public struct SanitizeOptions {
    public var stripHtmlContent: Bool?   // nil = auto
    public var normalizeUnicode: Bool
    public var keepEmojiVariation: Bool

    public init(stripHtmlContent: Bool? = nil, normalizeUnicode: Bool = true, keepEmojiVariation: Bool = false) {
        self.stripHtmlContent = stripHtmlContent
        self.normalizeUnicode = normalizeUnicode
        self.keepEmojiVariation = keepEmojiVariation
    }
}

public func sanitize(_ text: String, options: SanitizeOptions = SanitizeOptions()) -> SanitizeResult {
    runSanitize(text, options)
}

// Implementation under a distinct name so `Bulwark.sanitize(_:)` (the instance
// method) can call it without name-shadowing the public free function.
func runSanitize(_ text: String, _ options: SanitizeOptions) -> SanitizeResult {
    let originalLength = text.count
    var removed: [String: Int] = [:]
    var findings: [Finding] = []

    let doHtml = options.stripHtmlContent ?? looksLikeHtml(text)
    var working = text
    if doHtml {
        let r = stripHtml(working)
        working = r.text
        for (k, v) in r.counts { removed[k, default: 0] += v }
        findings.append(contentsOf: r.findings)
    }

    let inv = stripInvisible(working, keepEmojiVariation: options.keepEmojiVariation)
    working = inv.text
    for (k, v) in inv.counts { removed[k, default: 0] += v }
    findings.append(contentsOf: inv.findings)

    working = options.normalizeUnicode ? normalize(working) : wsRegex.replaceAll(working, with: " ").trimmingCharacters(in: .whitespacesAndNewlines)

    return SanitizeResult(text: working, originalLength: originalLength, cleanedLength: working.count,
                          removed: removed, findings: findings)
}

private let decEntityRegex = CompiledRegex(#"&#(\d+);"#, options: [])
private let hexEntityRegex = CompiledRegex(#"&#x([0-9a-fA-F]+);"#, options: [])

func unescapeHtml(_ s: String) -> String {
    var t = s
    // Numeric entities first.
    t = replaceEntities(t, decEntityRegex, radix: 10)
    t = replaceEntities(t, hexEntityRegex, radix: 16)
    let named: [(String, String)] = [
        ("&#39;", "'"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""),
        ("&apos;", "'"), ("&nbsp;", " "), ("&amp;", "&"),
    ]
    for (k, v) in named { t = t.replacingOccurrences(of: k, with: v) }
    return t
}

private func replaceEntities(_ text: String, _ regex: CompiledRegex, radix: Int) -> String {
    let matches = regex.allMatches(text)
    guard !matches.isEmpty else { return text }
    let ns = text as NSString
    var result = ""
    var last = 0
    for m in matches {
        result += ns.substring(with: NSRange(location: last, length: m.range.location - last))
        if let digits = m.group(1, in: text), let code = UInt32(digits, radix: radix), let scalar = Unicode.Scalar(code) {
            result.unicodeScalars.append(scalar)
        } else {
            result += ns.substring(with: m.range)
        }
        last = m.range.location + m.range.length
    }
    result += ns.substring(with: NSRange(location: last, length: ns.length - last))
    return result
}
