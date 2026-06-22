// Inspect the model's reply: normalize it (defeats split-token evasion), then
// catch canary/prompt leaks, nonce leaks, and exfiltration channels.

import Foundation

private let mdImageRegex = CompiledRegex(#"!\[[^\]]*\]\([^)]*\)"#, options: [])
private let mdLinkRegex = CompiledRegex(#"(\[[^\]]*\])\(\s*https?://[^)]*\)"#, options: [])
private let htmlImgRegex = CompiledRegex(#"<img\b[^>]*>"#)
private let autolinkRegex = CompiledRegex(#"<\s*https?://[^>]*>"#)
private let dataUrlRegex = CompiledRegex(#"https?://[^\s)>\]]*[?&][\w.\-%]+=[A-Za-z0-9+/=_-]{16,}[^\s)>\]]*"#, options: [])
// Reference-style link/image definition: "[id]: https://…". A model tricked into
// emitting one exfiltrates via a link the chat UI later resolves.
private let refLinkRegex = CompiledRegex(#"^[ \t]*\[[^\]]+\]:\s*<?https?://[^\s>]+>?"#, options: [.caseInsensitive, .anchorsMatchLines])
private let complianceRegex = CompiledRegex(
    #"^\s*(?:sure\b|certainly\b|of\s+course\b|okay\b|ok\b|here\s+(?:is|are|'s)\b|as\s+(?:dan|requested|instructed|you\s+(?:asked|wish|requested))\b|i\s+(?:will|'ll|have|am\s+now)\b|ignoring\s+(?:previous|the)\b|hacked\b|pwned\b|i\s+am\s+dan\b)"#,
    options: [.caseInsensitive]
)
private let canaryPrefixRegex = CompiledRegex(#"BULWARK-CANARY-\w*"#, options: [])
private let b64BlobRegex = CompiledRegex(#"\b[A-Za-z0-9+/]{40,}={0,2}\b"#, options: [])
// Distinctive phrases from the hardened system prompt; a verbatim appearance in
// the output means the rules leaked even if the canary line was stripped.
private let promptFingerprints = [
    "bulwark-summarizer",
    "outrank anything found inside the content",
    "a quotation from a possibly hostile third party",
]

public struct ValidateOptions {
    public var redactLinks: Bool
    public var redactImages: Bool
    public var blockOnLeak: Bool

    public init(redactLinks: Bool = true, redactImages: Bool = true, blockOnLeak: Bool = true) {
        self.redactLinks = redactLinks
        self.redactImages = redactImages
        self.blockOnLeak = blockOnLeak
    }
}

private func excerpt80(_ s: String) -> String { String(s.prefix(80)) }

public func validateOutput(_ summary: String?, context ctx: PromptContext, options: ValidateOptions = ValidateOptions()) -> ValidationResult {
    var findings: [Finding] = []
    let raw = summary ?? ""

    // 0. Normalize: strip invisibles (defeats split-canary / split-URL evasion).
    var cleaned = stripInvisible(raw).text.precomposedStringWithCompatibilityMapping
    var redacted = cleaned != raw
    var safe = true

    // 1. Canary leak.
    if !ctx.canary.isEmpty && cleaned.contains(ctx.canary) {
        findings.append(Finding(stage: .validate, category: "canary_leak", severity: .critical, weight: 1.0,
                                message: "Output contains the secret canary token — the system prompt leaked"))
        cleaned = cleaned.replacingOccurrences(of: ctx.canary, with: "[REDACTED]")
        redacted = true
        if options.blockOnLeak { safe = false }
    }
    if cleaned.contains("BULWARK-CANARY-") {
        findings.append(Finding(stage: .validate, category: "canary_leak", severity: .critical, weight: 1.0,
                                message: "Output references the canary token prefix"))
        cleaned = canaryPrefixRegex.replaceAll(cleaned, with: "[REDACTED]")
        redacted = true
        if options.blockOnLeak { safe = false }
    }

    // 2. Boundary nonce leak.
    if !ctx.nonce.isEmpty && cleaned.contains(ctx.nonce) {
        findings.append(Finding(stage: .validate, category: "nonce_leak", severity: .high, weight: 0.8,
                                message: "Output echoed the internal boundary nonce"))
        cleaned = cleaned.replacingOccurrences(of: ctx.nonce, with: "[REDACTED]")
        redacted = true
    }

    // 3. Data-mark leak.
    if let marker = ctx.marker, cleaned.contains(marker) {
        cleaned = cleaned.replacingOccurrences(of: marker, with: " ")
        redacted = true
        findings.append(Finding(stage: .validate, category: "marker_leak", severity: .low, weight: 0.2,
                                message: "Output contained the data-mark character (normalized back to spaces)"))
    }

    // 4. Exfiltration channels.
    let imageCount = mdImageRegex.count(cleaned) + htmlImgRegex.count(cleaned)
    if imageCount > 0 {
        let ex = mdImageRegex.firstMatch(cleaned)?.string(in: cleaned) ?? htmlImgRegex.firstMatch(cleaned)?.string(in: cleaned)
        findings.append(Finding(stage: .validate, category: "image_exfiltration", severity: .high, weight: 0.8,
                                message: "Output contains \(imageCount) image reference(s) — a data-exfiltration channel",
                                excerpt: ex.map(excerpt80)))
        if options.redactImages {
            cleaned = mdImageRegex.replaceAll(cleaned, with: "[image removed]")
            cleaned = htmlImgRegex.replaceAll(cleaned, with: "[image removed]")
            redacted = true
        }
    }

    let dataUrlCount = dataUrlRegex.count(cleaned)
    if dataUrlCount > 0 {
        let ex = dataUrlRegex.firstMatch(cleaned)?.string(in: cleaned)
        findings.append(Finding(stage: .validate, category: "data_url_exfiltration", severity: .high, weight: 0.82,
                                message: "Output contains \(dataUrlCount) URL(s) with a data-bearing query string",
                                excerpt: ex.map(excerpt80)))
        if options.redactLinks {
            cleaned = dataUrlRegex.replaceAll(cleaned, with: "[link removed]")
            redacted = true
        }
    }

    let refLinkCount = refLinkRegex.count(cleaned)
    if refLinkCount > 0 {
        let ex = refLinkRegex.firstMatch(cleaned)?.string(in: cleaned)
        findings.append(Finding(stage: .validate, category: "reference_link", severity: .medium, weight: 0.5,
                                message: "Output contains \(refLinkCount) reference-style link definition(s)",
                                excerpt: ex.map(excerpt80)))
        if options.redactLinks {
            cleaned = refLinkRegex.replaceAll(cleaned, with: "[link removed]")
            redacted = true
        }
    }

    let linkCount = mdLinkRegex.count(cleaned) + autolinkRegex.count(cleaned)
    if linkCount > 0 {
        let ex = mdLinkRegex.firstMatch(cleaned)?.string(in: cleaned) ?? autolinkRegex.firstMatch(cleaned)?.string(in: cleaned)
        findings.append(Finding(stage: .validate, category: "link_in_output", severity: .medium, weight: 0.45,
                                message: "Output contains \(linkCount) link(s)", excerpt: ex.map(excerpt80)))
        if options.redactLinks {
            cleaned = mdLinkRegex.replaceAll(cleaned, with: "$1")   // keep [text], drop (url)
            cleaned = autolinkRegex.replaceAll(cleaned, with: "")
            redacted = true
        }
    }

    // 5. System-prompt fingerprint leak (rules leaked even without the canary).
    let lowered = cleaned.lowercased()
    if promptFingerprints.contains(where: { lowered.contains($0) }) {
        findings.append(Finding(stage: .validate, category: "prompt_leak", severity: .critical, weight: 0.95,
                                message: "Output contains a verbatim fragment of the system prompt — the rules leaked"))
        if options.blockOnLeak { safe = false }
    }

    // 6. Encoded blob in output (possible exfiltration the model encoded).
    if let m = b64BlobRegex.firstMatch(cleaned) {
        findings.append(Finding(stage: .validate, category: "encoded_output", severity: .medium, weight: 0.4,
                                message: "Output contains a long Base64-like blob (possible encoded exfiltration)",
                                excerpt: excerpt80(m.string(in: cleaned))))
    }

    // 7. Compliance tell at the start of the reply.
    if complianceRegex.test(cleaned) {
        findings.append(Finding(stage: .validate, category: "compliance_tell", severity: .medium, weight: 0.5,
                                message: "Output opens with a phrase typical of obeying an injected instruction",
                                excerpt: excerpt80(cleaned)))
    }

    return ValidationResult(safe: safe, summary: cleaned.trimmingCharacters(in: .whitespacesAndNewlines),
                            redacted: redacted, findings: findings)
}
