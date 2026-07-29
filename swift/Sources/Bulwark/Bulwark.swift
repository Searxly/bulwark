// The high-level orchestrator: sanitize -> detect -> spotlight -> harden ->
// [your model] -> validate. Bring any model: an async ([ChatMessage]) throws -> String.

import Foundation

public struct BulwarkConfig: Sendable {
    // sanitize
    public var stripHtml: Bool?          // nil = auto-detect HTML
    public var normalizeUnicode: Bool
    public var keepEmojiVariation: Bool
    public var foldConfusables: Bool
    public var maxContentChars: Int
    // detect
    public var detectionThreshold: Double
    public var useHeuristics: Bool
    /// Recursively decode encoded payloads (Base64, hex, percent, entities,
    /// ROT13, zero-width bits …) and re-scan each layer. Runs on the raw
    /// content, before sanitization strips the invisible channels.
    public var decodeEncoded: Bool
    /// Discount findings that sit inside quoted or code-fenced passages of a
    /// document that reads as writing *about* attacks. Precision, not
    /// permission: weights drop, findings never disappear.
    public var useContext: Bool
    public var blockBeforeLlm: Severity?  // nil = never hard-block pre-LLM
    // spotlight
    public var spotlightMethods: [String]
    public var marker: String
    // prompt
    public var maxWords: Int?
    public var language: String?
    public var extraInstruction: String?
    // validate
    public var redactOutputLinks: Bool
    public var redactOutputImages: Bool
    public var blockOnOutputLeak: Bool
    /// Mark the summary unsafe when it carries a high-severity exfiltration
    /// channel. Without this a reply containing a confirmed exfiltration URL
    /// was still reported SAFE, which is the wrong headline to act on.
    public var blockOnExfiltration: Bool
    /// Check the reply against the source: hosts, URLs and addresses it
    /// mentions must appear in the document it was asked to summarize.
    public var checkGrounding: Bool
    /// The vocabulary-overlap half of grounding. Turn it off when the summary
    /// is requested in a different language than the source.
    public var checkLexicalGrounding: Bool
    /// Plant a positive control in the content and check whether the model
    /// obeyed it. Proof of compliance rather than a symptom — but it *is* an
    /// injection attempt, so a correctly-behaving model will note it. Opt-in.
    public var tripwire: Bool

    public init(
        stripHtml: Bool? = nil,
        normalizeUnicode: Bool = true,
        keepEmojiVariation: Bool = false,
        foldConfusables: Bool = true,
        maxContentChars: Int = 200_000,
        detectionThreshold: Double = 0.5,
        useHeuristics: Bool = true,
        decodeEncoded: Bool = true,
        useContext: Bool = true,
        blockBeforeLlm: Severity? = nil,
        spotlightMethods: [String] = ["delimit"],
        marker: String = defaultMarker,
        maxWords: Int? = 200,
        language: String? = nil,
        extraInstruction: String? = nil,
        redactOutputLinks: Bool = true,
        redactOutputImages: Bool = true,
        blockOnOutputLeak: Bool = true,
        blockOnExfiltration: Bool = true,
        checkGrounding: Bool = true,
        checkLexicalGrounding: Bool = true,
        tripwire: Bool = false
    ) {
        self.stripHtml = stripHtml
        self.normalizeUnicode = normalizeUnicode
        self.keepEmojiVariation = keepEmojiVariation
        self.foldConfusables = foldConfusables
        self.maxContentChars = maxContentChars
        self.detectionThreshold = detectionThreshold
        self.useHeuristics = useHeuristics
        self.decodeEncoded = decodeEncoded
        self.useContext = useContext
        self.blockBeforeLlm = blockBeforeLlm
        self.spotlightMethods = spotlightMethods
        self.marker = marker
        self.maxWords = maxWords
        self.language = language
        self.extraInstruction = extraInstruction
        self.redactOutputLinks = redactOutputLinks
        self.redactOutputImages = redactOutputImages
        self.blockOnOutputLeak = blockOnOutputLeak
        self.blockOnExfiltration = blockOnExfiltration
        self.checkGrounding = checkGrounding
        self.checkLexicalGrounding = checkLexicalGrounding
        self.tripwire = tripwire
    }

    /// Default posture: strong structural defence, never silently drops content.
    public static func balanced() -> BulwarkConfig { BulwarkConfig() }

    /// Adds data-marking and blocks the model call on CRITICAL pre-scan risk.
    public static func strict() -> BulwarkConfig {
        BulwarkConfig(detectionThreshold: 0.4, blockBeforeLlm: .critical, spotlightMethods: ["datamark", "delimit"])
    }

    /// Base64-encodes content and blocks on HIGH risk. Maximum safety, some quality cost.
    public static func paranoid() -> BulwarkConfig {
        BulwarkConfig(detectionThreshold: 0.3, blockBeforeLlm: .high,
                      spotlightMethods: ["base64", "delimit"], tripwire: true)
    }
}

public struct PreparedRequest {
    public let messages: [ChatMessage]
    public let context: PromptContext
    public let sanitize: SanitizeResult
    public let detect: DetectResult
    public let spotlight: SpotlightResult
    /// The planted positive control, when `BulwarkConfig.tripwire` is on.
    public let tripwire: Tripwire?

    public init(messages: [ChatMessage], context: PromptContext, sanitize: SanitizeResult,
                detect: DetectResult, spotlight: SpotlightResult, tripwire: Tripwire? = nil) {
        self.messages = messages
        self.context = context
        self.sanitize = sanitize
        self.detect = detect
        self.spotlight = spotlight
        self.tripwire = tripwire
    }
}

/// A model is any async closure mapping chat messages to a reply string.
public typealias Model = ([ChatMessage]) async throws -> String

public struct Bulwark {
    public let config: BulwarkConfig

    public init(config: BulwarkConfig = BulwarkConfig()) {
        self.config = config
    }

    public func sanitize(_ content: String) -> SanitizeResult {
        var working = content
        let truncated = working.count > config.maxContentChars
        if truncated { working = String(working.prefix(config.maxContentChars)) }
        var result = runSanitize(working, SanitizeOptions(
            stripHtmlContent: config.stripHtml,
            normalizeUnicode: config.normalizeUnicode,
            keepEmojiVariation: config.keepEmojiVariation
        ))
        if truncated {
            result.removed["truncated_chars"] = 1
            result.findings.append(Finding(
                stage: .sanitize, category: "truncated", severity: .info, weight: 0,
                message: "Input exceeded maxContentChars (\(config.maxContentChars)) and was truncated"
            ))
        }
        return result
    }

    /// Folded copy for the detector's second pass — leetspeak and cross-script
    /// homoglyph disguises. Detection runs primarily on the un-folded text so
    /// legitimate non-Latin scripts and multilingual signatures keep working.
    private func foldedText(_ san: SanitizeResult) -> String? {
        config.foldConfusables ? foldDetection(san.text) : nil
    }

    /// The raw content, capped. Kept un-sanitized because the decode stage needs
    /// the invisible channels that sanitization strips.
    private func truncated(_ content: String) -> String {
        String(content.prefix(config.maxContentChars))
    }

    private func runDetect(_ content: String, _ san: SanitizeResult) -> DetectResult {
        detect(san.text, options: DetectOptions(
            threshold: config.detectionThreshold,
            extraFindings: san.findings,
            useHeuristics: config.useHeuristics,
            alsoScan: foldedText(san),
            alsoDecode: config.decodeEncoded ? truncated(content) : nil,
            useContext: config.useContext
        ))
    }

    /// Sanitize + detect only — no model call. Use to gate content yourself.
    public func scan(_ content: String) -> DetectResult {
        runDetect(content, sanitize(content))
    }

    /// Sanitize, detect, spotlight and build messages — ready for any model.
    public func prepare(_ content: String) -> PreparedRequest {
        let san = sanitize(content)
        let det = runDetect(content, san)

        // The tripwire is planted after detection on purpose: it is
        // instruction-shaped, and scanning it would inflate the input's own risk
        // score with Bulwark's own text.
        let wire = config.tripwire ? makeTripwire() : nil
        let body = wire.map { plantTripwire(san.text, wire: $0) } ?? san.text

        let spot = spotlight(body, options: SpotlightOptions(methods: config.spotlightMethods, marker: config.marker))
        let (messages, context) = buildMessages(spot, options: BuildOptions(
            maxWords: config.maxWords, language: config.language, extraInstruction: config.extraInstruction
        ))
        return PreparedRequest(messages: messages, context: context, sanitize: san,
                               detect: det, spotlight: spot, tripwire: wire)
    }

    /// Validate a model reply produced from `prepare`.
    public func finalize(_ rawOutput: String, prepared: PreparedRequest) -> GuardResult {
        let val = validateOutput(rawOutput, context: prepared.context, options: ValidateOptions(
            redactLinks: config.redactOutputLinks, redactImages: config.redactOutputImages, blockOnLeak: config.blockOnOutputLeak
        ))
        return assemble(prepared.sanitize, prepared.detect, val, rawOutput, blocked: false)
    }

    /// Run the whole pipeline and return a GuardResult.
    public func summarize(_ content: String, using model: Model) async rethrows -> GuardResult {
        let prepared = prepare(content)
        if let block = config.blockBeforeLlm, prepared.detect.risk >= block {
            return assemble(prepared.sanitize, prepared.detect, nil, nil, blocked: true)
        }
        let rawOutput = try await model(prepared.messages)
        return finalize(rawOutput, prepared: prepared)
    }

    private func assemble(_ san: SanitizeResult, _ det: DetectResult, _ val: ValidationResult?, _ rawOutput: String?, blocked: Bool) -> GuardResult {
        var findings = det.findings
        if let val { findings.append(contentsOf: val.findings) }
        let riskScore = scoreFindings(findings)
        let risk = bucket(riskScore)

        // `safe` answers "is the returned summary safe to use?" — not "was the
        // input clean?". A contained injection whose output passed validation is
        // a success (status CONTAINED), still safe to use.
        let injectionDetected = det.injected
        let summary: String?
        let safe: Bool
        if blocked {
            summary = nil
            safe = false
        } else {
            summary = val?.summary
            safe = val?.safe ?? false
        }

        let status: GuardStatus = blocked ? .blocked : (!safe ? .unsafe : (injectionDetected ? .contained : .safe))
        return GuardResult(
            safe: safe, blocked: blocked, injectionDetected: injectionDetected, summary: summary,
            riskScore: riskScore, risk: risk, status: status, findings: findings,
            sanitize: san, detect: det, validation: val, rawOutput: rawOutput,
            report: formatReport(status: status, risk: risk, score: riskScore, findings: findings)
        )
    }
}

/// Sanitize then detect injection in `text` — convenience, no model call.
/// Detection runs on a folded copy so leetspeak ("1gn0r3") and homoglyph
/// disguises are caught.
public func scan(_ text: String, threshold: Double = 0.5) -> DetectResult {
    let s = sanitize(text)
    return detect(s.text, options: DetectOptions(
        threshold: threshold,
        extraFindings: s.findings,
        alsoScan: foldDetection(s.text),
        // The raw text, deliberately: channels such as zero-width bit strings
        // are removed by sanitization precisely because they are invisible, so
        // decoding the sanitized copy would find nothing.
        alsoDecode: text
    ))
}

public let bulwarkVersion = "1.1.0"
