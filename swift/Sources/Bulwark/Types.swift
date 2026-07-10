// Core data types shared across Bulwark's pipeline stages.

import Foundation

public enum Severity: String, Comparable, Sendable, CaseIterable {
    case info, low, medium, high, critical

    public var rank: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }
}

public enum Stage: String, Sendable {
    case sanitize, detect, validate, tool
}

public struct Finding: Sendable {
    public let stage: Stage
    public let category: String
    public let severity: Severity
    public let message: String
    public let weight: Double
    public let excerpt: String?
    public let patternId: String?

    public init(
        stage: Stage,
        category: String,
        severity: Severity,
        weight: Double,
        message: String,
        excerpt: String? = nil,
        patternId: String? = nil
    ) {
        self.stage = stage
        self.category = category
        self.severity = severity
        self.message = message
        self.weight = weight
        self.excerpt = excerpt
        self.patternId = patternId
    }
}

public struct SanitizeResult: Sendable {
    public var text: String
    public let originalLength: Int
    public var cleanedLength: Int
    public var removed: [String: Int]
    public var findings: [Finding]
}

public struct DetectResult: Sendable {
    public let score: Double
    public let risk: Severity
    public let injected: Bool
    public let threshold: Double
    public let findings: [Finding]
}

public struct SpotlightResult: Sendable {
    public let content: String
    public let nonce: String
    public let methods: [String]
    public let marker: String?
    public let base64Encoded: Bool
}

public struct PromptContext: Sendable {
    public let canary: String
    public let nonce: String
    public let marker: String?
    public let base64Encoded: Bool

    public init(canary: String, nonce: String, marker: String? = nil, base64Encoded: Bool = false) {
        self.canary = canary
        self.nonce = nonce
        self.marker = marker
        self.base64Encoded = base64Encoded
    }
}

public struct ValidationResult: Sendable {
    public let safe: Bool
    public let summary: String
    public let redacted: Bool
    public let findings: [Finding]
}

public struct ChatMessage: Sendable {
    public let role: String
    public let content: String

    public init(role: String, content: String) {
        self.role = role
        self.content = content
    }
}

public enum GuardStatus: String, Sendable {
    case blocked = "BLOCKED"
    case unsafe = "UNSAFE"
    case contained = "CONTAINED"
    case safe = "SAFE"
}

public struct GuardResult: Sendable {
    public let safe: Bool
    public let blocked: Bool
    /// True if an injection attempt was detected in the input (independent of `safe`).
    public let injectionDetected: Bool
    public let summary: String?
    public let riskScore: Double
    public let risk: Severity
    public let status: GuardStatus
    public let findings: [Finding]
    public let sanitize: SanitizeResult?
    public let detect: DetectResult?
    public let validation: ValidationResult?
    public let rawOutput: String?
    /// Human-readable explanation of what happened.
    public let report: String
}

/// Render a short human-readable report for a guard result.
public func formatReport(status: GuardStatus, risk: Severity, score: Double, findings: [Finding]) -> String {
    var lines: [String] = []
    lines.append("Bulwark: \(status.rawValue)  (risk=\(risk.rawValue), score=\(String(format: "%.2f", score)))")
    if findings.isEmpty {
        lines.append("  No injection signals detected.")
    } else {
        lines.append("  \(findings.count) finding(s):")
        let sorted = findings.sorted { $0.severity.rank > $1.severity.rank }
        for f in sorted.prefix(12) {
            let excerpt = f.excerpt.map { " — \"\($0)\"" } ?? ""
            let sev = f.severity.rawValue.leftPadded(to: 8)
            lines.append("    [\(sev)] \(f.stage.rawValue)/\(f.category): \(f.message)\(excerpt)")
        }
        if sorted.count > 12 {
            lines.append("    … and \(sorted.count - 12) more")
        }
    }
    return lines.joined(separator: "\n")
}

extension String {
    func leftPadded(to width: Int) -> String {
        count >= width ? self : String(repeating: " ", count: width - count) + self
    }
}
