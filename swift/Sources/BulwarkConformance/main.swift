// Conformance driver — Swift.
//
// Reads the merged corpus JSONL on stdin, writes one result object per line.
// The shape must match tools/drivers/scan_py.py exactly; tools/conformance.py
// diffs the three implementations.
//
//   swift build -c release --product bulwark-conformance
//   .build/release/bulwark-conformance < corpus/corpus.jsonl

import Foundation
import Bulwark

let threshold = 0.5

/// Hand-rolled, key-sorted JSON so the three drivers emit comparable text.
/// JSONSerialization would do it, but not with a guaranteed key order.
func jsonString(_ s: String) -> String {
    var out = "\""
    for scalar in s.unicodeScalars {
        switch scalar {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if scalar.value < 0x20 {
                out += String(format: "\\u%04x", scalar.value)
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
    }
    return out + "\""
}

func jsonArray(_ items: [String]) -> String {
    "[" + items.map(jsonString).joined(separator: ",") + "]"
}

func resultLine(id: String, text: String) -> String {
    let san = sanitize(text)
    let det = detect(san.text, options: DetectOptions(
        threshold: threshold,
        extraFindings: san.findings,
        alsoScan: foldDetection(san.text)
    ))
    let patterns = Array(Set(det.findings.compactMap { $0.patternId })).sorted()
    let categories = Array(Set(det.findings.map { $0.category })).sorted()
    // Match Python's round(x, 4) — banker's rounding is not in play at 4dp for
    // these magnitudes, so a plain half-up round agrees.
    let score = (det.score * 1e4).rounded() / 1e4

    // Keys emitted in sorted order: categories, id, injected, patterns, risk, score, sanitized_len
    var parts: [String] = []
    parts.append("\"categories\":" + jsonArray(categories))
    parts.append("\"id\":" + jsonString(id))
    parts.append("\"injected\":" + (det.injected ? "true" : "false"))
    parts.append("\"patterns\":" + jsonArray(patterns))
    parts.append("\"risk\":" + jsonString(det.risk.rawValue))
    parts.append("\"score\":" + String(format: "%g", score))
    parts.append("\"sanitized_len\":\(san.text.unicodeScalars.count)")
    return "{" + parts.joined(separator: ",") + "}"
}

let data = FileHandle.standardInput.readDataToEndOfFile()
guard let input = String(data: data, encoding: .utf8) else {
    FileHandle.standardError.write("stdin was not valid UTF-8\n".data(using: .utf8)!)
    exit(2)
}

var out = ""
for line in input.split(separator: "\n", omittingEmptySubsequences: true) {
    guard let lineData = line.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any],
          let id = obj["id"] as? String,
          let text = obj["text"] as? String
    else {
        FileHandle.standardError.write("skipping unparseable corpus line\n".data(using: .utf8)!)
        continue
    }
    out += resultLine(id: id, text: text) + "\n"
}
FileHandle.standardOutput.write(out.data(using: .utf8)!)
