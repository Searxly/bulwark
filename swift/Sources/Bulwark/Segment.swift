// Locate an injection inside a document instead of judging the whole thing.
//
// A page-level verdict forces a bad choice. "This 4,000-word article contains an injection" leaves
// you blocking the article — and the attacker, who only had to add one poisoned sentence to a page
// you wanted, has denied you the content. Do that a few times and the operator turns the guard off,
// which is the attack working perfectly.
//
// Segment analysis scores each passage on its own, so the answer becomes "the injection is in
// paragraph 7, and paragraphs 1-6 and 8-40 are clean". From there `neutralizeSegments` excises just
// the poisoned passages and hands the model a document that is still worth summarizing. The
// attacker loses their payload and keeps none of their leverage.
//
// The report also yields a **contamination ratio** — how much of the document is hostile. A page
// that is 2% injection is a normal page someone poisoned; a page that is 80% injection is an attack
// wearing a page as a costume, and callers may reasonably treat the two differently.

import Foundation

// MARK: - Budget

/// Segmentation budget. Detection is ~70 regexes per segment, so an unbounded split over a large
/// document multiplies the scan cost by the segment count.
public let maxSegments = 250

/// Runs shorter than this merge into their neighbour, so a one-word line never becomes a segment.
public let minSegmentChars = 40

/// Paragraphs above this length are broken down into sentences.
public let longSegmentChars = 1_200

public let defaultSegmentPlaceholder =
    "[removed: passage containing instructions addressed to the assistant]"

// MARK: - Patterns
//
// Dialect notes, because these are not a mechanical transliteration of the reference:
//
//   * The reference compiles these without flags. `CompiledRegex` defaults to
//     `.caseInsensitive` and `.anchorsMatchLines`, so every pattern here passes `[]` explicitly.
//     Neither flag would change these particular patterns, but relying on that is a trap for the
//     next person to edit one.
//   * The reference's sentence splitter writes the lookahead as `(?=[^\s])`. Python's `\s` is the
//     Unicode whitespace set — `\p{Z}` plus the C0 separators U+0009–U+000D and U+001C–U+001F and
//     U+0085 — whereas ICU's `\s` is only `[\t\n\f\r\p{Z}]`. It is spelled out below so that a
//     vertical tab or a NEL after the sentence break is treated as whitespace in both languages.

private let paragraphSplitRegex = CompiledRegex(#"\n[ \t]*\n"#, options: [])

private let sentenceSplitRegex = CompiledRegex(
    #"(?<=[.!?。！？])[ \t]+(?=[^ \t\n\x{0B}\f\r\x{1C}-\x{1F}\x{85}\p{Z}])|\n"#,
    options: []
)

private let blankRunRegex = CompiledRegex(#"\n{3,}"#, options: [])

/// Python's `str.isspace()` set, used for `str.strip()`. `CharacterSet.whitespacesAndNewlines`
/// covers `\p{Z}`, U+0009–U+000D and U+0085 but omits the four C0 separators, which Python counts.
///
/// It also *adds* one Python does not: U+200B ZERO WIDTH SPACE, which Foundation still treats as
/// whitespace even though Unicode reclassified it as `Cf` (format), so `str.isspace()` is False.
/// Removing it is not pedantry. This set decides which spans survive as segments, and a passage
/// built entirely from zero-width characters is a smuggling channel, not blank space — leaving
/// U+200B in would make the port silently discard exactly the passage a caller most wants scored.
private let pythonWhitespace = CharacterSet.whitespacesAndNewlines
    .union(CharacterSet(charactersIn: "\u{1C}\u{1D}\u{1E}\u{1F}"))
    .subtracting(CharacterSet(charactersIn: "\u{200B}"))

// MARK: - Types

/// One passage of the document, scored on its own.
public struct Segment: Sendable {
    public let text: String
    /// Half-open offsets into the source text, measured in **Unicode scalars** — see `ScalarText`.
    public let start: Int
    public let end: Int
    public let score: Double
    public let risk: Severity
    public let injected: Bool
    public let findings: [Finding]

    public init(
        text: String,
        start: Int,
        end: Int,
        score: Double,
        risk: Severity,
        injected: Bool,
        findings: [Finding] = []
    ) {
        self.text = text
        self.start = start
        self.end = end
        self.score = score
        self.risk = risk
        self.injected = injected
        self.findings = findings
    }

    public var length: Int { end - start }
}

/// Where the injection is, and how much of the document it occupies.
public struct SegmentReport: Sendable {
    public let segments: [Segment]
    /// Share of the characters that sit inside injected segments.
    public let contamination: Double
    public let injectedCount: Int
    public let worst: Segment?

    public init(
        segments: [Segment],
        contamination: Double,
        injectedCount: Int,
        worst: Segment? = nil
    ) {
        self.segments = segments
        self.contamination = contamination
        self.injectedCount = injectedCount
        self.worst = worst
    }

    public var clean: Bool { injectedCount == 0 }

    public var injectedSegments: [Segment] { segments.filter(\.injected) }

    public var summary: String {
        if clean { return "\(segments.count) segment(s), none flagged" }
        let percent = String(format: "%.0f", contamination * 100)
        return "\(injectedCount)/\(segments.count) segment(s) flagged, \(percent)% of the text by length"
    }
}

// MARK: - Coordinate system

/// The source text in the coordinate system this module works in: **Unicode scalars**.
///
/// Not `Character`s and not UTF-16 code units. The reference indexes Python strings, which are
/// sequences of code points, so scalars are what reproduce its offsets; Swift's `Character` is a
/// grapheme cluster, and a single combining mark would collapse two scalars into one and drift
/// every offset after it. `NSRegularExpression`, meanwhile, reports UTF-16 ranges, so an emoji
/// would advance offsets by two. Translating once, here, keeps the whole module in one system and
/// keeps `text[segment.start..<segment.end] == segment.text` true for both.
private struct ScalarText {
    let source: String
    let scalars: [Unicode.Scalar]
    /// UTF-16 offset → scalar offset, with one trailing entry for the end of the string.
    private let scalarForUTF16: [Int]
    /// Scalar offset → UTF-16 offset, likewise with a trailing entry.
    private let utf16ForScalar: [Int]

    init(_ text: String) {
        source = text
        let utf16Count = (text as NSString).length
        var scalars: [Unicode.Scalar] = []
        scalars.reserveCapacity(utf16Count)
        var forward = [Int](repeating: 0, count: utf16Count + 1)
        var backward: [Int] = []
        backward.reserveCapacity(utf16Count + 1)

        var unit = 0
        for value in text.unicodeScalars {
            backward.append(unit)
            for _ in 0..<UTF16.width(value) {
                forward[unit] = scalars.count
                unit += 1
            }
            scalars.append(value)
        }
        forward[utf16Count] = scalars.count
        backward.append(utf16Count)

        self.scalars = scalars
        scalarForUTF16 = forward
        utf16ForScalar = backward
    }

    var count: Int { scalars.count }

    func slice(_ start: Int, _ end: Int) -> String {
        String(String.UnicodeScalarView(scalars[start..<end]))
    }

    func scalarOffset(utf16 offset: Int) -> Int { scalarForUTF16[offset] }

    func utf16Range(_ start: Int, _ end: Int) -> NSRange {
        let lower = utf16ForScalar[start]
        return NSRange(location: lower, length: utf16ForScalar[end] - lower)
    }

    /// True if the half-open span holds anything Python's `str.strip()` would not strip.
    func hasContent(_ start: Int, _ end: Int) -> Bool {
        scalars[start..<end].contains { !pythonWhitespace.contains($0) }
    }
}

/// Python's `str.strip()`.
private func pythonStrip(_ text: String) -> String {
    let scalars = Array(text.unicodeScalars)
    var lower = 0
    var upper = scalars.count
    while lower < upper, pythonWhitespace.contains(scalars[lower]) { lower += 1 }
    while upper > lower, pythonWhitespace.contains(scalars[upper - 1]) { upper -= 1 }
    return String(String.UnicodeScalarView(scalars[lower..<upper]))
}

/// Python's `round(value, 4)`: four decimal places, halves to even.
///
/// Scaling by 10_000 and rounding is the obvious spelling and the wrong one. Python rounds the
/// *exact* binary value of the double, but the scaling multiply is itself rounded, which throws
/// away the sub-ulp information that decides the tie. `1/160` is stored a hair above 0.00625, so
/// Python gives 0.0063 while `0.00625 * 10_000` lands on exactly 62.5 and halves-to-even down to
/// 0.0062; `3/160` is stored a hair below and the two disagree in the other direction. Formatting
/// with `%.4f` rounds the exact value, half-to-even, which is precisely Python's rule.
private func roundTo4(_ value: Double) -> Double {
    Double(String(format: "%.4f", value)) ?? value
}

// MARK: - Segmentation

/// Split into paragraph spans, breaking overlong paragraphs into sentences and merging runts,
/// keeping every offset exact against the original text.
private func segmentSpans(_ text: ScalarText) -> [(start: Int, end: Int)] {
    let length = text.count
    if length == 0 { return [] }

    var raw: [(start: Int, end: Int)] = []
    var cursor = 0
    for match in paragraphSplitRegex.allMatches(text.source) {
        let start = text.scalarOffset(utf16: match.range.location)
        let end = text.scalarOffset(utf16: match.range.location + match.range.length)
        if start > cursor { raw.append((cursor, start)) }
        cursor = end
    }
    if cursor < length { raw.append((cursor, length)) }
    if raw.isEmpty { raw = [(0, length)] }

    // Break paragraphs that are long enough to hide a payload in a corner.
    var split: [(start: Int, end: Int)] = []
    for paragraph in raw {
        if paragraph.end - paragraph.start <= longSegmentChars {
            split.append(paragraph)
            continue
        }
        var pieceStart = paragraph.start
        // The reference calls `finditer(text, start, end)`, which narrows the search window
        // without slicing the string, so a lookbehind can still see the character before `start`.
        // `.withTransparentBounds` is ICU's spelling of that. (ICU also lets the *lookahead* read
        // past the window end, where Python's `endpos` would not, but a window only ever ends at a
        // paragraph break or at end-of-text, and `(?=[^\s])` fails under either reading there.)
        let window = text.utf16Range(paragraph.start, paragraph.end)
        for match in sentenceSplitRegex.re.matches(in: text.source, options: [.withTransparentBounds], range: window) {
            let matchStart = text.scalarOffset(utf16: match.range.location)
            let matchEnd = text.scalarOffset(utf16: match.range.location + match.range.length)
            if matchEnd > pieceStart {
                split.append((pieceStart, matchStart))
                pieceStart = matchEnd
            }
        }
        if pieceStart < paragraph.end { split.append((pieceStart, paragraph.end)) }
    }

    // Merge runts forward so a one-word line doesn't become its own segment.
    var merged: [(start: Int, end: Int)] = []
    for piece in split {
        if !merged.isEmpty, piece.end - piece.start < minSegmentChars {
            merged[merged.count - 1].end = piece.end
        } else {
            merged.append(piece)
        }
    }

    // Enforce the budget by fusing neighbours evenly rather than dropping tail segments — losing
    // the end of a document is exactly where a payload hides.
    while merged.count > maxSegments {
        var fused: [(start: Int, end: Int)] = []
        fused.reserveCapacity((merged.count + 1) / 2)
        var i = 0
        while i < merged.count {
            fused.append((merged[i].start, merged[min(i + 1, merged.count - 1)].end))
            i += 2
        }
        merged = fused
    }

    return merged.filter { text.hasContent($0.start, $0.end) }
}

// MARK: - Public API

/// Score every passage of `text` independently.
///
/// `useHeuristics` defaults to `false` here on purpose: the density heuristics measure a property
/// of a whole document (what fraction of its lines are imperative), and applying them to a
/// three-line segment turns any short instruction list into a hit.
public func analyzeSegments(
    _ text: String,
    threshold: Double = 0.5,
    useHeuristics: Bool = false,
    fold: Bool = true
) -> SegmentReport {
    let source = ScalarText(text)
    var segments: [Segment] = []
    var contaminatedChars = 0

    for span in segmentSpans(source) {
        let piece = source.slice(span.start, span.end)
        let result = detect(piece, options: DetectOptions(
            threshold: threshold,
            useHeuristics: useHeuristics,
            alsoScan: fold ? foldDetection(piece) : nil
        ))
        let segment = Segment(
            text: piece,
            start: span.start,
            end: span.end,
            score: result.score,
            risk: result.risk,
            injected: result.injected,
            findings: result.findings
        )
        segments.append(segment)
        if segment.injected { contaminatedChars += segment.length }
    }

    let total = segments.reduce(0) { $0 + $1.length }
    return SegmentReport(
        segments: segments,
        contamination: roundTo4(Double(contaminatedChars) / Double(total == 0 ? 1 : total)),
        injectedCount: segments.lazy.filter(\.injected).count,
        // `max(by:)` keeps the first of equal elements, as Python's `max` does.
        worst: segments.max { $0.score < $1.score }
    )
}

/// Excise the flagged passages, keeping the rest of the document intact.
///
/// Returns the neutralized text and how many passages were removed.
///
/// When contamination exceeds `maxContamination` nothing is excised and the text is returned
/// unchanged: at that point the document *is* the attack, and quietly handing back the 20%
/// remainder would misrepresent it as a cleaned version of something real. Callers should block
/// instead — which they can see from the report.
public func neutralizeSegments(
    _ text: String,
    report: SegmentReport? = nil,
    threshold: Double = 0.5,
    placeholder: String = defaultSegmentPlaceholder,
    maxContamination: Double = 0.75
) -> (text: String, removed: Int) {
    let report = report ?? analyzeSegments(text, threshold: threshold)
    if report.clean || report.contamination > maxContamination { return (text, 0) }

    let source = ScalarText(text)
    var out = ""
    var cursor = 0
    var removed = 0
    for segment in report.segments where segment.injected {
        out += source.slice(cursor, segment.start)
        out += placeholder
        cursor = segment.end
        removed += 1
    }
    out += source.slice(cursor, source.count)

    // Collapse the blank space left behind by an excised paragraph.
    return (pythonStrip(blankRunRegex.replaceAll(out, with: "\n\n")), removed)
}
