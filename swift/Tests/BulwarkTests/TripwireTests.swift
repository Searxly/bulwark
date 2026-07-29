// Tripwire: a positive control that proves whether the model obeyed content.

import XCTest
import Foundation
@testable import Bulwark

final class TripwireTests: XCTestCase {

    func testTokensAreUniquePerRequest() {
        let tokens = Set((0..<50).map { _ in makeTripwire().token })
        XCTAssertEqual(tokens.count, 50, "a reused token is one an attacker can pre-emptively echo")
    }

    func testSentenceCarriesTheToken() {
        let wire = makeTripwire()
        XCTAssertTrue(wire.sentence.contains(wire.token))
    }

    func testPlantAppendsAfterTheContent() {
        let wire = makeTripwire()
        let planted = plantTripwire("The council approved the transit plan.", wire: wire)
        XCTAssertTrue(planted.hasPrefix("The council approved the transit plan."))
        XCTAssertTrue(planted.hasSuffix(wire.sentence))
    }

    func testPlantHandlesEmptyContent() {
        let wire = makeTripwire()
        XCTAssertEqual(plantTripwire("", wire: wire), wire.sentence)
    }

    // MARK: - firing

    func testEchoingTheTokenIsACriticalFinding() {
        let wire = makeTripwire()
        let findings = checkTripwire("The council approved the plan. \(wire.token)", wire: wire)
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings[0].category, "tripwire_tripped")
        XCTAssertEqual(findings[0].severity, .critical)
        XCTAssertEqual(findings[0].stage, .validate)
        XCTAssertEqual(findings[0].weight, 0.95, accuracy: 1e-9)
    }

    func testACleanSummaryDoesNotTripIt() {
        let wire = makeTripwire()
        XCTAssertTrue(checkTripwire("The council approved the transit plan on Tuesday evening.", wire: wire).isEmpty)
    }

    func testCaseIsIgnored() {
        let wire = makeTripwire()
        XCTAssertFalse(checkTripwire(wire.token.lowercased(), wire: wire).isEmpty)
    }

    func testASpacedOutEchoStillCounts() {
        // Splitting the code to dodge a filter is still obeying the content.
        let wire = makeTripwire()
        let spaced = wire.token.map(String.init).joined(separator: " ")
        XCTAssertFalse(checkTripwire(spaced, wire: wire).isEmpty)
    }

    func testAnEchoSplitByInvisiblesStillCounts() {
        let wire = makeTripwire()
        let smuggled = wire.token.map(String.init).joined(separator: "\u{200B}")  // ZERO WIDTH SPACE
        XCTAssertFalse(checkTripwire(smuggled, wire: wire).isEmpty)
    }

    func testMarkdownEmphasisInsideTheTokenStillCounts() {
        let wire = makeTripwire()
        let head = String(wire.token.prefix(4))
        let tail = String(wire.token.dropFirst(4))
        XCTAssertFalse(checkTripwire("\(head)**\(tail)**", wire: wire).isEmpty)
    }

    func testNoWireMeansNoFindings() {
        XCTAssertTrue(checkTripwire("anything at all", wire: nil).isEmpty)
        XCTAssertTrue(checkTripwire("", wire: makeTripwire()).isEmpty)
    }

    // MARK: - redaction

    func testRedactionRemovesTheToken() {
        let wire = makeTripwire()
        let cleaned = redactTripwire("Summary text. \(wire.token) More text.", wire: wire)
        XCTAssertFalse(cleaned.contains(wire.token))
        XCTAssertTrue(cleaned.contains("[redacted]"))
        XCTAssertTrue(cleaned.contains("Summary text."))
        XCTAssertTrue(cleaned.contains("More text."))
    }

    func testRedactionIsANoOpWithoutAWire() {
        XCTAssertEqual(redactTripwire("untouched", wire: nil), "untouched")
    }

    // MARK: - Swift-specific dialect checks
    //
    // These pin down the places where Swift/Foundation would have diverged from the Python
    // reference if the port had been written naively.

    func testRedactionIsCaseInsensitive() {
        let wire = makeTripwire()
        let cleaned = redactTripwire("echo: \(wire.token.lowercased()) done", wire: wire)
        XCTAssertEqual(cleaned, "echo: [redacted] done")
    }

    func testRedactionTreatsTheTokenAsALiteralNotAPattern() {
        // The Python reference escapes the token before substituting; "-" must not act as a range.
        let wire = Tripwire(token: "QUARTZ-7F3A9C", sentence: "irrelevant")
        XCTAssertEqual(redactTripwire("QUARTZ-7F3A9C and QUARTZX7F3A9C", wire: wire),
                       "[redacted] and QUARTZX7F3A9C")
    }

    func testSquashedFormDropsEverySeparator() {
        let wire = Tripwire(token: "QUARTZ-7F3A9C", sentence: "irrelevant")
        XCTAssertEqual(wire.squashed, "QUARTZ7F3A9C")
    }

    func testFullwidthEchoStillCountsAfterNFKC() {
        let wire = Tripwire(token: "QUARTZ-7F3A9C", sentence: "irrelevant")
        // Fullwidth Latin letters normalise to ASCII under NFKC.
        XCTAssertFalse(checkTripwire("ＱＵＡＲＴＺ－７Ｆ３Ａ９Ｃ", wire: wire).isEmpty)
    }

    func testACombiningMarkAfterTheTokenDoesNotCount() {
        // Verified against the Python reference rather than reasoned about: the
        // check normalizes NFKC first, which composes the trailing "C" and the
        // combining acute into "Ć". The token is then no longer present, and the
        // separator-stripped fallback drops "Ć" as non-alphanumeric rather than
        // folding it to "C". So this does NOT trip, in Python or here.
        //
        // That is the conservative direction for a positive control: a tripwire
        // that fails to fire understates compliance, which is safe. One that
        // fires on a near-miss would report a compromise that did not happen.
        let wire = Tripwire(token: "QUARTZ-7F3A9C", sentence: "irrelevant")
        XCTAssertTrue(checkTripwire("QUARTZ-7F3A9C\u{0301}", wire: wire).isEmpty)
    }

    func testANonComposingCombiningMarkStillCounts() {
        // U+0332 has no precomposed form with "C", so NFKC leaves the token's code points
        // intact and Python's code-point `in` finds it. Foundation's *default* search
        // compares by canonical equivalence and would treat "C̲" as a single non-matching
        // grapheme, so the port searches with `.literal`. Verified against the reference.
        let wire = Tripwire(token: "QUARTZ-7F3A9C", sentence: "irrelevant")
        XCTAssertFalse(checkTripwire("QUARTZ-7F3A9C\u{0332}", wire: wire).isEmpty)
        XCTAssertFalse(checkTripwire("QUARTZ-7F3A9\u{0332}C", wire: wire).isEmpty)
    }

    func testANearMissDoesNotTrip() {
        let wire = Tripwire(token: "QUARTZ-7F3A9C", sentence: "irrelevant")
        XCTAssertTrue(checkTripwire("QUARTZ-7F3A9D is not the code", wire: wire).isEmpty)
        XCTAssertTrue(checkTripwire("QUARTZ alone is not the code", wire: wire).isEmpty)
    }

    func testTokenShape() {
        let wire = makeTripwire()
        let parts = wire.token.split(separator: "-")
        XCTAssertEqual(parts.count, 2)
        XCTAssertTrue(tripwireWords.contains(String(parts[0])))
        XCTAssertEqual(parts[1].count, 6)
        XCTAssertTrue(parts[1].allSatisfy { "0123456789ABCDEF".contains($0) })
    }

    // MARK: - simple vs full case folding
    //
    // `re.IGNORECASE` folds case one code point at a time; Foundation's `.caseInsensitive` folds
    // fully and expands single scalars into several. Every assertion below was read off the
    // Python reference, not reasoned about.

    func testRedactionDoesNotFoldLigaturesIntoTheToken() {
        // Foundation would fold U+FB00 to "ff" and redact this. CPython does not, and a token's
        // six hex digits really can contain "FF", so this is reachable in production.
        let wire = Tripwire(token: "BASALT-00FF11", sentence: "irrelevant")
        XCTAssertEqual(redactTripwire("basalt-00\u{FB00}11", wire: wire), "basalt-00\u{FB00}11")
        // ...yet `check` *does* fire on it, because it compares uppercased forms and Unicode's
        // uppercase mapping expands the ligature. The reference is asymmetric here; so are we.
        XCTAssertFalse(checkTripwire("basalt-00\u{FB00}11", wire: wire).isEmpty)
    }

    func testRedactionDoesNotFoldSharpSIntoTheToken() {
        let wire = Tripwire(token: "BASSALT-00FF11", sentence: "irrelevant")
        XCTAssertEqual(redactTripwire("ba\u{00DF}alt-00ff11", wire: wire), "ba\u{00DF}alt-00ff11")
    }

    func testRedactionTreatsDotlessAndDottedIAsI() {
        // The other direction: CPython unifies these with ASCII "I", Foundation does not — and
        // MERIDIAN, OBSIDIAN, PELICAN and VERMILION all contain an "I".
        let wire = Tripwire(token: "MERIDIAN-7F3A9C", sentence: "irrelevant")
        XCTAssertEqual(redactTripwire("mer\u{0131}dian-7f3a9c", wire: wire), "[redacted]")
        XCTAssertEqual(redactTripwire("MER\u{0130}DIAN-7F3A9C", wire: wire), "[redacted]")
    }

    func testRedactionTreatsLongSAsS() {
        let wire = Tripwire(token: "BASALT-00FF11", sentence: "irrelevant")
        XCTAssertEqual(redactTripwire("ba\u{017F}alt-00ff11", wire: wire), "[redacted]")
    }

    // MARK: - degenerate wires
    //
    // `makeTripwire` never mints these, but `Tripwire.init` is public and the reference has
    // definite behaviour for them: Python's `"" in x` is true where Foundation's search is nil.

    func testAWireWithNoAlphanumericsFiresOnEverything() {
        let wire = Tripwire(token: "---", sentence: "irrelevant")
        XCTAssertEqual(wire.squashed, "")
        XCTAssertFalse(checkTripwire("anything at all", wire: wire).isEmpty)
        // An empty output still short-circuits to no findings, wire or not.
        XCTAssertTrue(checkTripwire("", wire: wire).isEmpty)
    }

    func testAnEmptyTokenMatchesAtEveryPosition() {
        let wire = Tripwire(token: "", sentence: "irrelevant")
        XCTAssertFalse(checkTripwire("hey", wire: wire).isEmpty)
        XCTAssertEqual(redactTripwire("hey", wire: wire),
                       "[redacted]h[redacted]e[redacted]y[redacted]")
    }

    func testRedactionReplacesEveryOccurrence() {
        let wire = Tripwire(token: "TUNDRA-ABCDEF", sentence: "irrelevant")
        XCTAssertEqual(redactTripwire("TUNDRA-ABCDEF x tundra-abcdef", wire: wire),
                       "[redacted] x [redacted]")
    }

    func testPlantedContentContainsTheSentenceExactlyOnce() {
        let wire = makeTripwire()
        let planted = plantTripwire("Body.", wire: wire)
        XCTAssertEqual(planted, "Body.\n\n\(wire.sentence)")
    }
}
