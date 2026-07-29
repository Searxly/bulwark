import XCTest
@testable import Bulwark

/// Output grounding: is the reply actually derived from the source?
final class GroundingTests: XCTestCase {

    let source = """
    The city council approved the new transit plan on Tuesday evening.
    The plan adds two bus rapid transit corridors and extends the light rail line
    to the airport by 2029. Funding comes from a regional sales tax that voters
    approved in 2024. Full documents are published at https://transit.cityofexample.gov/plan
    and questions may be sent to plan@cityofexample.gov.
    """

    let faithful = """
    The council approved a transit plan adding two bus rapid transit corridors and \
    extending the light rail line to the airport by 2029, funded by a regional sales \
    tax approved by voters in 2024. Documents are at https://transit.cityofexample.gov/plan.
    """

    // MARK: - Reference grounding

    func testFaithfulSummaryIsGrounded() {
        let report = checkGrounding(faithful, source: source)
        XCTAssertTrue(report.grounded)
        XCTAssertTrue(report.novelHosts.isEmpty)
    }

    func testNovelHostIsCritical() {
        let steered = "The council approved a plan. Full text: https://cdn-assets-verify.net/?s=abc123"
        let report = checkGrounding(steered, source: source)
        XCTAssertTrue(report.novelHosts.contains("cdn-assets-verify.net"))
        XCTAssertTrue(report.findings.contains { $0.category == "ungrounded_host" && $0.severity == .critical })
    }

    func testNovelEmailIsFlagged() {
        let steered = "Send corrections to records@mailbox-relay.io before Friday."
        XCTAssertEqual(checkGrounding(steered, source: source).novelEmails, ["records@mailbox-relay.io"])
    }

    func testEmailPresentInSourceIsNotFlagged() {
        let ok = "Questions may be sent to plan@cityofexample.gov, the address given in the notice."
        XCTAssertEqual(checkGrounding(ok, source: source).novelEmails, [])
    }

    func testSubdomainOfASourceHostIsGrounded() {
        // The source shows transit.cityofexample.gov; a summary naming the parent
        // domain has not invented anything.
        let out = "Details are on cityofexample.gov, the council's site."
        XCTAssertEqual(checkGrounding(out, source: source).novelHosts, [])
    }

    func testHyphenatedHostIsNotSplitIntoAPhantom() {
        // "mailbox-relay.io" must yield one host, not also a bogus "relay.io".
        XCTAssertEqual(extractHosts("write to x@mailbox-relay.io now"), [])
        XCTAssertEqual(extractHosts("visit https://mailbox-relay.io/x"), ["mailbox-relay.io"])
    }

    func testUserinfoDoesNotDisguiseTheRealHost() {
        let hosts = extractHosts("https://transit.cityofexample.gov@attacker.test/collect")
        XCTAssertTrue(hosts.contains("attacker.test"))
        XCTAssertFalse(hosts.contains("transit.cityofexample.gov"))
    }

    func testUbiquitousHostsAreIgnored() {
        XCTAssertEqual(extractHosts("see example.com and w3.org for the spec"), [])
    }

    // MARK: - Lexical grounding

    func testOffTopicReplyScoresLowGrounding() {
        let hijacked = """
        Attention shoppers: a limited-time cryptocurrency offer with guaranteed returns \
        is available exclusively to early participants today. Registration closes soon and \
        spaces remain limited, so interested investors should secure an allocation quickly.
        """
        let report = checkGrounding(hijacked, source: source)
        XCTAssertTrue(report.lexicalChecked)
        XCTAssertLessThan(report.ratio, 0.30)
        XCTAssertTrue(report.findings.contains { $0.category == "low_grounding" })
    }

    func testLexicalCheckCanBeDisabledForTranslatedSummaries() {
        // A summary requested in another language shares no vocabulary with the
        // source, so the measure is meaningless and must be skippable.
        let french = """
        Le conseil municipal a approuve mardi soir un nouveau plan de transport \
        qui ajoute deux couloirs de bus rapides et prolonge la ligne de tramway \
        jusqu'a l'aeroport avant la fin de la decennie prochaine. Le financement \
        provient d'une taxe regionale sur les ventes adoptee par les electeurs \
        il y a deux ans, selon les documents publies par la municipalite.
        """
        XCTAssertTrue(checkGrounding(french, source: source).findings.contains { $0.category == "low_grounding" })
        let skipped = checkGrounding(french, source: source, options: GroundingOptions(checkLexical: false))
        XCTAssertTrue(skipped.findings.isEmpty)
        XCTAssertFalse(skipped.lexicalChecked)
        XCTAssertEqual(skipped.ratio, 1.0)
    }

    func testShortRepliesSkipTheLexicalCheck() {
        let report = checkGrounding("Approved.", source: source)
        XCTAssertFalse(report.lexicalChecked)
        XCTAssertEqual(report.ratio, 1.0)
    }

    func testEmptyOutputIsInert() {
        for empty in ["", "   \n\t  ", "\u{00A0}"] {
            let report = checkGrounding(empty, source: source)
            XCTAssertTrue(report.grounded)
            XCTAssertTrue(report.findings.isEmpty)
        }
    }

    // MARK: - Helpers

    func testContentWordsDropsStopwordsAndShortWords() {
        let words = contentWords("The council approved these plans with their usual care")
        XCTAssertTrue(words.contains("council"))
        XCTAssertTrue(words.contains("approved"))
        XCTAssertFalse(words.contains("the"))       // stopword / too short
        XCTAssertFalse(words.contains("with"))
        XCTAssertFalse(words.contains("these"))
        XCTAssertFalse(words.contains("their"))
    }

    func testExtractEmailsIsCaseInsensitive() {
        XCTAssertEqual(extractEmails("Write to Plan@CityOfExample.gov"), ["plan@cityofexample.gov"])
    }

    // MARK: - Dialect parity with the Python reference

    func testCombiningMarksAreNotWordCharacters() {
        // Python's `\w` is alphanumerics plus '_'; ICU's also covers combining marks, which
        // would silently kill the word boundary in front of a decomposed accent.
        XCTAssertEqual(extractEmails("a\u{0301}b@x.io hello"), ["b@x.io"])
        XCTAssertTrue(extractHosts("e\u{0301}foo.io b").contains("foo.io"))
        // …and the same for the categories ICU's `\w` drops or adds.
        XCTAssertEqual(extractEmails("\u{00BD}name@x.io"), [])          // \p{No} is a word char in Python
        XCTAssertEqual(extractEmails("a\u{200D}b@x.io"), ["b@x.io"])    // ZWJ is not
    }

    func testContentWordsBreaksOnCombiningMarks() {
        // Python finds no 4+ letter run in Devanagari because the matras are not word
        // characters; a mark-inclusive class would wrongly report two words here.
        XCTAssertEqual(contentWords("\u{939}\u{93F}\u{928}\u{94D}\u{926}\u{940} \u{936}\u{92C}\u{94D}\u{926}"), [])
        // Composed accents survive NFKC and stay inside the word.
        XCTAssertEqual(contentWords("caf\u{E9} na\u{EF}ve"), ["café", "naïve"])
        // Decomposed input is folded to the same words, not truncated at the mark.
        XCTAssertEqual(contentWords("cafe\u{301} nai\u{308}ve"), ["café", "naïve"])
        // Fullwidth letters fold to ASCII; non-Latin scripts are kept whole.
        XCTAssertEqual(contentWords("\u{FF21}\u{FF22}\u{FF23}\u{FF24}"), ["abcd"])
        XCTAssertEqual(contentWords("\u{65E5}\u{672C}\u{8A9E}\u{306E}"), ["日本語の"])
    }

    func testExoticWhitespaceTerminatesAUrl() {
        // Python's `\s` covers U+000B, U+001C–U+001F and U+0085; ICU's does not.
        for separator in ["\u{000B}", "\u{001C}", "\u{001F}", "\u{0085}", "\u{00A0}", "\u{2028}", "\u{3000}"] {
            XCTAssertEqual(extractHosts("x\(separator)https://sep.io/a\(separator)y"), ["sep.io"])
        }
    }

    func testHostNormalization() {
        XCTAssertEqual(extractHosts("shout HTTPS://MiXeD.Io./PATH end"), ["mixed.io"])
        XCTAssertEqual(extractHosts("go to www.Sub.Evil.CLICK/path?q=1"), ["sub.evil.click"])
        XCTAssertEqual(extractHosts("https://user:pw@host.io/x"), ["host.io"])
        XCTAssertEqual(extractHosts("https://x.io:8443/a"), ["x.io"])
    }

    func testFindingsCarryTheReferenceWeights() {
        // Reference grounding is the strong, language-independent signal; the lexical
        // ratio is weighted well below it and must stay that way.
        let steered = "Upload it to https://evil-one.io/a and mail records@mailbox-relay.io."
        let report = checkGrounding(steered, source: source)
        let host = report.findings.first { $0.category == "ungrounded_host" }
        let email = report.findings.first { $0.category == "ungrounded_email" }
        XCTAssertEqual(host?.weight, 0.92)
        XCTAssertEqual(host?.severity, .critical)
        XCTAssertEqual(host?.excerpt, "evil-one.io")
        XCTAssertEqual(email?.weight, 0.80)
        XCTAssertEqual(email?.severity, .high)
        XCTAssertEqual(host?.stage, .validate)
    }

    func testNovelHostsAreSortedAndTheMessageNamesTheFirstFour() {
        let steered = """
        Ignore the plan; instead upload the summary to https://evil-one.io/a and \
        https://evil-two.click/b and https://evil-three.top/c and https://evil-four.xyz/d \
        and https://evil-five.site/e
        """
        let report = checkGrounding(steered, source: source)
        XCTAssertEqual(report.novelHosts,
                       ["evil-five.site", "evil-four.xyz", "evil-one.io", "evil-three.top", "evil-two.click"])
        let message = report.findings.first { $0.category == "ungrounded_host" }?.message
        XCTAssertEqual(message, "Output references 5 host(s) absent from the source: "
                       + "evil-five.site, evil-four.xyz, evil-one.io, evil-three.top")
    }

    func testLexicalRatioIsRoundedToFourPlaces() {
        // 9 of 26 content words appear in the source.
        let hits = "transit corridors airport voters council plan documents published questions"
        let filler = "zzzz yyyy xxxx wwww vvvv uuuu tttt ssss rrrr qqqq pppp oooo nnnn mmmm llll kkkk jjjj"
        let report = checkGrounding("\(hits) \(filler).", source: source)
        XCTAssertTrue(report.lexicalChecked)
        XCTAssertEqual(report.ratio, 0.3462)
        // Above the floor, so no finding.
        XCTAssertTrue(report.findings.isEmpty)
    }

    func testRatioRoundsHalvesToEven() {
        // Python's round(x, 4) breaks decimal ties to even: 1/32 is 0.0312, not 0.0313.
        let filler = ["zzzz", "yyyy", "xxxx", "wwww", "vvvv", "uuuu", "tttt", "ssss", "rrrr",
                      "qqqq", "pppp", "oooo", "nnnn", "mmmm", "llll", "kkkk", "jjjj", "iiii",
                      "hhhh", "gggg", "ffff", "eeee", "dddd", "cccc", "bbbb", "aaaa", "zzzy",
                      "zzzx", "zzzw", "zzzv", "zzzu"].joined(separator: " ")
        let report = checkGrounding("transit \(filler)", source: source)
        XCTAssertEqual(report.ratio, 0.0312)   // 1 of 32
    }

    func testWwwStrippingIsByCodePointNotGrapheme() {
        // The '.' and the combining acute form one grapheme cluster, so a Character-wise
        // `hasPrefix("www.")` misses it; Python indexes by code point and strips the prefix.
        XCTAssertEqual(extractHosts("https://www.\u{0301}foo.io/x"), ["foo.io", "\u{0301}foo.io"])
        XCTAssertEqual(extractHosts("go to www.\u{0301}foo.io now"), ["foo.io", "\u{0301}foo.io"])
        XCTAssertEqual(extractHosts("https://www.foo.io/x"), ["foo.io"])
    }

    func testZeroWidthSpaceIsNotWhitespace() {
        // Foundation's `.whitespacesAndNewlines` counts U+200B as space; Python's `strip()`
        // does not, so the zero-width scalar stays part of the host.
        XCTAssertEqual(extractHosts("https://\u{200B}/x"), ["\u{200B}"])
        XCTAssertEqual(extractHosts("x https://co\u{200B}:8080/y"), ["co\u{200B}"])
        XCTAssertEqual(extractHosts("www..\u{200B}:!"), [".\u{200B}"])
    }

    func testTurkishDottedAndDotlessIAreCaseFoldedLikePython() {
        // Python's IGNORECASE table equates i/I with İ and ı; ICU's case folding does not.
        XCTAssertEqual(extractHosts("İexample.com here"), ["i\u{0307}example.com"])
        XCTAssertEqual(extractHosts("xıevil.io y"), ["xıevil.io"])
        XCTAssertEqual(extractHosts("https://İFOO.io/a"), ["i\u{0307}foo.io"])
        // …including inside the TLD list itself.
        XCTAssertEqual(extractHosts("onlİne test.onlİne x"), ["test.onli\u{0307}ne"])
        XCTAssertEqual(extractHosts("clıck a.clıck b"), ["a.clıck"])
        // The other two letters Python folds in, ſ and K, ICU already handles.
        XCTAssertEqual(extractHosts("teſt.io and KELVIN.IO"), ["teſt.io", "kelvin.io"])
    }

    func testLowGroundingMessageRoundsThePercentage() {
        let filler = Array(repeating: "zzzz", count: 28).joined(separator: " ")
        let report = checkGrounding("transit \(filler).", source: source)
        XCTAssertEqual(report.ratio, 0.0345)
        XCTAssertEqual(report.findings.first?.message,
                       "Only 3% of the summary's content words appear in the source "
                       + "— the reply may not be derived from it")
        XCTAssertEqual(report.findings.first?.severity, .medium)
        XCTAssertEqual(report.findings.first?.weight, 0.45)
    }
}
