import XCTest
import Foundation
@testable import Bulwark

final class RampartTests: XCTestCase {

    // MARK: - Detection

    func testEmailRedacted() {
        let r = Rampart.redact("Contact me at jane.doe@example.com please.")
        XCTAssertEqual(r.count, 1)
        XCTAssertTrue(r.text.contains("[EMAIL_1]"))
        XCTAssertFalse(r.text.contains("jane.doe@example.com"))
        XCTAssertEqual(r.summary, "EMAIL×1")
    }

    func testCreditCardLuhnGated() {
        // A Luhn-valid Visa test number is redacted…
        let good = Rampart.redact("card 4111 1111 1111 1111 on file")
        XCTAssertTrue(good.text.contains("[CREDIT_CARD_1]"))
        // …a 16-digit run that fails Luhn is left alone.
        let bad = Rampart.redact("order 1234 5678 9012 3456 shipped")
        XCTAssertFalse(bad.text.contains("[CREDIT_CARD"))
    }

    func testSSNStructuralValidation() {
        XCTAssertTrue(Rampart.redact("SSN 536-90-4399").text.contains("[SSN_1]"))
        // area 000 is invalid → not an SSN
        XCTAssertFalse(Rampart.redact("ref 000-12-3456 here").text.contains("[SSN"))
    }

    func testPhoneRequiresShape() {
        XCTAssertTrue(Rampart.redact("call 555-123-4567 now").text.contains("[PHONE_1]"))
        XCTAssertTrue(Rampart.redact("intl +44 20 7946 0958 desk").text.contains("[PHONE_1]"))
        // A bare 10-digit run with no separators is ambiguous — left alone to avoid false positives.
        XCTAssertFalse(Rampart.redact("id 5551234567 logged").text.contains("[PHONE"))
    }

    func testIPv4Validated() {
        XCTAssertTrue(Rampart.redact("from 192.168.15.24 today").text.contains("[IP_ADDRESS_1]"))
        // 999 is not a valid octet
        XCTAssertFalse(Rampart.redact("build 999.1.1.1 tag").text.contains("[IP_ADDRESS"))
    }

    func testIBANRedacted() {
        XCTAssertTrue(Rampart.redact("IBAN GB82 WEST 1234 5698 7654 32 ok").text.contains("[IBAN_1]"))
    }

    func testValidatorUnits() {
        XCTAssertTrue(Rampart.luhnValid("4111111111111111"))
        XCTAssertFalse(Rampart.luhnValid("4111111111111112"))
        XCTAssertTrue(Rampart.validSSN("536904399"))
        XCTAssertFalse(Rampart.validSSN("666904399"))   // area 666
        XCTAssertFalse(Rampart.validSSN("900456789"))   // area ≥ 900
        XCTAssertFalse(Rampart.validSSN("536004399"))   // group 00
    }

    // MARK: - Placeholders + rehydrate

    func testStablePlaceholderPerValue() {
        let r = Rampart.redact("write a@x.com, then a@x.com again, and b@x.com")
        // Three spans, two distinct values → two distinct tokens, one of them used twice.
        XCTAssertEqual(r.count, 3)
        XCTAssertEqual(r.map.count, 2, "two distinct emails → two tokens")
        let emailTokens = r.text.components(separatedBy: "[EMAIL_").count - 1
        XCTAssertEqual(emailTokens, 3, "all three occurrences are placeholdered")
        // The repeated value collapses to one stable token used twice.
        let repeated = r.map.first(where: { $0.value == "a@x.com" })!.key
        XCTAssertEqual(r.text.components(separatedBy: repeated).count - 1, 2)
    }

    func testRehydrateRestoresOriginals() {
        let r = Rampart.redact("email a@x.com and card 4111 1111 1111 1111")
        let restored = Rampart.rehydrate(r.text, map: r.map)
        XCTAssertEqual(restored, "email a@x.com and card 4111 1111 1111 1111")
    }

    func testKeepSetRetainsEntity() {
        let r = Rampart.redact("host 10.0.0.5 mail a@x.com", keep: [.ipAddress])
        XCTAssertTrue(r.text.contains("10.0.0.5"), "kept IP stays in place")
        XCTAssertTrue(r.text.contains("[EMAIL_1]"), "other PII still redacted")
    }

    func testCleanTextUnchanged() {
        let clean = "Boil water, add salt, cook the pasta for nine minutes."
        let r = Rampart.redact(clean)
        XCTAssertEqual(r.text, clean)
        XCTAssertEqual(r.count, 0)
        XCTAssertTrue(r.map.isEmpty)
    }

    func testSummaryIsLabelsAndCountsOnly() {
        let r = Rampart.redact("a@x.com b@x.com SSN 536-90-4399")
        // Order follows scrub order (right-to-left); assert content, not ordering.
        XCTAssertTrue(r.summary.contains("EMAIL×2"))
        XCTAssertTrue(r.summary.contains("SSN×1"))
        XCTAssertFalse(r.summary.contains("@"), "summary must never carry the values")
    }

    // MARK: - ToolGuard integration

    func testToolGuardRedactsOutputWhenEnabled() {
        let g = ToolGuard(config: ToolGuardConfig(redactOutputPII: true))
        let out = g.registerOutput(tool: "read_page",
                                   output: "Reach the author at editor@news.example or 555-123-4567.")
        XCTAssertEqual(out.piiRedactions, 2)
        XCTAssertFalse(out.wrapped.contains("editor@news.example"))
        XCTAssertTrue(out.wrapped.contains("[EMAIL_1]"))
        XCTAssertTrue(out.wrapped.contains("placeholders"), "the model is told values were replaced")
    }

    func testToolGuardLeavesOutputAloneWhenDisabled() {
        let g = ToolGuard()   // redactOutputPII defaults off
        let out = g.registerOutput(tool: "read_page", output: "Reach editor@news.example.")
        XCTAssertEqual(out.piiRedactions, 0)
        XCTAssertTrue(out.wrapped.contains("editor@news.example"))
    }
}
