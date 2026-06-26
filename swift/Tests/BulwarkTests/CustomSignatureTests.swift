import XCTest
@testable import Bulwark

final class CustomSignatureTests: XCTestCase {
    let codeword = makeSignature(
        id: "custom.codeword", category: "instruction_override", severity: .high,
        weight: 0.8, pattern: #"\bopen\s+sesame\b"#, description: "Internal trip phrase"
    )

    func testCustomSignatureFlowsThroughConfig() {
        let bulwark = Bulwark(config: BulwarkConfig(extraSignatures: [codeword]))
        let det = bulwark.scan("the cave door reads: open sesame")
        XCTAssertTrue(det.injected)
        XCTAssertTrue(det.findings.contains { $0.patternId == "custom.codeword" })
    }

    func testCustomSignatureDoesNotAffectDefaultScan() {
        XCTAssertFalse(scan("the cave door reads: open sesame").injected)
    }

    func testCustomSignatureRidesDeobfuscationPass() {
        let bulwark = Bulwark(config: BulwarkConfig(extraSignatures: [codeword]))
        XCTAssertTrue(bulwark.scan("the phrase is 0pen sesame").injected)
    }
}
