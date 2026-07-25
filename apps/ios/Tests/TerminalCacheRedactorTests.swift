import Foundation
import XCTest
@testable import CodexMobile

final class TerminalCacheRedactorTests: XCTestCase {
    func testRedactsCredentialSignalSplitAcrossFrames() {
        var redactor = TerminalCacheRedactor()
        XCTAssertTrue(redactor.process(Data("AUTHORIZATION: Bearer ghp_split".utf8)).isEmpty)
        let output = redactor.process(Data("AcrossFrames123456789\nnext line\n".utf8))
        XCTAssertEqual(String(decoding: output, as: UTF8.self), "[REDACTED]\nnext line\n")
    }

    func testRedactsKnownJWTURLCredentialAndOpaqueTokenShapes() {
        var redactor = TerminalCacheRedactor()
        let providerToken = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz123456"
        let jwt = [
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "signature_value_123456"
        ].joined(separator: ".")
        let input = """
        \(providerToken)
        \(jwt)
        https://user:password-value@example.test/path
        abcdefghijklmnopqrstuvwxyz0123456789ABCD
        """ + "\n"
        let output = String(decoding: redactor.process(Data(input.utf8)), as: UTF8.self)
        XCTAssertFalse(output.contains("gh" + "p_"))
        XCTAssertFalse(output.contains("eyJhbGci"))
        XCTAssertFalse(output.contains("password-value"))
        XCTAssertFalse(output.contains("abcdefghijklmnopqrstuvwxyz0123456789ABCD"))
        XCTAssertEqual(output.components(separatedBy: "[REDACTED]").count - 1, 4)
    }

    func testInvalidUTF8AndOversizedUnterminatedRecordsFailClosed() {
        var invalid = TerminalCacheRedactor()
        XCTAssertEqual(
            String(decoding: invalid.process(Data([0xFF, 0xFE, 0x0A])), as: UTF8.self),
            "[REDACTED]\n"
        )

        var oversized = TerminalCacheRedactor()
        let output = oversized.process(Data(repeating: 0x41, count: 16 * 1_024 + 1))
        XCTAssertEqual(String(decoding: output, as: UTF8.self), "[REDACTED]\n")
    }

    func testOrdinaryTextIsPreservedButUnterminatedTailIsDiscardedOnReset() {
        var redactor = TerminalCacheRedactor()
        XCTAssertEqual(
            String(decoding: redactor.process(Data("build passed\n".utf8)), as: UTF8.self),
            "build passed\n"
        )
        XCTAssertTrue(redactor.process(Data("partial prompt".utf8)).isEmpty)
        redactor.reset()
        XCTAssertEqual(
            String(decoding: redactor.process(Data("fresh output\n".utf8)), as: UTF8.self),
            "fresh output\n"
        )
    }
}
