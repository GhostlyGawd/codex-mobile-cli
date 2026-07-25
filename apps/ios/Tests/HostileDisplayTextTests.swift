import XCTest
@testable import CodexMobile

final class HostileDisplayTextTests: XCTestCase {
    func testEscapesControlsBidiOverridesAndLiteralEscapePrefixes() {
        let rawPath = "src/evil\u{202E}gpj\n\u{001B}[31m\\u{202E}"

        let displayed = HostileDisplayText.sanitized(rawPath)

        XCTAssertEqual(displayed, #"src/evil\u{202E}gpj\u{000A}\u{001B}[31m\u{005C}u{202E}"#)
        XCTAssertEqual(rawPath, "src/evil\u{202E}gpj\n\u{001B}[31m\\u{202E}", "display sanitization must not mutate the operational path")
    }

    func testEscapesInvisibleFormattingAndBoundsRenderedLabels() {
        XCTAssertEqual(
            HostileDisplayText.sanitized("a\u{200B}b\u{2066}c\u{2069}"),
            #"a\u{200B}b\u{2066}c\u{2069}"#
        )
        XCTAssertEqual(HostileDisplayText.sanitized("abcdef", scalarLimit: 4), "abcd…")
    }

    func testPreservesOrdinaryUnicodeNames() {
        XCTAssertEqual(HostileDisplayText.sanitized("Sources/Résumé/猫.swift"), "Sources/Résumé/猫.swift")
    }
}
