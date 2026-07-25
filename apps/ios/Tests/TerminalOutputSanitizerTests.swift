import Foundation
import XCTest
@testable import CodexMobile

final class TerminalOutputSanitizerTests: XCTestCase {
    func testDropsOSC52ClipboardWrite() {
        var sanitizer = TerminalOutputSanitizer()
        let bytes = Data("before\u{001B}]52;c;c2VjcmV0\u{0007}after".utf8)
        XCTAssertEqual(String(decoding: sanitizer.process(bytes), as: UTF8.self), "beforeafter")
    }

    func testDropsOSC52SplitAcrossFrames() {
        var sanitizer = TerminalOutputSanitizer()
        XCTAssertEqual(
            String(decoding: sanitizer.process(Data("safe\u{001B}]52;c;partial".utf8)), as: UTF8.self),
            "safe"
        )
        XCTAssertEqual(
            String(decoding: sanitizer.process(Data("payload\u{001B}\\tail".utf8)), as: UTF8.self),
            "tail"
        )
    }

    func testPreservesNonClipboardOSC() {
        var sanitizer = TerminalOutputSanitizer()
        let title = Data("\u{001B}]2;safe title\u{0007}".utf8)
        XCTAssertEqual(sanitizer.process(title), title)
    }

    func testDropsC1OSC52() {
        var sanitizer = TerminalOutputSanitizer()
        let data = Data([0x41, 0x9D]) + Data("52;c;blocked".utf8) + Data([0x9C, 0x42])
        XCTAssertEqual(sanitizer.process(data), Data("AB".utf8))
    }

    func testDropsOversizedOSCAsAWhole() {
        var sanitizer = TerminalOutputSanitizer()
        let oversized = Data("before\u{001B}]2;".utf8)
            + Data(repeating: 0x41, count: 8_193)
            + Data("\u{0007}after".utf8)
        XCTAssertEqual(String(decoding: sanitizer.process(oversized), as: UTF8.self), "beforeafter")
    }
}
