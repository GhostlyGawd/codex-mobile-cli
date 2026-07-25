import Foundation
import XCTest
@testable import CodexMobile

final class TerminalProtocolTests: XCTestCase {
    private let tabID = UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!

    func testGoldenOutputFrameMatchesFrozenWireLayout() throws {
        let frame = TerminalFrame(
            kind: .output,
            sequence: 0x0102_0304_0506_0708,
            tabID: tabID,
            payload: Data([0x68, 0x69])
        )
        let data = try TerminalProtocolCodec().encode(frame)

        XCTAssertEqual(data.count, 38)
        XCTAssertEqual(Array(data[0..<8]), [0x43, 0x4D, 0x01, 0x01, 0x00, 0x00, 0x00, 0x24])
        XCTAssertEqual(Array(data[8..<16]), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        XCTAssertEqual(Array(data[16..<32]), [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
        ])
        XCTAssertEqual(Array(data[32..<38]), [0, 0, 0, 2, 0x68, 0x69])
        XCTAssertEqual(try TerminalProtocolCodec().decode(data), frame)
    }

    func testResizeUsesFourBigEndianUInt16Values() throws {
        let payload = TerminalResizePayload(rows: 42, columns: 120, widthPixels: 1_200, heightPixels: 800)
        XCTAssertEqual(Array(payload.encoded), [0, 42, 0, 120, 0x04, 0xB0, 0x03, 0x20])
        let frame = TerminalFrame(kind: .resize, sequence: 0, tabID: tabID, payload: payload.encoded)
        XCTAssertEqual(try TerminalProtocolCodec().decode(try TerminalProtocolCodec().encode(frame)), frame)
    }

    func testRejectsUnknownFlagsAndMalformedPayloads() throws {
        XCTAssertThrowsError(try TerminalProtocolCodec().encode(TerminalFrame(
            kind: .input,
            flags: 0x8000,
            sequence: 0,
            tabID: tabID,
            payload: Data([1])
        ))) { XCTAssertEqual($0 as? TerminalProtocolError, .unknownFlags(0x8000)) }

        XCTAssertThrowsError(try TerminalProtocolCodec().encode(TerminalFrame(
            kind: .resize,
            sequence: 0,
            tabID: tabID,
            payload: Data(repeating: 0, count: 7)
        ))) { XCTAssertEqual($0 as? TerminalProtocolError, .invalidPayload) }
    }

    func testIdempotentInputAndApplicationReceiptRoundTrip() throws {
        let input = TerminalFrame(
            kind: .input,
            flags: TerminalFrameFlags.idempotentInput,
            sequence: 42,
            tabID: tabID,
            payload: Data("command\n".utf8)
        )
        let receipt = TerminalFrame(
            kind: .acknowledgement,
            flags: TerminalFrameFlags.inputReceipt,
            sequence: 42,
            tabID: tabID
        )
        let confirmation = TerminalFrame(
            kind: .acknowledgement,
            flags: TerminalFrameFlags.inputReceiptConfirmed,
            sequence: 42,
            tabID: tabID
        )

        for frame in [input, receipt, confirmation] {
            XCTAssertEqual(try TerminalProtocolCodec().decode(try TerminalProtocolCodec().encode(frame)), frame)
        }
    }

    func testIdempotentInputAndReceiptRequireNonzeroSequence() {
        XCTAssertThrowsError(try TerminalProtocolCodec().encode(TerminalFrame(
            kind: .input,
            flags: TerminalFrameFlags.idempotentInput,
            sequence: 0,
            tabID: tabID,
            payload: Data("x".utf8)
        ))) { XCTAssertEqual($0 as? TerminalProtocolError, .invalidPayload) }

        XCTAssertThrowsError(try TerminalProtocolCodec().encode(TerminalFrame(
            kind: .acknowledgement,
            flags: TerminalFrameFlags.inputReceipt,
            sequence: 0,
            tabID: tabID
        ))) { XCTAssertEqual($0 as? TerminalProtocolError, .invalidPayload) }

        XCTAssertThrowsError(try TerminalProtocolCodec().encode(TerminalFrame(
            kind: .acknowledgement,
            flags: TerminalFrameFlags.inputReceiptConfirmed,
            sequence: 0,
            tabID: tabID
        ))) { XCTAssertEqual($0 as? TerminalProtocolError, .invalidPayload) }

        XCTAssertThrowsError(try TerminalProtocolCodec().encode(TerminalFrame(
            kind: .acknowledgement,
            flags: TerminalFrameFlags.inputReceipt | TerminalFrameFlags.inputReceiptConfirmed,
            sequence: 42,
            tabID: tabID
        ))) { XCTAssertEqual($0 as? TerminalProtocolError, .invalidPayload) }

        XCTAssertThrowsError(try TerminalProtocolCodec().encode(TerminalFrame(
            kind: .replayGap,
            sequence: 0,
            tabID: tabID,
            payload: Data("scrollback_truncated".utf8)
        ))) { XCTAssertEqual($0 as? TerminalProtocolError, .invalidPayload) }
    }

    func testOnlyPingAndPongPermitConnectionScopedZeroTabID() throws {
        let zero = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        XCTAssertNoThrow(try TerminalProtocolCodec().encode(TerminalFrame(
            kind: .ping,
            sequence: 0,
            tabID: zero,
            payload: Data("ok".utf8)
        )))
        XCTAssertThrowsError(try TerminalProtocolCodec().encode(TerminalFrame(
            kind: .input,
            sequence: 0,
            tabID: zero,
            payload: Data("x".utf8)
        )))
    }

    func testEnforcesOneMiBPayloadLimit() {
        XCTAssertThrowsError(try TerminalProtocolCodec().encode(TerminalFrame(
            kind: .input,
            sequence: 0,
            tabID: tabID,
            payload: Data(repeating: 0, count: 1_048_577)
        ))) { XCTAssertEqual($0 as? TerminalProtocolError, .oversized(1_048_577)) }
    }
}
