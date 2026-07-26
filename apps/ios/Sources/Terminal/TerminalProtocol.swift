import Foundation

enum TerminalFrameKind: UInt8, Codable, Sendable {
    case output = 1
    case input = 2
    case acknowledgement = 3
    case resize = 4
    case ping = 5
    case pong = 6
    case replayGap = 7
    case leaseRequest = 8
    case leaseGranted = 9
    case leaseDenied = 10
    case tabClosed = 11
    case attention = 12
}

enum TerminalFrameFlags {
    static let takeLease: UInt16 = 1 << 0
    static let idempotentInput: UInt16 = 1 << 1
    static let inputReceipt: UInt16 = 1 << 2
    static let inputReceiptConfirmed: UInt16 = 1 << 3
}

struct TerminalFrame: Equatable, Sendable {
    static let protocolVersion: UInt8 = 1

    let kind: TerminalFrameKind
    let flags: UInt16
    let sequence: UInt64
    let tabID: UUID
    let payload: Data

    init(
        kind: TerminalFrameKind,
        flags: UInt16 = 0,
        sequence: UInt64,
        tabID: UUID,
        payload: Data = Data()
    ) {
        self.kind = kind
        self.flags = flags
        self.sequence = sequence
        self.tabID = tabID
        self.payload = payload
    }
}

enum TerminalProtocolError: LocalizedError, Equatable, Sendable {
    case truncated
    case badMagic
    case unsupportedVersion(UInt8)
    case unknownKind(UInt8)
    case oversized(Int)
    case invalidLength
    case invalidTabID
    case invalidHeaderLength(UInt16)
    case unknownFlags(UInt16)
    case invalidPayload

    var errorDescription: String? {
        switch self {
        case .truncated: "The terminal frame was truncated."
        case .badMagic: "The terminal frame magic value was invalid."
        case let .unsupportedVersion(version): "Terminal protocol version \(version) is unsupported."
        case let .unknownKind(kind): "Terminal frame kind \(kind) is unknown."
        case let .oversized(size): "Terminal frame payload \(size) exceeds the negotiated limit."
        case .invalidLength: "The terminal frame length was inconsistent."
        case .invalidTabID: "The terminal frame tab identifier was invalid."
        case let .invalidHeaderLength(length): "Terminal header length \(length) is invalid."
        case let .unknownFlags(flags): "Terminal flags 0x\(String(flags, radix: 16)) are unsupported."
        case .invalidPayload: "The terminal frame payload did not match its kind."
        }
    }
}

struct TerminalProtocolCodec: Sendable {
    static let headerLength = 36
    private static let magic = Data([0x43, 0x4D]) // CM
    private static let zeroTabID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    let maximumPayloadBytes: Int

    init(maximumPayloadBytes: Int = 1_048_576) {
        self.maximumPayloadBytes = maximumPayloadBytes
    }

    func encode(_ frame: TerminalFrame) throws -> Data {
        guard frame.payload.count <= maximumPayloadBytes else {
            throw TerminalProtocolError.oversized(frame.payload.count)
        }
        try validate(frame)
        var result = Data(capacity: Self.headerLength + frame.payload.count)
        result.append(Self.magic)
        result.append(TerminalFrame.protocolVersion)
        result.append(frame.kind.rawValue)
        result.appendBigEndian(frame.flags)
        result.appendBigEndian(UInt16(Self.headerLength))
        result.appendBigEndian(frame.sequence)
        var uuid = frame.tabID.uuid
        Swift.withUnsafeBytes(of: &uuid) { result.append(contentsOf: $0) }
        result.appendBigEndian(UInt32(frame.payload.count))
        result.append(frame.payload)
        return result
    }

    func decode(_ data: Data) throws -> TerminalFrame {
        guard data.count >= Self.headerLength else { throw TerminalProtocolError.truncated }
        guard data.prefix(2) == Self.magic else { throw TerminalProtocolError.badMagic }
        let version = data[2]
        guard version == TerminalFrame.protocolVersion else {
            throw TerminalProtocolError.unsupportedVersion(version)
        }
        guard let kind = TerminalFrameKind(rawValue: data[3]) else {
            throw TerminalProtocolError.unknownKind(data[3])
        }
        var offset = 4
        let flags: UInt16 = try data.readBigEndian(at: &offset)
        let headerLength: UInt16 = try data.readBigEndian(at: &offset)
        guard headerLength == Self.headerLength else {
            throw TerminalProtocolError.invalidHeaderLength(headerLength)
        }
        let sequence: UInt64 = try data.readBigEndian(at: &offset)
        guard offset + 16 <= data.count else { throw TerminalProtocolError.truncated }
        let uuidBytes = Array(data[offset..<(offset + 16)])
        offset += 16
        guard uuidBytes.count == 16 else { throw TerminalProtocolError.invalidTabID }
        let tabID = UUID(uuid: (
            uuidBytes[0], uuidBytes[1], uuidBytes[2], uuidBytes[3],
            uuidBytes[4], uuidBytes[5], uuidBytes[6], uuidBytes[7],
            uuidBytes[8], uuidBytes[9], uuidBytes[10], uuidBytes[11],
            uuidBytes[12], uuidBytes[13], uuidBytes[14], uuidBytes[15]
        ))
        let length: UInt32 = try data.readBigEndian(at: &offset)
        let payloadLength = Int(length)
        guard payloadLength <= maximumPayloadBytes else { throw TerminalProtocolError.oversized(payloadLength) }
        guard offset + payloadLength == data.count else { throw TerminalProtocolError.invalidLength }
        let frame = TerminalFrame(
            kind: kind,
            flags: flags,
            sequence: sequence,
            tabID: tabID,
            payload: Data(data[offset..<data.count])
        )
        try validate(frame)
        return frame
    }

    private func validate(_ frame: TerminalFrame) throws {
        let allowedFlags: UInt16 = switch frame.kind {
        case .leaseRequest: TerminalFrameFlags.takeLease
        case .input: TerminalFrameFlags.idempotentInput
        case .acknowledgement: TerminalFrameFlags.inputReceipt | TerminalFrameFlags.inputReceiptConfirmed
        default: 0
        }
        guard frame.flags & ~allowedFlags == 0 else { throw TerminalProtocolError.unknownFlags(frame.flags) }
        guard frame.tabID != Self.zeroTabID || frame.kind == .ping || frame.kind == .pong else {
            throw TerminalProtocolError.invalidTabID
        }
        switch frame.kind {
        case .output:
            guard frame.sequence > 0 else { throw TerminalProtocolError.invalidPayload }
        case .input:
            if frame.flags & TerminalFrameFlags.idempotentInput != 0 {
                guard frame.sequence > 0 else { throw TerminalProtocolError.invalidPayload }
            } else {
                guard frame.sequence == 0 else { throw TerminalProtocolError.invalidPayload }
            }
        case .acknowledgement:
            guard frame.payload.isEmpty else { throw TerminalProtocolError.invalidPayload }
            guard frame.flags == 0
                    || frame.flags == TerminalFrameFlags.inputReceipt
                    || frame.flags == TerminalFrameFlags.inputReceiptConfirmed else {
                throw TerminalProtocolError.invalidPayload
            }
            if frame.flags != 0 {
                guard frame.sequence > 0 else { throw TerminalProtocolError.invalidPayload }
            }
        case .resize:
            guard frame.sequence == 0, frame.payload.count == 8 else { throw TerminalProtocolError.invalidPayload }
        case .ping, .pong:
            guard frame.payload.count <= 64 else { throw TerminalProtocolError.invalidPayload }
        case .replayGap:
            guard frame.sequence > 0, String(data: frame.payload, encoding: .utf8) != nil else {
                throw TerminalProtocolError.invalidPayload
            }
        case .leaseRequest, .leaseGranted, .leaseDenied:
            guard frame.sequence == 0,
                  !frame.payload.isEmpty,
                  String(data: frame.payload, encoding: .utf8) != nil else {
                throw TerminalProtocolError.invalidPayload
            }
        case .tabClosed, .attention:
            guard String(data: frame.payload, encoding: .utf8) != nil else {
                throw TerminalProtocolError.invalidPayload
            }
        }
    }
}

struct TerminalResizePayload: Equatable, Sendable {
    let rows: UInt16
    let columns: UInt16
    let widthPixels: UInt16
    let heightPixels: UInt16

    var encoded: Data {
        var result = Data(capacity: 8)
        result.appendBigEndian(rows)
        result.appendBigEndian(columns)
        result.appendBigEndian(widthPixels)
        result.appendBigEndian(heightPixels)
        return result
    }
}

private extension Data {
    mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }

    func readBigEndian<T: FixedWidthInteger>(at offset: inout Int) throws -> T {
        guard offset + MemoryLayout<T>.size <= count else { throw TerminalProtocolError.truncated }
        var value: T = 0
        let range = offset..<(offset + MemoryLayout<T>.size)
        _ = Swift.withUnsafeMutableBytes(of: &value) { destination in
            copyBytes(to: destination, from: range)
        }
        offset += MemoryLayout<T>.size
        return T(bigEndian: value)
    }
}
