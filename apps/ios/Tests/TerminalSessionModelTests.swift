import Foundation
import UIKit
import XCTest
@testable import CodexMobile

private actor SessionModelCacheKeyProvider: CacheKeyProviding {
    func keyData() async throws -> Data { Data(repeating: 0x33, count: 32) }
}

private actor RecordingTerminalSocket: TerminalSocketClient {
    let failure: ClientError?
    let receiptAfterAttempt: Int?
    let finishConnectionNumbers: Set<Int>
    private var continuation: AsyncThrowingStream<TerminalFrame, Error>.Continuation?
    private var attemptsBySequence: [UInt64: Int] = [:]
    private(set) var frames: [TerminalFrame] = []
    private(set) var connectionCount = 0

    init(
        failure: ClientError? = nil,
        receiptAfterAttempt: Int? = nil,
        finishConnectionNumbers: Set<Int> = []
    ) {
        self.failure = failure
        self.receiptAfterAttempt = receiptAfterAttempt
        self.finishConnectionNumbers = finishConnectionNumbers
    }

    func connect(
        to descriptor: TerminalConnectionDescriptor,
        ownerID: UUID
    ) async -> AsyncThrowingStream<TerminalFrame, Error> {
        connectionCount += 1
        let pair = AsyncThrowingStream<TerminalFrame, Error>.makeStream(bufferingPolicy: .bufferingNewest(64))
        if finishConnectionNumbers.contains(connectionCount) {
            pair.continuation.finish()
        } else {
            continuation?.finish()
            continuation = pair.continuation
        }
        return pair.stream
    }

    func send(_ frame: TerminalFrame) async throws {
        if let failure { throw failure }
        frames.append(frame)
        guard frame.kind == .input,
              frame.flags == TerminalFrameFlags.idempotentInput,
              let receiptAfterAttempt else { return }
        let attempt = attemptsBySequence[frame.sequence, default: 0] + 1
        attemptsBySequence[frame.sequence] = attempt
        if attempt >= receiptAfterAttempt {
            continuation?.yield(TerminalFrame(
                kind: .acknowledgement,
                flags: TerminalFrameFlags.inputReceipt,
                sequence: frame.sequence,
                tabID: frame.tabID
            ))
        }
    }

    func emit(_ frame: TerminalFrame) {
        continuation?.yield(frame)
    }

    func disconnect(ownerID: UUID, code: URLSessionWebSocketTask.CloseCode) async {
        continuation?.finish()
        continuation = nil
    }
}

@MainActor
private final class RecordingRenderer: TerminalRendering {
    var onInput: ((Data) -> Void)?
    var onResize: ((Int, Int) -> Void)?
    var onLinkRequest: ((URL) -> Void)?
    var onTitleChange: ((String) -> Void)?
    private(set) var received: [Data] = []
    private(set) var resetCount = 0

    func makeView() -> UIView { UIView() }
    func receiveOutput(_ data: Data) { received.append(data) }
    func resetForReplay() { resetCount += 1 }
    func focus() {}
    func armControlModifier() {}
    func armOptionModifier() {}
    func dismissKeyboard() {}
    func search(_ term: String, backwards: Bool) -> String { "" }
    func clearSearch() {}
}

@MainActor
final class TerminalSessionModelTests: XCTestCase {
    private let tabID = UUID(uuidString: "00112233-4455-4677-8899-aabbccddeeff")!

    func testComposerUsesBracketedPasteAndReturnsOnlyAfterServerReceipt() async throws {
        let descriptor = makeDescriptor(reconnectToken: "reconnect-1")
        let api = FixtureAPIClient(scriptedTerminalConnections: [descriptor])
        let socket = RecordingTerminalSocket(receiptAfterAttempt: 1)
        let model = makeModel(api: api, socket: socket)
        model.start()
        defer { model.stop() }
        guard await eventually({ model.state == .connected }) else {
            XCTFail("Terminal did not connect")
            return
        }

        try await model.sendComposer(
            text: "inspect this",
            attachments: [AttachmentUpload(mediaType: "text/plain", contentBase64: Data("hello".utf8))]
        )

        let sentFrames = await socket.frames
        let frames = sentFrames.filter { $0.kind == .input }
        let frame = try XCTUnwrap(frames.first)
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frame.flags, TerminalFrameFlags.idempotentInput)
        XCTAssertNotEqual(frame.sequence, 0)
        XCTAssertTrue(frame.payload.starts(with: [0x1B, 0x5B, 0x32, 0x30, 0x30, 0x7E]))
        XCTAssertTrue(frame.payload.suffix(7).elementsEqual([0x1B, 0x5B, 0x32, 0x30, 0x31, 0x7E, 0x0D]))
        let value = String(decoding: frame.payload, as: UTF8.self)
        XCTAssertTrue(value.contains("inspect this"))
        XCTAssertTrue(value.contains("/codex-mobile-attachments/"))
        XCTAssertTrue(sentFrames.contains { candidate in
            candidate.kind == .acknowledgement
                && candidate.flags == TerminalFrameFlags.inputReceiptConfirmed
                && candidate.sequence == frame.sequence
        })
    }

    func testComposerRetriesSameIdempotencyKeyUntilReceipt() async throws {
        let descriptor = makeDescriptor(reconnectToken: "reconnect-1")
        let api = FixtureAPIClient(scriptedTerminalConnections: [descriptor])
        let socket = RecordingTerminalSocket(receiptAfterAttempt: 2)
        let model = makeModel(
            api: api,
            socket: socket,
            receiptTimeout: .seconds(1),
            retryDelay: .milliseconds(5)
        )
        model.start()
        defer { model.stop() }
        guard await eventually({ model.state == .connected }) else {
            XCTFail("Terminal did not connect")
            return
        }

        try await model.sendComposer(text: "retry safely", attachments: [])

        let inputs = await socket.frames.filter { $0.kind == .input }
        XCTAssertGreaterThanOrEqual(inputs.count, 2)
        XCTAssertTrue(inputs.allSatisfy { $0.sequence == inputs[0].sequence })
        XCTAssertTrue(inputs.allSatisfy { $0.payload == inputs[0].payload })
    }

    func testManualRetryAfterMissingReceiptReusesPendingDeliveryKey() async throws {
        let descriptor = makeDescriptor(reconnectToken: "reconnect-1")
        let api = FixtureAPIClient(scriptedTerminalConnections: [descriptor])
        let socket = RecordingTerminalSocket(receiptAfterAttempt: 2)
        let model = makeModel(
            api: api,
            socket: socket,
            receiptTimeout: .milliseconds(100),
            retryDelay: .milliseconds(250)
        )
        model.start()
        defer { model.stop() }
        guard await eventually({ model.state == .connected }) else {
            XCTFail("Terminal did not connect")
            return
        }

        do {
            try await model.sendComposer(text: "same retained draft", attachments: [])
            XCTFail("First attempt should time out without a receipt")
        } catch {}
        try await model.sendComposer(text: "same retained draft", attachments: [])

        let inputs = await socket.frames.filter { $0.kind == .input }
        XCTAssertEqual(inputs.count, 2)
        XCTAssertEqual(inputs[0].sequence, inputs[1].sequence)
        XCTAssertEqual(inputs[0].payload, inputs[1].payload)
    }

    func testComposerSurfacesSocketFailureWithoutAcceptingTransportSendAsDelivery() async {
        let socket = RecordingTerminalSocket(failure: ClientError.unavailable("socket dropped"))
        let model = makeModel(
            api: FixtureAPIClient(),
            socket: socket,
            receiptTimeout: .milliseconds(20),
            retryDelay: .milliseconds(5)
        )
        model.state = .connected
        model.holdsInputLease = true

        do {
            try await model.sendComposer(text: "keep draft", attachments: [])
            XCTFail("Expected the send to fail")
        } catch {
            XCTAssertEqual(error.localizedDescription, "socket dropped")
        }
        let frameCount = await socket.frames.count
        XCTAssertEqual(frameCount, 0)
    }

    func testRejectedReconnectTokenIsClearedAndRetriedOnceWithOwnerSession() async {
        let first = makeDescriptor(reconnectToken: "stale-reconnect")
        let recovered = makeDescriptor(reconnectToken: "fresh-reconnect")
        let api = FixtureAPIClient(
            scriptedTerminalConnections: [first, recovered],
            rejectedReconnectTokens: ["stale-reconnect"]
        )
        let socket = RecordingTerminalSocket(finishConnectionNumbers: [1])
        let model = makeModel(api: api, socket: socket)
        model.start()
        defer { model.stop() }

        let recoveredConnection = await eventually(timeout: .seconds(3)) {
            let requests = await api.observedTerminalReconnectTokens()
            return requests.count >= 3 && model.state == .connected
        }
        XCTAssertTrue(recoveredConnection)
        let requests = await api.observedTerminalReconnectTokens()
        XCTAssertGreaterThanOrEqual(requests.count, 3)
        XCTAssertNil(requests[0])
        XCTAssertEqual(requests[1], "stale-reconnect")
        XCTAssertNil(requests[2])
    }

    func testReplayGapClearsRendererAndCachedHistoryBeforeRebuildingRetainedWindow() async throws {
        let cacheURL = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: cacheURL) }
        let cache = EncryptedOfflineCache(fileURL: cacheURL, keyProvider: SessionModelCacheKeyProvider())
        try await cache.appendTerminalFrames(
            workspaceID: "workspace-1",
            tabID: tabID.uuidString.lowercased(),
            frames: [OfflineTerminalFrame(sequence: 1, output: Data("stale-history\n".utf8))]
        )
        let renderer = RecordingRenderer()
        let socket = RecordingTerminalSocket()
        let api = FixtureAPIClient(scriptedTerminalConnections: [makeDescriptor(reconnectToken: "reconnect-1")])
        let model = makeModel(api: api, socket: socket, renderer: renderer, cache: cache)
        model.start()
        defer { model.stop() }
        guard await eventually({ model.state == .connected }) else {
            XCTFail("Terminal did not connect")
            return
        }

        await socket.emit(TerminalFrame(
            kind: .replayGap,
            sequence: 5,
            tabID: tabID,
            payload: Data("scrollback_truncated".utf8)
        ))
        await socket.emit(TerminalFrame(kind: .output, sequence: 5, tabID: tabID, payload: Data("retained-a\n".utf8)))
        await socket.emit(TerminalFrame(kind: .output, sequence: 6, tabID: tabID, payload: Data("retained-b\n".utf8)))

        guard await eventually({ model.lastAcknowledgedSequence == 6 }) else {
            XCTFail("Retained replay window was not processed")
            return
        }
        try await Task.sleep(for: .seconds(1))
        let history = try await cache.terminalHistory(
            workspaceID: "workspace-1",
            tabID: tabID.uuidString.lowercased()
        )
        let rendered = renderer.received.reduce(into: Data()) { $0.append($1) }
        let cached = history?.frames.reduce(into: Data()) { $0.append($1.output) } ?? Data()

        XCTAssertEqual(renderer.resetCount, 1)
        XCTAssertEqual(String(decoding: rendered, as: UTF8.self), "retained-a\nretained-b\n")
        XCTAssertFalse(String(decoding: cached, as: UTF8.self).contains("stale-history"))
        XCTAssertEqual(history?.lastSequence, 6)
        XCTAssertTrue(model.hasReplayGap)
        XCTAssertEqual(model.state, .connected)
    }

    func testTerminalDerivedTitlesAndCloseReasonsAreSafeDisplayText() {
        let renderer = RecordingRenderer()
        let model = makeModel(api: FixtureAPIClient(), socket: RecordingTerminalSocket(), renderer: renderer)

        renderer.onTitleChange?("build\u{202E}gpj\n")

        XCTAssertEqual(model.terminalTitle, #"build\u{202E}gpj\u{000A}"#)
        XCTAssertEqual(
            TerminalSessionModel.ConnectionState.failed("closed\u{2066}hidden\u{2069}").title,
            #"closed\u{2066}hidden\u{2069}"#
        )
    }

    private func makeDescriptor(reconnectToken: String?) -> TerminalConnectionDescriptor {
        TerminalConnectionDescriptor(
            websocketURL: URL(string: "wss://terminal.example.test/v1/terminal")!,
            connectionTicket: "ticket",
            deviceID: "device-a",
            reconnectToken: reconnectToken,
            protocolVersion: TerminalFrame.protocolVersion,
            maximumFrameBytes: 1_048_576,
            leaseHolderDeviceID: "device-a"
        )
    }

    private func makeModel(
        api: any CodexMobileAPI,
        socket: RecordingTerminalSocket,
        renderer: RecordingRenderer = RecordingRenderer(),
        cache: EncryptedOfflineCache? = nil,
        receiptTimeout: Duration = .seconds(1),
        retryDelay: Duration = .milliseconds(10)
    ) -> TerminalSessionModel {
        let offlineCache = cache ?? EncryptedOfflineCache(
            fileURL: FileManager.default.temporaryDirectory.appending(path: UUID().uuidString),
            keyProvider: SessionModelCacheKeyProvider()
        )
        return TerminalSessionModel(
            api: api,
            workspaceID: "workspace-1",
            tab: TerminalTab(
                id: tabID.uuidString.lowercased(),
                workspaceID: "workspace-1",
                title: "Codex",
                kind: .codex,
                order: 0,
                isRunning: true
            ),
            renderer: renderer,
            offlineCache: offlineCache,
            socket: socket,
            inputReceiptTimeout: receiptTimeout,
            inputReceiptRetryDelay: retryDelay
        )
    }

    private func eventually(
        timeout: Duration = .seconds(1),
        _ condition: @escaping @MainActor () async -> Bool
    ) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while clock.now < deadline {
            if await condition() { return true }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return await condition()
    }
}
