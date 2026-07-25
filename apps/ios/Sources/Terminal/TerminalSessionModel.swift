import CryptoKit
import Foundation
import Observation

@MainActor
@Observable
final class TerminalSessionModel {
    private struct PendingComposerDelivery {
        let fingerprint: Data
        let frame: TerminalFrame
        let stagedContentExpiresAt: Date?
    }

    enum ConnectionState: Equatable {
        case disconnected
        case connecting
        case connected
        case reconnecting(attempt: Int)
        case replayGap
        case failed(String)

        var title: String {
            switch self {
            case .disconnected: "Disconnected"
            case .connecting: "Connecting"
            case .connected: "Connected"
            case let .reconnecting(attempt): "Reconnecting (\(attempt))"
            case .replayGap: "History gap"
            case let .failed(message): HostileDisplayText.sanitized(message)
            }
        }
    }

    private let api: any CodexMobileAPI
    private let socket: any TerminalSocketClient
    private let renderer: any TerminalRendering
    private let offlineCache: EncryptedOfflineCache
    private let workspaceID: String
    private let tab: TerminalTab
    private let tabUUID: UUID?
    private let inputReceiptTimeout: Duration
    private let inputReceiptRetryDelay: Duration
    private var connectionTask: Task<Void, Never>?
    private var connectionGeneration: UInt64 = 0
    private var connectionOwnerID: UUID?
    private var sanitizer = TerminalOutputSanitizer()
    private var cacheRedactor = TerminalCacheRedactor()
    private var cacheFrames: [OfflineTerminalFrame] = []
    private var cacheBufferedBytes = 0
    private var cacheFlushTask: Task<Void, Never>?
    private var didRestoreCachedHistory = false
    private var reconnectToken: String?
    private var deviceID: String?
    private var receivedInputReceipts: Set<UInt64> = []
    private var receivedInputReceiptOrder: [UInt64] = []
    private var pendingComposerDelivery: PendingComposerDelivery?

    var state: ConnectionState = .disconnected
    var lastAcknowledgedSequence: UInt64 = 0
    var holdsInputLease = false
    var mayTakeInputLease = false
    var leaseHolderDeviceID: String?
    var terminalTitle: String
    var pendingLink: URL?
    var hasReplayGap = false
    var lastAttentionKind: String?

    init(
        api: any CodexMobileAPI,
        workspaceID: String,
        tab: TerminalTab,
        renderer: any TerminalRendering,
        offlineCache: EncryptedOfflineCache,
        socket: any TerminalSocketClient = TerminalWebSocketClient(),
        inputReceiptTimeout: Duration = .seconds(30),
        inputReceiptRetryDelay: Duration = .milliseconds(500)
    ) {
        self.api = api
        self.workspaceID = workspaceID
        self.tab = tab
        self.renderer = renderer
        self.offlineCache = offlineCache
        self.socket = socket
        self.inputReceiptTimeout = inputReceiptTimeout
        self.inputReceiptRetryDelay = inputReceiptRetryDelay
        self.tabUUID = UUID(uuidString: tab.id)
        self.terminalTitle = HostileDisplayText.sanitized(tab.title)

        renderer.onInput = { [weak self] data in self?.sendInput(data) }
        renderer.onResize = { [weak self] columns, rows in self?.resize(columns: columns, rows: rows) }
        renderer.onLinkRequest = { [weak self] url in self?.pendingLink = url }
        renderer.onTitleChange = { [weak self] title in
            self?.terminalTitle = HostileDisplayText.sanitized(title)
        }
    }

    func start() {
        guard connectionTask == nil else { return }
        guard tabUUID != nil else {
            state = .failed("The terminal tab identifier is invalid.")
            return
        }
        connectionGeneration &+= 1
        let generation = connectionGeneration
        let ownerID = UUID()
        connectionOwnerID = ownerID
        connectionTask = Task { [weak self] in
            await self?.connectionLoop(generation: generation, ownerID: ownerID)
        }
    }

    func stop() {
        connectionGeneration &+= 1
        let ownerID = connectionOwnerID
        connectionOwnerID = nil
        connectionTask?.cancel()
        connectionTask = nil
        flushCachedHistoryWithoutWaiting()
        Task { [weak self] in
            guard let self, let ownerID else { return }
            await self.socket.disconnect(ownerID: ownerID, code: .goingAway)
        }
        holdsInputLease = false
        mayTakeInputLease = false
        state = .disconnected
    }

    func setNetworkAvailable(_ available: Bool) {
        if available { start() } else { stop() }
    }

    func restoreCachedHistory() async {
        guard !didRestoreCachedHistory else { return }
        didRestoreCachedHistory = true
        do {
            guard let history = try await offlineCache.terminalHistory(
                workspaceID: workspaceID,
                tabID: tab.id
            ) else { return }
            renderer.resetForReplay()
            for frame in history.frames where !frame.output.isEmpty {
                renderer.receiveOutput(frame.output)
            }
            lastAcknowledgedSequence = max(lastAcknowledgedSequence, history.lastSequence)
        } catch {
            // An authenticated-cache failure removes the cache and must not block a live PTY.
        }
    }

    func focus() { renderer.focus() }

    func sendAccessory(_ bytes: [UInt8]) {
        sendInput(Data(bytes))
    }

    func armControlModifier() { renderer.armControlModifier() }
    func armOptionModifier() { renderer.armOptionModifier() }
    func dismissKeyboard() { renderer.dismissKeyboard() }
    func search(_ term: String, backwards: Bool = false) -> String {
        renderer.search(term, backwards: backwards)
    }
    func clearSearch() { renderer.clearSearch() }

    func takeInputLease() {
        guard mayTakeInputLease else { return }
        requestLease(explicitTakeControl: true)
    }

    func sendComposer(text: String, attachments: [AttachmentUpload]) async throws {
        guard let tabUUID else { throw ClientError.malformedData("The terminal tab identifier is invalid.") }
        guard state == .connected else { throw ClientError.unavailable("Reconnect before sending this draft.") }
        guard holdsInputLease else { throw ClientError.conflict("Take control of this terminal before sending.") }
        guard !text.isEmpty || !attachments.isEmpty else {
            throw ClientError.malformedData("Enter a message or choose an attachment.")
        }

        let fingerprint = composerFingerprint(text: text, attachments: attachments)
        if let pendingComposerDelivery,
           pendingComposerDelivery.fingerprint == fingerprint,
           pendingComposerDelivery.stagedContentExpiresAt.map({ $0 > Date().addingTimeInterval(5) }) ?? true {
            try await deliverComposerFrame(pendingComposerDelivery.frame)
            if self.pendingComposerDelivery?.frame.sequence == pendingComposerDelivery.frame.sequence {
                self.pendingComposerDelivery = nil
            }
            return
        }

        var staged: [StagedAttachment] = []
        if !attachments.isEmpty {
            staged = (try await api.stageTerminalAttachments(
                workspaceID: workspaceID,
                tabID: tab.id,
                request: StageAttachmentsRequest(attachments: attachments)
            )).attachments
        }
        var message = text
        if !staged.isEmpty {
            if !message.isEmpty { message += "\n\n" }
            message += "Temporary attachments (available for 30 minutes):\n"
            message += staged.enumerated().map { index, value in
                "Attachment \(index + 1): \(value.path) (\(value.mediaType))"
            }.joined(separator: "\n")
        }
        let body = Data(message.utf8)
        let pasteStart = Data([0x1B, 0x5B, 0x32, 0x30, 0x30, 0x7E])
        let pasteEndAndReturn = Data([0x1B, 0x5B, 0x32, 0x30, 0x31, 0x7E, 0x0D])
        guard body.count + pasteStart.count + pasteEndAndReturn.count <= 64 * 1_024 else {
            throw ClientError.malformedData("The composed terminal input exceeded 64 KiB.")
        }
        // Uploads can outlive a transient reconnect, so re-check the writer
        // lease immediately before the authoritative WebSocket send.
        guard state == .connected, holdsInputLease else {
            throw ClientError.conflict("Terminal control changed before the draft could be sent. Attachments will expire automatically.")
        }
        var payload = Data(capacity: body.count + pasteStart.count + pasteEndAndReturn.count)
        payload.append(pasteStart)
        payload.append(body)
        payload.append(pasteEndAndReturn)
        let frame = TerminalFrame(
            kind: .input,
            flags: TerminalFrameFlags.idempotentInput,
            sequence: nextInputIdempotencyKey(),
            tabID: tabUUID,
            payload: payload
        )
        pendingComposerDelivery = PendingComposerDelivery(
            fingerprint: fingerprint,
            frame: frame,
            stagedContentExpiresAt: staged.map(\.expiresAt).min()
        )
        try await deliverComposerFrame(frame)
        if pendingComposerDelivery?.frame.sequence == frame.sequence {
            pendingComposerDelivery = nil
        }
    }

    private func connectionLoop(generation: UInt64, ownerID: UUID) async {
        var attempt = 0
        while !Task.isCancelled, generation == connectionGeneration {
            state = attempt == 0 ? .connecting : .reconnecting(attempt: attempt)
            let requestedReconnectToken = reconnectToken
            var receivedDescriptor = false
            do {
                let descriptor = try await api.terminalConnection(
                    workspaceID: workspaceID,
                    tabID: tab.id,
                    request: TerminalConnectRequest(
                        afterSequence: lastAcknowledgedSequence,
                        reconnectToken: requestedReconnectToken
                    )
                )
                receivedDescriptor = true
                guard generation == connectionGeneration, !Task.isCancelled else { break }
                guard descriptor.protocolVersion == TerminalFrame.protocolVersion else {
                    throw TerminalProtocolError.unsupportedVersion(descriptor.protocolVersion)
                }
                reconnectToken = descriptor.reconnectToken
                deviceID = descriptor.deviceID
                leaseHolderDeviceID = descriptor.leaseHolderDeviceID
                holdsInputLease = descriptor.leaseHolderDeviceID == descriptor.deviceID
                mayTakeInputLease = !holdsInputLease

                let stream = await socket.connect(to: descriptor, ownerID: ownerID)
                guard generation == connectionGeneration, !Task.isCancelled else {
                    await socket.disconnect(ownerID: ownerID)
                    break
                }
                state = .connected
                attempt = 0
                if descriptor.leaseHolderDeviceID == nil {
                    requestLease(explicitTakeControl: false)
                }
                for try await frame in stream {
                    guard generation == connectionGeneration, !Task.isCancelled else { break }
                    try await handle(frame)
                }
                if Task.isCancelled || generation != connectionGeneration { break }
                throw ClientError.unavailable("The terminal connection closed.")
            } catch is CancellationError {
                break
            } catch {
                guard generation == connectionGeneration, !Task.isCancelled else { break }
                if !receivedDescriptor,
                   requestedReconnectToken != nil,
                   (error as? ClientError) == .unauthorized {
                    // Reconnect tokens rotate on every descriptor request. A process
                    // restart or lost response can leave the client holding a stale
                    // value, so recover once with the still-authenticated owner session.
                    reconnectToken = nil
                    continue
                }
                attempt += 1
                state = .reconnecting(attempt: attempt)
                let delay = min(pow(2.0, Double(min(attempt, 4))) * 0.35, 8.0)
                try? await Task.sleep(for: .seconds(delay))
            }
        }
        if !Task.isCancelled, generation == connectionGeneration {
            if case .failed = state {
                // Preserve the terminal's final non-sensitive close reason.
            } else {
                state = .disconnected
            }
        }
    }

    private func handle(_ frame: TerminalFrame) async throws {
        guard let tabUUID else { throw TerminalProtocolError.invalidTabID }
        let zeroTab = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        let isConnectionPing = (frame.kind == .ping || frame.kind == .pong) && frame.tabID == zeroTab
        guard frame.tabID == tabUUID || isConnectionPing else { throw TerminalProtocolError.invalidTabID }
        switch frame.kind {
        case .output:
            if frame.sequence <= lastAcknowledgedSequence {
                try await acknowledge(frame.sequence)
                return
            }
            if lastAcknowledgedSequence == UInt64.max || frame.sequence != lastAcknowledgedSequence + 1 {
                state = .replayGap
                hasReplayGap = true
                throw TerminalProtocolError.invalidLength
            }
            let safeOutput = sanitizer.process(frame.payload)
            if !safeOutput.isEmpty { renderer.receiveOutput(safeOutput) }
            lastAcknowledgedSequence = frame.sequence
            recordCachedOutput(sequence: frame.sequence, output: safeOutput)
            if state == .replayGap { state = .connected }
            try await acknowledge(frame.sequence)
        case .replayGap:
            guard frame.sequence > 0 else { throw TerminalProtocolError.invalidPayload }
            hasReplayGap = true
            state = .replayGap
            sanitizer.reset()
            cacheRedactor.reset()
            cacheFlushTask?.cancel()
            cacheFlushTask = nil
            cacheFrames.removeAll(keepingCapacity: true)
            cacheBufferedBytes = 0
            renderer.resetForReplay()
            lastAcknowledgedSequence = frame.sequence - 1
            do {
                try await offlineCache.resetTerminalHistory(workspaceID: workspaceID, tabID: tab.id)
            } catch {
                // Never retain a renderer history that the protocol declared
                // incoherent. If a targeted rewrite fails, erase the cache.
                try? await offlineCache.clear()
            }
        case .leaseGranted:
            guard frame.payload.count <= 128,
                  let holder = String(data: frame.payload, encoding: .utf8) else {
                throw TerminalProtocolError.invalidPayload
            }
            leaseHolderDeviceID = holder
            holdsInputLease = holder == deviceID
            mayTakeInputLease = !holdsInputLease
        case .leaseDenied:
            guard frame.payload.count <= 128,
                  let holder = String(data: frame.payload, encoding: .utf8) else {
                throw TerminalProtocolError.invalidPayload
            }
            leaseHolderDeviceID = holder
            holdsInputLease = false
            mayTakeInputLease = true
        case .ping:
            try await socket.send(TerminalFrame(
                kind: .pong,
                sequence: frame.sequence,
                tabID: frame.tabID,
                payload: frame.payload
            ))
        case .tabClosed:
            holdsInputLease = false
            let reason = String(decoding: frame.payload.prefix(1_024), as: UTF8.self)
            state = .failed(reason.isEmpty ? "Terminal tab closed" : "Terminal closed: \(reason)")
            throw CancellationError()
        case .attention:
            lastAttentionKind = HostileDisplayText.sanitized(String(decoding: frame.payload.prefix(128), as: UTF8.self))
        case .acknowledgement:
            guard frame.flags == TerminalFrameFlags.inputReceipt,
                  frame.sequence > 0,
                  frame.payload.isEmpty else {
                throw TerminalProtocolError.invalidPayload
            }
            // Confirm only after the receipt reached the application model. If
            // this send is ambiguous, reconnecting with the same input key is
            // still safe because the server retains a confirmed-key tombstone.
            try await socket.send(TerminalFrame(
                kind: .acknowledgement,
                flags: TerminalFrameFlags.inputReceiptConfirmed,
                sequence: frame.sequence,
                tabID: frame.tabID
            ))
            rememberInputReceipt(frame.sequence)
        case .pong:
            break
        case .input, .resize, .leaseRequest:
            throw TerminalProtocolError.invalidPayload
        }
    }

    private func acknowledge(_ sequence: UInt64) async throws {
        guard let tabUUID else { throw TerminalProtocolError.invalidTabID }
        try await socket.send(TerminalFrame(
            kind: .acknowledgement,
            sequence: sequence,
            tabID: tabUUID
        ))
    }

    private func sendInput(_ data: Data) {
        guard let tabUUID,
              holdsInputLease, state == .connected, data.count <= 64 * 1_024 else { return }
        Task {
            try? await socket.send(TerminalFrame(
                kind: .input,
                sequence: 0,
                tabID: tabUUID,
                payload: data
            ))
        }
    }

    private func nextInputIdempotencyKey() -> UInt64 {
        var idempotencyKey: UInt64 = 0
        repeat {
            idempotencyKey = UInt64.random(in: 1...UInt64.max)
        } while receivedInputReceipts.contains(idempotencyKey)
        return idempotencyKey
    }

    private func deliverComposerFrame(_ frame: TerminalFrame) async throws {
        let idempotencyKey = frame.sequence
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: inputReceiptTimeout)
        var attempted = false
        var lastSendError: Error?

        while clock.now < deadline {
            try Task.checkCancellation()
            if consumeInputReceipt(idempotencyKey) { return }

            // After an ambiguous first write, retry the exact same frame even if
            // the visible lease changed. The gateway acknowledges an already-applied
            // key without writing it again or requiring the old lease.
            if state == .connected, holdsInputLease || attempted {
                attempted = true
                do {
                    try await socket.send(frame)
                    lastSendError = nil
                } catch {
                    lastSendError = error
                }
            }
            if consumeInputReceipt(idempotencyKey) { return }

            let remaining = clock.now.duration(to: deadline)
            guard remaining > .zero else { break }
            try await Task.sleep(for: remaining < inputReceiptRetryDelay ? remaining : inputReceiptRetryDelay)
        }

        _ = consumeInputReceipt(idempotencyKey)
        if let lastSendError { throw lastSendError }
        throw ClientError.unavailable("The terminal did not acknowledge this draft. It was kept so you can retry safely.")
    }

    private func composerFingerprint(text: String, attachments: [AttachmentUpload]) -> Data {
        var hasher = SHA256()
        updateFingerprint(&hasher, field: Data("codex-mobile-composer-v1".utf8))
        updateFingerprint(&hasher, field: Data(text.utf8))
        for attachment in attachments {
            updateFingerprint(&hasher, field: Data(attachment.mediaType.utf8))
            updateFingerprint(&hasher, field: attachment.contentBase64)
        }
        return Data(hasher.finalize())
    }

    private func updateFingerprint(_ hasher: inout SHA256, field: Data) {
        var length = UInt64(field.count).bigEndian
        let lengthData = withUnsafeBytes(of: &length) { Data($0) }
        hasher.update(data: lengthData)
        hasher.update(data: field)
    }

    private func rememberInputReceipt(_ sequence: UInt64) {
        guard receivedInputReceipts.insert(sequence).inserted else { return }
        receivedInputReceiptOrder.append(sequence)
        while receivedInputReceiptOrder.count > 64 {
            receivedInputReceipts.remove(receivedInputReceiptOrder.removeFirst())
        }
    }

    private func consumeInputReceipt(_ sequence: UInt64) -> Bool {
        guard receivedInputReceipts.remove(sequence) != nil else { return false }
        receivedInputReceiptOrder.removeAll { $0 == sequence }
        return true
    }

    private func resize(columns: Int, rows: Int) {
        guard let tabUUID,
              holdsInputLease,
              columns > 0, rows > 0,
              columns <= Int(UInt16.max), rows <= Int(UInt16.max) else { return }
        let resize = TerminalResizePayload(
            rows: UInt16(rows),
            columns: UInt16(columns),
            widthPixels: 0,
            heightPixels: 0
        )
        Task {
            try? await socket.send(TerminalFrame(
                kind: .resize,
                sequence: 0,
                tabID: tabUUID,
                payload: resize.encoded
            ))
        }
    }

    private func requestLease(explicitTakeControl: Bool) {
        guard let tabUUID,
              let deviceID,
              let payload = deviceID.data(using: .utf8),
              payload.count <= 128 else { return }
        Task {
            try? await socket.send(TerminalFrame(
                kind: .leaseRequest,
                flags: explicitTakeControl ? TerminalFrameFlags.takeLease : 0,
                sequence: 0,
                tabID: tabUUID,
                payload: payload
            ))
        }
    }

    private func recordCachedOutput(sequence: UInt64, output: Data) {
        let redacted = cacheRedactor.process(output)
        let cachedOutput: Data
        if redacted.count <= 128 * 1_024,
           cacheBufferedBytes + redacted.count <= 512 * 1_024 {
            cachedOutput = redacted
            cacheBufferedBytes += redacted.count
        } else {
            cachedOutput = Data()
        }
        cacheFrames.append(OfflineTerminalFrame(sequence: sequence, output: cachedOutput))
        while cacheFrames.count > 256 {
            cacheBufferedBytes -= cacheFrames.removeFirst().output.count
        }
        scheduleCacheFlush()
    }

    private func scheduleCacheFlush() {
        guard cacheFlushTask == nil else { return }
        cacheFlushTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(750))
            guard !Task.isCancelled else { return }
            await self?.flushCachedHistory()
        }
    }

    private func flushCachedHistory() async {
        cacheFlushTask = nil
        let pending = cacheFrames
        cacheFrames.removeAll(keepingCapacity: true)
        cacheBufferedBytes = 0
        guard !pending.isEmpty else { return }
        try? await offlineCache.appendTerminalFrames(
            workspaceID: workspaceID,
            tabID: tab.id,
            frames: pending
        )
    }

    private func flushCachedHistoryWithoutWaiting() {
        cacheFlushTask?.cancel()
        cacheFlushTask = nil
        let pending = cacheFrames
        cacheFrames.removeAll(keepingCapacity: true)
        cacheBufferedBytes = 0
        guard !pending.isEmpty else { return }
        let cache = offlineCache
        let cachedWorkspaceID = workspaceID
        let cachedTabID = tab.id
        Task {
            try? await cache.appendTerminalFrames(
                workspaceID: cachedWorkspaceID,
                tabID: cachedTabID,
                frames: pending
            )
        }
    }

}
