import Foundation

protocol TerminalSocketClient: Sendable {
    func connect(
        to descriptor: TerminalConnectionDescriptor,
        ownerID: UUID
    ) async -> AsyncThrowingStream<TerminalFrame, Error>
    func send(_ frame: TerminalFrame) async throws
    func disconnect(ownerID: UUID, code: URLSessionWebSocketTask.CloseCode) async
}

actor TerminalWebSocketClient: TerminalSocketClient {
    private var task: URLSessionWebSocketTask?
    private var continuation: AsyncThrowingStream<TerminalFrame, Error>.Continuation?
    private var ownerID: UUID?
    private var codec = TerminalProtocolCodec()
    private let session: URLSession

    init(session: URLSession? = nil) {
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.urlCache = nil
            configuration.httpCookieStorage = nil
            configuration.urlCredentialStorage = nil
            configuration.httpShouldSetCookies = false
            configuration.timeoutIntervalForRequest = 20
            self.session = URLSession(configuration: configuration)
        }
    }

    func connect(
        to descriptor: TerminalConnectionDescriptor,
        ownerID: UUID
    ) -> AsyncThrowingStream<TerminalFrame, Error> {
        disconnect(code: .goingAway)
        self.ownerID = ownerID
        let connectionCodec = TerminalProtocolCodec(
            maximumPayloadBytes: min(max(descriptor.maximumFrameBytes, 1_024), 1_048_576)
        )
        codec = connectionCodec

        var request = URLRequest(url: descriptor.websocketURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
        request.setValue("Bearer \(descriptor.connectionTicket)", forHTTPHeaderField: "Authorization")
        request.setValue("codex-mobile-terminal-v1", forHTTPHeaderField: "Sec-WebSocket-Protocol")
        let socket = session.webSocketTask(with: request)
        task = socket

        let pair = AsyncThrowingStream<TerminalFrame, Error>.makeStream(
            // Bound decoded output in memory. Sequence-gap detection forces a replay reconnect
            // if a sustained flood causes this newest-frame buffer to evict older output.
            bufferingPolicy: .bufferingNewest(16)
        )
        let stream = pair.stream
        let streamContinuation = pair.continuation
        continuation = streamContinuation
        streamContinuation.onTermination = { @Sendable _ in
            Task { await self.disconnect(ifCurrent: socket, code: .goingAway) }
        }
        socket.resume()
        Task { await receiveLoop(socket: socket, codec: connectionCodec) }
        return stream
    }

    func send(_ frame: TerminalFrame) async throws {
        guard let task else { throw ClientError.unavailable("The terminal is not connected.") }
        let data = try codec.encode(frame)
        try await task.send(.data(data))
    }

    func disconnect(code: URLSessionWebSocketTask.CloseCode = .normalClosure) {
        task?.cancel(with: code, reason: nil)
        task = nil
        ownerID = nil
        continuation?.finish()
        continuation = nil
    }

    func disconnect(
        ownerID: UUID,
        code: URLSessionWebSocketTask.CloseCode = .normalClosure
    ) {
        guard self.ownerID == ownerID else { return }
        disconnect(code: code)
    }

    private func disconnect(
        ifCurrent socket: URLSessionWebSocketTask,
        code: URLSessionWebSocketTask.CloseCode
    ) {
        guard task === socket else { return }
        disconnect(code: code)
    }

    private func receiveLoop(
        socket: URLSessionWebSocketTask,
        codec: TerminalProtocolCodec
    ) async {
        do {
            while task === socket {
                let message = try await socket.receive()
                // A cancelled task can still deliver a final message. Never route bytes from
                // an earlier connection into the continuation installed by a reconnect.
                guard task === socket else { break }
                guard case let .data(data) = message else {
                    throw TerminalProtocolError.invalidLength
                }
                let frame = try codec.decode(data)
                continuation?.yield(frame)
            }
        } catch {
            if task === socket {
                task = nil
                ownerID = nil
                continuation?.finish(throwing: error)
                continuation = nil
            }
        }
    }
}
