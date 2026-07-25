import Foundation

/// Defense-in-depth for terminal bytes admitted to the encrypted offline cache.
/// The server authoritatively removes active granted values before transport;
/// this local filter conservatively removes common unknown credential shapes.
/// It deliberately does not alter bytes sent to the live terminal renderer.
struct TerminalCacheRedactor: Sendable {
    private var pending = Data()
    private let maximumInputBytes = 128 * 1_024
    private let maximumRecordBytes = 16 * 1_024
    private let marker = "[REDACTED]"

    private let patterns = [
        #"(?i)(?:gh[pousr][_][A-Za-z0-9]{16,}|github[_]pat[_][A-Za-z0-9_]{16,}|sk-(?:proj-)?[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16})"#,
        #"(?i)(?:authorization\s*:\s*(?:bearer|basic)|(?:token|secret|password|passwd|api[_-]?key|client[_-]?secret|private[_-]?key|credential)\s*[=:])\s*[^\s\x1B]{4,}"#,
        #"(?i)://[^\s/:@]{1,128}:[^\s/@]{4,}@"#,
        #"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"#,
        #"[A-Za-z0-9_+/=-]{32,}"#
    ]

    private let sensitiveSignals = [
        "authorization:", "password", "passwd", "secret", "api_key", "api-key",
        "apikey", "client_secret", "client-secret", "private_key", "private-key",
        "credential", "begin rsa " + "private key", "begin ec " + "private key",
        "begin " + "private key"
    ]

    mutating func process(_ incoming: Data) -> Data {
        guard incoming.count <= maximumInputBytes else {
            reset()
            return markerData(terminated: true)
        }
        pending.append(incoming)
        var output = Data()

        while let newline = pending.firstIndex(of: 0x0A) {
            let end = pending.index(after: newline)
            let record = Data(pending[..<end])
            pending.replaceSubrange(..<end, with: EmptyCollection<UInt8>())
            output.append(sanitize(record))
        }

        if pending.count > maximumRecordBytes {
            reset()
            output.append(markerData(terminated: true))
        }
        return output
    }

    /// Discards an unterminated record. Retaining it would allow a credential
    /// split at a replay/reconnect boundary to bypass a stateless expression.
    mutating func reset() {
        pending.resetBytes(in: pending.startIndex..<pending.endIndex)
        pending.removeAll(keepingCapacity: false)
    }

    private func sanitize(_ record: Data) -> Data {
        let terminated = record.last == 0x0A
        guard record.count <= maximumRecordBytes,
              var value = String(data: record, encoding: .utf8) else {
            return markerData(terminated: terminated)
        }

        let lowercase = value.lowercased()
        if sensitiveSignals.contains(where: { lowercase.contains($0) }) {
            return markerData(terminated: terminated)
        }
        for pattern in patterns {
            value = value.replacingOccurrences(
                of: pattern,
                with: marker,
                options: [.regularExpression, .caseInsensitive]
            )
        }
        guard let encoded = value.data(using: .utf8),
              encoded.count <= maximumRecordBytes + 4 * marker.utf8.count else {
            return markerData(terminated: terminated)
        }
        return encoded
    }

    private func markerData(terminated: Bool) -> Data {
        Data((marker + (terminated ? "\n" : "")).utf8)
    }
}
