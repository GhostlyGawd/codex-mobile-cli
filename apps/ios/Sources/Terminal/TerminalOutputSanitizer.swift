import Foundation

/// Removes remote clipboard commands before bytes reach the terminal parser. The delegate also
/// denies clipboard callbacks, providing defense in depth for split OSC sequences.
struct TerminalOutputSanitizer: Sendable {
    private var pending = Data()
    private let maximumOSCBytes = 8_192

    mutating func process(_ incoming: Data) -> Data {
        pending.append(incoming)
        var safe = Data()
        var cursor = pending.startIndex

        while cursor < pending.endIndex {
            guard let start = nextOSCStart(from: cursor) else {
                safe.append(pending[cursor..<pending.endIndex])
                pending.removeAll(keepingCapacity: true)
                return safe
            }
            safe.append(pending[cursor..<start.index])
            guard let terminator = oscTerminator(after: start.contentStart) else {
                let incomplete = Data(pending[start.index..<pending.endIndex])
                if incomplete.count > maximumOSCBytes {
                    // Drop a pathological unterminated OSC rather than feeding it to the renderer.
                    pending.removeAll(keepingCapacity: true)
                } else {
                    pending = incomplete
                }
                return safe
            }

            let content = pending[start.contentStart..<terminator.contentEnd]
            let contentLength = pending.distance(from: start.contentStart, to: terminator.contentEnd)
            if contentLength <= maximumOSCBytes, !isClipboardOSC(content) {
                safe.append(pending[start.index..<terminator.sequenceEnd])
            }
            cursor = terminator.sequenceEnd
        }

        pending.removeAll(keepingCapacity: true)
        return safe
    }

    mutating func reset() {
        pending.removeAll(keepingCapacity: false)
    }

    private func nextOSCStart(from offset: Data.Index) -> (index: Data.Index, contentStart: Data.Index)? {
        var index = offset
        while index < pending.endIndex {
            if pending[index] == 0x9D {
                return (index, pending.index(after: index))
            }
            if pending[index] == 0x1B {
                let next = pending.index(after: index)
                if next == pending.endIndex { return (index, next) }
                if pending[next] == 0x5D { return (index, pending.index(after: next)) }
            }
            index = pending.index(after: index)
        }
        return nil
    }

    private func oscTerminator(after contentStart: Data.Index) -> (contentEnd: Data.Index, sequenceEnd: Data.Index)? {
        var index = contentStart
        while index < pending.endIndex {
            if pending[index] == 0x07 || pending[index] == 0x9C {
                return (index, pending.index(after: index))
            }
            if pending[index] == 0x1B {
                let next = pending.index(after: index)
                if next == pending.endIndex { return nil }
                if pending[next] == 0x5C {
                    return (index, pending.index(after: next))
                }
            }
            index = pending.index(after: index)
        }
        return nil
    }

    private func isClipboardOSC(_ content: Data.SubSequence) -> Bool {
        content.starts(with: [0x35, 0x32, 0x3B]) // "52;"
    }
}
