import Foundation

/// Converts repository- and terminal-controlled labels into inert display text.
/// The caller must retain the original value for API requests and identifiers.
enum HostileDisplayText {
    static let defaultScalarLimit = 512

    static func sanitized(_ rawValue: String, scalarLimit: Int = defaultScalarLimit) -> String {
        let limit = max(1, min(scalarLimit, 4_096))
        var result = ""
        var consumed = 0

        for scalar in rawValue.unicodeScalars {
            guard consumed < limit else {
                result.append("…")
                break
            }
            consumed += 1
            if scalar.value == 0x5C || isUnsafeForDisplay(scalar.value) {
                result.append(visibleEscape(scalar.value))
            } else {
                result.unicodeScalars.append(scalar)
            }
        }
        return result
    }

    private static func visibleEscape(_ value: UInt32) -> String {
        let digits = String(value, radix: 16, uppercase: true)
        let padding = String(repeating: "0", count: max(0, 4 - digits.count))
        return "\\u{\(padding)\(digits)}"
    }

    private static func isUnsafeForDisplay(_ value: UInt32) -> Bool {
        switch value {
        case 0x0000...0x001F, 0x007F...0x009F,
             0x00AD, 0x061C, 0x180E,
             0x200B...0x200F, 0x2028...0x202E,
             0x2060...0x206F, 0xFEFF, 0xFFF9...0xFFFB,
             0xE0001, 0xE0020...0xE007F:
            return true
        default:
            return false
        }
    }
}
