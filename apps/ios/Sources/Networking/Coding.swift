import Foundation

extension JSONEncoder {
    static var codex: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .custom { codingPath in
            let propertyKey = codingPath.last?.stringValue ?? ""
            if isEnvironmentVariableKey(codingPath) {
                return CodexJSONCodingKey(stringValue: propertyKey)!
            }
            return CodexJSONCodingKey(stringValue: codexWireKey(for: propertyKey))!
        }
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }
}

extension JSONDecoder {
    static var codex: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .custom { codingPath in
            let wireKey = codingPath.last?.stringValue ?? ""
            if isEnvironmentVariableKey(codingPath) {
                return CodexJSONCodingKey(stringValue: wireKey)!
            }
            return CodexJSONCodingKey(stringValue: codexPropertyName(for: wireKey))!
        }
        decoder.dateDecodingStrategy = .custom { decoder in
            let value = try decoder.singleValueContainer().decode(String.self)
            let fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = fractional.date(from: value) { return date }
            let regular = ISO8601DateFormatter()
            regular.formatOptions = [.withInternetDateTime]
            if let date = regular.date(from: value) { return date }
            throw DecodingError.dataCorruptedError(
                in: try decoder.singleValueContainer(),
                debugDescription: "Invalid RFC 3339 timestamp"
            )
        }
        return decoder
    }
}

private struct CodexJSONCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func isEnvironmentVariableKey(_ codingPath: [any CodingKey]) -> Bool {
    guard codingPath.count >= 2 else { return false }
    let parent = codingPath[codingPath.count - 2].stringValue
    return parent == "environmentVariables" || parent == "environment_variables"
}

private func codexPropertyName(for wireKey: String) -> String {
    guard wireKey.contains("_") else { return wireKey }

    let components = wireKey.split(separator: "_", omittingEmptySubsequences: false).map(String.init)
    guard let first = components.first else { return wireKey }

    var propertyName = first
    var index = 1
    while index < components.count {
        let component = components[index]
        let next = index + 1 < components.count ? components[index + 1] : nil

        switch (component, next) {
        case ("gi", "b"):
            propertyName += "GiB"
            index += 2
        case ("e", "tag"):
            propertyName += "ETag"
            index += 2
        case ("id", _):
            propertyName += "ID"
            index += 1
        case ("ids", _):
            propertyName += "IDs"
            index += 1
        case ("url", _):
            propertyName += "URL"
            index += 1
        case ("json", _):
            propertyName += "JSON"
            index += 1
        case ("uuid", _):
            propertyName += "UUID"
            index += 1
        default:
            propertyName += component.prefix(1).uppercased() + String(component.dropFirst())
            index += 1
        }
    }
    return propertyName
}

private func codexWireKey(for propertyKey: String) -> String {
    var normalized = propertyKey
    let acronyms = [
        (swift: "IDs", wire: "ids"),
        (swift: "UUID", wire: "uuid"),
        (swift: "JSON", wire: "json"),
        (swift: "URL", wire: "url"),
        (swift: "ETag", wire: "e_tag"),
        (swift: "GiB", wire: "gi_b"),
        (swift: "ID", wire: "id")
    ]
    for acronym in acronyms {
        normalized = normalized.replacingOccurrences(
            of: acronym.swift,
            with: "_\(acronym.wire)_"
        )
    }

    return normalized
        .split(separator: "_", omittingEmptySubsequences: true)
        .flatMap { snakeCaseWords(in: String($0)) }
        .joined(separator: "_")
}

private func snakeCaseWords(in component: String) -> [String] {
    var words: [String] = []
    var current = ""
    for character in component {
        if character.isUppercase, !current.isEmpty {
            words.append(current.lowercased())
            current = String(character)
        } else {
            current.append(character)
        }
    }
    if !current.isEmpty { words.append(current.lowercased()) }
    return words
}

extension Data {
    var base64URLEncodedString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLEncoded value: String) {
        guard (1...1_048_576).contains(value.utf8.count),
              value.utf8.allSatisfy({
                  (0x30...0x39).contains($0)
                      || (0x41...0x5A).contains($0)
                      || (0x61...0x7A).contains($0)
                      || $0 == 0x2D
                      || $0 == 0x5F
              }) else { return nil }
        var normalized = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = normalized.count % 4
        if remainder > 0 { normalized.append(String(repeating: "=", count: 4 - remainder)) }
        self.init(base64Encoded: normalized)
    }
}
