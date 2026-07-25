import Foundation

struct AppConfiguration: Equatable, Sendable {
    let apiBaseURL: URL
    let passkeyRelyingPartyID: String
    let previewAllowedHostSuffix: String

    static func load(bundle: Bundle = .main) -> AppConfiguration {
        let apiString = bundle.object(forInfoDictionaryKey: "APIBaseURL") as? String ?? "https://api.codex.invalid"
        let relyingPartyID = (bundle.object(forInfoDictionaryKey: "PasskeyRelyingPartyIdentifier") as? String) ?? "codex.invalid"
        let previewSuffix = (bundle.object(forInfoDictionaryKey: "PreviewAllowedHostSuffix") as? String) ?? ".preview.codex.invalid"
        return AppConfiguration(
            apiBaseURL: URL(string: apiString) ?? (URL(string: "https://api.codex.invalid")!),
            passkeyRelyingPartyID: relyingPartyID,
            previewAllowedHostSuffix: previewSuffix
        )
    }

    var configurationProblem: String? {
        guard apiBaseURL.scheme?.lowercased() == "https",
              let host = apiBaseURL.host?.lowercased(),
              !host.hasSuffix(".invalid"),
              apiBaseURL.user == nil,
              apiBaseURL.password == nil,
              apiBaseURL.query == nil,
              apiBaseURL.fragment == nil else {
            return "Set an HTTPS API_BASE_URL and stable PASSKEY_RP_ID in Config/Local.xcconfig."
        }
        let relyingParty = passkeyRelyingPartyID.lowercased()
        guard Self.isValidDNSName(relyingParty),
              !relyingParty.hasSuffix(".invalid"),
              host == relyingParty || host.hasSuffix("." + relyingParty) else {
            return "The API host must be the relying-party domain or one of its subdomains."
        }
        return nil
    }

    var isConfigured: Bool { configurationProblem == nil }

    func permitsPreviewHost(_ candidate: String) -> Bool {
        let host = candidate.lowercased()
        let suffix = previewAllowedHostSuffix.lowercased()
        let relyingParty = passkeyRelyingPartyID.lowercased()
        guard suffix.hasPrefix("."),
              suffix.utf8.count > 2,
              !suffix.hasSuffix(".invalid"),
              Self.isValidDNSName(String(suffix.dropFirst())),
              Self.isValidDNSName(host) else { return false }

        let bareSuffix = String(suffix.dropFirst())
        guard bareSuffix == relyingParty || bareSuffix.hasSuffix("." + relyingParty) else {
            return false
        }
        return host.count > suffix.count && host.hasSuffix(suffix)
    }

    private static func isValidDNSName(_ value: String) -> Bool {
        guard (1...253).contains(value.utf8.count), !value.hasSuffix(".") else { return false }
        return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            let bytes = Array(label.utf8)
            guard (1...63).contains(bytes.count),
                  let first = bytes.first,
                  let last = bytes.last,
                  isASCIIAlphaNumeric(first),
                  isASCIIAlphaNumeric(last) else { return false }
            return bytes.allSatisfy { isASCIIAlphaNumeric($0) || $0 == 0x2D }
        }
    }

    private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte) || (0x61...0x7A).contains(byte)
    }
}
