import Foundation

enum AppRoute: Equatable, Sendable {
    case workspace(String)
    case approval(String)
    case activity
}

struct DeepLinkRouter: Sendable {
    private let configuration: AppConfiguration

    init(configuration: AppConfiguration) {
        self.configuration = configuration
    }

    func route(for url: URL) -> AppRoute? {
        guard url.scheme?.lowercased() == "https",
              url.host?.lowercased() == configuration.passkeyRelyingPartyID.lowercased(),
              (url.port ?? 443) == 443,
              url.user == nil,
              url.password == nil,
              url.query == nil,
              url.fragment == nil else { return nil }

        let components = url.pathComponents.filter { $0 != "/" }
        guard components.first == "app" else { return nil }
        if components == ["app", "activity"] { return .activity }
        guard components.count == 3, validOpaqueID(components[2]) else { return nil }
        switch components[1] {
        case "workspaces": return .workspace(components[2])
        case "approvals": return .approval(components[2])
        default: return nil
        }
    }

    private func validOpaqueID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard (1...128).contains(bytes.count), let first = bytes.first, isASCIIAlphaNumeric(first) else {
            return false
        }
        return bytes.dropFirst().allSatisfy {
            isASCIIAlphaNumeric($0) || $0 == 0x2E || $0 == 0x5F || $0 == 0x3A || $0 == 0x2D
        }
    }

    private func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
    }
}
