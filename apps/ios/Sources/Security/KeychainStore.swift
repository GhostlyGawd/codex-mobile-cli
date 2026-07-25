import Foundation
import Security

enum KeychainError: LocalizedError, Equatable, Sendable {
    case status(OSStatus)
    case invalidData

    var errorDescription: String? {
        switch self {
        case let .status(status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown Keychain error"
            return "Keychain error \(status): \(message)"
        case .invalidData:
            return "The Keychain item contained invalid data."
        }
    }
}
final class KeychainStore: @unchecked Sendable {
    private let service: String
    private let accessGroup: String?

    init(service: String = "CodexMobile", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    func data(for account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        guard let data = result as? Data else { throw KeychainError.invalidData }
        return data
    }

    func set(_ data: Data, for account: String) throws {
        let query = baseQuery(account: account)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else { throw KeychainError.status(updateStatus) }

        var item = query
        attributes.forEach { item[$0.key] = $0.value }
        let addStatus = SecItemAdd(item as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw KeychainError.status(addStatus) }
    }

    func delete(_ account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.status(status)
        }
    }

    private func baseQuery(account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}

actor SessionStore {
    private let keychain: KeychainStore
    private let account = "owner-session-v1"
    private var cached: SessionTokens?
    private var didLoad = false

    init(keychain: KeychainStore = KeychainStore()) {
        self.keychain = keychain
    }

    func restore() throws -> SessionTokens? {
        if didLoad { return cached }
        didLoad = true
        guard let data = try keychain.data(for: account) else { return nil }
        do {
            let tokens = try JSONDecoder.codex.decode(SessionTokens.self, from: data)
            cached = tokens
            return tokens
        } catch {
            try? keychain.delete(account)
            throw KeychainError.invalidData
        }
    }

    func save(_ tokens: SessionTokens) throws {
        let encoded = try JSONEncoder.codex.encode(tokens)
        try keychain.set(encoded, for: account)
        cached = tokens
        didLoad = true
    }

    func current() throws -> SessionTokens? {
        try restore()
    }

    func accessToken() throws -> String? {
        try restore()?.accessToken
    }

    func clear() throws {
        try keychain.delete(account)
        cached = nil
        didLoad = true
    }
}
