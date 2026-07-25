import CryptoKit
import Foundation
import Security

protocol ComposerKeyProviding: Sendable {
    func keyData() async throws -> Data
    func destroyKey() async throws
}

extension ComposerKeyProviding {
    func destroyKey() async throws {}
}

actor KeychainComposerKeyProvider: ComposerKeyProviding {
    private let keychain: KeychainStore
    private let account = "composer-aes256-v1"

    init(keychain: KeychainStore = KeychainStore()) {
        self.keychain = keychain
    }

    func keyData() async throws -> Data {
        if let existing = try keychain.data(for: account), existing.count == 32 {
            return existing
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw KeychainError.status(status) }
        let data = Data(bytes)
        try keychain.set(data, for: account)
        return data
    }

    func destroyKey() async throws {
        try keychain.delete(account)
    }
}

actor EncryptedComposerStore {
    private struct Target: Codable {
        var draft: String
        var history: [String]
        var updatedAt: Date
    }

    private struct State: Codable {
        var targets: [String: Target] = [:]
    }

    private static let maximumTextBytes = 64 * 1_024
    private static let maximumHistoryCount = 50
    private static let maximumTargets = 64
    private static let maximumEncryptedBytes = 2 * 1_024 * 1_024
    private static let associatedData = Data("CodexMobile.composer.v1".utf8)

    private let fileURL: URL
    private let keyProvider: any ComposerKeyProviding
    private var loadedState: State?

    init(fileURL: URL? = nil, keyProvider: any ComposerKeyProviding = KeychainComposerKeyProvider()) {
        if let fileURL {
            self.fileURL = fileURL
        } else {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            self.fileURL = support.appending(path: "CodexMobile/composer-v1.bin")
        }
        self.keyProvider = keyProvider
    }

    func draft(workspaceID: String, tabID: String) async throws -> String {
        try validateTarget(workspaceID: workspaceID, tabID: tabID)
        return (try await loadState()).targets[targetKey(workspaceID: workspaceID, tabID: tabID)]?.draft ?? ""
    }

    func saveDraft(_ value: String, workspaceID: String, tabID: String) async throws {
        try validateTarget(workspaceID: workspaceID, tabID: tabID)
        try validateText(value, allowEmpty: true)
        var state = try await loadState()
        let key = targetKey(workspaceID: workspaceID, tabID: tabID)
        var target = state.targets[key] ?? Target(draft: "", history: [], updatedAt: Date())
        target.draft = value
        target.updatedAt = Date()
        if target.draft.isEmpty, target.history.isEmpty {
            state.targets.removeValue(forKey: key)
        } else {
            state.targets[key] = target
        }
        trimTargets(&state)
        try await persist(state)
    }

    func history(workspaceID: String, tabID: String) async throws -> [String] {
        try validateTarget(workspaceID: workspaceID, tabID: tabID)
        return (try await loadState()).targets[targetKey(workspaceID: workspaceID, tabID: tabID)]?.history ?? []
    }

    // The UI calls this only after the WebSocket send has returned success.
    // Keeping draft clearing and history insertion in one authenticated write
    // prevents a crash between those two state transitions from losing input.
    func recordSuccessfulSend(_ value: String, workspaceID: String, tabID: String) async throws {
        try validateTarget(workspaceID: workspaceID, tabID: tabID)
        try validateText(value, allowEmpty: false)
        var state = try await loadState()
        let key = targetKey(workspaceID: workspaceID, tabID: tabID)
        var target = state.targets[key] ?? Target(draft: "", history: [], updatedAt: Date())
        target.draft = ""
        target.history.removeAll(where: { $0 == value })
        target.history.insert(value, at: 0)
        if target.history.count > Self.maximumHistoryCount {
            target.history.removeLast(target.history.count - Self.maximumHistoryCount)
        }
        target.updatedAt = Date()
        state.targets[key] = target
        trimTargets(&state)
        try await persist(state)
    }

    func clear() async throws {
        var keyError: Error?
        do { try await keyProvider.destroyKey() } catch { keyError = error }
        var fileError: Error?
        do {
            if FileManager.default.fileExists(atPath: fileURL.path) {
                try FileManager.default.removeItem(at: fileURL)
            }
        } catch { fileError = error }
        loadedState = State()
        if let keyError { throw keyError }
        if let fileError { throw fileError }
    }

    private func loadState() async throws -> State {
        if let loadedState { return loadedState }
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            let state = State()
            loadedState = state
            return state
        }
        let encrypted = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
        guard encrypted.count <= Self.maximumEncryptedBytes else {
            try? FileManager.default.removeItem(at: fileURL)
            throw ClientError.malformedData("The encrypted composer state exceeded its size limit and was removed.")
        }
        do {
            let key = SymmetricKey(data: try await keyProvider.keyData())
            let box = try AES.GCM.SealedBox(combined: encrypted)
            let plaintext = try AES.GCM.open(box, using: key, authenticating: Self.associatedData)
            var state = try JSONDecoder.codex.decode(State.self, from: plaintext)
            try validateLoadedState(&state)
            loadedState = state
            return state
        } catch {
            try? FileManager.default.removeItem(at: fileURL)
            throw ClientError.malformedData("The encrypted composer state failed authentication and was removed.")
        }
    }

    private func persist(_ state: State) async throws {
        let plaintext = try JSONEncoder.codex.encode(state)
        guard plaintext.count <= Self.maximumEncryptedBytes / 2 else {
            throw ClientError.unavailable("The encrypted composer history reached its size limit.")
        }
        let key = SymmetricKey(data: try await keyProvider.keyData())
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: Self.associatedData)
        guard let combined = box.combined, combined.count <= Self.maximumEncryptedBytes else {
            throw ClientError.unavailable("The encrypted composer history reached its size limit.")
        }
        var directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try directory.setResourceValues(resourceValues)
        try combined.write(to: fileURL, options: [.atomic, .completeFileProtection])
        loadedState = state
    }

    private func validateLoadedState(_ state: inout State) throws {
        guard state.targets.count <= Self.maximumTargets else { throw ClientError.invalidResponse }
        for (key, var target) in Array(state.targets) {
            guard !key.isEmpty, key.utf8.count <= 260, target.history.count <= Self.maximumHistoryCount else {
                throw ClientError.invalidResponse
            }
            try validateText(target.draft, allowEmpty: true)
            for value in target.history { try validateText(value, allowEmpty: false) }
            target.history = Array(target.history.prefix(Self.maximumHistoryCount))
            state.targets[key] = target
        }
    }

    private func validateTarget(workspaceID: String, tabID: String) throws {
        guard (1...128).contains(workspaceID.utf8.count), (1...128).contains(tabID.utf8.count),
              !workspaceID.contains("\0"), !tabID.contains("\0") else {
            throw ClientError.malformedData("The composer target was invalid.")
        }
    }

    private func validateText(_ value: String, allowEmpty: Bool) throws {
        let count = value.utf8.count
        guard count <= Self.maximumTextBytes, (allowEmpty || count > 0), !value.contains("\0") else {
            throw ClientError.malformedData("The composer text exceeded its size limit.")
        }
    }

    private func trimTargets(_ state: inout State) {
        while state.targets.count > Self.maximumTargets,
              let oldest = state.targets.min(by: { $0.value.updatedAt < $1.value.updatedAt }) {
            state.targets.removeValue(forKey: oldest.key)
        }
    }

    private func targetKey(workspaceID: String, tabID: String) -> String {
        workspaceID + "\u{001F}" + tabID
    }
}
