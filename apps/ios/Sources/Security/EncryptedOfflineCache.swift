import CryptoKit
import Foundation
import Security

protocol CacheKeyProviding: Sendable {
    func keyData() async throws -> Data
    func destroyKey() async throws
}

extension CacheKeyProviding {
    func destroyKey() async throws {}
}

struct OfflineTerminalFrame: Codable, Equatable, Sendable {
    let sequence: UInt64
    let output: Data
}

struct OfflineTerminalHistory: Codable, Equatable, Sendable {
    let lastSequence: UInt64
    let frames: [OfflineTerminalFrame]
}

struct OfflineTerminalTabHistory: Equatable, Sendable {
    let tabID: String
    let history: OfflineTerminalHistory
}

actor KeychainCacheKeyProvider: CacheKeyProviding {
    private let keychain: KeychainStore
    private let account = "offline-cache-aes256-v1"

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

actor EncryptedOfflineCache {
    private struct CachedFile: Codable {
        let workspaceID: String
        let document: FileDocument
        let viewedAt: Date
    }

    private struct CachedDiff: Codable {
        let workspaceID: String
        let document: DiffDocument
        let viewedAt: Date
    }

    private struct CachedTerminalHistory: Codable {
        let workspaceID: String
        let tabID: String
        var lastSequence: UInt64
        var frames: [OfflineTerminalFrame]
        var viewedAt: Date
    }

    private struct State: Codable {
        var dashboard: DashboardCacheSnapshot? = nil
        var files: [String: CachedFile] = [:]
        var diffs: [String: CachedDiff] = [:]
        var terminalHistories: [String: CachedTerminalHistory] = [:]

        private enum CodingKeys: String, CodingKey {
            case dashboard, files, diffs, terminalHistories
        }

        init() {}

        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            dashboard = try values.decodeIfPresent(DashboardCacheSnapshot.self, forKey: .dashboard)
            files = try values.decodeIfPresent([String: CachedFile].self, forKey: .files) ?? [:]
            diffs = try values.decodeIfPresent([String: CachedDiff].self, forKey: .diffs) ?? [:]
            terminalHistories = try values.decodeIfPresent(
                [String: CachedTerminalHistory].self,
                forKey: .terminalHistories
            ) ?? [:]
        }
    }

    private let fileURL: URL
    private let keyProvider: any CacheKeyProviding
    private let pathPolicy: SensitivePathPolicy
    private let maximumEncryptedBytes: Int
    private var loadedState: State?

    init(
        fileURL: URL? = nil,
        keyProvider: any CacheKeyProviding = KeychainCacheKeyProvider(),
        pathPolicy: SensitivePathPolicy = SensitivePathPolicy(),
        maximumEncryptedBytes: Int = 8 * 1_024 * 1_024
    ) {
        if let fileURL {
            self.fileURL = fileURL
        } else {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            self.fileURL = support.appending(path: "CodexMobile/offline-cache-v1.bin")
        }
        self.keyProvider = keyProvider
        self.pathPolicy = pathPolicy
        self.maximumEncryptedBytes = maximumEncryptedBytes
    }

    func saveDashboard(_ snapshot: DashboardCacheSnapshot) async throws {
        var state = try await loadState()
        state.dashboard = snapshot
        try await persist(state)
    }

    func dashboard() async throws -> DashboardCacheSnapshot? {
        (try await loadState()).dashboard
    }

    func saveFile(workspaceID: String, document: FileDocument) async throws {
        guard document.kind == .text,
              document.cacheDirective == .ordinary,
              pathPolicy.permitsCaching(path: document.path) else {
            throw ClientError.forbidden("This file is excluded from the offline cache.")
        }
        var state = try await loadState()
        state.files[fileKey(workspaceID: workspaceID, path: document.path)] = CachedFile(
            workspaceID: workspaceID,
            document: document,
            viewedAt: Date()
        )
        trim(&state)
        try await persist(state)
    }

    func file(workspaceID: String, path: String) async throws -> FileDocument? {
        guard pathPolicy.permitsCaching(path: path) else { return nil }
        return (try await loadState()).files[fileKey(workspaceID: workspaceID, path: path)]?.document
    }

    func files(workspaceID: String) async throws -> [FileDocument] {
        (try await loadState()).files.values
            .filter { $0.workspaceID == workspaceID && pathPolicy.permitsCaching(path: $0.document.path) }
            .sorted { $0.viewedAt > $1.viewedAt }
            .map(\.document)
    }

    func saveDiff(workspaceID: String, document: DiffDocument) async throws {
        guard !document.isBinary,
              document.cacheDirective == .ordinary,
              pathPolicy.permitsCaching(path: document.path) else {
            throw ClientError.forbidden("This diff is excluded from the offline cache.")
        }
        var state = try await loadState()
        state.diffs[fileKey(workspaceID: workspaceID, path: document.path)] = CachedDiff(
            workspaceID: workspaceID,
            document: document,
            viewedAt: Date()
        )
        trim(&state)
        try await persist(state)
    }

    func diff(workspaceID: String, path: String) async throws -> DiffDocument? {
        guard pathPolicy.permitsCaching(path: path) else { return nil }
        return (try await loadState()).diffs[fileKey(workspaceID: workspaceID, path: path)]?.document
    }

    func diffs(workspaceID: String) async throws -> [DiffDocument] {
        (try await loadState()).diffs.values
            .filter { $0.workspaceID == workspaceID && pathPolicy.permitsCaching(path: $0.document.path) }
            .sorted { $0.viewedAt > $1.viewedAt }
            .map(\.document)
    }

    func appendTerminalFrames(
        workspaceID: String,
        tabID: String,
        frames: [OfflineTerminalFrame]
    ) async throws {
        guard !workspaceID.isEmpty, !tabID.isEmpty, !frames.isEmpty else { return }
        var state = try await loadState()
        let key = terminalKey(workspaceID: workspaceID, tabID: tabID)
        var history = state.terminalHistories[key] ?? CachedTerminalHistory(
            workspaceID: workspaceID,
            tabID: tabID,
            lastSequence: 0,
            frames: [],
            viewedAt: Date()
        )
        var recordedSequences = Set(history.frames.map(\.sequence))
        for frame in frames.sorted(by: { $0.sequence < $1.sequence }) {
            history.lastSequence = max(history.lastSequence, frame.sequence)
            if !recordedSequences.contains(frame.sequence),
               !frame.output.isEmpty,
               frame.output.count <= 128 * 1_024 {
                history.frames.append(frame)
                recordedSequences.insert(frame.sequence)
            }
        }
        history.frames.sort { $0.sequence < $1.sequence }
        history.viewedAt = Date()
        trimTerminalFrames(&history.frames)
        state.terminalHistories[key] = history
        trim(&state)
        try await persist(state)
    }

    func terminalHistory(workspaceID: String, tabID: String) async throws -> OfflineTerminalHistory? {
        let key = terminalKey(workspaceID: workspaceID, tabID: tabID)
        guard let history = (try await loadState()).terminalHistories[key] else { return nil }
        return OfflineTerminalHistory(lastSequence: history.lastSequence, frames: history.frames)
    }

    func terminalHistories(workspaceID: String) async throws -> [OfflineTerminalTabHistory] {
        (try await loadState()).terminalHistories.values
            .filter { $0.workspaceID == workspaceID }
            .sorted { $0.viewedAt > $1.viewedAt }
            .map {
                OfflineTerminalTabHistory(
                    tabID: $0.tabID,
                    history: OfflineTerminalHistory(lastSequence: $0.lastSequence, frames: $0.frames)
                )
            }
    }

    func resetTerminalHistory(workspaceID: String, tabID: String) async throws {
        guard !workspaceID.isEmpty, !tabID.isEmpty else { return }
        var state = try await loadState()
        let key = terminalKey(workspaceID: workspaceID, tabID: tabID)
        guard state.terminalHistories.removeValue(forKey: key) != nil else { return }
        try await persist(state)
    }

    func clear() async throws {
        var keyDeletionError: Error?
        do {
            try await keyProvider.destroyKey()
        } catch {
            keyDeletionError = error
        }

        var fileDeletionError: Error?
        do {
            if FileManager.default.fileExists(atPath: fileURL.path) {
                try FileManager.default.removeItem(at: fileURL)
            }
        } catch {
            fileDeletionError = error
        }
        loadedState = State()

        // Attempt both cryptographic erasure and physical removal before surfacing either
        // failure. A successful key deletion makes a leftover ciphertext unrecoverable.
        if let keyDeletionError { throw keyDeletionError }
        if let fileDeletionError { throw fileDeletionError }
    }

    private func loadState() async throws -> State {
        if let loadedState { return loadedState }
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            let empty = State()
            loadedState = empty
            return empty
        }

        let encrypted = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
        guard encrypted.count <= maximumEncryptedBytes else {
            throw ClientError.malformedData("The offline cache exceeded its configured size limit.")
        }
        let key = SymmetricKey(data: try await keyProvider.keyData())
        do {
            let box = try AES.GCM.SealedBox(combined: encrypted)
            let plaintext = try AES.GCM.open(box, using: key, authenticating: Data("CodexMobile.offline.v1".utf8))
            let state = try JSONDecoder.codex.decode(State.self, from: plaintext)
            loadedState = state
            return state
        } catch {
            try? FileManager.default.removeItem(at: fileURL)
            throw ClientError.malformedData("The offline cache failed authentication and was removed.")
        }
    }

    private func persist(_ proposed: State) async throws {
        var state = proposed
        var plaintext = try JSONEncoder.codex.encode(state)
        while plaintext.count > maximumEncryptedBytes / 2,
              !state.files.isEmpty || !state.diffs.isEmpty || !state.terminalHistories.isEmpty {
            removeOldestRecord(from: &state)
            plaintext = try JSONEncoder.codex.encode(state)
        }
        guard plaintext.count <= maximumEncryptedBytes / 2 else {
            throw ClientError.unavailable("The offline metadata is too large to cache safely.")
        }

        let key = SymmetricKey(data: try await keyProvider.keyData())
        let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: Data("CodexMobile.offline.v1".utf8))
        guard let combined = sealed.combined, combined.count <= maximumEncryptedBytes else {
            throw ClientError.unavailable("The encrypted offline cache exceeded its size limit.")
        }

        var directoryURL = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try directoryURL.setResourceValues(resourceValues)
        try combined.write(to: fileURL, options: .atomic)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: fileURL.path)
        loadedState = state
    }

    private func trim(_ state: inout State) {
        while state.files.count > 12 {
            guard let oldest = state.files.min(by: { $0.value.viewedAt < $1.value.viewedAt }) else { break }
            state.files.removeValue(forKey: oldest.key)
        }
        while state.diffs.count > 12 {
            guard let oldest = state.diffs.min(by: { $0.value.viewedAt < $1.value.viewedAt }) else { break }
            state.diffs.removeValue(forKey: oldest.key)
        }
        while state.terminalHistories.count > 12 {
            guard let oldest = state.terminalHistories.min(by: { $0.value.viewedAt < $1.value.viewedAt }) else {
                break
            }
            state.terminalHistories.removeValue(forKey: oldest.key)
        }
    }

    private func removeOldestRecord(from state: inout State) {
        let oldestFile = state.files.min(by: { $0.value.viewedAt < $1.value.viewedAt })
        let oldestDiff = state.diffs.min(by: { $0.value.viewedAt < $1.value.viewedAt })
        let oldestTerminal = state.terminalHistories.min(by: { $0.value.viewedAt < $1.value.viewedAt })
        let candidates: [(date: Date, kind: Int, key: String)] = [
            oldestFile.map { (date: $0.value.viewedAt, kind: 0, key: $0.key) },
            oldestDiff.map { (date: $0.value.viewedAt, kind: 1, key: $0.key) },
            oldestTerminal.map { (date: $0.value.viewedAt, kind: 2, key: $0.key) }
        ].compactMap { $0 }
        guard let oldest = candidates.min(by: { $0.date < $1.date }) else { return }
        switch oldest.kind {
        case 0: state.files.removeValue(forKey: oldest.key)
        case 1: state.diffs.removeValue(forKey: oldest.key)
        default: state.terminalHistories.removeValue(forKey: oldest.key)
        }
    }

    private func fileKey(workspaceID: String, path: String) -> String {
        workspaceID + "\u{001F}" + path
    }

    private func terminalKey(workspaceID: String, tabID: String) -> String {
        workspaceID + "\u{001F}" + tabID
    }

    private func trimTerminalFrames(_ frames: inout [OfflineTerminalFrame]) {
        var bytes = frames.reduce(0) { $0 + $1.output.count }
        while frames.count > 256 || bytes > 512 * 1_024 {
            guard let first = frames.first else { break }
            bytes -= first.output.count
            frames.removeFirst()
        }
    }
}
