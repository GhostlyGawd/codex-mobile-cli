import Foundation
import XCTest
@testable import CodexMobile

private actor TestCacheKeyProvider: CacheKeyProviding {
    private(set) var wasDestroyed = false

    func keyData() async throws -> Data { Data(repeating: 0x5A, count: 32) }
    func destroyKey() async throws { wasDestroyed = true }
}

@MainActor
final class EncryptedOfflineCacheTests: XCTestCase {
    func testEncryptsAndRestoresOrdinaryText() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        let cache = EncryptedOfflineCache(fileURL: url, keyProvider: TestCacheKeyProvider())
        let document = FileDocument(
            path: "Sources/App.swift",
            content: "private fixture marker",
            etag: "etag-1",
            languageHint: "swift",
            kind: .text,
            isReadOnly: false,
            cacheDirective: .ordinary
        )
        try await cache.saveFile(workspaceID: "workspace", document: document)

        let encrypted = try Data(contentsOf: url)
        let restored = try await cache.file(workspaceID: "workspace", path: document.path)
        let listed = try await cache.files(workspaceID: "workspace")
        XCTAssertNil(String(data: encrypted, encoding: .utf8)?.range(of: "private fixture marker"))
        XCTAssertEqual(restored, document)
        XCTAssertEqual(listed, [document])
    }

    func testRefusesSensitivePathsAndServerNeverDirective() async {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let cache = EncryptedOfflineCache(fileURL: url, keyProvider: TestCacheKeyProvider())
        let sensitive = FileDocument(
            path: ".env",
            content: "TOKEN=secret",
            etag: "etag",
            languageHint: nil,
            kind: .text,
            isReadOnly: true,
            cacheDirective: .ordinary
        )
        do {
            try await cache.saveFile(workspaceID: "workspace", document: sensitive)
            XCTFail("Sensitive path should not be cached")
        } catch {}

        let denied = FileDocument(
            path: "Sources/App.swift",
            content: "ordinary path, server denied",
            etag: "etag",
            languageHint: "swift",
            kind: .text,
            isReadOnly: false,
            cacheDirective: .never
        )
        do {
            try await cache.saveFile(workspaceID: "workspace", document: denied)
            XCTFail("Never directive should not be cached")
        } catch {}
    }

    func testClearRemovesCiphertextAndDestroysItsKey() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        let keyProvider = TestCacheKeyProvider()
        let cache = EncryptedOfflineCache(fileURL: url, keyProvider: keyProvider)
        try await cache.saveDashboard(DashboardCacheSnapshot(savedAt: Date(), workspaces: [], activities: []))

        try await cache.clear()

        let wasDestroyed = await keyProvider.wasDestroyed
        let restoredDashboard = try await cache.dashboard()
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        XCTAssertTrue(wasDestroyed)
        XCTAssertNil(restoredDashboard)
    }

    func testStoresBoundedTerminalHistoryAndHighestProcessedSequence() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        let cache = EncryptedOfflineCache(fileURL: url, keyProvider: TestCacheKeyProvider())
        try await cache.appendTerminalFrames(
            workspaceID: "workspace",
            tabID: "00112233-4455-4677-8899-aabbccddeeff",
            frames: [
                OfflineTerminalFrame(sequence: 1, output: Data("hello\n".utf8)),
                OfflineTerminalFrame(sequence: 2, output: Data(repeating: 0x41, count: 129 * 1_024))
            ]
        )

        let restored = try await cache.terminalHistory(
            workspaceID: "workspace",
            tabID: "00112233-4455-4677-8899-aabbccddeeff"
        )
        let listed = try await cache.terminalHistories(workspaceID: "workspace")
        let encrypted = try Data(contentsOf: url)

        XCTAssertEqual(restored?.lastSequence, 2)
        XCTAssertEqual(restored?.frames, [OfflineTerminalFrame(sequence: 1, output: Data("hello\n".utf8))])
        XCTAssertEqual(listed.map(\.tabID), ["00112233-4455-4677-8899-aabbccddeeff"])
        XCTAssertNil(String(data: encrypted, encoding: .utf8)?.range(of: "hello"))
    }

    func testReplayResetRemovesOnlySelectedTerminalHistory() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        let cache = EncryptedOfflineCache(fileURL: url, keyProvider: TestCacheKeyProvider())
        for tabID in ["tab-a", "tab-b"] {
            try await cache.appendTerminalFrames(
                workspaceID: "workspace",
                tabID: tabID,
                frames: [OfflineTerminalFrame(sequence: 7, output: Data(tabID.utf8))]
            )
        }

        try await cache.resetTerminalHistory(workspaceID: "workspace", tabID: "tab-a")

        let resetHistory = try await cache.terminalHistory(workspaceID: "workspace", tabID: "tab-a")
        let retainedHistory = try await cache.terminalHistory(workspaceID: "workspace", tabID: "tab-b")

        XCTAssertNil(resetHistory)
        XCTAssertEqual(
            retainedHistory,
            OfflineTerminalHistory(
                lastSequence: 7,
                frames: [OfflineTerminalFrame(sequence: 7, output: Data("tab-b".utf8))]
            )
        )
    }

    func testTamperedCiphertextFailsClosedAndIsRemoved() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        let keyProvider = TestCacheKeyProvider()
        let cache = EncryptedOfflineCache(fileURL: url, keyProvider: keyProvider)
        try await cache.saveDashboard(DashboardCacheSnapshot(savedAt: Date(), workspaces: [], activities: []))

        var bytes = try Data(contentsOf: url)
        bytes[bytes.startIndex] ^= 0x01
        try bytes.write(to: url, options: .atomic)
        let reopened = EncryptedOfflineCache(fileURL: url, keyProvider: keyProvider)

        do {
            _ = try await reopened.dashboard()
            XCTFail("Tampered offline ciphertext should not authenticate")
        } catch {
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        }
    }
}
