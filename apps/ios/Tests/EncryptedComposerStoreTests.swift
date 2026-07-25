import Foundation
import XCTest
@testable import CodexMobile

private actor TestComposerKeyProvider: ComposerKeyProviding {
    func keyData() async throws -> Data { Data(repeating: 0x71, count: 32) }
}

@MainActor
final class EncryptedComposerStoreTests: XCTestCase {
    func testDraftAndHistoryAreEncryptedAndTargetScoped() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        let store = EncryptedComposerStore(fileURL: url, keyProvider: TestComposerKeyProvider())

        try await store.saveDraft("private draft marker", workspaceID: "workspace-a", tabID: "tab-a")
        let targetDraft = try await store.draft(workspaceID: "workspace-a", tabID: "tab-a")
        let otherDraft = try await store.draft(workspaceID: "workspace-a", tabID: "tab-b")
        XCTAssertEqual(targetDraft, "private draft marker")
        XCTAssertEqual(otherDraft, "")

        let ciphertext = try Data(contentsOf: url)
        XCTAssertNil(String(data: ciphertext, encoding: .utf8)?.range(of: "private draft marker"))

        let reopened = EncryptedComposerStore(fileURL: url, keyProvider: TestComposerKeyProvider())
        let reopenedDraft = try await reopened.draft(workspaceID: "workspace-a", tabID: "tab-a")
        XCTAssertEqual(reopenedDraft, "private draft marker")
    }

    func testDraftClearsOnlyWhenSuccessfulSendIsRecorded() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        let store = EncryptedComposerStore(fileURL: url, keyProvider: TestComposerKeyProvider())
        try await store.saveDraft("do not lose me", workspaceID: "workspace", tabID: "tab")

        let beforeSend = try await store.draft(workspaceID: "workspace", tabID: "tab")
        XCTAssertEqual(beforeSend, "do not lose me")
        try await store.recordSuccessfulSend("do not lose me", workspaceID: "workspace", tabID: "tab")

        let afterSend = try await store.draft(workspaceID: "workspace", tabID: "tab")
        let history = try await store.history(workspaceID: "workspace", tabID: "tab")
        XCTAssertEqual(afterSend, "")
        XCTAssertEqual(history, ["do not lose me"])
    }

    func testHistoryIsBoundedAndDeduplicated() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        let store = EncryptedComposerStore(fileURL: url, keyProvider: TestComposerKeyProvider())
        for index in 0..<60 {
            try await store.recordSuccessfulSend("message-\(index)", workspaceID: "workspace", tabID: "tab")
        }
        try await store.recordSuccessfulSend("message-40", workspaceID: "workspace", tabID: "tab")
        let history = try await store.history(workspaceID: "workspace", tabID: "tab")

        XCTAssertEqual(history.count, 50)
        XCTAssertEqual(history.first, "message-40")
        XCTAssertEqual(history.filter { $0 == "message-40" }.count, 1)
    }
}
