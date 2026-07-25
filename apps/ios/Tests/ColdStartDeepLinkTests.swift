import XCTest
@testable import CodexMobile

@MainActor
final class ColdStartDeepLinkTests: XCTestCase {
    func testValidatedLinkWaitsForSessionBootstrap() async {
        let model = AppModel.fixture()
        model.handleDeepLink(URL(string: "https://codex.example.test/app/approvals/approval_cold_start")!)

        XCTAssertNil(model.presentedApprovalID)
        await model.bootstrap()
        XCTAssertEqual(model.presentedApprovalID, "approval_cold_start")
    }

    func testColdStartInboxRetainsThenConsumesLinkOnce() {
        let inbox = ColdStartDeepLinkInbox()
        let url = URL(string: "https://codex.example.test/app/activity")!

        inbox.store(url)

        XCTAssertEqual(inbox.take(), url)
        XCTAssertNil(inbox.take())
    }
}
