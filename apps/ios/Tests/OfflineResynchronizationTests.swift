import XCTest
@testable import CodexMobile

@MainActor
final class OfflineResynchronizationTests: XCTestCase {
    func testConnectivityTransitionMarksSnapshotStaleThenResynchronizes() async {
        let model = AppModel.fixture()
        await model.bootstrap()
        XCTAssertFalse(model.isShowingStaleData)

        await model.connectivityDidChange(isConnected: false)
        XCTAssertTrue(model.isShowingStaleData)

        await model.connectivityDidChange(isConnected: true)
        XCTAssertFalse(model.isShowingStaleData)
        XCTAssertFalse(model.workspaces.isEmpty)
        XCTAssertNil(model.lastError)
    }
}
