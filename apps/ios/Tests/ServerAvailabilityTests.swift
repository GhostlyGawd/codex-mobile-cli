import Foundation
import XCTest
@testable import CodexMobile

final class ServerAvailabilityTests: XCTestCase {
    func testSeparatesServerLossSignalsFromAuthenticationAndOfflineState() {
        XCTAssertTrue(AppModel.isServerAvailabilityFailure(URLError(.cannotConnectToHost)))
        XCTAssertTrue(AppModel.isServerAvailabilityFailure(ClientError.unavailable("maintenance")))
        XCTAssertTrue(AppModel.isServerAvailabilityFailure(ClientError.server(status: 500, message: "failed")))
        XCTAssertFalse(AppModel.isServerAvailabilityFailure(ClientError.unauthorized))
        XCTAssertFalse(AppModel.isServerAvailabilityFailure(ClientError.offline))
    }
}
