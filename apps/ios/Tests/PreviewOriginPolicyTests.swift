import Foundation
import XCTest
@testable import CodexMobile

final class PreviewOriginPolicyTests: XCTestCase {
    private let policy = PreviewOriginPolicy(allowedHost: "ws-1.preview.codex.example.test", allowedPort: 443)

    func testAllowsSameOriginPathsQueriesAndFragments() throws {
        let base = try XCTUnwrap(URL(string: "https://ws-1.preview.codex.example.test/app"))
        let withQuery = try XCTUnwrap(URL(string: "https://ws-1.preview.codex.example.test/app?screen=files"))
        let withFragment = try XCTUnwrap(URL(string: "https://ws-1.preview.codex.example.test/app#details"))

        XCTAssertTrue(policy.permits(base))
        XCTAssertTrue(policy.permits(withQuery))
        XCTAssertTrue(policy.permits(withFragment))
    }

    func testRejectsOriginChangesAndUserInfo() throws {
        XCTAssertFalse(policy.permits(try XCTUnwrap(URL(string: "http://ws-1.preview.codex.example.test/app"))))
        XCTAssertFalse(policy.permits(try XCTUnwrap(URL(string: "https://other.preview.codex.example.test/app"))))
        XCTAssertFalse(policy.permits(try XCTUnwrap(URL(string: "https://ws-1.preview.codex.example.test:8443/app"))))
        XCTAssertFalse(policy.permits(try XCTUnwrap(URL(string: "https://user@ws-1.preview.codex.example.test/app"))))
    }
}
