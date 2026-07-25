import Foundation
import XCTest
@testable import CodexMobile

final class DeepLinkRouterTests: XCTestCase {
    private let router = DeepLinkRouter(configuration: AppConfiguration(
        apiBaseURL: URL(string: "https://api.codex.example.com")!,
        passkeyRelyingPartyID: "codex.example.com",
        previewAllowedHostSuffix: ".preview.codex.example.com"
    ))

    func testRoutesAuthenticatedUniversalLinks() {
        XCTAssertEqual(
            router.route(for: URL(string: "https://codex.example.com/app/approvals/a_123")!),
            .approval("a_123")
        )
        XCTAssertEqual(
            router.route(for: URL(string: "https://codex.example.com/app/workspaces/w-123")!),
            .workspace("w-123")
        )
        XCTAssertEqual(
            router.route(for: URL(string: "https://codex.example.com/app/workspaces/w:123.4")!),
            .workspace("w:123.4")
        )
    }

    func testRejectsForeignHostsCustomSchemesQueriesAndTraversal() {
        XCTAssertNil(router.route(for: URL(string: "https://evil.example/app/approvals/a")!))
        XCTAssertNil(router.route(for: URL(string: "https://codex.example.com:444/app/approvals/a")!))
        XCTAssertNil(router.route(for: URL(string: "codex-mobile://app/approvals/a")!))
        XCTAssertNil(router.route(for: URL(string: "https://codex.example.com/app/approvals/a?decision=approve")!))
        XCTAssertNil(router.route(for: URL(string: "https://codex.example.com/app/approvals/..")!))
    }
}
