import XCTest
@testable import CodexMobile

final class SensitivePathPolicyTests: XCTestCase {
    private let policy = SensitivePathPolicy()

    func testAllowsOrdinaryRepositoryText() {
        XCTAssertTrue(policy.permitsCaching(path: "Sources/Feature/App.swift"))
        XCTAssertTrue(policy.permitsCaching(path: "docs/security.md"))
    }

    func testRejectsTraversalAndAbsolutePaths() {
        XCTAssertFalse(policy.permitsCaching(path: "../secret"))
        XCTAssertFalse(policy.permitsCaching(path: "/etc/passwd"))
        XCTAssertFalse(policy.permitsCaching(path: "Sources/../.env"))
    }

    func testRejectsCredentialsAndSensitiveDirectories() {
        for path in [
            ".env", ".env.production", ".ssh/id_ed25519", ".aws/credentials",
            ".codex/auth.json", "certificates/AuthKey.p8", ".git/config",
            "config/client-secret.json", ".config/gh/hosts.yml", ".docker/config.json",
            ".terraform/terraform.tfstate", "state/terraform.tfstate.backup"
        ] {
            XCTAssertFalse(policy.permitsCaching(path: path), path)
        }
    }
}
