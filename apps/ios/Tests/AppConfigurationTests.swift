import Foundation
import XCTest
@testable import CodexMobile

final class AppConfigurationTests: XCTestCase {
    func testPreviewHostRequiresARealChildOfTheConfiguredSuffix() {
        let configuration = AppConfiguration(
            apiBaseURL: URL(string: "https://api.codex.example.com")!,
            passkeyRelyingPartyID: "codex.example.com",
            previewAllowedHostSuffix: ".preview.codex.example.com"
        )

        XCTAssertTrue(configuration.permitsPreviewHost("workspace-1.preview.codex.example.com"))
        XCTAssertFalse(configuration.permitsPreviewHost("preview.codex.example.com"))
        XCTAssertFalse(configuration.permitsPreviewHost("evilpreview.codex.example.com"))
        XCTAssertFalse(configuration.permitsPreviewHost("workspace-1.preview.evil.example"))
        XCTAssertFalse(configuration.permitsPreviewHost("-workspace.preview.codex.example.com"))
        XCTAssertFalse(configuration.permitsPreviewHost("workspace-.preview.codex.example.com"))
        XCTAssertFalse(configuration.permitsPreviewHost("workspace..preview.codex.example.com"))
    }

    func testInvalidOrForeignPreviewSuffixFailsClosed() {
        let invalid = AppConfiguration(
            apiBaseURL: URL(string: "https://api.codex.example.com")!,
            passkeyRelyingPartyID: "codex.example.com",
            previewAllowedHostSuffix: ".preview.codex.invalid"
        )
        let foreign = AppConfiguration(
            apiBaseURL: URL(string: "https://api.codex.example.com")!,
            passkeyRelyingPartyID: "codex.example.com",
            previewAllowedHostSuffix: ".preview.foreign.example"
        )

        XCTAssertFalse(invalid.permitsPreviewHost("workspace.preview.codex.invalid"))
        XCTAssertFalse(foreign.permitsPreviewHost("workspace.preview.foreign.example"))
    }

    func testConfigurationValidatesRelyingPartyAsDNSNameCaseInsensitively() {
        let valid = AppConfiguration(
            apiBaseURL: URL(string: "https://API.CODEX.EXAMPLE.COM")!,
            passkeyRelyingPartyID: "Codex.Example.Com",
            previewAllowedHostSuffix: ".preview.codex.example.com"
        )
        let invalid = AppConfiguration(
            apiBaseURL: URL(string: "https://api.codex.example.com")!,
            passkeyRelyingPartyID: "-codex.example.com",
            previewAllowedHostSuffix: ".preview.codex.example.com"
        )

        XCTAssertNil(valid.configurationProblem)
        XCTAssertNotNil(invalid.configurationProblem)
    }
}
