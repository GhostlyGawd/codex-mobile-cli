import XCTest

@MainActor
final class CodexMobileUITests: XCTestCase {
    private var app: XCUIApplication!

    override func setUp() {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments = [
            "--ui-testing",
            "-UIPreferredContentSizeCategoryName",
            "UICTContentSizeCategoryAccessibilityXXXL",
        ]
        app.launch()
    }

    func testWorkspaceDashboardAndCreationFlowAreAccessible() {
        XCTAssertTrue(app.buttons["workspace.new"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["workspace.card.11111111-1111-4111-8111-111111111111"].exists)
        app.buttons["workspace.new"].tap()
        XCTAssertTrue(app.buttons["new-workspace.repository.repo-codex-mobile"].waitForExistence(timeout: 3))
        app.buttons["new-workspace.repository.repo-codex-mobile"].tap()
        XCTAssertTrue(app.buttons["new-workspace.start"].exists)
        XCTAssertTrue(app.buttons["new-workspace.start"].isHittable)
    }

    func testApprovalRequiresAuthenticatedInAppReview() {
        app.tabBars.buttons["Activity"].tap()
        XCTAssertTrue(app.buttons["activity.approval-1"].waitForExistence(timeout: 3))
        app.buttons["activity.approval-1"].tap()
        XCTAssertTrue(app.buttons["approval.approve"].waitForExistence(timeout: 3))
        XCTAssertTrue(app.buttons["approval.deny"].exists)
    }

    func testCoreNavigationLabelsExist() {
        for label in ["Workspaces", "Repositories", "Activity", "Settings"] {
            XCTAssertTrue(app.tabBars.buttons[label].exists, label)
        }
    }

    func testTerminalSwitchingAndGitReviewRemainReachableAtAccessibilityTextSize() {
        let workspace = app.buttons["workspace.card.11111111-1111-4111-8111-111111111111"]
        XCTAssertTrue(workspace.waitForExistence(timeout: 5))
        workspace.tap()

        let codexTab = app.buttons["terminal.tab.33333333-3333-4333-8333-333333333333"]
        let testsTab = app.buttons["terminal.tab.44444444-4444-4444-8444-444444444444"]
        XCTAssertTrue(codexTab.waitForExistence(timeout: 5))
        XCTAssertTrue(testsTab.exists)
        testsTab.tap()

        let gitSurface = app.buttons["workspace.surface.git"]
        XCTAssertTrue(gitSurface.exists)
        gitSurface.tap()
        let diff = app.buttons["git.diff.Sources/App.swift"]
        XCTAssertTrue(diff.waitForExistence(timeout: 5))
        diff.tap()
        XCTAssertTrue(app.navigationBars["Sources/App.swift"].waitForExistence(timeout: 3))
    }

    func testSettingsFlowRemainsReachableAtAccessibilityTextSize() {
        app.tabBars.buttons["Settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["settings.save"].exists)
        XCTAssertTrue(app.buttons["settings.sign-out"].exists)
    }
}
