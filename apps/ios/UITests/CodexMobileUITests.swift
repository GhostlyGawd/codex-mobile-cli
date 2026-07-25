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

    private func assertReachable(
        _ element: XCUIElement,
        maximumSwipes: Int = 24,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        for attempt in 0...maximumSwipes {
            let timeout = attempt == 0 ? 2.0 : 0.5
            if element.waitForExistence(timeout: timeout), element.isHittable {
                return
            }
            if attempt < maximumSwipes {
                activeScrollContainer().swipeUp()
            }
        }
        XCTFail(
            "Could not scroll \(element) into a hittable position after \(maximumSwipes) swipes",
            file: file,
            line: line
        )
    }

    private func activeScrollContainer() -> XCUIElement {
        for query in [app.collectionViews, app.tables, app.scrollViews] {
            if let container = query.allElementsBoundByIndex.first(where: { $0.isHittable }) {
                return container
            }
        }
        return app
    }

    func testWorkspaceDashboardAndCreationFlowAreAccessible() {
        XCTAssertTrue(app.buttons["workspace.new"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["workspace.card.11111111-1111-4111-8111-111111111111"].exists)
        app.buttons["workspace.new"].tap()
        XCTAssertTrue(app.buttons["new-workspace.repository.repo-codex-mobile"].waitForExistence(timeout: 3))
        app.buttons["new-workspace.repository.repo-codex-mobile"].tap()
        assertReachable(app.buttons["new-workspace.start"])
    }

    func testApprovalRequiresAuthenticatedInAppReview() {
        app.tabBars.buttons["Activity"].tap()
        XCTAssertTrue(app.buttons["activity.approval-1"].waitForExistence(timeout: 3))
        app.buttons["activity.approval-1"].tap()
        assertReachable(app.buttons["approval.approve"])
        assertReachable(app.buttons["approval.deny"])
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
        let diffIdentifier = "git.diff.staged:Sources/App.swift"
        let diff = app.buttons[diffIdentifier]
        assertReachable(diff)
        XCTAssertEqual(app.buttons.matching(identifier: diffIdentifier).count, 1)
        // Activate inside the file label, away from the row actions and fixed workspace controls.
        diff.coordinate(withNormalizedOffset: CGVector(dx: 0.2, dy: 0.25)).tap()
        let diffContent = app.descendants(matching: .any)["git.diff.review.content"]
        XCTAssertTrue(diffContent.waitForExistence(timeout: 5))
    }

    func testSettingsFlowRemainsReachableAtAccessibilityTextSize() {
        app.tabBars.buttons["Settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 5))
        assertReachable(app.buttons["settings.save"])
        assertReachable(app.buttons["settings.sign-out"])
    }
}
