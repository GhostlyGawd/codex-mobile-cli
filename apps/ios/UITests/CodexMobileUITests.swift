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
        var firstFiniteFrame: CGRect?
        var lastFiniteFrame: CGRect?
        var recentFiniteFrames: [CGRect] = []
        var correctionUpward: Bool?
        var previousAttemptHadFiniteFrame = false

        for attempt in 0...maximumSwipes {
            let timeout = attempt == 0 ? 2.0 : 0.5
            let exists = element.waitForExistence(timeout: timeout)
            let frame = exists ? element.frame : .null
            let hasFiniteFrame = isFiniteNonempty(frame)

            if hasFiniteFrame {
                if firstFiniteFrame == nil {
                    firstFiniteFrame = frame
                }
                lastFiniteFrame = frame
                if recentFiniteFrames.last != frame {
                    recentFiniteFrames.append(frame)
                    if recentFiniteFrames.count > 4 {
                        recentFiniteFrames.removeFirst()
                    }
                }
                if element.isHittable {
                    return
                }

                correctionUpward = frame.midY >= app.frame.midY
            } else if previousAttemptHadFiniteFrame, let direction = correctionUpward {
                // Lazy lists remove an overscrolled row from the accessibility
                // tree. Reverse once, then preserve that direction until it
                // appears again.
                correctionUpward = !direction
            }

            previousAttemptHadFiniteFrame = hasFiniteFrame

            if attempt < maximumSwipes {
                if let correctionUpward {
                    dragApplication(upward: correctionUpward)
                } else {
                    app.swipeUp()
                }
            }
        }

        let gitSurface = app.buttons["workspace.surface.git"]
        let gitSurfaceFrame = gitSurface.exists ? gitSurface.frame : .null
        let frameDescription = lastFiniteFrame.map { "\($0)" } ?? "none"
        let firstFrameDescription = firstFiniteFrame.map { "\($0)" } ?? "none"
        let midpointDelta = if let firstFiniteFrame, let lastFiniteFrame {
            lastFiniteFrame.midY - firstFiniteFrame.midY
        } else {
            CGFloat.zero
        }
        XCTFail(
            """
            Could not scroll \(element) into a hittable position after \(maximumSwipes) gestures; \
            app frame: \(app.frame); first finite frame: \(firstFrameDescription); \
            last finite frame: \(frameDescription); midpoint delta: \(midpointDelta); \
            workspace Git control frame: \(gitSurfaceFrame); \
            target overlaps Git control: \(lastFiniteFrame?.intersects(gitSurfaceFrame) == true); \
            recent finite frames: \(recentFiniteFrames)
            """,
            file: file,
            line: line
        )
    }

    private func isFiniteNonempty(_ frame: CGRect) -> Bool {
        !frame.isNull
            && !frame.isEmpty
            && frame.minX.isFinite
            && frame.minY.isFinite
            && frame.maxX.isFinite
            && frame.maxY.isFinite
    }

    private func dragApplication(upward: Bool) {
        let start = app.coordinate(
            withNormalizedOffset: CGVector(dx: 0.5, dy: 0.50)
        )
        let end = app.coordinate(
            withNormalizedOffset: CGVector(dx: 0.5, dy: upward ? 0.35 : 0.65)
        )
        start.press(forDuration: 0.05, thenDragTo: end)
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
        diff.tap()
        let loadedDiff = app.staticTexts["git.diff.review.loaded"]
        XCTAssertTrue(
            loadedDiff.waitForExistence(timeout: 10),
            "The diff destination did not load. Accessibility hierarchy:\n\(app.debugDescription)"
        )
    }

    func testSettingsFlowRemainsReachableAtAccessibilityTextSize() {
        app.tabBars.buttons["Settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 5))
        assertReachable(app.buttons["settings.save"])
        assertReachable(app.buttons["settings.sign-out"])
    }
}
