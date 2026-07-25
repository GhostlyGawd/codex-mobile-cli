import SwiftUI

@main
struct CodexMobileApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model: AppModel

    init() {
        #if DEBUG
        let usesFixture = ProcessInfo.processInfo.arguments.contains("--ui-testing")
        _model = State(initialValue: usesFixture ? AppModel.fixture() : AppModel.live())
        #else
        _model = State(initialValue: AppModel.live())
        #endif
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .task {
                    // Notification responses may precede SwiftUI subscription
                    // installation on a cold launch. Transfer them into the
                    // model before restore; AppModel keeps them until sign-in.
                    consumeColdStartDeepLink()
                    await model.bootstrap()
                    consumeColdStartDeepLink()
                }
                .onOpenURL { model.handleDeepLink($0) }
                .onReceive(NotificationCenter.default.publisher(for: .codexPushToken)) { notification in
                    guard let token = notification.object as? Data else { return }
                    Task { await model.registerPushToken(token) }
                }
                .onReceive(NotificationCenter.default.publisher(for: .codexNotificationDeepLink)) { notification in
                    guard let url = appDelegate.takeColdStartDeepLink() ?? (notification.object as? URL) else { return }
                    model.handleDeepLink(url)
                }
        }
    }

    private func consumeColdStartDeepLink() {
        guard let url = appDelegate.takeColdStartDeepLink() else { return }
        model.handleDeepLink(url)
    }
}
