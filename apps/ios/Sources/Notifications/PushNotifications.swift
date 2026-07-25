import Foundation
import UIKit
import UserNotifications

extension Notification.Name {
    static let codexPushToken = Notification.Name("CodexMobile.pushToken")
    static let codexNotificationDeepLink = Notification.Name("CodexMobile.notificationDeepLink")
}

@MainActor
enum PushNotificationRegistration {
    static func requestAndRegister() async throws {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        switch settings.authorizationStatus {
        case .notDetermined:
            let granted = try await center.requestAuthorization(options: [.alert, .badge, .sound])
            if granted { UIApplication.shared.registerForRemoteNotifications() }
        case .authorized, .provisional, .ephemeral:
            UIApplication.shared.registerForRemoteNotifications()
        case .denied:
            throw ClientError.forbidden("Notifications are disabled in iOS Settings.")
        @unknown default:
            throw ClientError.unavailable("The notification authorization state is unknown.")
        }
    }
}

@MainActor
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    private let coldStartDeepLinks = ColdStartDeepLinkInbox()

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        if let userInfo = launchOptions?[.remoteNotification] as? [AnyHashable: Any] {
            captureDeepLink(from: userInfo)
        }
        return true
    }

    func takeColdStartDeepLink() -> URL? {
        coldStartDeepLinks.take()
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        NotificationCenter.default.post(name: .codexPushToken, object: deviceToken)
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        // The Settings surface reads registration state after an explicit owner action.
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .list, .sound])
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        defer { completionHandler() }
        let userInfo = response.notification.request.content.userInfo
        guard let url = captureDeepLink(from: userInfo) else { return }
        NotificationCenter.default.post(name: .codexNotificationDeepLink, object: url)
    }

    @discardableResult
    private func captureDeepLink(from userInfo: [AnyHashable: Any]) -> URL? {
        guard let value = userInfo["deep_link"] as? String,
              let url = URL(string: value) else { return nil }
        coldStartDeepLinks.store(url)
        return url
    }
}

@MainActor
final class ColdStartDeepLinkInbox {
    private var pendingURL: URL?

    func store(_ url: URL) {
        pendingURL = url
    }

    func take() -> URL? {
        defer { pendingURL = nil }
        return pendingURL
    }
}
