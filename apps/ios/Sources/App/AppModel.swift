import Foundation
import Observation
import UIKit

@MainActor
@Observable
final class AppModel {
    enum AuthenticationState: Equatable {
        case restoring
        case signedOut
        case signedIn
        case configurationRequired(String)
    }

    let configuration: AppConfiguration
    let api: any CodexMobileAPI
    let sessionStore: SessionStore
    let offlineCache: EncryptedOfflineCache
    let composerStore: EncryptedComposerStore
    let network = NetworkMonitor()

    private let passkeyAuth: PasskeyAuthService
    private let deepLinkRouter: DeepLinkRouter
    private let fixtureMode: Bool
    private var pendingDeepLinkRoute: AppRoute?

    var authenticationState: AuthenticationState = .restoring
    var capabilities: ClientCapabilities?
    var workspaces: [WorkspaceSummary] = []
    var repositories: [RepositorySummary] = []
    var activities: [ActivityItem] = []
    var userSettings: UserSettings?
    var isRefreshing = false
    var isShowingStaleData = false
    var isServerUnavailable = false
    var lastError: String?
    var presentedWorkspaceID: String?
    var presentedApprovalID: String?
    var requestedSection: AppSection?

    init(
        configuration: AppConfiguration,
        api: any CodexMobileAPI,
        sessionStore: SessionStore,
        offlineCache: EncryptedOfflineCache,
        composerStore: EncryptedComposerStore = EncryptedComposerStore(),
        passkeyPerformer: any PasskeyPerforming,
        fixtureMode: Bool = false
    ) {
        self.configuration = configuration
        self.api = api
        self.sessionStore = sessionStore
        self.offlineCache = offlineCache
        self.composerStore = composerStore
        self.passkeyAuth = PasskeyAuthService(api: api, performer: passkeyPerformer, sessionStore: sessionStore)
        self.deepLinkRouter = DeepLinkRouter(configuration: configuration)
        self.fixtureMode = fixtureMode
    }

    static func live() -> AppModel {
        let configuration = AppConfiguration.load()
        let sessionStore = SessionStore()
        let api = HTTPAPIClient(configuration: configuration, sessionStore: sessionStore)
        return AppModel(
            configuration: configuration,
            api: api,
            sessionStore: sessionStore,
            offlineCache: EncryptedOfflineCache(),
            passkeyPerformer: PlatformPasskeyClient(expectedRelyingPartyID: configuration.passkeyRelyingPartyID)
        )
    }

    func bootstrap() async {
        if fixtureMode {
            authenticationState = .signedIn
            capabilities = try? await api.capabilities()
            isServerUnavailable = false
            await refreshSettings()
            await refreshAll()
            applyPendingDeepLinkIfReady()
            return
        }
        guard configuration.isConfigured else {
            authenticationState = .configurationRequired(
                configuration.configurationProblem ?? "The API is not configured."
            )
            return
        }
        do {
            capabilities = try await api.capabilities()
            isServerUnavailable = false
        } catch {
            capabilities = nil
            isServerUnavailable = Self.isServerAvailabilityFailure(error)
            lastError = error.localizedDescription
        }
        do {
            if let session = try await sessionStore.restore(), session.refreshExpiresAt > Date() {
                authenticationState = .signedIn
            } else {
                try? await sessionStore.clear()
                authenticationState = .signedOut
            }
            if authenticationState == .signedIn {
                await refreshSettings()
                await refreshAll()
                applyPendingDeepLinkIfReady()
            }
        } catch {
            authenticationState = .signedOut
            lastError = error.localizedDescription
        }
    }

    func signIn() async {
        await performAuthentication {
            _ = try await passkeyAuth.authenticate()
        }
    }

    func registerFirstPasskey(bootstrapToken: String) async {
        await performAuthentication {
            _ = try await passkeyAuth.registerFirstPasskey(bootstrapToken: bootstrapToken)
        }
    }

    func addPasskey() async throws -> PasskeyMetadata {
        guard authenticationState == .signedIn, network.isConnected else {
            throw ClientError.offline
        }
        return try await passkeyAuth.registerAdditionalPasskey()
    }

    func signOut() async {
        do { try await api.revokeCurrentSession() } catch { /* Local revocation still wins. */ }
        try? await sessionStore.clear()
        try? await offlineCache.clear()
        try? await composerStore.clear()
        workspaces = []
        repositories = []
        activities = []
        userSettings = nil
        isServerUnavailable = false
        lastError = nil
        authenticationState = .signedOut
    }

    func refreshAll() async {
        guard authenticationState == .signedIn else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        async let workspaceResult = api.workspaces()
        async let activityResult = api.activities()
        do {
            let (freshWorkspaces, freshActivities) = try await (workspaceResult, activityResult)
            workspaces = freshWorkspaces
            activities = freshActivities
            isShowingStaleData = false
            isServerUnavailable = false
            lastError = nil
            try? await offlineCache.saveDashboard(DashboardCacheSnapshot(
                savedAt: Date(),
                workspaces: freshWorkspaces,
                activities: freshActivities
            ))
        } catch {
            await loadCachedDashboard(fallbackError: error)
        }
    }

    func connectivityDidChange(isConnected: Bool) async {
        guard authenticationState == .signedIn else { return }
        guard isConnected else {
            // Keep the last authenticated snapshot visible, but make its stale state
            // explicit immediately. Individual feature surfaces switch to their
            // encrypted read-only records through connectivity-keyed tasks.
            isShowingStaleData = true
            return
        }
        await refreshSettings()
        await refreshAll()
    }

    func refreshRepositories(search: String? = nil) async {
        guard authenticationState == .signedIn, network.isConnected else { return }
        do {
            repositories = try await api.repositories(search: search)
            isServerUnavailable = false
            lastError = nil
        } catch {
            isServerUnavailable = Self.isServerAvailabilityFailure(error)
            lastError = error.localizedDescription
        }
    }

    func refreshActivities() async {
        guard authenticationState == .signedIn else { return }
        do {
            activities = try await api.activities()
            isServerUnavailable = false
            lastError = nil
        } catch {
            isServerUnavailable = Self.isServerAvailabilityFailure(error)
            lastError = error.localizedDescription
        }
    }

    func refreshSettings() async {
        guard authenticationState == .signedIn else { return }
        do {
            userSettings = try await api.settings()
        } catch {
            // Settings are non-critical to restoring a terminal or dashboard; keep safe defaults.
        }
    }

    func handleDeepLink(_ url: URL) {
        guard let route = deepLinkRouter.route(for: url) else { return }
        guard authenticationState == .signedIn else {
            // Universal links and notification responses can arrive before the
            // Keychain-backed session restore finishes. Retain only the newest
            // validated destination until authenticated navigation is available.
            pendingDeepLinkRoute = route
            return
        }
        applyDeepLink(route)
    }

    private func applyDeepLink(_ route: AppRoute) {
        switch route {
        case let .workspace(id): presentedWorkspaceID = id
        case let .approval(id): presentedApprovalID = id
        case .activity: requestedSection = .activity
        }
    }

    private func applyPendingDeepLinkIfReady() {
        guard authenticationState == .signedIn, let route = pendingDeepLinkRoute else { return }
        pendingDeepLinkRoute = nil
        applyDeepLink(route)
    }

    func registerPushToken(_ data: Data) async {
        guard authenticationState == .signedIn, capabilities?.apnsConfigured == true else { return }
        let token = data.map { String(format: "%02x", $0) }.joined()
        #if DEBUG
        let environment = "sandbox"
        #else
        let environment = "production"
        #endif
        do {
            try await api.registerPushDevice(PushDeviceRegistration(
                token: token,
                environment: environment,
                locale: Locale.current.identifier
            ))
        } catch {
            lastError = "Push registration failed: \(error.localizedDescription)"
        }
    }

    private func performAuthentication(_ operation: () async throws -> Void) async {
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            try await operation()
            authenticationState = .signedIn
            lastError = nil
            await refreshSettings()
            await refreshAll()
            applyPendingDeepLinkIfReady()
        } catch {
            if error is URLError || error is ClientError {
                isServerUnavailable = Self.isServerAvailabilityFailure(error)
            }
            lastError = error.localizedDescription
        }
    }

    private func loadCachedDashboard(fallbackError: Error) async {
        let cached: DashboardCacheSnapshot?
        do {
            cached = try await offlineCache.dashboard()
        } catch {
            cached = nil
        }
        if let cached {
            workspaces = cached.workspaces
            activities = cached.activities
            isShowingStaleData = true
        }
        lastError = fallbackError.localizedDescription
        isServerUnavailable = Self.isServerAvailabilityFailure(fallbackError)
    }

    nonisolated static func isServerAvailabilityFailure(_ error: Error) -> Bool {
        if error is URLError { return true }
        guard let clientError = error as? ClientError else { return false }
        switch clientError {
        case .invalidResponse, .unavailable, .server, .malformedData:
            return true
        case .notConfigured, .unauthorized, .forbidden, .conflict, .offline:
            return false
        }
    }
}
