import Foundation

private struct APIProblem: Decodable, Sendable {
    let title: String?
    let detail: String?
}

actor HTTPAPIClient: CodexMobileAPI {
    private enum Authorization: Equatable {
        case none
        case session
    }

    private struct WorkspaceActionBody: Encodable {
        let action: WorkspaceAction
        let retention: RetentionPolicy?
        let idleTimeoutMinutes: Int?
        let autonomy: AutonomyMode?
    }
    private struct TerminalTabBody: Encodable { let kind: TerminalTab.Kind }
    private struct ApprovalBody: Encodable { let decision: ApprovalDecision }
    private struct StageBody: Encodable { let path: String; let staged: Bool }
    private struct PreviewBody: Encodable { let previewID: String }

    private let configuration: AppConfiguration
    private let sessionStore: SessionStore
    private let urlSession: URLSession
    private let maximumJSONBytes = 10 * 1_024 * 1_024
    private let maximumRequestBytes = 12 * 1_024 * 1_024
    private var refreshTask: Task<Void, Error>?

    init(
        configuration: AppConfiguration,
        sessionStore: SessionStore,
        urlSession: URLSession? = nil
    ) {
        self.configuration = configuration
        self.sessionStore = sessionStore
        if let urlSession {
            self.urlSession = urlSession
        } else {
            let config = URLSessionConfiguration.ephemeral
            config.urlCache = nil
            config.requestCachePolicy = .reloadIgnoringLocalCacheData
            config.httpCookieStorage = nil
            config.urlCredentialStorage = nil
            config.httpShouldSetCookies = false
            config.timeoutIntervalForRequest = 30
            config.timeoutIntervalForResource = 60
            config.waitsForConnectivity = false
            self.urlSession = URLSession(configuration: config)
        }
    }

    func capabilities() async throws -> ClientCapabilities {
        try await send(method: "GET", path: "v1/capabilities", authorization: .none)
    }

    func connections() async throws -> ConnectionStatus {
        let value: ConnectionStatus = try await send(method: "GET", path: "v1/connections", authorization: .session)
        guard Self.validConnections(value) else {
            throw ClientError.malformedData("The connection status exceeded the supported contract.")
        }
        return value
    }

    func disconnectGitHub(installationID: Int64) async throws {
        guard installationID > 0 else {
            throw ClientError.malformedData("The GitHub installation identifier was invalid.")
        }
        let _: EmptyResponse = try await send(
            method: "DELETE",
            path: "v1/connections/github/\(installationID)",
            authorization: .session
        )
    }

    func codexConnection(workspaceID: String) async throws -> CodexWorkspaceConnection {
        guard Self.validIdentifier(workspaceID) else {
            throw ClientError.malformedData("The workspace identifier was invalid.")
        }
        let value: CodexWorkspaceConnection = try await send(
            method: "GET",
            path: "v1/workspaces/\(workspaceID)/connections/codex",
            authorization: .session
        )
        guard Self.validCodexConnection(value) else {
            throw ClientError.malformedData("The Codex connection status exceeded the supported contract.")
        }
        return value
    }

    func disconnectCodex(workspaceID: String) async throws {
        guard Self.validIdentifier(workspaceID) else {
            throw ClientError.malformedData("The workspace identifier was invalid.")
        }
        let _: EmptyResponse = try await send(
            method: "DELETE",
            path: "v1/workspaces/\(workspaceID)/connections/codex",
            body: ConfirmConnectionDisconnectRequest(confirmed: true),
            authorization: .session
        )
    }

    func beginPasskeyRegistration(_ request: BootstrapRegistrationRequest) async throws -> PasskeyRegistrationChallenge {
        try await send(
            method: "POST",
            path: "v1/auth/passkeys/registration/options",
            body: request,
            authorization: .none
        )
    }

    func finishPasskeyRegistration(_ credential: PasskeyRegistrationCredential) async throws -> SessionTokens {
        let tokens: SessionTokens = try await send(
            method: "POST",
            path: "v1/auth/passkeys/registration/verify",
            body: credential,
            authorization: .none
        )
        guard Self.validSessionTokens(tokens) else {
            throw ClientError.malformedData("The registration session did not satisfy the token contract.")
        }
        return tokens
    }

    func beginPasskeyAuthentication(_ identity: DeviceIdentityRequest) async throws -> PasskeyAuthenticationChallenge {
        try await send(
            method: "POST",
            path: "v1/auth/passkeys/authentication/options",
            body: identity,
            authorization: .none
        )
    }

    func finishPasskeyAuthentication(_ credential: PasskeyAssertionCredential) async throws -> SessionTokens {
        let tokens: SessionTokens = try await send(
            method: "POST",
            path: "v1/auth/passkeys/authentication/verify",
            body: credential,
            authorization: .none
        )
        guard Self.validSessionTokens(tokens) else {
            throw ClientError.malformedData("The authentication session did not satisfy the token contract.")
        }
        return tokens
    }

    func beginAdditionalPasskeyRegistration(_ identity: DeviceIdentityRequest) async throws -> PasskeyRegistrationChallenge {
        try await send(
            method: "POST",
            path: "v1/passkeys/registration/options",
            body: identity,
            authorization: .session
        )
    }

    func finishAdditionalPasskeyRegistration(_ credential: PasskeyRegistrationCredential) async throws -> PasskeyMetadata {
        let value: PasskeyMetadata = try await send(
            method: "POST",
            path: "v1/passkeys/registration/verify",
            body: credential,
            authorization: .session
        )
        guard Self.validPasskey(value) else {
            throw ClientError.malformedData("The passkey metadata did not satisfy the response contract.")
        }
        return value
    }

    func passkeys() async throws -> [PasskeyMetadata] {
        let values: [PasskeyMetadata] = try await send(method: "GET", path: "v1/passkeys", authorization: .session)
        guard values.count <= 20, values.allSatisfy(Self.validPasskey) else {
            throw ClientError.malformedData("The passkey list exceeded the supported contract.")
        }
        return values
    }

    func revokePasskey(id: String) async throws {
        guard Self.validPasskeyID(id) else { throw ClientError.malformedData("The passkey identifier was invalid.") }
        let _: EmptyResponse = try await send(method: "DELETE", path: "v1/passkeys/\(id)", authorization: .session)
    }

    func revokeCurrentSession() async throws {
        let _: EmptyResponse = try await send(
            method: "DELETE",
            path: "v1/auth/session",
            authorization: .session
        )
    }

    func devices() async throws -> [DeviceSummary] {
        try await send(method: "GET", path: "v1/devices", authorization: .session)
    }

    func revokeDevice(id: String) async throws {
        let _: EmptyResponse = try await send(
            method: "DELETE",
            path: "v1/devices/\(id)",
            authorization: .session
        )
    }

    func secrets(repositoryID: String?) async throws -> [SecretMetadata] {
        let query = repositoryID.map { [URLQueryItem(name: "repository_id", value: $0)] } ?? []
        return try await send(method: "GET", path: "v1/secrets", query: query, authorization: .session)
    }

    func createSecret(_ request: CreateSecretRequest) async throws -> SecretMetadata {
        try await send(method: "POST", path: "v1/secrets", body: request, authorization: .session)
    }

    func updateSecret(id: String, request: UpdateSecretRequest) async throws -> SecretMetadata {
        guard Self.validIdentifier(id) else { throw ClientError.malformedData("The secret identifier was invalid.") }
        return try await send(method: "PUT", path: "v1/secrets/\(id)", body: request, authorization: .session)
    }

    func deleteSecret(id: String) async throws {
        guard Self.validIdentifier(id) else { throw ClientError.malformedData("The secret identifier was invalid.") }
        let _: EmptyResponse = try await send(method: "DELETE", path: "v1/secrets/\(id)", authorization: .session)
    }

    func workspaceSecretGrants(workspaceID: String) async throws -> [WorkspaceSecretGrant] {
        guard Self.validIdentifier(workspaceID) else { throw ClientError.malformedData("The workspace identifier was invalid.") }
        return try await send(
            method: "GET",
            path: "v1/workspaces/\(workspaceID)/secret-grants",
            authorization: .session
        )
    }

    func grantSecret(workspaceID: String, secretID: String) async throws {
        guard Self.validIdentifier(workspaceID), Self.validIdentifier(secretID) else {
            throw ClientError.malformedData("The secret grant identifiers were invalid.")
        }
        let _: EmptyResponse = try await send(
            method: "PUT",
            path: "v1/workspaces/\(workspaceID)/secret-grants/\(secretID)",
            authorization: .session
        )
    }

    func revokeSecretGrant(workspaceID: String, secretID: String) async throws {
        guard Self.validIdentifier(workspaceID), Self.validIdentifier(secretID) else {
            throw ClientError.malformedData("The secret grant identifiers were invalid.")
        }
        let _: EmptyResponse = try await send(
            method: "DELETE",
            path: "v1/workspaces/\(workspaceID)/secret-grants/\(secretID)",
            authorization: .session
        )
    }

    func repositories(search: String?) async throws -> [RepositorySummary] {
        let items = search.flatMap { $0.isEmpty ? nil : [URLQueryItem(name: "search", value: $0)] } ?? []
        return try await send(method: "GET", path: "v1/repositories", query: items, authorization: .session)
    }

    func workspaces() async throws -> [WorkspaceSummary] {
        try await send(method: "GET", path: "v1/workspaces", authorization: .session)
    }

    func workspace(id: String) async throws -> WorkspaceDetail {
        try await send(method: "GET", path: "v1/workspaces/\(id)", authorization: .session)
    }

    func createWorkspace(_ request: NewWorkspaceRequest) async throws -> WorkspaceDetail {
        try await send(method: "POST", path: "v1/workspaces", body: request, authorization: .session)
    }

    func performWorkspaceAction(
        id: String,
        action: WorkspaceAction,
        retention: RetentionPolicy? = nil,
        idleTimeoutMinutes: Int? = nil,
        autonomy: AutonomyMode? = nil
    ) async throws -> WorkspaceDetail {
        try await send(
            method: "POST",
            path: "v1/workspaces/\(id)/actions",
            body: WorkspaceActionBody(
                action: action,
                retention: retention,
                idleTimeoutMinutes: idleTimeoutMinutes,
                autonomy: autonomy
            ),
            authorization: .session
        )
    }

    func activities() async throws -> [ActivityItem] {
        try await send(method: "GET", path: "v1/activity", authorization: .session)
    }

    func approval(id: String) async throws -> ApprovalReview {
        try await send(method: "GET", path: "v1/approvals/\(id)", authorization: .session)
    }

    func resolveApproval(id: String, decision: ApprovalDecision) async throws -> ApprovalReview {
        try await send(
            method: "POST",
            path: "v1/approvals/\(id)/decision",
            body: ApprovalBody(decision: decision),
            authorization: .session
        )
    }

    func terminalTabs(workspaceID: String) async throws -> [TerminalTab] {
        let tabs: [TerminalTab] = try await send(
            method: "GET",
            path: "v1/workspaces/\(workspaceID)/terminal-tabs",
            authorization: .session
        )
        guard tabs.count <= 64,
              Set(tabs.map(\.id)).count == tabs.count,
              tabs.enumerated().allSatisfy({ index, tab in
                  Self.validTerminalTab(tab, workspaceID: workspaceID, expectedOrder: index)
              }) else {
            throw ClientError.malformedData("The terminal tab list did not satisfy the bounded ordered contract.")
        }
        return tabs
    }

    func createTerminalTab(workspaceID: String, kind: TerminalTab.Kind) async throws -> TerminalTab {
        let tab: TerminalTab = try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/terminal-tabs",
            body: TerminalTabBody(kind: kind),
            authorization: .session
        )
        guard Self.validTerminalTab(tab, workspaceID: workspaceID, expectedOrder: tab.order) else {
            throw ClientError.malformedData("The terminal tab did not satisfy the response contract.")
        }
        return tab
    }

    func renameTerminalTab(
        workspaceID: String,
        tabID: String,
        request: RenameTerminalTabRequest
    ) async throws -> TerminalTab {
        guard Self.validTerminalTabID(tabID), let title = Self.canonicalTerminalTitle(request.title) else {
            throw ClientError.malformedData("The terminal tab identifier or title was invalid.")
        }
        let tab: TerminalTab = try await send(
            method: "PATCH",
            path: "v1/workspaces/\(workspaceID)/terminal-tabs/\(tabID)",
            body: RenameTerminalTabRequest(title: title),
            authorization: .session
        )
        guard tab.id == tabID,
              tab.title == title,
              Self.validTerminalTab(tab, workspaceID: workspaceID, expectedOrder: tab.order) else {
            throw ClientError.malformedData("The renamed terminal tab did not satisfy the response contract.")
        }
        return tab
    }

    func reorderTerminalTabs(
        workspaceID: String,
        request: ReorderTerminalTabsRequest
    ) async throws -> [TerminalTab] {
        guard (1...64).contains(request.tabIDs.count),
              Set(request.tabIDs).count == request.tabIDs.count,
              request.tabIDs.allSatisfy(Self.validTerminalTabID) else {
            throw ClientError.malformedData("The terminal order must contain every active tab exactly once.")
        }
        let tabs: [TerminalTab] = try await send(
            method: "PUT",
            path: "v1/workspaces/\(workspaceID)/terminal-tabs/order",
            body: request,
            authorization: .session
        )
        guard tabs.count == request.tabIDs.count,
              tabs.enumerated().allSatisfy({ index, tab in
                  tab.id == request.tabIDs[index]
                      && Self.validTerminalTab(tab, workspaceID: workspaceID, expectedOrder: index)
              }) else {
            throw ClientError.malformedData("The reordered terminal tabs did not match the requested membership.")
        }
        return tabs
    }

    func closeTerminalTab(
        workspaceID: String,
        tabID: String,
        request: CloseTerminalTabRequest
    ) async throws {
        guard Self.validTerminalTabID(tabID), request.confirmed else {
            throw ClientError.malformedData("Closing a terminal tab requires explicit confirmation.")
        }
        let _: EmptyResponse = try await send(
            method: "DELETE",
            path: "v1/workspaces/\(workspaceID)/terminal-tabs/\(tabID)",
            body: request,
            authorization: .session
        )
    }

    func terminalConnection(
        workspaceID: String,
        tabID: String,
        request: TerminalConnectRequest
    ) async throws -> TerminalConnectionDescriptor {
        guard request.afterSequence <= UInt64(Int64.max),
              request.reconnectToken.map({ (32...512).contains($0.utf8.count) }) ?? true else {
            throw ClientError.malformedData("The terminal reconnect state exceeded the API contract.")
        }
        let descriptor: TerminalConnectionDescriptor = try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/terminal-tabs/\(tabID)/connection",
            body: request,
            authorization: .session,
            // A rotating reconnect token can be stale while the owner session is
            // still valid. Surface that first 401 to the terminal model so it can
            // retry without the hint; a token-free retry retains normal refresh.
            mayRefresh: request.reconnectToken == nil
        )
        let websocketQuery = URLComponents(
            url: descriptor.websocketURL,
            resolvingAgainstBaseURL: false
        )?.queryItems ?? []
        let queryIsSafe = websocketQuery.isEmpty || (
            websocketQuery.count == 1
                && websocketQuery[0].name == "after_sequence"
                && websocketQuery[0].value.flatMap { UInt64($0) } == request.afterSequence
        )
        guard descriptor.websocketURL.scheme?.lowercased() == "wss",
              descriptor.websocketURL.host?.lowercased() == configuration.apiBaseURL.host?.lowercased(),
              (descriptor.websocketURL.port ?? 443) == (configuration.apiBaseURL.port ?? 443),
              descriptor.websocketURL.user == nil,
              descriptor.websocketURL.password == nil,
              descriptor.websocketURL.fragment == nil,
              queryIsSafe,
              (32...512).contains(descriptor.connectionTicket.utf8.count),
              Self.validIdentifier(descriptor.deviceID),
              descriptor.reconnectToken.map { (32...512).contains($0.utf8.count) } ?? true,
              descriptor.leaseHolderDeviceID.map { Self.validIdentifier($0) } ?? true,
              descriptor.protocolVersion == TerminalFrame.protocolVersion,
              descriptor.maximumFrameBytes >= 1_024,
              descriptor.maximumFrameBytes <= 1_048_576 else {
            throw ClientError.forbidden("The terminal connection descriptor failed origin or protocol validation.")
        }
        return descriptor
    }

    func stageTerminalAttachments(
        workspaceID: String,
        tabID: String,
        request: StageAttachmentsRequest
    ) async throws -> StageAttachmentsResult {
        guard (1...4).contains(request.attachments.count) else {
            throw ClientError.malformedData("Choose between one and four attachments.")
        }
        let allowed = Set([
            "image/png", "image/jpeg", "image/heic", "application/pdf",
            "application/json", "text/plain", "text/markdown", "text/csv"
        ])
        var total = 0
        for attachment in request.attachments {
            guard allowed.contains(attachment.mediaType),
                  (1...(5 * 1_024 * 1_024)).contains(attachment.contentBase64.count) else {
                throw ClientError.malformedData("An attachment type or size is not allowed.")
            }
            total += attachment.contentBase64.count
        }
        guard total <= 8 * 1_024 * 1_024 else {
            throw ClientError.malformedData("Attachments exceed the eight MiB total limit.")
        }
        let result: StageAttachmentsResult = try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/terminal-tabs/\(tabID)/attachments",
            body: request,
            authorization: .session
        )
        guard result.attachments.count == request.attachments.count else {
            throw ClientError.malformedData("The attachment staging response was incomplete.")
        }
        let now = Date()
        for (index, staged) in result.attachments.enumerated() {
            let source = request.attachments[index]
            guard Self.validIdentifier(staged.id), staged.id.hasPrefix("att_"),
                  staged.mediaType == source.mediaType,
                  staged.sizeBytes == source.contentBase64.count,
                  Self.validStagedAttachmentPath(staged.path, id: staged.id),
                  staged.expiresAt > now.addingTimeInterval(-300),
                  staged.expiresAt < now.addingTimeInterval(3_600) else {
                throw ClientError.malformedData("The attachment staging response was invalid.")
            }
        }
        return result
    }

    func fileTree(workspaceID: String) async throws -> [FileEntry] {
        try await send(method: "GET", path: "v1/workspaces/\(workspaceID)/files", authorization: .session)
    }

    func searchFiles(workspaceID: String, query: String) async throws -> [FileSearchResult] {
        try await send(
            method: "GET",
            path: "v1/workspaces/\(workspaceID)/file-search",
            query: [URLQueryItem(name: "query", value: query)],
            authorization: .session
        )
    }

    func file(workspaceID: String, path: String) async throws -> FileDocument {
        try await send(
            method: "GET",
            path: "v1/workspaces/\(workspaceID)/file",
            query: [URLQueryItem(name: "path", value: path)],
            authorization: .session
        )
    }

    func saveFile(workspaceID: String, path: String, request: SaveFileRequest) async throws -> FileDocument {
        try await send(
            method: "PUT",
            path: "v1/workspaces/\(workspaceID)/file",
            query: [URLQueryItem(name: "path", value: path)],
            body: request,
            authorization: .session
        )
    }

    func gitStatus(workspaceID: String) async throws -> GitStatusDetail {
        try await send(method: "GET", path: "v1/workspaces/\(workspaceID)/git/status", authorization: .session)
    }

    func diff(workspaceID: String, path: String) async throws -> DiffDocument {
        try await send(
            method: "GET",
            path: "v1/workspaces/\(workspaceID)/git/diff",
            query: [URLQueryItem(name: "path", value: path)],
            authorization: .session
        )
    }

    func setStaged(workspaceID: String, path: String, staged: Bool) async throws -> GitStatusDetail {
        try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/git/stage",
            body: StageBody(path: path, staged: staged),
            authorization: .session
        )
    }

    func commit(workspaceID: String, request: CommitRequest) async throws -> GitStatusDetail {
        try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/git/commits",
            body: request,
            authorization: .session
        )
    }

    func pull(workspaceID: String) async throws -> GitStatusDetail {
        try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/git/pull",
            authorization: .session
        )
    }

    func push(workspaceID: String) async throws -> GitStatusDetail {
        try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/git/push",
            authorization: .session
        )
    }

    func discardGitChanges(workspaceID: String, request: GitDiscardRequest) async throws -> GitDiscardResult {
        guard Self.validIdentifier(workspaceID), request.confirmed,
              (1...500).contains(request.paths.count),
              Set(request.paths).count == request.paths.count else {
            throw ClientError.malformedData("The confirmed discard selection was invalid.")
        }
        return try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/git/discard",
            body: request,
            authorization: .session
        )
    }

    func checkpoints(workspaceID: String) async throws -> [CheckpointSummary] {
        guard Self.validIdentifier(workspaceID) else {
            throw ClientError.malformedData("The workspace identifier was invalid.")
        }
        let values: [CheckpointSummary] = try await send(
            method: "GET",
            path: "v1/workspaces/\(workspaceID)/checkpoints",
            authorization: .session
        )
        guard values.count <= 128, values.allSatisfy({
            Self.validIdentifier($0.id) && ($0.hashStatus == "verified" || $0.hashStatus == "failed")
                && (0...2).contains($0.archiveVersion) && $0.archiveSHA256.count == 64
        }) else {
            throw ClientError.malformedData("The checkpoint list exceeded the supported contract.")
        }
        return values
    }

    func restoreCheckpointFile(
        workspaceID: String,
        checkpointID: String,
        request: CheckpointRestoreFileRequest
    ) async throws -> CheckpointRestoreResult {
        guard Self.validIdentifier(workspaceID), Self.validIdentifier(checkpointID), request.confirmed else {
            throw ClientError.malformedData("The confirmed file restore request was invalid.")
        }
        return try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/checkpoints/\(checkpointID)/restore-file",
            body: request,
            authorization: .session
        )
    }

    func restoreCheckpointWorkspace(
        workspaceID: String,
        checkpointID: String,
        request: CheckpointRestoreWorkspaceRequest
    ) async throws -> CheckpointRestoreResult {
        guard Self.validIdentifier(workspaceID), Self.validIdentifier(checkpointID), request.confirmed else {
            throw ClientError.malformedData("The confirmed workspace restore request was invalid.")
        }
        return try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/checkpoints/\(checkpointID)/restore-workspace",
            body: request,
            authorization: .session
        )
    }

    func createPullRequest(workspaceID: String, request: PullRequestRequest) async throws -> PullRequestResult {
        try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/pull-requests",
            body: request,
            authorization: .session
        )
    }

    func previews(workspaceID: String) async throws -> [PreviewEndpoint] {
        try await send(method: "GET", path: "v1/workspaces/\(workspaceID)/previews", authorization: .session)
    }

    func createPreviewAccess(workspaceID: String, previewID: String) async throws -> PreviewAccess {
        try await send(
            method: "POST",
            path: "v1/workspaces/\(workspaceID)/previews/access",
            body: PreviewBody(previewID: previewID),
            authorization: .session
        )
    }

    func revokePreviewAccess(workspaceID: String, previewID: String) async throws {
        let _: EmptyResponse = try await send(
            method: "DELETE",
            path: "v1/workspaces/\(workspaceID)/previews/\(previewID)/access",
            authorization: .session
        )
    }

    func maintenance() async throws -> MaintenanceStatus {
        try await send(method: "GET", path: "v1/maintenance", authorization: .session)
    }

    func scheduleMaintenance(urgent: Bool) async throws -> MaintenanceStatus {
        try await send(
            method: "POST",
            path: "v1/maintenance/schedule",
            body: ScheduleMaintenanceRequest(urgent: urgent),
            authorization: .session
        )
    }

    func cancelMaintenance(id: String) async throws -> MaintenanceStatus {
        guard Self.validIdentifier(id) else {
            throw ClientError.malformedData("The maintenance run identifier was invalid.")
        }
        return try await send(
            method: "DELETE",
            path: "v1/maintenance/\(id)",
            authorization: .session
        )
    }

    func advanceMaintenance(id: String, request: MaintenanceActionRequest) async throws -> MaintenanceStatus {
        guard Self.validIdentifier(id) else {
            throw ClientError.malformedData("The maintenance run identifier was invalid.")
        }
        return try await send(
            method: "POST",
            path: "v1/maintenance/\(id)/actions",
            body: request,
            authorization: .session
        )
    }

    func diagnostics() async throws -> DiagnosticsReport {
        let report: DiagnosticsReport = try await send(
            method: "GET",
            path: "v1/diagnostics",
            authorization: .session
        )
        guard report.metadataOnly, !report.includesSensitiveData,
              report.workspaceTotal >= 0, report.workspaceTotal <= 10_000 else {
            throw ClientError.malformedData("The diagnostics report violated its metadata-only contract.")
        }
        return report
    }

    func settings() async throws -> UserSettings {
        let value: UserSettings = try await send(method: "GET", path: "v1/settings", authorization: .session)
        guard Self.validUserSettings(value) else {
            throw ClientError.malformedData("The settings response exceeded the supported contract.")
        }
        return value
    }

    func updateSettings(_ settings: UserSettings) async throws -> UserSettings {
        guard Self.validUserSettings(settings) else {
            throw ClientError.malformedData("The settings values exceeded the supported contract.")
        }
        let value: UserSettings = try await send(
            method: "PUT",
            path: "v1/settings",
            body: settings,
            authorization: .session
        )
        guard Self.validUserSettings(value) else {
            throw ClientError.malformedData("The updated settings response exceeded the supported contract.")
        }
        return value
    }

    func registerPushDevice(_ registration: PushDeviceRegistration) async throws {
        guard Self.validPushRegistration(registration) else {
            throw ClientError.malformedData("The APNs device registration did not satisfy the API contract.")
        }
        let _: EmptyResponse = try await send(
            method: "PUT",
            path: "v1/devices/push",
            body: registration,
            authorization: .session
        )
    }

    private func send<Output: Decodable>(
        method: String,
        path: String,
        query: [URLQueryItem] = [],
        authorization: Authorization
    ) async throws -> Output {
        try await send(method: method, path: path, query: query, body: Optional<EmptyResponse>.none, authorization: authorization)
    }

    private func send<Input: Encodable, Output: Decodable>(
        method: String,
        path: String,
        query: [URLQueryItem] = [],
        body: Input?,
        authorization: Authorization,
        mayRefresh: Bool = true
    ) async throws -> Output {
        guard configuration.isConfigured else {
            throw ClientError.notConfigured(configuration.configurationProblem ?? "The API is not configured.")
        }
        var request = try makeRequest(method: method, path: path, query: query, body: body)
        if authorization == .session {
            guard let token = try await sessionStore.accessToken() else { throw ClientError.unauthorized }
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await urlSession.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ClientError.invalidResponse }
        guard data.count <= maximumJSONBytes else {
            throw ClientError.malformedData("The server response exceeded the client size limit.")
        }

        if http.statusCode == 401, authorization == .session, mayRefresh {
            try await refreshSession()
            return try await send(
                method: method,
                path: path,
                query: query,
                body: body,
                authorization: authorization,
                mayRefresh: false
            )
        }
        guard (200..<300).contains(http.statusCode) else {
            throw mapError(status: http.statusCode, data: data)
        }
        if Output.self == EmptyResponse.self, data.isEmpty {
            guard let empty = EmptyResponse() as? Output else { throw ClientError.invalidResponse }
            return empty
        }
        do {
            return try JSONDecoder.codex.decode(Output.self, from: data)
        } catch {
            throw ClientError.malformedData("The server response did not match the typed client contract.")
        }
    }

    private func refreshSession() async throws {
        if let refreshTask {
            try await refreshTask.value
            return
        }
        let storedTokens = try await sessionStore.current()
        // The Keychain actor hop above permits this actor to re-enter. A second caller may
        // have installed the shared refresh while this caller was suspended.
        if let refreshTask {
            try await refreshTask.value
            return
        }
        guard let tokens = storedTokens, tokens.refreshExpiresAt > Date() else {
            try? await sessionStore.clear()
            throw ClientError.unauthorized
        }
        let requestBody = ["refresh_token": tokens.refreshToken]
        var request = try makeRequest(method: "POST", path: "v1/auth/session/refresh", body: requestBody)
        request.setValue(nil, forHTTPHeaderField: "Authorization")
        let urlSession = self.urlSession
        let sessionStore = self.sessionStore
        let maximumJSONBytes = self.maximumJSONBytes
        let refreshRequest = request
        let task = Task {
            do {
                let (data, response) = try await urlSession.data(for: refreshRequest)
                guard let http = response as? HTTPURLResponse,
                      (200..<300).contains(http.statusCode),
                      data.count <= maximumJSONBytes,
                      let refreshed = try? JSONDecoder.codex.decode(SessionTokens.self, from: data),
                      Self.validSessionTokens(refreshed) else {
                    throw ClientError.unauthorized
                }
                try await sessionStore.save(refreshed)
            } catch {
                throw ClientError.unauthorized
            }
        }
        refreshTask = task
        do {
            try await task.value
            refreshTask = nil
        } catch {
            refreshTask = nil
            try? await sessionStore.clear()
            throw ClientError.unauthorized
        }
    }

    private func makeRequest<Input: Encodable>(
        method: String,
        path: String,
        query: [URLQueryItem] = [],
        body: Input?
    ) throws -> URLRequest {
        var url = configuration.apiBaseURL
        for component in path.split(separator: "/") {
            url.append(path: String(component))
        }
        if !query.isEmpty {
            guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
                throw ClientError.invalidResponse
            }
            components.queryItems = query
            guard let queryURL = components.url else { throw ClientError.invalidResponse }
            url = queryURL
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("CodexMobile-iOS/0.1", forHTTPHeaderField: "User-Agent")
        if let body {
            let encoded = try JSONEncoder.codex.encode(body)
            guard encoded.count <= maximumRequestBytes else {
                throw ClientError.malformedData("The request exceeded the client size limit.")
            }
            request.httpBody = encoded
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return request
    }

    private func mapError(status: Int, data: Data) -> ClientError {
        let problem = try? JSONDecoder.codex.decode(APIProblem.self, from: Data(data.prefix(4_096)))
        let message = problem?.detail ?? problem?.title ?? HTTPURLResponse.localizedString(forStatusCode: status)
        switch status {
        case 401: .unauthorized
        case 403: .forbidden(message)
        case 409, 412: .conflict(message)
        case 423, 429, 503: .unavailable(message)
        default: .server(status: status, message: message)
        }
    }

    nonisolated private static func validTerminalTabID(_ value: String) -> Bool {
        guard let id = UUID(uuidString: value) else { return false }
        return id != UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    }

    nonisolated private static func validTerminalTab(
        _ tab: TerminalTab,
        workspaceID: String,
        expectedOrder: Int
    ) -> Bool {
        validTerminalTabID(tab.id)
            && tab.workspaceID == workspaceID
            && tab.order == expectedOrder
            && (0...63).contains(tab.order)
            && canonicalTerminalTitle(tab.title) == tab.title
    }

    nonisolated private static func canonicalTerminalTitle(_ value: String) -> String? {
        let title = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...120).contains(title.count),
              !title.unicodeScalars.contains(where: { scalar in
                  CharacterSet.controlCharacters.contains(scalar)
                      || scalar.value == 0x2028 || scalar.value == 0x2029
                      || (0x202A...0x202E).contains(scalar.value)
                      || (0x2066...0x2069).contains(scalar.value)
              }) else { return nil }
        return title
    }

    nonisolated private static func validStagedAttachmentPath(_ value: String, id: String) -> Bool {
        let prefix = "/codex-mobile-attachments/stage-"
        guard value.hasPrefix(prefix), value.utf8.count <= 512,
              !value.contains(".."), !value.contains("\\"),
              value.split(separator: "/").last.map({ String($0).hasPrefix(id + ".") }) == true else {
            return false
        }
        return value.utf8.allSatisfy {
            (0x2D...0x39).contains($0) || (0x41...0x5A).contains($0) ||
                $0 == 0x5F || (0x61...0x7A).contains($0)
        }
    }

    nonisolated private static func validIdentifier(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard (1...128).contains(bytes.count), let first = bytes.first, isASCIIAlphaNumeric(first) else {
            return false
        }
        return bytes.dropFirst().allSatisfy {
            isASCIIAlphaNumeric($0) || $0 == 0x2E || $0 == 0x5F || $0 == 0x3A || $0 == 0x2D
        }
    }

    nonisolated private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
    }

    nonisolated private static func validSessionTokens(_ tokens: SessionTokens) -> Bool {
        (32...512).contains(tokens.accessToken.utf8.count)
            && (32...512).contains(tokens.refreshToken.utf8.count)
            && tokens.accessExpiresAt > Date()
            && tokens.refreshExpiresAt > tokens.accessExpiresAt
            && validIdentifier(tokens.deviceID)
    }

    nonisolated private static func validPasskey(_ value: PasskeyMetadata) -> Bool {
        validPasskeyID(value.id)
            && (1...120).contains(value.deviceName.utf8.count)
            && value.deviceName == value.deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
            && !value.deviceName.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    }

    nonisolated private static func validPasskeyID(_ value: String) -> Bool {
        guard (1...1_366).contains(value.utf8.count),
              let decoded = Data(base64URLEncoded: value),
              (1...1_024).contains(decoded.count) else { return false }
        return decoded.base64URLEncodedString == value
    }

    nonisolated private static func validUserSettings(_ settings: UserSettings) -> Bool {
        (5...10_080).contains(settings.idleTimeoutMinutes)
            && (8.0...48.0).contains(settings.terminalFontSize)
            && (1...100).contains(settings.terminalTheme.utf8.count)
            && ["block", "beam", "underline"].contains(settings.terminalCursorStyle)
    }

    nonisolated private static func validConnections(_ value: ConnectionStatus) -> Bool {
        guard value.github.installations.count <= 100,
              value.github.connected == !value.github.installations.isEmpty,
              value.github.configured || (!value.github.connected && value.github.installations.isEmpty),
              value.github.installations.allSatisfy({ installation in
                  installation.installationID > 0
                      && (1...255).contains(installation.accountLogin.utf8.count)
                      && ["User", "Organization", "Enterprise", "Bot"].contains(installation.accountType)
                      && ["all", "selected"].contains(installation.repositorySelection)
              }),
              value.codex.scope == "per_workspace",
              value.codex.workspaces.count <= 1_000,
              value.codex.workspaces.allSatisfy(validCodexConnection),
              Set(value.codex.workspaces.map(\.workspaceID)).count == value.codex.workspaces.count else {
            return false
        }
        let connected = value.codex.workspaces.filter { $0.state == .connected }.count
        let authenticating = value.codex.workspaces.filter { $0.state == .authenticating }.count
        let disconnected = value.codex.workspaces.filter { $0.state == .disconnected }.count
        let unavailable = value.codex.workspaces.filter { $0.state == .unavailable }.count
        return value.codex.connectedWorkspaceCount == connected
            && value.codex.authenticatingWorkspaceCount == authenticating
            && value.codex.disconnectedWorkspaceCount == disconnected
            && value.codex.unavailableWorkspaceCount == unavailable
    }

    nonisolated private static func validCodexConnection(_ value: CodexWorkspaceConnection) -> Bool {
        validIdentifier(value.workspaceID) && (1...120).contains(value.workspaceName.utf8.count)
    }

    nonisolated private static func validPushRegistration(_ registration: PushDeviceRegistration) -> Bool {
        (64...200).contains(registration.token.utf8.count)
            && registration.token.utf8.allSatisfy {
                (0x30...0x39).contains($0) || (0x41...0x46).contains($0) || (0x61...0x66).contains($0)
            }
            && ["sandbox", "production"].contains(registration.environment)
            && (2...35).contains(registration.locale.utf8.count)
    }
}
