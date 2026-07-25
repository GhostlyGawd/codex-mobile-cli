import Foundation

protocol CodexMobileAPI: Sendable {
    func capabilities() async throws -> ClientCapabilities
    func connections() async throws -> ConnectionStatus
    func disconnectGitHub(installationID: Int64) async throws
    func codexConnection(workspaceID: String) async throws -> CodexWorkspaceConnection
    func disconnectCodex(workspaceID: String) async throws

    func beginPasskeyRegistration(_ request: BootstrapRegistrationRequest) async throws -> PasskeyRegistrationChallenge
    func finishPasskeyRegistration(_ credential: PasskeyRegistrationCredential) async throws -> SessionTokens
    func beginPasskeyAuthentication(_ identity: DeviceIdentityRequest) async throws -> PasskeyAuthenticationChallenge
    func finishPasskeyAuthentication(_ credential: PasskeyAssertionCredential) async throws -> SessionTokens
    func beginAdditionalPasskeyRegistration(_ identity: DeviceIdentityRequest) async throws -> PasskeyRegistrationChallenge
    func finishAdditionalPasskeyRegistration(_ credential: PasskeyRegistrationCredential) async throws -> PasskeyMetadata
    func passkeys() async throws -> [PasskeyMetadata]
    func revokePasskey(id: String) async throws
    func revokeCurrentSession() async throws
    func devices() async throws -> [DeviceSummary]
    func revokeDevice(id: String) async throws
    func secrets(repositoryID: String?) async throws -> [SecretMetadata]
    func createSecret(_ request: CreateSecretRequest) async throws -> SecretMetadata
    func updateSecret(id: String, request: UpdateSecretRequest) async throws -> SecretMetadata
    func deleteSecret(id: String) async throws
    func workspaceSecretGrants(workspaceID: String) async throws -> [WorkspaceSecretGrant]
    func grantSecret(workspaceID: String, secretID: String) async throws
    func revokeSecretGrant(workspaceID: String, secretID: String) async throws

    func repositories(search: String?) async throws -> [RepositorySummary]
    func workspaces() async throws -> [WorkspaceSummary]
    func workspace(id: String) async throws -> WorkspaceDetail
    func createWorkspace(_ request: NewWorkspaceRequest) async throws -> WorkspaceDetail
    func performWorkspaceAction(
        id: String,
        action: WorkspaceAction,
        retention: RetentionPolicy?,
        idleTimeoutMinutes: Int?,
        autonomy: AutonomyMode?
    ) async throws -> WorkspaceDetail

    func activities() async throws -> [ActivityItem]
    func approval(id: String) async throws -> ApprovalReview
    func resolveApproval(id: String, decision: ApprovalDecision) async throws -> ApprovalReview

    func terminalTabs(workspaceID: String) async throws -> [TerminalTab]
    func createTerminalTab(workspaceID: String, kind: TerminalTab.Kind) async throws -> TerminalTab
    func renameTerminalTab(workspaceID: String, tabID: String, request: RenameTerminalTabRequest) async throws -> TerminalTab
    func reorderTerminalTabs(workspaceID: String, request: ReorderTerminalTabsRequest) async throws -> [TerminalTab]
    func closeTerminalTab(workspaceID: String, tabID: String, request: CloseTerminalTabRequest) async throws
    func terminalConnection(workspaceID: String, tabID: String, request: TerminalConnectRequest) async throws -> TerminalConnectionDescriptor
    func stageTerminalAttachments(workspaceID: String, tabID: String, request: StageAttachmentsRequest) async throws -> StageAttachmentsResult

    func fileTree(workspaceID: String) async throws -> [FileEntry]
    func searchFiles(workspaceID: String, query: String) async throws -> [FileSearchResult]
    func file(workspaceID: String, path: String) async throws -> FileDocument
    func saveFile(workspaceID: String, path: String, request: SaveFileRequest) async throws -> FileDocument

    func gitStatus(workspaceID: String) async throws -> GitStatusDetail
    func diff(workspaceID: String, path: String) async throws -> DiffDocument
    func setStaged(workspaceID: String, path: String, staged: Bool) async throws -> GitStatusDetail
    func commit(workspaceID: String, request: CommitRequest) async throws -> GitStatusDetail
    func pull(workspaceID: String) async throws -> GitStatusDetail
    func push(workspaceID: String) async throws -> GitStatusDetail
    func discardGitChanges(workspaceID: String, request: GitDiscardRequest) async throws -> GitDiscardResult
    func createPullRequest(workspaceID: String, request: PullRequestRequest) async throws -> PullRequestResult
    func checkpoints(workspaceID: String) async throws -> [CheckpointSummary]
    func restoreCheckpointFile(workspaceID: String, checkpointID: String, request: CheckpointRestoreFileRequest) async throws -> CheckpointRestoreResult
    func restoreCheckpointWorkspace(workspaceID: String, checkpointID: String, request: CheckpointRestoreWorkspaceRequest) async throws -> CheckpointRestoreResult

    func previews(workspaceID: String) async throws -> [PreviewEndpoint]
    func createPreviewAccess(workspaceID: String, previewID: String) async throws -> PreviewAccess
    func revokePreviewAccess(workspaceID: String, previewID: String) async throws

    func maintenance() async throws -> MaintenanceStatus
    func scheduleMaintenance(urgent: Bool) async throws -> MaintenanceStatus
    func cancelMaintenance(id: String) async throws -> MaintenanceStatus
    func advanceMaintenance(id: String, request: MaintenanceActionRequest) async throws -> MaintenanceStatus
    func diagnostics() async throws -> DiagnosticsReport

    func settings() async throws -> UserSettings
    func updateSettings(_ settings: UserSettings) async throws -> UserSettings
    func registerPushDevice(_ registration: PushDeviceRegistration) async throws
}

enum ClientError: LocalizedError, Equatable, Sendable {
    case notConfigured(String)
    case invalidResponse
    case unauthorized
    case forbidden(String)
    case conflict(String)
    case unavailable(String)
    case server(status: Int, message: String)
    case malformedData(String)
    case offline

    var errorDescription: String? {
        switch self {
        case let .notConfigured(message), let .forbidden(message), let .conflict(message),
             let .unavailable(message), let .malformedData(message): message
        case .invalidResponse: "The server returned an invalid response."
        case .unauthorized: "Your session has expired. Sign in again with your passkey."
        case let .server(_, message): message
        case .offline: "This action is unavailable while offline."
        }
    }
}
