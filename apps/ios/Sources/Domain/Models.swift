import Foundation

enum WorkspaceLifecycle: String, Codable, CaseIterable, Hashable, Sendable {
    case queued
    case provisioning
    case awaitingSetupApproval = "awaiting_setup_approval"
    case ready
    case running
    case needsAttention = "needs_attention"
    case idle
    case suspending
    case suspended
    case failed
    case maintenance
    case deleting

    var title: String {
        switch self {
        case .awaitingSetupApproval: "Setup approval"
        case .needsAttention: "Needs attention"
        default: rawValue.replacingOccurrences(of: "_", with: " ").capitalized
        }
    }

    var symbol: String {
        switch self {
        case .running, .ready: "play.circle.fill"
        case .queued, .provisioning, .suspending: "clock.arrow.circlepath"
        case .awaitingSetupApproval, .needsAttention: "exclamationmark.bubble.fill"
        case .failed: "xmark.octagon.fill"
        case .maintenance: "wrench.and.screwdriver.fill"
        case .suspended, .idle: "pause.circle.fill"
        case .deleting: "trash.fill"
        }
    }
}

enum ConnectivityState: String, Codable, Hashable, Sendable {
    case connected
    case reconnecting
    case offline
    case unavailable
}

enum ResourcePressure: String, Codable, Hashable, Sendable {
    case nominal
    case elevated
    case constrained

    var title: String { rawValue.capitalized }
}

enum AutonomyMode: String, Codable, CaseIterable, Identifiable, Sendable {
    case safe
    case balanced
    case fullAccess = "full_access"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .safe: "Safe"
        case .balanced: "Balanced"
        case .fullAccess: "Full Access"
        }
    }

    var explanation: String {
        switch self {
        case .safe: "Read-only with interactive approval for changes and boundary crossings."
        case .balanced: "Workspace writes with on-request approvals and controlled network access."
        case .fullAccess: "No Codex approvals inside this isolated workspace. Host isolation remains enforced."
        }
    }
}

enum RetentionPolicy: String, Codable, CaseIterable, Identifiable, Sendable {
    case sevenDays = "7_days"
    case thirtyDays = "30_days"
    case ninetyDays = "90_days"
    case keepForever = "keep_forever"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .sevenDays: "7 days"
        case .thirtyDays: "30 days"
        case .ninetyDays: "90 days"
        case .keepForever: "Keep forever"
        }
    }
}

struct ClientCapabilities: Codable, Equatable, Sendable {
    let githubConfigured: Bool
    let passkeyBootstrapAvailable: Bool
    let apnsConfigured: Bool
    let previewsConfigured: Bool
    let structuredApprovalsAvailable: Bool
    let maximumRunningWorkspaces: Int
}

struct ConnectionStatus: Codable, Equatable, Sendable {
    let github: GitHubConnectionStatus
    let codex: CodexConnectionStatus
}

struct GitHubConnectionStatus: Codable, Equatable, Sendable {
    let configured: Bool
    let connected: Bool
    let installations: [GitHubInstallationConnection]
}

struct GitHubInstallationConnection: Codable, Identifiable, Equatable, Sendable {
    var id: Int64 { installationID }
    let installationID: Int64
    let accountLogin: String
    let accountType: String
    let repositorySelection: String
    let updatedAt: Date
}

struct CodexConnectionStatus: Codable, Equatable, Sendable {
    let scope: String
    let connectedWorkspaceCount: Int
    let authenticatingWorkspaceCount: Int
    let disconnectedWorkspaceCount: Int
    let unavailableWorkspaceCount: Int
    let workspaces: [CodexWorkspaceConnection]
}

enum CodexConnectionState: String, Codable, Sendable {
    case connected
    case authenticating
    case disconnected
    case unavailable

    var title: String {
        switch self {
        case .connected: "Connected"
        case .authenticating: "Authenticating"
        case .disconnected: "Not connected"
        case .unavailable: "Resume to check"
        }
    }
}

struct CodexWorkspaceConnection: Codable, Identifiable, Equatable, Sendable {
    var id: String { workspaceID }
    let workspaceID: String
    let workspaceName: String
    let state: CodexConnectionState
    let checkedAt: Date
}

struct ConfirmConnectionDisconnectRequest: Codable, Equatable, Sendable {
    let confirmed: Bool
}

struct SessionTokens: Codable, Equatable, Sendable {
    let accessToken: String
    let accessExpiresAt: Date
    let refreshToken: String
    let refreshExpiresAt: Date
    let deviceID: String
}

struct DeviceSummary: Codable, Identifiable, Equatable, Sendable {
    let id: String
    let name: String
    let platform: String
    let current: Bool
    let createdAt: Date
    let lastSeenAt: Date
}

struct PasskeyMetadata: Codable, Identifiable, Equatable, Sendable {
    let id: String
    let deviceName: String
    let createdAt: Date
    let lastUsedAt: Date?
}

enum SecretScope: String, Codable, Sendable {
    case global
    case repository
}

struct SecretMetadata: Codable, Identifiable, Equatable, Sendable {
    let id: String
    let name: String
    let scope: SecretScope
    let repositoryID: String?
    let valueBytes: Int
    let createdAt: Date
    let updatedAt: Date
}

struct CreateSecretRequest: Codable, Sendable {
    let name: String
    let value: String
    let repositoryID: String?
}

struct UpdateSecretRequest: Codable, Sendable {
    let value: String
}

struct WorkspaceSecretGrant: Codable, Identifiable, Equatable, Sendable {
    let secret: SecretMetadata
    let granted: Bool
    let grantedAt: Date?

    var id: String { secret.id }
}

struct RepositorySummary: Codable, Identifiable, Hashable, Sendable {
    let id: String
    let owner: String
    let name: String
    let defaultBranch: String
    let isPrivate: Bool
    let installationAccount: String
    let isFavorite: Bool
    let lastUsedAt: Date?

    var fullName: String { "\(owner)/\(name)" }
}

struct ResourceShare: Codable, Equatable, Hashable, Sendable {
    let cpuCores: Double
    let memoryGiB: Double
    let writableDiskGiB: Double
    let pressure: ResourcePressure
}

struct GitSummary: Codable, Equatable, Hashable, Sendable {
    let stagedCount: Int
    let unstagedCount: Int
    let untrackedCount: Int
    let ahead: Int
    let behind: Int
    let hasConflicts: Bool
    let hasUnpushedCommits: Bool

    var isDirty: Bool { stagedCount + unstagedCount + untrackedCount > 0 }
}

struct WorkspaceSummary: Codable, Identifiable, Hashable, Sendable {
    let id: String
    let repositoryOwner: String
    let repositoryName: String
    let taskName: String
    let branch: String
    let worktreeLabel: String
    let taskSummary: String?
    let lifecycle: WorkspaceLifecycle
    let connectivity: ConnectivityState
    let unreadActivityCount: Int
    let pendingApprovalCount: Int
    let failureMessage: String?
    let git: GitSummary
    let resourceShare: ResourceShare
    let updatedAt: Date
    let elapsedSeconds: Int

    var repositoryFullName: String { "\(repositoryOwner)/\(repositoryName)" }
}

struct WorkspaceDetail: Codable, Identifiable, Sendable {
    let id: String
    let summary: WorkspaceSummary
    let baseBranch: String
    let autonomy: AutonomyMode
    let retention: RetentionPolicy
    let idleTimeoutMinutes: Int
    let nestedDockerEnabled: Bool
    let environmentDetected: String?
    let provisioningSteps: [ProvisioningStep]
}

struct ProvisioningStep: Codable, Identifiable, Sendable {
    let id: String
    let title: String
    let state: StepState
    let detail: String?

    enum StepState: String, Codable, Sendable {
        case pending
        case running
        case succeeded
        case failed
        case awaitingApproval = "awaiting_approval"
    }
}

struct NewWorkspaceRequest: Codable, Equatable, Sendable {
    let repositoryID: String
    let initialPrompt: String?
    let baseBranch: String?
    let taskName: String?
    let autonomy: AutonomyMode
    let nestedDocker: Bool
    let retention: RetentionPolicy
    let environmentVariables: [String: String]
    let requestedDiskGiB: Int?
}

enum WorkspaceAction: String, Codable, Sendable {
    case start
    case suspend
    case resume
    case stop
    case retryProvisioning = "retry_provisioning"
    case delete
    case keepAlive = "keep_alive"
    case updatePolicy = "update_policy"
    case updateAutonomy = "update_autonomy"
}

enum ActivityKind: String, Codable, Hashable, Sendable {
    case approval
    case question
    case completion
    case failure
    case maintenance
    case security
}

enum ActivityState: String, Codable, Hashable, Sendable {
    case unread
    case read
    case pending
    case resolved
    case expired
}

struct ActivityItem: Codable, Identifiable, Hashable, Sendable {
    let id: String
    let workspaceID: String?
    let kind: ActivityKind
    let state: ActivityState
    let title: String
    let genericSummary: String
    let createdAt: Date
    let deepLinkPath: String?
    let structuredDetailAvailable: Bool
}

struct ApprovalReview: Codable, Identifiable, Sendable {
    let id: String
    let workspaceID: String
    let workspaceName: String
    let requestedAction: String?
    let reason: String?
    let filesystemScope: [String]
    let networkScope: [String]
    let affectedPaths: [String]
    let riskExplanation: String?
    let structuredDetailAvailable: Bool
    let state: ActivityState
}

enum ApprovalDecision: String, Codable, Sendable {
    case approve
    case deny
}

struct TerminalTab: Codable, Identifiable, Hashable, Sendable {
    let id: String
    let workspaceID: String
    let title: String
    let kind: Kind
    let order: Int
    let isRunning: Bool

    enum Kind: String, Codable, Hashable, Sendable {
        case codex
        case shell
        case server
        case test
        case log
    }
}

struct RenameTerminalTabRequest: Codable, Sendable {
    let title: String
}

struct ReorderTerminalTabsRequest: Codable, Sendable {
    let tabIDs: [String]
}

struct CloseTerminalTabRequest: Codable, Sendable {
    let confirmed: Bool
}

struct TerminalConnectionDescriptor: Codable, Sendable {
    let websocketURL: URL
    let connectionTicket: String
    let deviceID: String
    let reconnectToken: String?
    let protocolVersion: UInt8
    let maximumFrameBytes: Int
    let leaseHolderDeviceID: String?
}

struct TerminalConnectRequest: Codable, Sendable {
    let afterSequence: UInt64
    let reconnectToken: String?
}

struct AttachmentUpload: Codable, Sendable {
    let mediaType: String
    let contentBase64: Data
}

struct StageAttachmentsRequest: Codable, Sendable {
    let attachments: [AttachmentUpload]
}

struct StagedAttachment: Codable, Identifiable, Sendable {
    let id: String
    let path: String
    let mediaType: String
    let sizeBytes: Int
    let expiresAt: Date
}

struct StageAttachmentsResult: Codable, Sendable {
    let attachments: [StagedAttachment]
}

enum FileKind: String, Codable, Hashable, Sendable {
    case directory
    case text
    case image
    case binary
    case tooLarge = "too_large"
    case sensitive
}

struct FileEntry: Codable, Identifiable, Hashable, Sendable {
    var id: String { path }
    let path: String
    let name: String
    let kind: FileKind
    let isIgnored: Bool
    let sizeBytes: Int64?
    let children: [FileEntry]?
}

enum CacheDirective: String, Codable, Sendable {
    case ordinary
    case never
}

struct FileDocument: Codable, Identifiable, Equatable, Sendable {
    var id: String { path }
    let path: String
    let content: String
    let etag: String
    let languageHint: String?
    let kind: FileKind
    let isReadOnly: Bool
    let cacheDirective: CacheDirective
}

struct SaveFileRequest: Codable, Sendable {
    let content: String
    let expectedETag: String
}

struct FileSearchResult: Codable, Identifiable, Hashable, Sendable {
    var id: String { "\(path):\(line):\(column)" }
    let path: String
    let line: Int
    let column: Int
    let preview: String
}

enum GitChangeGroup: String, Codable, Hashable, Sendable {
    case staged
    case unstaged
    case untracked
    case conflicted
}

struct GitFileChange: Codable, Identifiable, Hashable, Sendable {
    var id: String { "\(group.rawValue):\(path)" }
    let path: String
    let status: String
    let group: GitChangeGroup
    let isBinary: Bool
}

struct GitStatusDetail: Codable, Sendable {
    let branch: String
    let upstream: String?
    let ahead: Int
    let behind: Int
    let changes: [GitFileChange]
    let operationInProgress: String?
}

struct DiffDocument: Codable, Identifiable, Equatable, Sendable {
    var id: String { path }
    let path: String
    let unifiedDiff: String?
    let imageBeforeURL: URL?
    let imageAfterURL: URL?
    let isBinary: Bool
    let cacheDirective: CacheDirective
}

struct CommitRequest: Codable, Sendable {
    let message: String
    let authorName: String
    let authorEmail: String
}

struct PullRequestRequest: Codable, Sendable {
    let title: String
    let body: String
    let baseBranch: String
}

struct PullRequestResult: Codable, Sendable {
    let number: Int
    let url: URL
    let state: String
}

struct GitDiscardRequest: Codable, Sendable {
    let paths: [String]
    let confirmed: Bool
}

struct GitDiscardResult: Codable, Sendable {
    let recoveryCheckpointID: String
    let status: GitStatusDetail
    let restoreURL: String
}

struct CheckpointSummary: Codable, Identifiable, Hashable, Sendable {
    let id: String
    let reason: String
    let createdAt: Date
    let archiveSHA256: String
    let hashStatus: String
    let archiveVersion: Int
    let workspaceRestoreSupported: Bool
    let compressedBytes: Int64
    let expandedBytes: Int64
    let fileCount: Int
    let deletedCount: Int
    let omittedSensitive: Int
    let omittedUnsafe: Int
    let head: String?
}

struct CheckpointRestoreFileRequest: Codable, Sendable {
    let path: String
    let confirmed: Bool
}

struct CheckpointRestoreWorkspaceRequest: Codable, Sendable {
    let confirmed: Bool
}

struct CheckpointRestoreResult: Codable, Sendable {
    let restoredCheckpointID: String
    let preRestoreCheckpointID: String
    let restoreSemantics: String
    let status: GitStatusDetail?
}

struct PreviewEndpoint: Codable, Identifiable, Hashable, Sendable {
    let id: String
    let port: Int
    let processName: String
    let workspaceID: String
    let status: String
}

struct PreviewAccess: Codable, Sendable {
    let url: URL
    let expiresAt: Date
    let allowedHost: String
}

struct UserSettings: Codable, Equatable, Sendable {
    var autonomyDefault: AutonomyMode
    var retentionDefault: RetentionPolicy
    var idleTimeoutMinutes: Int
    var terminalFontSize: Double
    var terminalTheme: String
    var terminalCursorStyle: String
    var quietHoursEnabled: Bool
    var notificationDetailEnabled: Bool
}

enum MaintenanceState: String, Codable, Sendable {
    case scheduled
    case warning
    case draining
    case readyForUpdate = "ready_for_update"
    case updating
    case rebootRequired = "reboot_required"
    case verifying
    case completed
    case failed
    case cancelled

    var title: String { rawValue.replacingOccurrences(of: "_", with: " ").capitalized }
    var isActive: Bool { self != .completed && self != .failed && self != .cancelled }
}

struct MaintenanceStatus: Codable, Identifiable, Equatable, Sendable {
    let id: String
    let state: MaintenanceState
    let urgent: Bool
    let bestEffort: Bool
    let scheduledFor: Date
    let warningAt: Date
    let createdAt: Date
    let updatedAt: Date
    let startedAt: Date?
    let completedAt: Date?
    let checkpointedWorkspaces: Int
    let drainedWorkspaces: Int
    let failedWorkspaces: Int
    let rebootRequired: Bool
    let message: String
}

struct ScheduleMaintenanceRequest: Codable, Sendable { let urgent: Bool }

enum MaintenanceAction: String, Codable, Sendable {
    case beginUpdate = "begin_update"
    case updatesApplied = "updates_applied"
    case beginVerification = "begin_verification"
    case complete
}

struct MaintenanceActionRequest: Codable, Sendable {
    let action: MaintenanceAction
    let rebootRequired: Bool?
}

struct DiagnosticsReport: Codable, Equatable, Sendable {
    let generatedAt: Date
    let serviceVersion: String
    let metadataOnly: Bool
    let includesSensitiveData: Bool
    let health: String
    let githubConfigured: Bool
    let apnsConfigured: Bool
    let previewsConfigured: Bool
    let maximumRunningWorkspaces: Int
    let workspaceTotal: Int
    let workspaceRunning: Int
    let workspaceQueued: Int
    let workspaceSuspended: Int
    let workspaceNeedsAttention: Int
    let workspaceFailed: Int
    let maintenanceState: String
}

struct PushDeviceRegistration: Codable, Sendable {
    let token: String
    let environment: String
    let locale: String
}

struct PasskeyRegistrationChallenge: Codable, Sendable {
    let ceremonyID: String
    let challenge: String
    let relyingPartyID: String
    let userID: String
    let userName: String
    let userDisplayName: String
    let excludedCredentialIDs: [String]
}

struct PasskeyAuthenticationChallenge: Codable, Sendable {
    let ceremonyID: String
    let challenge: String
    let relyingPartyID: String
    let allowedCredentialIDs: [String]
}

struct PasskeyRegistrationCredential: Codable, Sendable {
    let ceremonyID: String
    let credentialID: String
    let rawID: String
    let clientDataJSON: String
    let attestationObject: String
    let deviceInstanceID: String
    let deviceName: String
}

struct PasskeyAssertionCredential: Codable, Sendable {
    let ceremonyID: String
    let credentialID: String
    let rawID: String
    let clientDataJSON: String
    let authenticatorData: String
    let signature: String
    let userHandle: String?
    let deviceInstanceID: String
    let deviceName: String
}

struct BootstrapRegistrationRequest: Codable, Sendable {
    let bootstrapToken: String
    let deviceInstanceID: String
    let deviceName: String
}

struct DeviceIdentityRequest: Codable, Sendable {
    let deviceInstanceID: String
    let deviceName: String
}

struct EmptyResponse: Codable, Sendable {}

struct DashboardCacheSnapshot: Codable, Equatable, Sendable {
    let savedAt: Date
    let workspaces: [WorkspaceSummary]
    let activities: [ActivityItem]
}
