#if DEBUG
import Foundation

actor FixtureAPIClient: CodexMobileAPI {
    private var workspaceItems = FixtureData.workspaces
    private var settingsValue = FixtureData.settings
    private var secretItems = FixtureData.secrets
    private var grantedSecretIDs: Set<String> = ["fixture_secret"]
    private var passkeyItems = FixtureData.passkeys
    private var terminalTabItems = FixtureData.terminalTabs
    private var scriptedTerminalConnections: [TerminalConnectionDescriptor]
    private let rejectedReconnectTokens: Set<String>
    private var terminalReconnectRequests: [String?] = []
    private var githubConnected = true
    private var disconnectedCodexWorkspaces: Set<String> = []

    init(
        scriptedTerminalConnections: [TerminalConnectionDescriptor] = [],
        rejectedReconnectTokens: Set<String> = []
    ) {
        self.scriptedTerminalConnections = scriptedTerminalConnections
        self.rejectedReconnectTokens = rejectedReconnectTokens
    }

    func capabilities() async throws -> ClientCapabilities {
        ClientCapabilities(
            githubConfigured: true,
            passkeyBootstrapAvailable: false,
            apnsConfigured: true,
            previewsConfigured: true,
            structuredApprovalsAvailable: true,
            maximumRunningWorkspaces: 10
        )
    }

    func connections() async throws -> ConnectionStatus {
        let now = Date()
        let codexWorkspaces = workspaceItems.map { workspace in
            CodexWorkspaceConnection(
                workspaceID: workspace.id,
                workspaceName: workspace.taskName,
                state: disconnectedCodexWorkspaces.contains(workspace.id)
                    ? .disconnected
                    : (workspace.lifecycle == .suspended ? .unavailable : .connected),
                checkedAt: now
            )
        }
        return ConnectionStatus(
            github: GitHubConnectionStatus(
                configured: true,
                connected: githubConnected,
                installations: githubConnected
                    ? [GitHubInstallationConnection(
                        installationID: 42,
                        accountLogin: "fixture-owner",
                        accountType: "User",
                        repositorySelection: "selected",
                        updatedAt: now
                    )]
                    : []
            ),
            codex: CodexConnectionStatus(
                scope: "per_workspace",
                connectedWorkspaceCount: codexWorkspaces.filter { $0.state == .connected }.count,
                authenticatingWorkspaceCount: 0,
                disconnectedWorkspaceCount: codexWorkspaces.filter { $0.state == .disconnected }.count,
                unavailableWorkspaceCount: codexWorkspaces.filter { $0.state == .unavailable }.count,
                workspaces: codexWorkspaces
            )
        )
    }

    func disconnectGitHub(installationID: Int64) async throws {
        guard installationID == 42 else { throw ClientError.server(status: 404, message: "Installation not found") }
        githubConnected = false
    }

    func codexConnection(workspaceID: String) async throws -> CodexWorkspaceConnection {
        guard let value = try await connections().codex.workspaces.first(where: { $0.workspaceID == workspaceID }) else {
            throw ClientError.server(status: 404, message: "Workspace not found")
        }
        return value
    }

    func disconnectCodex(workspaceID: String) async throws {
        guard workspaceItems.contains(where: { $0.id == workspaceID }) else {
            throw ClientError.server(status: 404, message: "Workspace not found")
        }
        disconnectedCodexWorkspaces.insert(workspaceID)
    }

    func beginPasskeyRegistration(_ request: BootstrapRegistrationRequest) async throws -> PasskeyRegistrationChallenge {
        throw ClientError.unavailable("Passkey ceremonies are not simulated by UI fixtures.")
    }

    func finishPasskeyRegistration(_ credential: PasskeyRegistrationCredential) async throws -> SessionTokens {
        throw ClientError.unavailable("Passkey ceremonies are not simulated by UI fixtures.")
    }

    func beginPasskeyAuthentication(_ identity: DeviceIdentityRequest) async throws -> PasskeyAuthenticationChallenge {
        throw ClientError.unavailable("Passkey ceremonies are not simulated by UI fixtures.")
    }

    func finishPasskeyAuthentication(_ credential: PasskeyAssertionCredential) async throws -> SessionTokens {
        throw ClientError.unavailable("Passkey ceremonies are not simulated by UI fixtures.")
    }

    func beginAdditionalPasskeyRegistration(_ identity: DeviceIdentityRequest) async throws -> PasskeyRegistrationChallenge {
        throw ClientError.unavailable("Passkey ceremonies are not simulated by UI fixtures.")
    }

    func finishAdditionalPasskeyRegistration(_ credential: PasskeyRegistrationCredential) async throws -> PasskeyMetadata {
        throw ClientError.unavailable("Passkey ceremonies are not simulated by UI fixtures.")
    }

    func passkeys() async throws -> [PasskeyMetadata] { passkeyItems }

    func revokePasskey(id: String) async throws {
        guard passkeyItems.contains(where: { $0.id == id }) else { return }
        guard passkeyItems.count > 1 else {
            throw ClientError.conflict("Keep at least one passkey enrolled so you cannot lock yourself out.")
        }
        passkeyItems.removeAll { $0.id == id }
    }

    func revokeCurrentSession() async throws {}

    func devices() async throws -> [DeviceSummary] { FixtureData.devices }

    func revokeDevice(id: String) async throws {
        guard FixtureData.devices.contains(where: { $0.id == id }) else {
            throw ClientError.server(status: 404, message: "Device not found")
        }
    }

    func secrets(repositoryID: String?) async throws -> [SecretMetadata] {
        guard let repositoryID else { return secretItems }
        return secretItems.filter { $0.repositoryID == nil || $0.repositoryID == repositoryID }
    }

    func createSecret(_ request: CreateSecretRequest) async throws -> SecretMetadata {
        let now = Date()
        let value = SecretMetadata(
            id: "secret_\(UUID().uuidString.lowercased())",
            name: request.name,
            scope: request.repositoryID == nil ? .global : .repository,
            repositoryID: request.repositoryID,
            valueBytes: request.value.utf8.count,
            createdAt: now,
            updatedAt: now
        )
        secretItems.append(value)
        return value
    }

    func updateSecret(id: String, request: UpdateSecretRequest) async throws -> SecretMetadata {
        guard let index = secretItems.firstIndex(where: { $0.id == id }) else {
            throw ClientError.server(status: 404, message: "Secret not found")
        }
        let old = secretItems[index]
        let value = SecretMetadata(
            id: old.id, name: old.name, scope: old.scope, repositoryID: old.repositoryID,
            valueBytes: request.value.utf8.count, createdAt: old.createdAt, updatedAt: Date()
        )
        secretItems[index] = value
        return value
    }

    func deleteSecret(id: String) async throws {
        secretItems.removeAll { $0.id == id }
        grantedSecretIDs.remove(id)
    }

    func workspaceSecretGrants(workspaceID: String) async throws -> [WorkspaceSecretGrant] {
        secretItems.map {
            WorkspaceSecretGrant(
                secret: $0,
                granted: grantedSecretIDs.contains($0.id),
                grantedAt: grantedSecretIDs.contains($0.id) ? FixtureData.now : nil
            )
        }
    }

    func grantSecret(workspaceID: String, secretID: String) async throws {
        grantedSecretIDs.insert(secretID)
    }

    func revokeSecretGrant(workspaceID: String, secretID: String) async throws {
        grantedSecretIDs.remove(secretID)
    }

    func repositories(search: String?) async throws -> [RepositorySummary] {
        guard let search, !search.isEmpty else { return FixtureData.repositories }
        return FixtureData.repositories.filter { $0.fullName.localizedCaseInsensitiveContains(search) }
    }

    func workspaces() async throws -> [WorkspaceSummary] { workspaceItems }

    func workspace(id: String) async throws -> WorkspaceDetail {
        guard let summary = workspaceItems.first(where: { $0.id == id }) else {
            throw ClientError.server(status: 404, message: "Workspace not found")
        }
        return FixtureData.detail(for: summary)
    }

    func createWorkspace(_ request: NewWorkspaceRequest) async throws -> WorkspaceDetail {
        guard let repository = FixtureData.repositories.first(where: { $0.id == request.repositoryID }) else {
            throw ClientError.server(status: 404, message: "Repository not found")
        }
        let summary = WorkspaceSummary(
            id: UUID().uuidString.lowercased(),
            repositoryOwner: repository.owner,
            repositoryName: repository.name,
            taskName: request.taskName ?? "New mobile task",
            branch: "codex-mobile/new-mobile-task-a1b2",
            worktreeLabel: "worktree-a1b2",
            taskSummary: request.initialPrompt,
            lifecycle: .provisioning,
            connectivity: .connected,
            unreadActivityCount: 0,
            pendingApprovalCount: 0,
            failureMessage: nil,
            git: GitSummary(
                stagedCount: 0,
                unstagedCount: 0,
                untrackedCount: 0,
                ahead: 0,
                behind: 0,
                hasConflicts: false,
                hasUnpushedCommits: false
            ),
            resourceShare: ResourceShare(cpuCores: 1.5, memoryGiB: 3, writableDiskGiB: 12, pressure: .nominal),
            updatedAt: Date(),
            elapsedSeconds: 1
        )
        workspaceItems.insert(summary, at: 0)
        return FixtureData.detail(for: summary)
    }

    func performWorkspaceAction(
        id: String,
        action: WorkspaceAction,
        retention: RetentionPolicy? = nil,
        idleTimeoutMinutes: Int? = nil,
        autonomy: AutonomyMode? = nil
    ) async throws -> WorkspaceDetail {
        try await workspace(id: id)
    }

    func activities() async throws -> [ActivityItem] { FixtureData.activities }

    func approval(id: String) async throws -> ApprovalReview {
        FixtureData.approval
    }

    func resolveApproval(id: String, decision: ApprovalDecision) async throws -> ApprovalReview {
        ApprovalReview(
            id: FixtureData.approval.id,
            workspaceID: FixtureData.approval.workspaceID,
            workspaceName: FixtureData.approval.workspaceName,
            requestedAction: FixtureData.approval.requestedAction,
            reason: FixtureData.approval.reason,
            filesystemScope: FixtureData.approval.filesystemScope,
            networkScope: FixtureData.approval.networkScope,
            affectedPaths: FixtureData.approval.affectedPaths,
            riskExplanation: FixtureData.approval.riskExplanation,
            structuredDetailAvailable: true,
            state: .resolved
        )
    }

    func terminalTabs(workspaceID: String) async throws -> [TerminalTab] {
        terminalTabItems.map {
            TerminalTab(id: $0.id, workspaceID: workspaceID, title: $0.title, kind: $0.kind, order: $0.order, isRunning: $0.isRunning)
        }
    }

    func createTerminalTab(workspaceID: String, kind: TerminalTab.Kind) async throws -> TerminalTab {
        let tab = TerminalTab(
            id: UUID().uuidString.lowercased(),
            workspaceID: workspaceID,
            title: kind.rawValue.capitalized,
            kind: kind,
            order: terminalTabItems.count,
            isRunning: true
        )
        terminalTabItems.append(tab)
        return tab
    }

    func renameTerminalTab(
        workspaceID: String,
        tabID: String,
        request: RenameTerminalTabRequest
    ) async throws -> TerminalTab {
        guard let index = terminalTabItems.firstIndex(where: { $0.id == tabID }) else {
            throw ClientError.unavailable("The fixture terminal tab no longer exists.")
        }
        let current = terminalTabItems[index]
        let updated = TerminalTab(
            id: current.id,
            workspaceID: workspaceID,
            title: request.title.trimmingCharacters(in: .whitespacesAndNewlines),
            kind: current.kind,
            order: current.order,
            isRunning: current.isRunning
        )
        terminalTabItems[index] = updated
        return updated
    }

    func reorderTerminalTabs(
        workspaceID: String,
        request: ReorderTerminalTabsRequest
    ) async throws -> [TerminalTab] {
        guard Set(request.tabIDs) == Set(terminalTabItems.map(\.id)),
              request.tabIDs.count == terminalTabItems.count else {
            throw ClientError.conflict("The fixture terminal order is stale.")
        }
        let byID = Dictionary(uniqueKeysWithValues: terminalTabItems.map { ($0.id, $0) })
        terminalTabItems = request.tabIDs.enumerated().compactMap { index, id in
            guard let tab = byID[id] else { return nil }
            return TerminalTab(
                id: tab.id, workspaceID: workspaceID, title: tab.title,
                kind: tab.kind, order: index, isRunning: tab.isRunning
            )
        }
        return terminalTabItems
    }

    func closeTerminalTab(
        workspaceID: String,
        tabID: String,
        request: CloseTerminalTabRequest
    ) async throws {
        guard request.confirmed else { throw ClientError.conflict("Confirm the terminal close first.") }
        guard let index = terminalTabItems.firstIndex(where: { $0.id == tabID }) else { return }
        if terminalTabItems[index].kind == .codex {
            throw ClientError.conflict("The primary Codex tab cannot be closed.")
        }
        terminalTabItems.remove(at: index)
        terminalTabItems = terminalTabItems.enumerated().map { order, tab in
            TerminalTab(
                id: tab.id, workspaceID: workspaceID, title: tab.title,
                kind: tab.kind, order: order, isRunning: tab.isRunning
            )
        }
    }

    func terminalConnection(
        workspaceID: String,
        tabID: String,
        request: TerminalConnectRequest
    ) async throws -> TerminalConnectionDescriptor {
        terminalReconnectRequests.append(request.reconnectToken)
        if let token = request.reconnectToken, rejectedReconnectTokens.contains(token) {
            throw ClientError.unauthorized
        }
        if !scriptedTerminalConnections.isEmpty {
            return scriptedTerminalConnections.removeFirst()
        }
        throw ClientError.unavailable("The local UI fixture does not imitate a PTY. Configure the real terminal gateway.")
    }

    func observedTerminalReconnectTokens() -> [String?] {
        terminalReconnectRequests
    }

    func stageTerminalAttachments(
        workspaceID: String,
        tabID: String,
        request: StageAttachmentsRequest
    ) async throws -> StageAttachmentsResult {
        StageAttachmentsResult(attachments: request.attachments.enumerated().map { index, item in
            StagedAttachment(
                id: "att_fixture_\(index)",
                path: "/codex-mobile-attachments/stage-1784205000-fixture/att_fixture_\(index).txt",
                mediaType: item.mediaType,
                sizeBytes: item.contentBase64.count,
                expiresAt: Date().addingTimeInterval(30 * 60)
            )
        })
    }

    func fileTree(workspaceID: String) async throws -> [FileEntry] { FixtureData.fileTree }

    func searchFiles(workspaceID: String, query: String) async throws -> [FileSearchResult] {
        [FileSearchResult(path: "Sources/App.swift", line: 8, column: 14, preview: "struct CodexMobileApp: App")]
    }

    func file(workspaceID: String, path: String) async throws -> FileDocument {
        FileDocument(
            path: path,
            content: FixtureData.fileContents[path] ?? "No fixture content for \(path)\n",
            etag: "fixture-etag-1",
            languageHint: path.hasSuffix(".swift") ? "swift" : nil,
            kind: .text,
            isReadOnly: false,
            cacheDirective: .ordinary
        )
    }

    func saveFile(workspaceID: String, path: String, request: SaveFileRequest) async throws -> FileDocument {
        FileDocument(
            path: path,
            content: request.content,
            etag: "fixture-etag-2",
            languageHint: "swift",
            kind: .text,
            isReadOnly: false,
            cacheDirective: .ordinary
        )
    }

    func gitStatus(workspaceID: String) async throws -> GitStatusDetail { FixtureData.gitStatus }
    func diff(workspaceID: String, path: String) async throws -> DiffDocument { FixtureData.diff(path: path) }
    func setStaged(workspaceID: String, path: String, staged: Bool) async throws -> GitStatusDetail { FixtureData.gitStatus }
    func commit(workspaceID: String, request: CommitRequest) async throws -> GitStatusDetail { FixtureData.gitStatus }
    func pull(workspaceID: String) async throws -> GitStatusDetail { FixtureData.gitStatus }
    func push(workspaceID: String) async throws -> GitStatusDetail { FixtureData.gitStatus }
    func discardGitChanges(workspaceID: String, request: GitDiscardRequest) async throws -> GitDiscardResult {
        GitDiscardResult(recoveryCheckpointID: FixtureData.checkpoints[0].id, status: FixtureData.gitStatus, restoreURL: "/restore")
    }
    func checkpoints(workspaceID: String) async throws -> [CheckpointSummary] { FixtureData.checkpoints }
    func restoreCheckpointFile(workspaceID: String, checkpointID: String, request: CheckpointRestoreFileRequest) async throws -> CheckpointRestoreResult {
        CheckpointRestoreResult(restoredCheckpointID: checkpointID, preRestoreCheckpointID: FixtureData.checkpoints[0].id, restoreSemantics: "recorded-delta-over-current-workspace", status: FixtureData.gitStatus)
    }
    func restoreCheckpointWorkspace(workspaceID: String, checkpointID: String, request: CheckpointRestoreWorkspaceRequest) async throws -> CheckpointRestoreResult {
        CheckpointRestoreResult(restoredCheckpointID: checkpointID, preRestoreCheckpointID: FixtureData.checkpoints[0].id, restoreSemantics: "recorded-delta-over-current-workspace", status: FixtureData.gitStatus)
    }

    func createPullRequest(workspaceID: String, request: PullRequestRequest) async throws -> PullRequestResult {
        PullRequestResult(number: 42, url: URL(string: "https://github.com/GhostlyGawd/codex-mobile-cli/pull/42")!, state: "open")
    }

    func previews(workspaceID: String) async throws -> [PreviewEndpoint] { FixtureData.previews }

    func createPreviewAccess(workspaceID: String, previewID: String) async throws -> PreviewAccess {
        PreviewAccess(
            url: URL(string: "https://fixture.preview.codex.example.test/")!,
            expiresAt: Date().addingTimeInterval(300),
            allowedHost: "fixture.preview.codex.example.test"
        )
    }

    func revokePreviewAccess(workspaceID: String, previewID: String) async throws {}

    func maintenance() async throws -> MaintenanceStatus { FixtureData.maintenance }

    func scheduleMaintenance(urgent: Bool) async throws -> MaintenanceStatus {
        let now = Date()
        let lead: TimeInterval = urgent ? 300 : 86_400
        return MaintenanceStatus(
            id: "maint_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())",
            state: .scheduled,
            urgent: urgent,
            bestEffort: urgent,
            scheduledFor: now.addingTimeInterval(lead),
            warningAt: now,
            createdAt: now,
            updatedAt: now,
            startedAt: nil,
            completedAt: nil,
            checkpointedWorkspaces: 0,
            drainedWorkspaces: 0,
            failedWorkspaces: 0,
            rebootRequired: false,
            message: urgent ? "Urgent maintenance is scheduled after a short warning." : "Weekly maintenance is scheduled."
        )
    }

    func cancelMaintenance(id: String) async throws -> MaintenanceStatus {
        let value = FixtureData.maintenance
        return MaintenanceStatus(
            id: id,
            state: .cancelled,
            urgent: value.urgent,
            bestEffort: value.bestEffort,
            scheduledFor: value.scheduledFor,
            warningAt: value.warningAt,
            createdAt: value.createdAt,
            updatedAt: Date(),
            startedAt: value.startedAt,
            completedAt: Date(),
            checkpointedWorkspaces: value.checkpointedWorkspaces,
            drainedWorkspaces: value.drainedWorkspaces,
            failedWorkspaces: value.failedWorkspaces,
            rebootRequired: false,
            message: "Maintenance cancelled by the owner."
        )
    }

    func advanceMaintenance(id: String, request: MaintenanceActionRequest) async throws -> MaintenanceStatus {
        let value = FixtureData.maintenance
        let state: MaintenanceState = switch request.action {
        case .beginUpdate: .updating
        case .updatesApplied: request.rebootRequired == true ? .rebootRequired : .verifying
        case .beginVerification: .verifying
        case .complete: .completed
        }
        return MaintenanceStatus(
            id: id,
            state: state,
            urgent: value.urgent,
            bestEffort: value.bestEffort,
            scheduledFor: value.scheduledFor,
            warningAt: value.warningAt,
            createdAt: value.createdAt,
            updatedAt: Date(),
            startedAt: value.startedAt,
            completedAt: state == .completed ? Date() : nil,
            checkpointedWorkspaces: value.checkpointedWorkspaces,
            drainedWorkspaces: value.drainedWorkspaces,
            failedWorkspaces: value.failedWorkspaces,
            rebootRequired: state == .rebootRequired,
            message: "Fixture maintenance advanced to \(state.title)."
        )
    }

    func diagnostics() async throws -> DiagnosticsReport { FixtureData.diagnostics }

    func settings() async throws -> UserSettings { settingsValue }

    func updateSettings(_ settings: UserSettings) async throws -> UserSettings {
        settingsValue = settings
        return settings
    }

    func registerPushDevice(_ registration: PushDeviceRegistration) async throws {}
}

@MainActor
final class FixturePasskeyPerformer: PasskeyPerforming {
    func register(
        _ challenge: PasskeyRegistrationChallenge,
        identity: DeviceIdentityRequest
    ) async throws -> PasskeyRegistrationCredential {
        throw ClientError.unavailable("Passkey ceremonies are unavailable in fixture mode.")
    }

    func authenticate(
        _ challenge: PasskeyAuthenticationChallenge,
        identity: DeviceIdentityRequest
    ) async throws -> PasskeyAssertionCredential {
        throw ClientError.unavailable("Passkey ceremonies are unavailable in fixture mode.")
    }
}

actor FixtureCacheKeyProvider: CacheKeyProviding {
    func keyData() async throws -> Data { Data(repeating: 0xA5, count: 32) }
}

enum FixtureData {
    static let now = Date(timeIntervalSince1970: 1_783_993_200)

    static let maintenance = MaintenanceStatus(
        id: "maint_0123456789abcdef01234567",
        state: .warning,
        urgent: false,
        bestEffort: false,
        scheduledFor: now.addingTimeInterval(3_600),
        warningAt: now.addingTimeInterval(-82_800),
        createdAt: now.addingTimeInterval(-86_400),
        updatedAt: now.addingTimeInterval(-82_800),
        startedAt: nil,
        completedAt: nil,
        checkpointedWorkspaces: 0,
        drainedWorkspaces: 0,
        failedWorkspaces: 0,
        rebootRequired: false,
        message: "Server maintenance is scheduled soon. Running workspaces will be checkpointed and suspended."
    )

    static let diagnostics = DiagnosticsReport(
        generatedAt: now,
        serviceVersion: "0.1.0",
        metadataOnly: true,
        includesSensitiveData: false,
        health: "healthy",
        githubConfigured: true,
        apnsConfigured: true,
        previewsConfigured: true,
        maximumRunningWorkspaces: 10,
        workspaceTotal: 2,
        workspaceRunning: 2,
        workspaceQueued: 0,
        workspaceSuspended: 0,
        workspaceNeedsAttention: 1,
        workspaceFailed: 0,
        maintenanceState: "warning"
    )

    static let devices = [
        DeviceSummary(
            id: "fixture-device",
            name: "iPhone",
            platform: "ios",
            current: true,
            createdAt: now.addingTimeInterval(-86_400),
            lastSeenAt: now
        )
    ]

    static let passkeys = [
        PasskeyMetadata(
            id: "Zml4dHVyZS1wYXNza2V5",
            deviceName: "iPhone",
            createdAt: now.addingTimeInterval(-86_400),
            lastUsedAt: now.addingTimeInterval(-600)
        )
    ]

    static let secrets = [
        SecretMetadata(
            id: "fixture_secret",
            name: "DEPLOY_TOKEN",
            scope: .global,
            repositoryID: nil,
            valueBytes: 32,
            createdAt: now.addingTimeInterval(-86_400),
            updatedAt: now.addingTimeInterval(-3_600)
        )
    ]

    static let repositories = [
        RepositorySummary(
            id: "repo-codex-mobile",
            owner: "GhostlyGawd",
            name: "codex-mobile-cli",
            defaultBranch: "main",
            isPrivate: true,
            installationAccount: "GhostlyGawd",
            isFavorite: true,
            lastUsedAt: now.addingTimeInterval(-600)
        ),
        RepositorySummary(
            id: "repo-control-plane",
            owner: "ExampleOrg",
            name: "control-plane",
            defaultBranch: "main",
            isPrivate: true,
            installationAccount: "ExampleOrg",
            isFavorite: false,
            lastUsedAt: now.addingTimeInterval(-86_400)
        )
    ]

    static let workspaces = [
        WorkspaceSummary(
            id: "11111111-1111-4111-8111-111111111111",
            repositoryOwner: "GhostlyGawd",
            repositoryName: "codex-mobile-cli",
            taskName: "Native terminal reconnect",
            branch: "codex-mobile/terminal-reconnect-a3f1",
            worktreeLabel: "worktree-a3f1",
            taskSummary: "Verify replay and writer lease behavior",
            lifecycle: .needsAttention,
            connectivity: .connected,
            unreadActivityCount: 2,
            pendingApprovalCount: 1,
            failureMessage: nil,
            git: GitSummary(
                stagedCount: 1,
                unstagedCount: 2,
                untrackedCount: 1,
                ahead: 2,
                behind: 0,
                hasConflicts: false,
                hasUnpushedCommits: true
            ),
            resourceShare: ResourceShare(cpuCores: 1.5, memoryGiB: 3, writableDiskGiB: 12, pressure: .elevated),
            updatedAt: now.addingTimeInterval(-90),
            elapsedSeconds: 2_460
        ),
        WorkspaceSummary(
            id: "22222222-2222-4222-8222-222222222222",
            repositoryOwner: "ExampleOrg",
            repositoryName: "control-plane",
            taskName: "Admission policy tests",
            branch: "codex-mobile/admission-tests-b7d2",
            worktreeLabel: "worktree-b7d2",
            taskSummary: "Add fair-share queue coverage",
            lifecycle: .running,
            connectivity: .connected,
            unreadActivityCount: 0,
            pendingApprovalCount: 0,
            failureMessage: nil,
            git: GitSummary(
                stagedCount: 0,
                unstagedCount: 0,
                untrackedCount: 0,
                ahead: 0,
                behind: 1,
                hasConflicts: false,
                hasUnpushedCommits: false
            ),
            resourceShare: ResourceShare(cpuCores: 1.5, memoryGiB: 3, writableDiskGiB: 12, pressure: .nominal),
            updatedAt: now.addingTimeInterval(-300),
            elapsedSeconds: 5_220
        )
    ]

    static let activities = [
        ActivityItem(
            id: "approval-1",
            workspaceID: workspaces[0].id,
            kind: .approval,
            state: .pending,
            title: "Session needs attention",
            genericSummary: "Review the request inside the authenticated app.",
            createdAt: now.addingTimeInterval(-75),
            deepLinkPath: "/app/approvals/approval-1",
            structuredDetailAvailable: true
        ),
        ActivityItem(
            id: "completion-1",
            workspaceID: workspaces[1].id,
            kind: .completion,
            state: .unread,
            title: "Session completed",
            genericSummary: "A Codex turn completed.",
            createdAt: now.addingTimeInterval(-480),
            deepLinkPath: nil,
            structuredDetailAvailable: false
        )
    ]

    static let approval = ApprovalReview(
        id: "approval-1",
        workspaceID: workspaces[0].id,
        workspaceName: workspaces[0].taskName,
        requestedAction: "Run the repository test suite",
        reason: "Validate terminal protocol changes before committing.",
        filesystemScope: ["Workspace write access"],
        networkScope: ["No additional network access"],
        affectedPaths: ["apps/ios/Tests"],
        riskExplanation: "Tests execute repository-controlled code inside the isolated workspace.",
        structuredDetailAvailable: true,
        state: .pending
    )

    static let terminalTabs = [
        TerminalTab(id: "33333333-3333-4333-8333-333333333333", workspaceID: workspaces[0].id, title: "Codex", kind: .codex, order: 0, isRunning: true),
        TerminalTab(id: "44444444-4444-4444-8444-444444444444", workspaceID: workspaces[0].id, title: "Tests", kind: .test, order: 1, isRunning: true)
    ]

    static let fileTree = [
        FileEntry(
            path: "Sources",
            name: "Sources",
            kind: .directory,
            isIgnored: false,
            sizeBytes: nil,
            children: [
                FileEntry(path: "Sources/App.swift", name: "App.swift", kind: .text, isIgnored: false, sizeBytes: 1_284, children: nil),
                FileEntry(path: "Sources/Terminal.swift", name: "Terminal.swift", kind: .text, isIgnored: false, sizeBytes: 4_812, children: nil)
            ]
        ),
        FileEntry(path: "README.md", name: "README.md", kind: .text, isIgnored: false, sizeBytes: 2_024, children: nil),
        FileEntry(path: ".env", name: ".env", kind: .sensitive, isIgnored: true, sizeBytes: nil, children: nil)
    ]

    static let fileContents = [
        "Sources/App.swift": "import SwiftUI\n\n@main\nstruct CodexMobileApp: App {\n    var body: some Scene {\n        WindowGroup {\n            Text(\"Codex Mobile\")\n        }\n    }\n}\n",
        "README.md": "# Fixture repository\n\nThis content exists only for previews and UI tests.\n"
    ]

    static let gitStatus = GitStatusDetail(
        branch: workspaces[0].branch,
        upstream: "origin/\(workspaces[0].branch)",
        ahead: 2,
        behind: 0,
        changes: [
            GitFileChange(path: "Sources/App.swift", status: "modified", group: .staged, isBinary: false),
            GitFileChange(path: "Sources/Terminal.swift", status: "modified", group: .unstaged, isBinary: false),
            GitFileChange(path: "Tests/TerminalTests.swift", status: "new", group: .untracked, isBinary: false)
        ],
        operationInProgress: nil
    )

    static let checkpoints = [
        CheckpointSummary(
            id: "cp_20260716T010203.000000000Z_aaaaaaaaaaaaaaaaaaaaaaaa",
            reason: "before-git-discard",
            createdAt: Date().addingTimeInterval(-300),
            archiveSHA256: String(repeating: "a", count: 64),
            hashStatus: "verified",
            archiveVersion: 2,
            workspaceRestoreSupported: true,
            compressedBytes: 4_096,
            expandedBytes: 12_288,
            fileCount: 3,
            deletedCount: 1,
            omittedSensitive: 0,
            omittedUnsafe: 0,
            head: String(repeating: "b", count: 40)
        )
    ]

    static func diff(path: String) -> DiffDocument {
        DiffDocument(
            path: path,
            unifiedDiff: "@@ -1,3 +1,4 @@\n import Foundation\n+import Observation\n \n struct Terminal {}\n",
            imageBeforeURL: nil,
            imageAfterURL: nil,
            isBinary: false,
            cacheDirective: .ordinary
        )
    }

    static let previews = [
        PreviewEndpoint(id: "preview-3000", port: 3000, processName: "next dev", workspaceID: workspaces[0].id, status: "ready")
    ]

    static let settings = UserSettings(
        autonomyDefault: .balanced,
        retentionDefault: .thirtyDays,
        idleTimeoutMinutes: 30,
        terminalFontSize: 13,
        terminalTheme: "system",
        terminalCursorStyle: "block",
        quietHoursEnabled: false,
        notificationDetailEnabled: false
    )

    static func detail(for summary: WorkspaceSummary) -> WorkspaceDetail {
        WorkspaceDetail(
            id: summary.id,
            summary: summary,
            baseBranch: "main",
            autonomy: .balanced,
            retention: .thirtyDays,
            idleTimeoutMinutes: 30,
            nestedDockerEnabled: false,
            environmentDetected: "devcontainer detected; trust not yet granted",
            provisioningSteps: [
                ProvisioningStep(id: "capacity", title: "Reserve fair-share capacity", state: .succeeded, detail: nil),
                ProvisioningStep(id: "clone", title: "Create isolated branch and worktree", state: .succeeded, detail: nil),
                ProvisioningStep(id: "setup", title: "Repository setup", state: .awaitingApproval, detail: "Owner review required before lifecycle scripts run")
            ]
        )
    }
}

extension AppModel {
    static func fixture() -> AppModel {
        let configuration = AppConfiguration(
            apiBaseURL: URL(string: "https://api.codex.example.test")!,
            passkeyRelyingPartyID: "codex.example.test",
            previewAllowedHostSuffix: ".preview.codex.example.test"
        )
        let cacheURL = FileManager.default.temporaryDirectory
            .appending(path: "codex-mobile-fixture-cache-\(UUID().uuidString).bin")
        return AppModel(
            configuration: configuration,
            api: FixtureAPIClient(),
            sessionStore: SessionStore(keychain: KeychainStore(service: "CodexMobile.Fixture")),
            offlineCache: EncryptedOfflineCache(fileURL: cacheURL, keyProvider: FixtureCacheKeyProvider()),
            passkeyPerformer: FixturePasskeyPerformer(),
            fixtureMode: true
        )
    }
}
#endif
