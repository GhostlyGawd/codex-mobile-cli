import SwiftUI

private enum WorkspaceSurface: String, CaseIterable, Identifiable {
    case terminal
    case files
    case git
    case preview
    case secrets
    case details

    var id: String { rawValue }
    var title: String { rawValue.capitalized }
    var symbol: String {
        switch self {
        case .terminal: "terminal.fill"
        case .files: "doc.text.fill"
        case .git: "arrow.triangle.branch"
        case .preview: "safari.fill"
        case .secrets: "key.fill"
        case .details: "info.circle.fill"
        }
    }
}

struct WorkspaceScreen: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    let workspaceID: String

    @State private var detail: WorkspaceDetail?
    @State private var surface: WorkspaceSurface = .terminal
    @State private var errorMessage: String?

    var body: some View {
        Group {
            if let detail {
                surfaceView(detail)
            } else if let summary = cachedSummary,
                      !model.network.isConnected || errorMessage != nil {
                offlineSurfaceView(summary)
            } else if let errorMessage {
                ContentUnavailableView("Workspace Unavailable", systemImage: "exclamationmark.triangle", description: Text(errorMessage))
            } else {
                ProgressView("Loading workspace…")
            }
        }
        .navigationTitle(HostileDisplayText.sanitized(detail?.summary.taskName ?? cachedSummary?.taskName ?? "Workspace"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    ForEach(WorkspaceSurface.allCases) { destination in
                        Button { surface = destination } label: {
                            Label(destination.title, systemImage: destination.symbol)
                        }
                    }
                } label: { Label(surface.title, systemImage: surface.symbol) }
                .accessibilityLabel("Workspace section, \(surface.title)")
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            surfaceNavigation
        }
        .task(id: model.network.isConnected) { await load() }
    }

    @ViewBuilder
    private var surfaceNavigation: some View {
        if dynamicTypeSize.isAccessibilitySize {
            LazyVGrid(
                columns: Array(
                    repeating: GridItem(.flexible(minimum: 0), spacing: 6),
                    count: 3
                ),
                spacing: 6
            ) {
                ForEach(WorkspaceSurface.allCases) { destination in
                    surfaceButton(destination)
                }
            }
            .padding(6)
            .background(.bar)
        } else {
            HStack {
                ForEach(WorkspaceSurface.allCases) { destination in
                    surfaceButton(destination)
                }
            }
            .padding(.horizontal, 6)
            .background(.bar)
        }
    }

    private func surfaceButton(_ destination: WorkspaceSurface) -> some View {
        Button {
            surface = destination
        } label: {
            VStack(spacing: 3) {
                Image(systemName: destination.symbol)
                Text(destination.title)
                    .font(.caption2)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, minHeight: 44)
            .contentShape(Rectangle())
            .foregroundStyle(surface == destination ? Color.accentColor : Color.secondary)
        }
        .accessibilityIdentifier("workspace.surface.\(destination.rawValue)")
        .accessibilityAddTraits(surface == destination ? .isSelected : [])
    }

    @ViewBuilder
    private func surfaceView(_ detail: WorkspaceDetail) -> some View {
        switch surface {
        case .terminal:
            TerminalWorkspaceView(workspaceID: workspaceID)
        case .files:
            WorkspaceFilesView(workspaceID: workspaceID)
        case .git:
            WorkspaceGitView(workspaceID: workspaceID, baseBranch: detail.baseBranch)
        case .preview:
            WorkspacePreviewsView(workspaceID: workspaceID)
        case .secrets:
            WorkspaceSecretGrantsView(workspaceID: workspaceID)
        case .details:
            WorkspaceDetailsView(detail: detail, isOnline: model.network.isConnected) { action in
                await perform(action)
            } updatePolicy: { retention, idleTimeoutMinutes in
                await updatePolicy(retention: retention, idleTimeoutMinutes: idleTimeoutMinutes)
            } updateAutonomy: { autonomy in
                await updateAutonomy(autonomy)
            }
        }
    }

    @ViewBuilder
    private func offlineSurfaceView(_ summary: WorkspaceSummary) -> some View {
        switch surface {
        case .terminal:
            TerminalWorkspaceView(workspaceID: workspaceID)
        case .files:
            WorkspaceFilesView(workspaceID: workspaceID)
        case .git:
            WorkspaceGitView(workspaceID: workspaceID, baseBranch: summary.branch)
        case .preview:
            ContentUnavailableView(
                "Preview Unavailable Offline",
                systemImage: "wifi.slash",
                description: Text("Authenticated preview routes require a live control-plane connection.")
            )
        case .secrets:
            ContentUnavailableView(
                "Secret Grants Unavailable Offline",
                systemImage: "key.slash",
                description: Text("Secret metadata and values are never stored in the offline cache.")
            )
        case .details:
            List {
                Section("Cached workspace metadata") {
                    LabeledContent("Repository", value: HostileDisplayText.sanitized(summary.repositoryFullName))
                    LabeledContent("Task branch", value: HostileDisplayText.sanitized(summary.branch))
                    LabeledContent("State", value: summary.lifecycle.title)
                    LabeledContent("Connectivity", value: summary.connectivity.rawValue.capitalized)
                }
                Section {
                    Label("Encrypted cached copy — lifecycle actions are disabled", systemImage: "lock.fill")
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    private var cachedSummary: WorkspaceSummary? {
        model.workspaces.first { $0.id == workspaceID }
    }

    private func load() async {
        guard model.network.isConnected else {
            if cachedSummary == nil { errorMessage = "No encrypted workspace metadata is available offline." }
            return
        }
        do {
            detail = try await model.api.workspace(id: workspaceID)
            errorMessage = nil
        }
        catch { errorMessage = error.localizedDescription }
    }

    private func perform(_ action: WorkspaceAction) async {
        guard model.network.isConnected else { return }
        do {
            detail = try await model.api.performWorkspaceAction(
                id: workspaceID,
                action: action,
                retention: nil,
                idleTimeoutMinutes: nil,
                autonomy: nil
            )
            await model.refreshAll()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func updatePolicy(retention: RetentionPolicy, idleTimeoutMinutes: Int) async {
        guard model.network.isConnected else { return }
        do {
            detail = try await model.api.performWorkspaceAction(
                id: workspaceID,
                action: .updatePolicy,
                retention: retention,
                idleTimeoutMinutes: idleTimeoutMinutes,
                autonomy: nil
            )
            await model.refreshAll()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func updateAutonomy(_ autonomy: AutonomyMode) async {
        guard model.network.isConnected else { return }
        do {
            detail = try await model.api.performWorkspaceAction(
                id: workspaceID,
                action: .updateAutonomy,
                retention: nil,
                idleTimeoutMinutes: nil,
                autonomy: autonomy
            )
            await model.refreshAll()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private struct WorkspaceDetailsView: View {
    let detail: WorkspaceDetail
    let isOnline: Bool
    let perform: (WorkspaceAction) async -> Void
    let updatePolicy: (RetentionPolicy, Int) async -> Void
    let updateAutonomy: (AutonomyMode) async -> Void
    @State private var isPerforming = false
    @State private var showsDeleteConfirmation = false
    @State private var showsFullAccessConfirmation = false

    var body: some View {
        List {
            Section("Identity") {
                LabeledContent("Repository", value: HostileDisplayText.sanitized(detail.summary.repositoryFullName))
                LabeledContent("Task branch", value: HostileDisplayText.sanitized(detail.summary.branch))
                LabeledContent("Worktree", value: HostileDisplayText.sanitized(detail.summary.worktreeLabel))
                LabeledContent("Base branch", value: HostileDisplayText.sanitized(detail.baseBranch))
            }
            Section("Policy") {
                LabeledContent("Autonomy", value: detail.autonomy.title)
                Menu("Change autonomy") {
                    ForEach(AutonomyMode.allCases) { mode in
                        Button(mode.title) { requestAutonomy(mode) }
                    }
                }
                .disabled(detail.summary.lifecycle != .suspended)
                Text("Suspend the workspace before changing autonomy. The next resume applies the matching network policy and managed Codex configuration before terminals become available.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if detail.autonomy == .fullAccess {
                    Label("Full Access lets Codex act without approval inside this isolated workspace.", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                LabeledContent("Retention", value: detail.retention.title)
                LabeledContent("Idle timeout", value: "\(detail.idleTimeoutMinutes) minutes")
                LabeledContent("Nested Docker", value: detail.nestedDockerEnabled ? "Approved" : "Off")
                Menu("Change retention") {
                    ForEach(RetentionPolicy.allCases) { retention in
                        Button(retention.title) { savePolicy(retention, detail.idleTimeoutMinutes) }
                    }
                }
                Menu("Change idle timeout") {
                    Button("Use account default") { savePolicy(detail.retention, 0) }
                    ForEach([15, 30, 60, 120], id: \.self) { minutes in
                        Button("\(minutes) minutes") { savePolicy(detail.retention, minutes) }
                    }
                }
            }
            Section("Equal resource share") {
                LabeledContent("CPU", value: "\(detail.summary.resourceShare.cpuCores.formatted()) cores")
                LabeledContent("Memory", value: "\(detail.summary.resourceShare.memoryGiB.formatted()) GiB")
                LabeledContent("Writable disk", value: "\(detail.summary.resourceShare.writableDiskGiB.formatted()) GiB")
                LabeledContent("Pressure", value: detail.summary.resourceShare.pressure.title)
            }
            if !detail.provisioningSteps.isEmpty {
                Section("Provisioning") {
                    ForEach(detail.provisioningSteps) { step in
                        HStack {
                            Image(systemName: symbol(for: step.state)).foregroundStyle(color(for: step.state))
                            VStack(alignment: .leading) {
                                Text(step.title)
                                if let detail = step.detail { Text(detail).font(.caption).foregroundStyle(.secondary) }
                            }
                        }
                    }
                }
            }
            Section("Lifecycle") {
                if detail.summary.lifecycle == .suspended {
                    Button("Resume") { run(.resume) }
                } else if [.running, .ready, .idle, .needsAttention].contains(detail.summary.lifecycle) {
                    Button("Suspend") { run(.suspend) }
                    Button("Stop") { run(.stop) }
                }
                if detail.summary.lifecycle == .failed {
                    Button("Retry Provisioning") { run(.retryProvisioning) }
                }
                if [.running, .ready, .idle, .needsAttention].contains(detail.summary.lifecycle) {
                    Button("Keep Awake") { run(.keepAlive) }
                }
                Button("Delete Workspace", role: .destructive) {
                    showsDeleteConfirmation = true
                }
                .disabled(isPerforming || !isOnline)
                Text("Deletion is explicit and the control plane checkpoints dirty or unpushed work before removing the workspace.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .disabled(isPerforming || !isOnline)
        .alert("Delete this workspace?", isPresented: $showsDeleteConfirmation) {
            Button("Delete Workspace", role: .destructive) { run(.delete) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes the remote workspace after the server creates any required local checkpoint. This action cannot be undone from the app.")
        }
        .alert("Use Full Access for this workspace?", isPresented: $showsFullAccessConfirmation) {
            Button("Use Full Access", role: .destructive) { saveAutonomy(.fullAccess) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Full Access lets Codex act without approval inside the workspace. Host isolation, secret grants, and the no-host-socket rule still apply.")
        }
    }

    private func run(_ action: WorkspaceAction) {
        guard !isPerforming, isOnline else { return }
        isPerforming = true
        Task {
            await perform(action)
            isPerforming = false
        }
    }

    private func savePolicy(_ retention: RetentionPolicy, _ idleTimeoutMinutes: Int) {
        guard !isPerforming, isOnline else { return }
        isPerforming = true
        Task {
            await updatePolicy(retention, idleTimeoutMinutes)
            isPerforming = false
        }
    }

    private func requestAutonomy(_ mode: AutonomyMode) {
        guard !isPerforming, isOnline, detail.summary.lifecycle == .suspended else { return }
        if mode == .fullAccess {
            showsFullAccessConfirmation = true
        } else {
            saveAutonomy(mode)
        }
    }

    private func saveAutonomy(_ mode: AutonomyMode) {
        guard !isPerforming, isOnline, detail.summary.lifecycle == .suspended else { return }
        isPerforming = true
        Task {
            await updateAutonomy(mode)
            isPerforming = false
        }
    }

    private func symbol(for state: ProvisioningStep.StepState) -> String {
        switch state {
        case .pending: "circle"
        case .running: "clock.arrow.circlepath"
        case .succeeded: "checkmark.circle.fill"
        case .failed: "xmark.circle.fill"
        case .awaitingApproval: "exclamationmark.circle.fill"
        }
    }

    private func color(for state: ProvisioningStep.StepState) -> Color {
        switch state {
        case .succeeded: .green
        case .failed: .red
        case .awaitingApproval: .orange
        default: .secondary
        }
    }
}
