import SwiftUI

struct MaintenanceView: View {
    @Environment(AppModel.self) private var model
    @State private var status: MaintenanceStatus?
    @State private var errorMessage: String?
    @State private var isWorking = false
    @State private var confirmation: MaintenanceConfirmation?

    var body: some View {
        List {
            Section {
                Text("Weekly maintenance warns in advance, stops new admissions, checkpoints dirty workspaces, and suspends them before host updates. Active processes cannot survive a reboot.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let status {
                Section("Current run") {
                    LabeledContent("State", value: status.state.title)
                    LabeledContent("Scheduled", value: status.scheduledFor.formatted(date: .abbreviated, time: .shortened))
                    LabeledContent("Mode", value: status.urgent ? "Urgent · best effort" : "Scheduled · mandatory checkpoints")
                    LabeledContent("Checkpointed", value: "\(status.checkpointedWorkspaces)")
                    LabeledContent("Suspended", value: "\(status.drainedWorkspaces)")
                    if status.failedWorkspaces > 0 {
                        LabeledContent("Failures", value: "\(status.failedWorkspaces)")
                            .foregroundStyle(.red)
                    }
                    Text(status.message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if status.state.isActive {
                    Section("Owner controls") {
                        controls(for: status)
                    }
                }
            } else if errorMessage == nil {
                Section { ProgressView("Loading maintenance status…") }
            }

            Section("Schedule") {
                Button("Schedule next weekly window") { schedule(urgent: false) }
                    .disabled(isWorking || !model.network.isConnected || status?.state.isActive == true)
                Button("Schedule urgent security maintenance", role: .destructive) {
                    confirmation = .urgent
                }
                .disabled(isWorking || !model.network.isConnected || status?.state.isActive == true)
                Text("Urgent maintenance still warns and attempts checkpoints, but proceeds best-effort when a security update cannot wait.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let errorMessage {
                Section { Text(errorMessage).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Maintenance")
        .refreshable { await load() }
        .task { await load() }
        .confirmationDialog(
            confirmation?.title ?? "Confirm maintenance action",
            isPresented: Binding(
                get: { confirmation != nil },
                set: { if !$0 { confirmation = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let confirmation {
                Button(confirmation.buttonTitle, role: confirmation.role) {
                    let selected = confirmation
                    self.confirmation = nil
                    Task { await perform(selected) }
                }
                Button("Cancel", role: .cancel) { self.confirmation = nil }
            }
        } message: {
            if let confirmation { Text(confirmation.message) }
        }
    }

    @ViewBuilder
    private func controls(for status: MaintenanceStatus) -> some View {
        switch status.state {
        case .scheduled, .warning:
            Button("Cancel maintenance", role: .destructive) { confirmation = .cancel }
        case .readyForUpdate:
            Button("Confirm host update started") { confirmation = .beginUpdate }
        case .updating:
            Button("Updates applied — reboot required") { confirmation = .updatesApplied(reboot: true) }
            Button("Updates applied — no reboot") { confirmation = .updatesApplied(reboot: false) }
        case .rebootRequired:
            Button("Begin post-reboot verification") { confirmation = .beginVerification }
        case .verifying:
            Button("Run health check and complete") { confirmation = .complete }
        case .draining:
            Label("Checkpoint and suspend in progress", systemImage: "hourglass")
                .foregroundStyle(.secondary)
        case .completed, .failed, .cancelled:
            EmptyView()
        }

        if status.state == .readyForUpdate || status.state == .updating || status.state == .rebootRequired {
            Text("These controls only record root-owned host maintenance stages. They do not execute package, container, Coder, Codex, or OS updates from the app.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func load() async {
        guard model.network.isConnected else {
            errorMessage = "Maintenance controls require a live authenticated connection."
            return
        }
        do {
            status = try await model.api.maintenance()
            errorMessage = nil
        } catch let ClientError.server(code, _) where code == 404 {
            status = nil
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func schedule(urgent: Bool) {
        Task {
            await execute { try await model.api.scheduleMaintenance(urgent: urgent) }
        }
    }

    private func perform(_ value: MaintenanceConfirmation) async {
        guard let status else { return }
        switch value {
        case .urgent:
            await execute { try await model.api.scheduleMaintenance(urgent: true) }
        case .cancel:
            await execute { try await model.api.cancelMaintenance(id: status.id) }
        case .beginUpdate:
            await execute {
                try await model.api.advanceMaintenance(
                    id: status.id,
                    request: MaintenanceActionRequest(action: .beginUpdate, rebootRequired: nil)
                )
            }
        case let .updatesApplied(reboot):
            await execute {
                try await model.api.advanceMaintenance(
                    id: status.id,
                    request: MaintenanceActionRequest(action: .updatesApplied, rebootRequired: reboot)
                )
            }
        case .beginVerification:
            await execute {
                try await model.api.advanceMaintenance(
                    id: status.id,
                    request: MaintenanceActionRequest(action: .beginVerification, rebootRequired: nil)
                )
            }
        case .complete:
            await execute {
                try await model.api.advanceMaintenance(
                    id: status.id,
                    request: MaintenanceActionRequest(action: .complete, rebootRequired: nil)
                )
            }
        }
    }

    private func execute(_ operation: () async throws -> MaintenanceStatus) async {
        isWorking = true
        defer { isWorking = false }
        do {
            status = try await operation()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private enum MaintenanceConfirmation: Equatable {
    case urgent
    case cancel
    case beginUpdate
    case updatesApplied(reboot: Bool)
    case beginVerification
    case complete

    var title: String {
        switch self {
        case .urgent: "Schedule urgent maintenance?"
        case .cancel: "Cancel maintenance?"
        case .beginUpdate: "Has the root-owned update started?"
        case .updatesApplied: "Have controlled updates finished?"
        case .beginVerification: "Has the host restarted?"
        case .complete: "Complete maintenance?"
        }
    }

    var buttonTitle: String {
        switch self {
        case .urgent: "Schedule Urgent Maintenance"
        case .cancel: "Cancel Maintenance"
        case .beginUpdate: "Record Update Started"
        case let .updatesApplied(reboot): reboot ? "Require Reboot" : "Begin Verification"
        case .beginVerification: "Begin Verification"
        case .complete: "Run Health Check"
        }
    }

    var message: String {
        switch self {
        case .urgent:
            "The server will provide a short warning, attempt checkpoints, stop admissions, and suspend running workspaces best-effort."
        case .cancel:
            "Only scheduled or warning maintenance can be cancelled."
        case .beginUpdate:
            "The app does not update the host. Confirm only after the audited root-owned update workflow has actually begun."
        case .updatesApplied:
            "Confirm only after the controlled OS, container, Coder, Codex, and app update groups have finished."
        case .beginVerification:
            "Active processes do not survive a host reboot. Confirm only after the host and control plane have returned."
        case .complete:
            "The control plane will perform its health check before reopening workspace admission."
        }
    }

    var role: ButtonRole? {
        self == .urgent || self == .cancel ? .destructive : nil
    }
}

struct DiagnosticsView: View {
    @Environment(AppModel.self) private var model
    @State private var report: DiagnosticsReport?
    @State private var errorMessage: String?

    var body: some View {
        List {
            Section {
                Label("Metadata only", systemImage: "checkmark.shield.fill")
                    .foregroundStyle(.green)
                Text("This report excludes repositories, prompts, commands, terminal output, file paths and contents, diffs, attachments, and credentials.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let report {
                Section("Service") {
                    LabeledContent("Health", value: report.health.capitalized)
                    LabeledContent("Version", value: report.serviceVersion)
                    LabeledContent("Generated", value: report.generatedAt.formatted(date: .abbreviated, time: .standard))
                    LabeledContent("Maintenance", value: report.maintenanceState.replacingOccurrences(of: "_", with: " ").capitalized)
                }
                Section("Capacity") {
                    LabeledContent("Workspaces", value: "\(report.workspaceTotal)")
                    LabeledContent("Running", value: "\(report.workspaceRunning)")
                    LabeledContent("Queued", value: "\(report.workspaceQueued)")
                    LabeledContent("Suspended", value: "\(report.workspaceSuspended)")
                    LabeledContent("Needs attention", value: "\(report.workspaceNeedsAttention)")
                    LabeledContent("Failed", value: "\(report.workspaceFailed)")
                    LabeledContent("Running limit", value: "\(report.maximumRunningWorkspaces)")
                }
                Section("Integrations") {
                    integration("GitHub App", configured: report.githubConfigured)
                    integration("APNs", configured: report.apnsConfigured)
                    integration("Previews", configured: report.previewsConfigured)
                }
            } else if errorMessage == nil {
                Section { ProgressView("Loading diagnostics…") }
            }

            if let errorMessage {
                Section { Text(errorMessage).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Diagnostics")
        .refreshable { await load() }
        .task { await load() }
    }

    private func integration(_ name: String, configured: Bool) -> some View {
        LabeledContent(name, value: configured ? "Configured" : "Not configured")
    }

    private func load() async {
        guard model.network.isConnected else {
            errorMessage = "Diagnostics require a live authenticated connection."
            return
        }
        do {
            report = try await model.api.diagnostics()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
