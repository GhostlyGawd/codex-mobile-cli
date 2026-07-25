import SwiftUI

struct WorkspacesView: View {
    @Environment(AppModel.self) private var model
    @State private var showsNewWorkspace = false

    var body: some View {
        Group {
            if model.workspaces.isEmpty && !model.isRefreshing {
                ContentUnavailableView {
                    Label("No Workspaces", systemImage: "rectangle.stack.badge.plus")
                } description: {
                    Text("Start an isolated task branch from an authorized GitHub repository.")
                } actions: {
                    Button("New Workspace") { showsNewWorkspace = true }
                        .buttonStyle(.borderedProminent)
                        .disabled(!model.network.isConnected)
                }
            } else {
                ScrollView {
                    LazyVStack(spacing: 12) {
                        Button {
                            showsNewWorkspace = true
                        } label: {
                            Label("New Workspace", systemImage: "plus.circle.fill")
                                .font(.headline)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!model.network.isConnected)
                        .accessibilityIdentifier("workspace.new")

                        ForEach(model.workspaces) { workspace in
                            NavigationLink {
                                WorkspaceScreen(workspaceID: workspace.id)
                            } label: {
                                WorkspaceCard(workspace: workspace)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding()
                }
            }
        }
        .navigationTitle("Workspaces")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showsNewWorkspace = true } label: { Image(systemName: "plus") }
                    .accessibilityLabel("New Workspace")
                    .disabled(!model.network.isConnected)
            }
        }
        .refreshable { await model.refreshAll() }
        .task { if model.workspaces.isEmpty { await model.refreshAll() } }
        .sheet(isPresented: $showsNewWorkspace) {
            NavigationStack { NewWorkspaceView() }
        }
    }
}

private struct WorkspaceCard: View {
    let workspace: WorkspaceSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(HostileDisplayText.sanitized(workspace.taskName))
                        .font(.headline)
                        .foregroundStyle(.primary)
                    Text(HostileDisplayText.sanitized(workspace.repositoryFullName))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                lifecycleLabel
            }

            if let summary = workspace.taskSummary, !summary.isEmpty {
                Text(HostileDisplayText.sanitized(summary))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            Label(HostileDisplayText.sanitized(workspace.branch), systemImage: "arrow.triangle.branch")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(1)

            HStack(spacing: 12) {
                Label(workspace.connectivity.rawValue.capitalized, systemImage: connectivitySymbol)
                    .foregroundStyle(workspace.connectivity == .connected ? Color.green : Color.orange)
                if workspace.unreadActivityCount > 0 {
                    Label("\(workspace.unreadActivityCount) unread", systemImage: "bell.badge.fill")
                        .foregroundStyle(.orange)
                }
            }
            .font(.caption.weight(.semibold))

            if let failure = workspace.failureMessage {
                Label(HostileDisplayText.sanitized(failure), systemImage: "xmark.octagon.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .lineLimit(2)
            } else if workspace.pendingApprovalCount > 0 {
                Label("\(workspace.pendingApprovalCount) request pending", systemImage: "exclamationmark.bubble.fill")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.orange)
            }

            HStack(spacing: 14) {
                statusMetric(
                    "\(workspace.resourceShare.cpuCores.formatted(.number.precision(.fractionLength(1)))) CPU",
                    symbol: "cpu"
                )
                statusMetric(
                    "\(workspace.resourceShare.memoryGiB.formatted(.number.precision(.fractionLength(1)))) GiB",
                    symbol: "memorychip"
                )
                if workspace.git.isDirty {
                    statusMetric("Dirty", symbol: "circle.dotted")
                }
                if workspace.git.hasUnpushedCommits {
                    statusMetric("Unpushed", symbol: "arrow.up.circle")
                }
                Spacer()
                Text(elapsedText)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            if workspace.resourceShare.pressure != .nominal {
                Label(
                    "Server pressure: \(workspace.resourceShare.pressure.title). Equal shares may run slower.",
                    systemImage: "gauge.with.dots.needle.67percent"
                )
                .font(.caption2)
                .foregroundStyle(.orange)
            }
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemBackground), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(Color(uiColor: .separator).opacity(0.35), lineWidth: 0.5)
        }
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(HostileDisplayText.sanitized(workspace.taskName)), \(HostileDisplayText.sanitized(workspace.repositoryFullName)), \(workspace.lifecycle.title)")
        .accessibilityValue(accessibilitySummary)
        .accessibilityIdentifier("workspace.card.\(workspace.id)")
    }

    private var lifecycleLabel: some View {
        Label(workspace.lifecycle.title, systemImage: workspace.lifecycle.symbol)
            .font(.caption.weight(.semibold))
            .foregroundStyle(lifecycleColor)
            .labelStyle(.titleAndIcon)
    }

    private var lifecycleColor: Color {
        switch workspace.lifecycle {
        case .running, .ready: .green
        case .needsAttention, .awaitingSetupApproval: .orange
        case .failed: .red
        default: .secondary
        }
    }

    private var connectivitySymbol: String {
        switch workspace.connectivity {
        case .connected: "network"
        case .reconnecting: "arrow.triangle.2.circlepath"
        case .offline: "wifi.slash"
        case .unavailable: "exclamationmark.icloud.fill"
        }
    }

    private func statusMetric(_ title: String, symbol: String) -> some View {
        Label(title, systemImage: symbol)
            .font(.caption2)
            .foregroundStyle(.secondary)
    }

    private var elapsedText: String {
        let hours = workspace.elapsedSeconds / 3_600
        let minutes = (workspace.elapsedSeconds % 3_600) / 60
        return hours > 0 ? "\(hours)h \(minutes)m" : "\(minutes)m"
    }

    private var accessibilitySummary: String {
        var parts = [
            "Branch \(workspace.branch)",
            workspace.connectivity.rawValue,
            "\(workspace.unreadActivityCount) unread activities",
            "\(workspace.pendingApprovalCount) pending approvals"
        ]
        if workspace.git.isDirty { parts.append("working tree has changes") }
        if workspace.git.hasUnpushedCommits { parts.append("has unpushed commits") }
        if let failure = workspace.failureMessage { parts.append("failure: \(failure)") }
        return parts.joined(separator: ", ")
    }
}
