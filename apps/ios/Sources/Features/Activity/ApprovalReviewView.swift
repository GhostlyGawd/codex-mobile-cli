import SwiftUI

struct ApprovalReviewView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let approvalID: String

    @State private var approval: ApprovalReview?
    @State private var errorMessage: String?
    @State private var isResolving = false

    var body: some View {
        Group {
            if let approval {
                List {
                    Section("Session") {
                        LabeledContent("Workspace", value: HostileDisplayText.sanitized(approval.workspaceName))
                    }
                    if approval.structuredDetailAvailable {
                        Section("Request") {
                            if let action = approval.requestedAction { LabeledContent("Action", value: HostileDisplayText.sanitized(action)) }
                            if let reason = approval.reason { LabeledContent("Reason", value: HostileDisplayText.sanitized(reason)) }
                        }
                        detailSection("Filesystem scope", values: approval.filesystemScope)
                        detailSection("Network scope", values: approval.networkScope)
                        detailSection("Affected paths", values: approval.affectedPaths)
                        if let risk = approval.riskExplanation {
                            Section("Risk") { Text(HostileDisplayText.sanitized(risk)).foregroundStyle(.orange) }
                        }
                        if approval.state == .pending {
                            Section {
                                Button("Approve") { Task { await resolve(.approve) } }
                                    .disabled(isResolving || !model.network.isConnected)
                                    .accessibilityIdentifier("approval.approve")
                                Button("Deny", role: .destructive) { Task { await resolve(.deny) } }
                                    .disabled(isResolving || !model.network.isConnected)
                                    .accessibilityIdentifier("approval.deny")
                            } footer: {
                                Text("Approval is available only after authenticated in-app review. There is no lock-screen approval action.")
                            }
                        }
                    } else {
                        Section {
                            Label("Structured details are unavailable. Inspect the live Codex TUI before responding.", systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                            Button("Open Live Terminal") {
                                dismiss()
                                model.presentedWorkspaceID = approval.workspaceID
                            }
                        }
                    }
                    if let errorMessage { Section { Text(errorMessage).foregroundStyle(.red) } }
                }
            } else if let errorMessage {
                ContentUnavailableView("Approval Unavailable", systemImage: "exclamationmark.triangle", description: Text(errorMessage))
            } else {
                ProgressView("Loading authenticated review…")
            }
        }
        .navigationTitle("Approval")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
        .task { await load() }
    }

    @ViewBuilder
    private func detailSection(_ title: String, values: [String]) -> some View {
        if !values.isEmpty {
            Section(title) { ForEach(values, id: \.self) { Text(HostileDisplayText.sanitized($0)).font(.callout.monospaced()) } }
        }
    }

    private func load() async {
        do { approval = try await model.api.approval(id: approvalID) }
        catch { errorMessage = error.localizedDescription }
    }

    private func resolve(_ decision: ApprovalDecision) async {
        isResolving = true
        defer { isResolving = false }
        do {
            approval = try await model.api.resolveApproval(id: approvalID, decision: decision)
            await model.refreshActivities()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
