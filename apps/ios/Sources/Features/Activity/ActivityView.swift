import SwiftUI

struct ActivityView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if model.activities.isEmpty {
                ContentUnavailableView("No Activity", systemImage: "bell.slash", description: Text("Approvals, questions, completions, failures, and maintenance appear here."))
            } else {
                List(model.activities) { activity in
                    Button {
                        if activity.kind == .approval { model.presentedApprovalID = activity.id }
                        else if let workspaceID = activity.workspaceID { model.presentedWorkspaceID = workspaceID }
                    } label: {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: symbol(for: activity.kind))
                                .foregroundStyle(color(for: activity.kind))
                                .frame(width: 26)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(HostileDisplayText.sanitized(activity.title)).font(.headline).foregroundStyle(.primary)
                                Text(HostileDisplayText.sanitized(activity.genericSummary)).font(.subheadline).foregroundStyle(.secondary)
                                Text(activity.createdAt, style: .relative).font(.caption).foregroundStyle(.tertiary)
                            }
                            Spacer()
                            if activity.state == .pending || activity.state == .unread {
                                Circle().fill(.tint).frame(width: 8, height: 8).accessibilityLabel("Unread")
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("activity.\(activity.id)")
                }
            }
        }
        .navigationTitle("Activity")
        .refreshable { await model.refreshActivities() }
        .task { if model.activities.isEmpty { await model.refreshActivities() } }
    }

    private func symbol(for kind: ActivityKind) -> String {
        switch kind {
        case .approval: "checkmark.shield.fill"
        case .question: "questionmark.bubble.fill"
        case .completion: "checkmark.circle.fill"
        case .failure: "xmark.octagon.fill"
        case .maintenance: "wrench.and.screwdriver.fill"
        case .security: "lock.shield.fill"
        }
    }

    private func color(for kind: ActivityKind) -> Color {
        switch kind {
        case .approval, .question: .orange
        case .completion: .green
        case .failure, .security: .red
        case .maintenance: .blue
        }
    }
}
