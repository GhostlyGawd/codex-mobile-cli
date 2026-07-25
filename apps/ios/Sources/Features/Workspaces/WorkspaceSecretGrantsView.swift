import SwiftUI

struct WorkspaceSecretGrantsView: View {
    @Environment(AppModel.self) private var model
    let workspaceID: String

    @State private var grants: [WorkspaceSecretGrant] = []
    @State private var changingSecretID: String?
    @State private var errorMessage: String?

    var body: some View {
        List {
            Section {
                Text("Only explicitly granted values become eligible for this workspace runtime. Values are never shown or cached on this device.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("Eligible secrets") {
                if grants.isEmpty {
                    Text("No global or repository secrets are available")
                        .foregroundStyle(.secondary)
                }
                ForEach(grants) { grant in
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(grant.secret.name).font(.body.monospaced())
                            Text(grant.secret.scope == .global ? "Global" : "Repository")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(grant.granted ? "Revoke" : "Grant", role: grant.granted ? .destructive : nil) {
                            Task { await setGranted(!grant.granted, grant: grant) }
                        }
                        .disabled(changingSecretID != nil || !model.network.isConnected)
                        .accessibilityIdentifier("workspace.secret.\(grant.secret.id).\(grant.granted ? "revoke" : "grant")")
                    }
                }
            }
            if let errorMessage { Section { Text(errorMessage).foregroundStyle(.red) } }
        }
        .task { await load() }
        .refreshable { await load() }
    }

    private func load() async {
        guard model.network.isConnected else { return }
        do {
            grants = try await model.api.workspaceSecretGrants(workspaceID: workspaceID)
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func setGranted(_ granted: Bool, grant: WorkspaceSecretGrant) async {
        changingSecretID = grant.secret.id
        defer { changingSecretID = nil }
        do {
            if granted {
                try await model.api.grantSecret(workspaceID: workspaceID, secretID: grant.secret.id)
            } else {
                try await model.api.revokeSecretGrant(workspaceID: workspaceID, secretID: grant.secret.id)
            }
            await load()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
