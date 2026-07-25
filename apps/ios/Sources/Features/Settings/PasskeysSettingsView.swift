import SwiftUI

struct PasskeysSettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var passkeys: [PasskeyMetadata] = []
    @State private var pendingRevocation: PasskeyMetadata?
    @State private var isShowingRevocationConfirmation = false
    @State private var isWorking = false
    @State private var errorMessage: String?

    var body: some View {
        Form {
            Section {
                if passkeys.isEmpty, isWorking {
                    ProgressView("Loading passkeys…")
                } else if passkeys.isEmpty {
                    Text("No passkeys were returned. Use SSH recovery before signing out.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(passkeys) { passkey in
                        VStack(alignment: .leading, spacing: 7) {
                            HStack(alignment: .firstTextBaseline) {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(passkey.deviceName)
                                    Text("Added \(passkey.createdAt.formatted(date: .abbreviated, time: .shortened))")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if passkeys.count == 1 {
                                    Text("Required")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                } else {
                                    Button("Revoke", role: .destructive) {
                                        pendingRevocation = passkey
                                        isShowingRevocationConfirmation = true
                                    }
                                    .disabled(isWorking || !model.network.isConnected)
                                    .accessibilityIdentifier("settings.passkey.\(passkey.id).revoke")
                                }
                            }
                            if let lastUsedAt = passkey.lastUsedAt {
                                Text("Last used \(lastUsedAt.formatted(.relative(presentation: .named)))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            } else {
                                Text("Not used to sign in yet")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            } header: {
                Text("Enrolled passkeys")
            } footer: {
                Text("The device name records where enrollment started. Apple may sync the passkey through iCloud Keychain, so it does not prove which devices hold a copy.")
            }

            Section("Lockout protection") {
                Text("Keep at least two passkeys when possible. The server refuses to revoke your final passkey. If all passkeys are lost, use the SSH-only recovery runbook to enroll a replacement, then add a second passkey here.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Revoking a passkey does not revoke app sessions. Revoking an app device does not necessarily invalidate a synced passkey.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let errorMessage {
                Section { Text(errorMessage).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Passkeys")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    Task { await addPasskey() }
                } label: {
                    Label("Add Passkey", systemImage: "plus")
                }
                .disabled(isWorking || !model.network.isConnected)
                .accessibilityIdentifier("settings.passkeys.add")
            }
        }
        .task { await load() }
        .confirmationDialog(
            "Revoke passkey?",
            isPresented: $isShowingRevocationConfirmation,
            presenting: pendingRevocation
        ) { passkey in
            Button("Revoke \(passkey.deviceName) passkey", role: .destructive) {
                Task { await revoke(passkey) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("This passkey will stop working for future sign-ins. Existing app sessions remain active.")
        }
    }

    private func load() async {
        isWorking = true
        defer { isWorking = false }
        do {
            passkeys = try await model.api.passkeys()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func addPasskey() async {
        isWorking = true
        defer { isWorking = false }
        do {
            _ = try await model.addPasskey()
            passkeys = try await model.api.passkeys()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func revoke(_ passkey: PasskeyMetadata) async {
        isWorking = true
        defer { isWorking = false }
        do {
            try await model.api.revokePasskey(id: passkey.id)
            passkeys = try await model.api.passkeys()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
