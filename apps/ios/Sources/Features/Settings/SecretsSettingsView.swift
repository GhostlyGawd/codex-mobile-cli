import SwiftUI

struct SecretsSettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var secrets: [SecretMetadata] = []
    @State private var repositories: [RepositorySummary] = []
    @State private var editingSecret: SecretMetadata?
    @State private var isCreating = false
    @State private var pendingDeletion: SecretMetadata?
    @State private var isShowingDeletionConfirmation = false
    @State private var errorMessage: String?

    var body: some View {
        List {
            Section {
                Text("Secret names use environment-variable syntax. Values must be 4–8,192 bytes, are encrypted before storage, and are never displayed again.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("Active secrets") {
                if secrets.isEmpty {
                    Text("No encrypted secrets")
                        .foregroundStyle(.secondary)
                }
                ForEach(secrets) { secret in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(secret.name).font(.body.monospaced())
                            Spacer()
                            Button("Rotate") { editingSecret = secret }
                                .accessibilityIdentifier("secrets.\(secret.id).rotate")
                        }
                        Text(scopeLabel(secret))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("Stored value: \(secret.valueBytes) bytes · updated \(secret.updatedAt.formatted(.relative(presentation: .named)))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .swipeActions {
                        Button("Delete", role: .destructive) {
                            pendingDeletion = secret
                            isShowingDeletionConfirmation = true
                        }
                    }
                }
            }
            if let errorMessage {
                Section { Text(errorMessage).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Secrets")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { isCreating = true } label: { Label("Add Secret", systemImage: "plus") }
                    .disabled(!model.network.isConnected)
                    .accessibilityIdentifier("secrets.add")
            }
        }
        .task { await load() }
        .sheet(isPresented: $isCreating) {
            SecretValueEditor(repositories: repositories, existing: nil) { request in
                _ = try await model.api.createSecret(request)
                await load()
            }
        }
        .sheet(item: $editingSecret) { secret in
            SecretValueEditor(repositories: repositories, existing: secret) { request in
                _ = try await model.api.updateSecret(id: secret.id, request: UpdateSecretRequest(value: request.value))
                await load()
            }
        }
        .confirmationDialog(
            "Delete secret?",
            isPresented: $isShowingDeletionConfirmation,
            presenting: pendingDeletion
        ) { secret in
            Button("Delete \(secret.name)", role: .destructive) { Task { await delete(secret) } }
            Button("Cancel", role: .cancel) {}
        } message: { secret in
            Text("This revokes every workspace grant for \(secret.name). The stored value cannot be recovered.")
        }
    }

    private func load() async {
        guard model.network.isConnected else { return }
        do {
            async let secretRequest = model.api.secrets(repositoryID: nil)
            async let repositoryRequest = model.api.repositories(search: nil)
            (secrets, repositories) = try await (secretRequest, repositoryRequest)
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func delete(_ secret: SecretMetadata) async {
        do {
            try await model.api.deleteSecret(id: secret.id)
            await load()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func scopeLabel(_ secret: SecretMetadata) -> String {
        guard let repositoryID = secret.repositoryID else { return "Global" }
        let name = repositories.first { $0.id == repositoryID }?.fullName ?? repositoryID
        return "Repository · \(HostileDisplayText.sanitized(name))"
    }
}

private struct SecretValueEditor: View {
    @Environment(\.dismiss) private var dismiss
    let repositories: [RepositorySummary]
    let existing: SecretMetadata?
    let save: (CreateSecretRequest) async throws -> Void

    @State private var name: String
    @State private var value = ""
    @State private var repositoryID: String?
    @State private var isSaving = false
    @State private var errorMessage: String?

    init(
        repositories: [RepositorySummary],
        existing: SecretMetadata?,
        save: @escaping (CreateSecretRequest) async throws -> Void
    ) {
        self.repositories = repositories
        self.existing = existing
        self.save = save
        _name = State(initialValue: existing?.name ?? "")
        _repositoryID = State(initialValue: existing?.repositoryID)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Metadata") {
                    if existing == nil {
                        TextField("NAME", text: $name)
                            .textInputAutocapitalization(.characters)
                            .autocorrectionDisabled()
                        Picker("Scope", selection: $repositoryID) {
                            Text("Global").tag(String?.none)
                            ForEach(repositories) { repository in
                                Text(HostileDisplayText.sanitized(repository.fullName)).tag(Optional(repository.id))
                            }
                        }
                    } else {
                        LabeledContent("Name", value: name)
                        LabeledContent("Scope", value: repositoryID == nil ? "Global" : "Repository")
                    }
                }
                Section(existing == nil ? "Value" : "New value") {
                    SecureField("Secret value", text: $value)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Text("4–8,192 UTF-8 bytes. The value is sent once over the authenticated connection and is never returned.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let errorMessage { Section { Text(errorMessage).foregroundStyle(.red) } }
            }
            .navigationTitle(existing == nil ? "Add Secret" : "Rotate Secret")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { clearAndDismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { await submit() } }
                        .disabled(isSaving || name.isEmpty || !(4 ... 8192).contains(value.utf8.count))
                }
            }
            .interactiveDismissDisabled(isSaving)
            .onDisappear { value = "" }
        }
    }

    private func submit() async {
        isSaving = true
        defer { isSaving = false }
        do {
            let request = CreateSecretRequest(name: name, value: value, repositoryID: repositoryID)
            try await save(request)
            value = ""
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func clearAndDismiss() {
        value = ""
        dismiss()
    }
}
