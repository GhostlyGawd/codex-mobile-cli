import SwiftUI

struct NewWorkspaceView: View {
    private struct EnvironmentDraft: Identifiable {
        let id = UUID()
        var name = ""
        var value = ""
    }

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let preselectedRepositoryID: String?

    @State private var selectedRepositoryID: String?
    @State private var search = ""
    @State private var initialPrompt = ""
    @State private var showsAdvanced = false
    @State private var baseBranch = ""
    @State private var taskName = ""
    @State private var autonomy: AutonomyMode = .balanced
    @State private var retention: RetentionPolicy = .thirtyDays
    @State private var nestedDocker = false
    @State private var requestedDisk = 12
    @State private var environment: [EnvironmentDraft] = []
    @State private var showsFullAccessWarning = false
    @State private var hasAppliedUserDefaults = false
    @State private var isStarting = false
    @State private var errorMessage: String?

    init(preselectedRepositoryID: String? = nil) {
        self.preselectedRepositoryID = preselectedRepositoryID
        _selectedRepositoryID = State(initialValue: preselectedRepositoryID)
    }

    var body: some View {
        Form {
            Section("1. Repository") {
                if model.repositories.isEmpty {
                    ProgressView("Loading authorized repositories…")
                } else {
                    ForEach(filteredRepositories) { repository in
                        Button {
                            selectedRepositoryID = repository.id
                            if baseBranch.isEmpty { baseBranch = repository.defaultBranch }
                        } label: {
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(HostileDisplayText.sanitized(repository.fullName)).foregroundStyle(.primary)
                                    Text(HostileDisplayText.sanitized(repository.defaultBranch)).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if selectedRepositoryID == repository.id {
                                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.tint)
                                }
                            }
                        }
                        .accessibilityIdentifier("new-workspace.repository.\(repository.id)")
                    }
                }
            }

            if selectedRepositoryID != nil {
                Section("2. Initial Codex prompt (optional)") {
                    TextEditor(text: $initialPrompt)
                        .frame(minHeight: 100)
                        .accessibilityLabel("Initial Codex prompt")
                    Text("\(initialPrompt.count.formatted()) / 100,000 characters")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(initialPrompt.count > 100_000 ? Color.red : Color.secondary)
                    Text("The backend sends this only after provisioning and the real Codex TUI are ready.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section {
                    DisclosureGroup("Advanced", isExpanded: $showsAdvanced) {
                        TextField("Task name", text: $taskName)
                        TextField("Base branch", text: $baseBranch)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Picker("Autonomy", selection: $autonomy) {
                            ForEach(AutonomyMode.allCases) { Text($0.title).tag($0) }
                        }
                        Picker("Retention", selection: $retention) {
                            ForEach(RetentionPolicy.allCases) { Text($0.title).tag($0) }
                        }
                        Stepper("Writable disk: \(requestedDisk) GiB", value: $requestedDisk, in: 8...16, step: 4)
                        Toggle("Nested Docker compatibility", isOn: $nestedDocker)
                            .disabled(true)
                        Text("Unavailable until the selected VPS passes the rootless nested-container isolation spike. The host socket and privileged mode are never used as fallbacks.")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        ForEach($environment) { $entry in
                            VStack(alignment: .leading) {
                                TextField("Environment variable name", text: $entry.name)
                                    .textInputAutocapitalization(.characters)
                                    .autocorrectionDisabled()
                                SecureField("Value", text: $entry.value)
                            }
                        }
                        Button("Add environment variable") { environment.append(EnvironmentDraft()) }
                            .disabled(environment.count >= 100)
                    }
                } footer: {
                    Text("CPU and memory are always shared equally; priority boosts are not offered. Persistent disk is fixed at creation between 8 and 16 GiB.")
                }

                Section {
                    Button {
                        Task { await startWorkspace() }
                    } label: {
                        HStack {
                            Spacer()
                            if isStarting { ProgressView().padding(.trailing, 4) }
                            Text("Start Workspace").fontWeight(.semibold)
                            Spacer()
                        }
                    }
                    .disabled(isStarting || !model.network.isConnected)
                    .accessibilityIdentifier("new-workspace.start")
                } footer: {
                    Text("Your saved autonomy and retention defaults are preselected. Equal resource sharing and nested Docker off remain fixed defaults.")
                }
            }

            if let errorMessage {
                Section { Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red) }
            }
        }
        .navigationTitle("New Workspace")
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $search, prompt: "Search authorized repositories")
        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        .task {
            if !hasAppliedUserDefaults {
                if model.userSettings == nil { await model.refreshSettings() }
                if let defaults = model.userSettings {
                    autonomy = defaults.autonomyDefault
                    retention = defaults.retentionDefault
                    if defaults.autonomyDefault == .fullAccess {
                        showsFullAccessWarning = true
                    }
                }
                hasAppliedUserDefaults = true
            }
            if model.repositories.isEmpty { await model.refreshRepositories() }
            if let selected = model.repositories.first(where: { $0.id == selectedRepositoryID }), baseBranch.isEmpty {
                baseBranch = selected.defaultBranch
            }
        }
        .onChange(of: autonomy) { oldValue, newValue in
            if newValue == .fullAccess && oldValue != .fullAccess { showsFullAccessWarning = true }
        }
        .alert("Full Access inside the workspace", isPresented: $showsFullAccessWarning) {
            Button("Use Full Access", role: .destructive) {}
            Button("Keep Balanced", role: .cancel) { autonomy = .balanced }
        } message: {
            Text("Codex can act without approvals inside this one isolated container. Host isolation, network policy, secret grants, and the no-host-socket rule remain enforced.")
        }
    }

    private var filteredRepositories: [RepositorySummary] {
        guard !search.isEmpty else { return model.repositories }
        return model.repositories.filter { $0.fullName.localizedCaseInsensitiveContains(search) }
    }

    private func startWorkspace() async {
        guard let repositoryID = selectedRepositoryID else { return }
        guard initialPrompt.count <= 100_000,
              baseBranch.count <= 255,
              taskName.count <= 200 else {
            errorMessage = "The prompt, branch, or task name exceeds the control-plane limit."
            return
        }
        let activeEnvironment = environment.filter { !$0.name.isEmpty }
        guard activeEnvironment.count <= 100,
              activeEnvironment.allSatisfy({ $0.value.count <= 8_192 }),
              Set(activeEnvironment.map(\.name)).count == activeEnvironment.count else {
            errorMessage = "Environment variable names must be unique and each value must be at most 8,192 characters."
            return
        }
        var variables: [String: String] = [:]
        for entry in activeEnvironment {
            variables[entry.name] = entry.value
        }
        isStarting = true
        defer { isStarting = false }
        do {
            let detail = try await model.api.createWorkspace(NewWorkspaceRequest(
                repositoryID: repositoryID,
                initialPrompt: initialPrompt.isEmpty ? nil : initialPrompt,
                baseBranch: baseBranch.isEmpty ? nil : baseBranch,
                taskName: taskName.isEmpty ? nil : taskName,
                autonomy: autonomy,
                nestedDocker: nestedDocker,
                retention: retention,
                environmentVariables: variables,
                requestedDiskGiB: requestedDisk
            ))
            environment.removeAll()
            await model.refreshAll()
            dismiss()
            model.presentedWorkspaceID = detail.id
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
