import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var settings: UserSettings?
    @State private var devices: [DeviceSummary] = []
    @State private var connectionStatus: ConnectionStatus?
    @State private var errorMessage: String?
    @State private var isSaving = false
    @State private var pendingRevocation: DeviceSummary?
    @State private var isShowingRevocationConfirmation = false
    @State private var revokingDeviceID: String?
    @State private var isShowingFullAccessDefaultConfirmation = false
    @State private var pendingGitHubDisconnect: GitHubInstallationConnection?
    @State private var pendingCodexDisconnect: CodexWorkspaceConnection?
    @State private var isShowingGitHubDisconnectConfirmation = false
    @State private var isShowingCodexDisconnectConfirmation = false
    @State private var disconnectingConnectionID: String?

    var body: some View {
        Form {
            Section("Connections") {
                NavigationLink {
                    PasskeysSettingsView()
                } label: {
                    Label("Passkeys", systemImage: "person.badge.key.fill")
                }
                if let connectionStatus {
                    LabeledContent("GitHub") {
                        Text(gitHubStatusTitle(connectionStatus.github))
                            .foregroundStyle(connectionStatus.github.connected ? Color.green : Color.secondary)
                    }
                    ForEach(connectionStatus.github.installations) { installation in
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(HostileDisplayText.sanitized(installation.accountLogin))
                                Text("\(installation.accountType) · \(installation.repositorySelection) repositories")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Disconnect", role: .destructive) {
                                pendingGitHubDisconnect = installation
                                isShowingGitHubDisconnectConfirmation = true
                            }
                            .disabled(disconnectingConnectionID != nil || !model.network.isConnected)
                            .accessibilityIdentifier("settings.github.\(installation.installationID).disconnect")
                        }
                    }

                    LabeledContent("ChatGPT Codex") {
                        Text(codexStatusTitle(connectionStatus.codex))
                            .foregroundStyle(connectionStatus.codex.connectedWorkspaceCount > 0 ? Color.green : Color.secondary)
                    }
                    ForEach(connectionStatus.codex.workspaces) { workspace in
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(HostileDisplayText.sanitized(workspace.workspaceName))
                                Text(workspace.state.title)
                                    .font(.caption)
                                    .foregroundStyle(codexStatusColor(workspace.state))
                            }
                            Spacer()
                            if workspace.state == .connected || workspace.state == .authenticating {
                                Button("Disconnect", role: .destructive) {
                                    pendingCodexDisconnect = workspace
                                    isShowingCodexDisconnectConfirmation = true
                                }
                                .disabled(disconnectingConnectionID != nil || !model.network.isConnected)
                                .accessibilityIdentifier("settings.codex.\(workspace.workspaceID).disconnect")
                            }
                        }
                    }
                } else {
                    ProgressView("Checking account connections…")
                }
                Text("GitHub App setup remains owner-controlled. ChatGPT Codex authentication is separate for each workspace: resume it and run codex login --device-auth in the real terminal to connect or reauthenticate.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Devices") {
                if devices.isEmpty {
                    Text("No active devices")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(devices) { device in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text(device.name)
                                if device.current {
                                    Text("This device")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Revoke", role: .destructive) {
                                    pendingRevocation = device
                                    isShowingRevocationConfirmation = true
                                }
                                .disabled(revokingDeviceID != nil || !model.network.isConnected)
                                .accessibilityIdentifier("settings.device.\(device.id).revoke")
                            }
                            HStack(spacing: 4) {
                                Text(device.platform.uppercased())
                                Text("·")
                                Text("Last seen")
                                Text(device.lastSeenAt, style: .relative)
                            }
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        }
                    }
                }
                Text("Revoking a device ends its sessions, terminal leases, and push notifications. A synced passkey remains valid and can sign in from another installation.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let binding = Binding($settings) {
                Section("Terminal") {
                    Stepper(
                        "Font size: \(Int(binding.wrappedValue.terminalFontSize))",
                        value: binding.terminalFontSize,
                        in: 8...48
                    )
                    Picker("Cursor", selection: binding.terminalCursorStyle) {
                        Text("Block").tag("block")
                        Text("Beam").tag("beam")
                        Text("Underline").tag("underline")
                    }
                    Picker("Theme", selection: binding.terminalTheme) {
                        Text("System").tag("system")
                        Text("Dark").tag("dark")
                        Text("Light").tag("light")
                        Text("High Contrast").tag("high_contrast")
                    }
                }

                Section {
                    Picker("Default autonomy", selection: autonomyDefaultBinding(binding)) {
                        ForEach(AutonomyMode.allCases) { Text($0.title).tag($0) }
                    }
                    Picker("Retention", selection: binding.retentionDefault) {
                        ForEach(RetentionPolicy.allCases) { Text($0.title).tag($0) }
                    }
                    Stepper(
                        "Idle timeout: \(binding.wrappedValue.idleTimeoutMinutes) min",
                        value: binding.idleTimeoutMinutes,
                        in: 5...10_080,
                        step: 5
                    )
                    if binding.wrappedValue.autonomyDefault == .fullAccess {
                        Label("Full Access is the saved default", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                } header: {
                    Text("Autonomy and lifecycle")
                } footer: {
                    Text("Full Access lets Codex act without approval inside each new isolated workspace. Host isolation, network policy, secret grants, and the no-host-socket rule still apply.")
                }

                Section("Notifications") {
                    Toggle("Quiet hours", isOn: binding.quietHoursEnabled)
                    Toggle("More notification detail", isOn: binding.notificationDetailEnabled)
                    Button("Enable iOS Notifications") {
                        Task {
                            do { try await PushNotificationRegistration.requestAndRegister() }
                            catch { errorMessage = error.localizedDescription }
                        }
                    }
                    .disabled(model.capabilities?.apnsConfigured != true)
                    Text("Lock-screen text remains generic by default and never includes repositories, prompts, commands, paths, output, diffs, or secrets.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section {
                    Button("Save Settings") { Task { await save(binding.wrappedValue) } }
                        .disabled(isSaving || !model.network.isConnected)
                        .accessibilityIdentifier("settings.save")
                }
            } else {
                Section { ProgressView("Loading settings…") }
            }

            Section("Secrets") {
                NavigationLink {
                    SecretsSettingsView()
                } label: {
                    Label("Encrypted vault management", systemImage: "lock.square.stack")
                }
                Text("Values are accepted only when created or rotated. They are never returned by the API or saved in the offline cache.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Maintenance and diagnostics") {
                NavigationLink {
                    MaintenanceView()
                } label: {
                    Label("Server maintenance", systemImage: "wrench.and.screwdriver")
                }
                NavigationLink {
                    DiagnosticsView()
                } label: {
                    Label("Metadata-only diagnostics", systemImage: "stethoscope")
                }
                Text("Host updates remain a root-owned workflow. Diagnostics exclude user content and credentials.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let errorMessage { Section { Text(errorMessage).foregroundStyle(.red) } }

            Section {
                Button("Sign Out", role: .destructive) { Task { await model.signOut() } }
                    .accessibilityIdentifier("settings.sign-out")
            }
        }
        .navigationTitle("Settings")
        .task { await load() }
        .confirmationDialog(
            "Revoke device?",
            isPresented: $isShowingRevocationConfirmation,
            presenting: pendingRevocation
        ) { device in
            Button("Revoke \(device.name)", role: .destructive) {
                Task { await revoke(device) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { device in
            Text(device.current
                ? "This will sign out this installation immediately."
                : "This device will lose its sessions, terminal access, and notifications.")
        }
        .confirmationDialog(
            "Disconnect GitHub?",
            isPresented: $isShowingGitHubDisconnectConfirmation,
            presenting: pendingGitHubDisconnect
        ) { installation in
            Button("Disconnect \(HostileDisplayText.sanitized(installation.accountLogin))", role: .destructive) {
                Task { await disconnectGitHub(installation) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("This revokes the server's local authority to mint new tokens and hides its repositories. It does not uninstall or change the external GitHub App installation.")
        }
        .confirmationDialog(
            "Disconnect ChatGPT Codex?",
            isPresented: $isShowingCodexDisconnectConfirmation,
            presenting: pendingCodexDisconnect
        ) { workspace in
            Button("Disconnect from \(HostileDisplayText.sanitized(workspace.workspaceName))", role: .destructive) {
                Task { await disconnectCodex(workspace) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("This stops app-owned Codex terminals and removes runtime and encrypted credentials from the workspace. Conversation history and non-Codex terminal processes remain.")
        }
        .alert("Use Full Access by default?", isPresented: $isShowingFullAccessDefaultConfirmation) {
            Button("Use Full Access", role: .destructive) {
                settings?.autonomyDefault = .fullAccess
            }
            Button("Keep Current Default", role: .cancel) {}
        } message: {
            Text("Every new workspace will start with Codex able to act without approvals unless you change it during creation.")
        }
    }

    private func autonomyDefaultBinding(_ settings: Binding<UserSettings>) -> Binding<AutonomyMode> {
        Binding(
            get: { settings.wrappedValue.autonomyDefault },
            set: { requestedMode in
                if requestedMode == .fullAccess,
                   settings.wrappedValue.autonomyDefault != .fullAccess {
                    isShowingFullAccessDefaultConfirmation = true
                } else {
                    settings.wrappedValue.autonomyDefault = requestedMode
                }
            }
        )
    }

    private func load() async {
        do {
            async let settingsRequest = model.api.settings()
            async let devicesRequest = model.api.devices()
            async let connectionsRequest = model.api.connections()
            let (value, deviceValues, connectionsValue) = try await (settingsRequest, devicesRequest, connectionsRequest)
            settings = value
            devices = deviceValues
            connectionStatus = connectionsValue
            model.userSettings = value
        }
        catch { errorMessage = error.localizedDescription }
    }

    private func disconnectGitHub(_ installation: GitHubInstallationConnection) async {
        disconnectingConnectionID = "github:\(installation.installationID)"
        defer { disconnectingConnectionID = nil }
        do {
            try await model.api.disconnectGitHub(installationID: installation.installationID)
            connectionStatus = try await model.api.connections()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func disconnectCodex(_ workspace: CodexWorkspaceConnection) async {
        disconnectingConnectionID = "codex:\(workspace.workspaceID)"
        defer { disconnectingConnectionID = nil }
        do {
            try await model.api.disconnectCodex(workspaceID: workspace.workspaceID)
            connectionStatus = try await model.api.connections()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func gitHubStatusTitle(_ status: GitHubConnectionStatus) -> String {
        if !status.configured { return "Owner setup required" }
        if status.connected { return "\(status.installations.count) connected" }
        return "Not connected"
    }

    private func codexStatusTitle(_ status: CodexConnectionStatus) -> String {
        if status.workspaces.isEmpty { return "No workspaces" }
        if status.connectedWorkspaceCount > 0 { return "\(status.connectedWorkspaceCount) connected" }
        if status.authenticatingWorkspaceCount > 0 { return "Authenticating" }
        return "Not connected"
    }

    private func codexStatusColor(_ state: CodexConnectionState) -> Color {
        switch state {
        case .connected: .green
        case .authenticating: .orange
        case .disconnected, .unavailable: .secondary
        }
    }

    private func revoke(_ device: DeviceSummary) async {
        revokingDeviceID = device.id
        defer { revokingDeviceID = nil }
        do {
            try await model.api.revokeDevice(id: device.id)
            errorMessage = nil
            if device.current {
                await model.signOut()
            } else {
                devices = try await model.api.devices()
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func save(_ value: UserSettings) async {
        isSaving = true
        defer { isSaving = false }
        do {
            let updated = try await model.api.updateSettings(value)
            settings = updated
            model.userSettings = updated
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
