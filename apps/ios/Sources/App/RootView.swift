import SwiftUI

enum AppSection: String, CaseIterable, Identifiable, Hashable, Sendable {
    case workspaces
    case repositories
    case activity
    case settings

    var id: String { rawValue }
    var title: String { rawValue.capitalized }

    var symbol: String {
        switch self {
        case .workspaces: "rectangle.stack.fill"
        case .repositories: "shippingbox.fill"
        case .activity: "bell.badge.fill"
        case .settings: "gearshape.fill"
        }
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        switch model.authenticationState {
        case .restoring:
            ProgressView("Restoring secure session…")
                .accessibilityIdentifier("auth.restoring")
        case .signedOut:
            PasskeySignInView()
        case .signedIn:
            AdaptiveApplicationView()
        case let .configurationRequired(message):
            ConfigurationRequiredView(message: message)
        }
    }
}

private struct ConfigurationRequiredView: View {
    let message: String

    var body: some View {
        ContentUnavailableView {
            Label("Configuration Required", systemImage: "wrench.and.screwdriver")
        } description: {
            Text(message)
        } actions: {
            Text("The checked-in .invalid endpoints deliberately disable external access.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding()
        .accessibilityIdentifier("auth.configuration-required")
    }
}

private struct PasskeySignInView: View {
    @Environment(AppModel.self) private var model
    @State private var bootstrapToken = ""
    @State private var showsEnrollment = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Spacer()
                Image(systemName: "terminal.fill")
                    .font(.system(size: 58, weight: .medium))
                    .accessibilityHidden(true)
                VStack(spacing: 8) {
                    Text(AppDisplayName.value)
                        .font(.largeTitle.bold())
                    Text("Sign in with the passkey registered for this private control plane.")
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                Button {
                    Task { await model.signIn() }
                } label: {
                    Label("Sign in with Passkey", systemImage: "person.badge.key.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(model.isRefreshing)
                .accessibilityIdentifier("auth.sign-in")

                if model.capabilities?.passkeyBootstrapAvailable == true {
                    DisclosureGroup("Register first owner passkey", isExpanded: $showsEnrollment) {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Use the short-lived token generated on the server console. Enrollment disables automatically after the first passkey.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                            SecureField("Bootstrap token", text: $bootstrapToken)
                                .textContentType(.oneTimeCode)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            Button("Register Passkey") {
                                let token = bootstrapToken
                                bootstrapToken = ""
                                Task { await model.registerFirstPasskey(bootstrapToken: token) }
                            }
                            .disabled(bootstrapToken.isEmpty || model.isRefreshing)
                        }
                        .padding(.top, 8)
                    }
                }

                if let error = model.lastError {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("auth.error")
                }
                if model.isServerUnavailable {
                    VStack(alignment: .leading, spacing: 4) {
                        Label("Server unavailable", systemImage: "server.rack")
                            .font(.footnote.weight(.semibold))
                        Text(serverLossRecoveryMessage)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(.orange.opacity(0.14), in: RoundedRectangle(cornerRadius: 10))
                    .accessibilityIdentifier("server.unavailable.notice")
                }
                Spacer()
            }
            .padding(24)
            .overlay { if model.isRefreshing { ProgressView().controlSize(.large) } }
        }
    }
}

private struct AdaptiveApplicationView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @State private var selection: AppSection = .workspaces

    var body: some View {
        Group {
            if horizontalSizeClass == .regular {
                NavigationSplitView {
                    List(selection: sidebarSelection) {
                        ForEach(AppSection.allCases) { section in
                            Label(section.title, systemImage: section.symbol)
                                .tag(section)
                        }
                    }
                    .navigationTitle(AppDisplayName.value)
                } detail: {
                    NavigationStack { destination(for: selection) }
                }
            } else {
                TabView(selection: $selection) {
                    ForEach(AppSection.allCases) { section in
                        NavigationStack { destination(for: section) }
                            .tabItem { Label(section.title, systemImage: section.symbol) }
                            .tag(section)
                    }
                }
            }
        }
        .safeAreaInset(edge: .top, spacing: 0) { connectionBanner }
        .onChange(of: model.requestedSection) { _, requested in
            guard let requested else { return }
            selection = requested
            model.requestedSection = nil
        }
        .task(id: model.network.isConnected) {
            await model.connectivityDidChange(isConnected: model.network.isConnected)
        }
        .fullScreenCover(isPresented: Binding(
            get: { model.presentedWorkspaceID != nil },
            set: { if !$0 { model.presentedWorkspaceID = nil } }
        )) {
            if let id = model.presentedWorkspaceID {
                NavigationStack { WorkspaceScreen(workspaceID: id) }
            }
        }
        .sheet(isPresented: Binding(
            get: { model.presentedApprovalID != nil },
            set: { if !$0 { model.presentedApprovalID = nil } }
        )) {
            if let id = model.presentedApprovalID {
                NavigationStack { ApprovalReviewView(approvalID: id) }
                    .presentationDetents([.medium, .large])
            }
        }
    }

    private var sidebarSelection: Binding<AppSection?> {
        Binding(
            get: { selection },
            set: { proposedSelection in
                guard let proposedSelection else { return }
                selection = proposedSelection
            }
        )
    }

    @ViewBuilder
    private func destination(for section: AppSection) -> some View {
        switch section {
        case .workspaces: WorkspacesView()
        case .repositories: RepositoriesView()
        case .activity: ActivityView()
        case .settings: SettingsView()
        }
    }

    @ViewBuilder
    private var connectionBanner: some View {
        if !model.network.isConnected || model.isServerUnavailable || model.isShowingStaleData {
            VStack(spacing: 3) {
                Label(
                    model.network.isConnected
                        ? (model.isServerUnavailable ? "Server unavailable — cached data is read only" : "Showing encrypted cached data")
                        : "Offline — read-only cached data",
                    systemImage: !model.network.isConnected
                        ? "wifi.slash"
                        : (model.isServerUnavailable ? "server.rack" : "wifi.slash")
                )
                .font(.caption.weight(.semibold))
                if model.network.isConnected, model.isServerUnavailable {
                    Text(serverLossRecoveryMessage)
                        .font(.caption2)
                        .multilineTextAlignment(.center)
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(.orange.opacity(0.18))
            .accessibilityIdentifier(
                !model.network.isConnected
                    ? "offline.banner"
                    : (model.isServerUnavailable ? "server.unavailable.banner" : "offline.banner")
            )
        }
    }
}

private let serverLossRecoveryMessage = "The server may be offline because the owner PC, WSL, local services, network, or secure ingress is unavailable. If storage was lost, follow the host-loss runbook with verified owner-controlled recovery material. This app cannot recreate the server."
