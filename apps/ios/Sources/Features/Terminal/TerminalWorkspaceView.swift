import SwiftUI
import UIKit

struct TerminalWorkspaceView: View {
    @Environment(AppModel.self) private var model
    let workspaceID: String

    @State private var tabs: [TerminalTab] = []
    @State private var selectedTabID: String?
    @State private var errorMessage: String?
    @State private var showsTabManagement = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(tabs) { tab in
                            Button {
                                selectedTabID = tab.id
                            } label: {
                                Label(HostileDisplayText.sanitized(tab.title), systemImage: tab.kind == .codex ? "sparkles" : "terminal")
                                    .font(.subheadline.weight(selectedTabID == tab.id ? .semibold : .regular))
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 7)
                                    .background(selectedTabID == tab.id ? Color.accentColor.opacity(0.16) : .clear, in: Capsule())
                            }
                            .buttonStyle(.plain)
                            .accessibilityIdentifier("terminal.tab.\(tab.id)")
                        }
                    }
                }
                Button { showsTabManagement = true } label: {
                    Image(systemName: "slider.horizontal.3")
                        .font(.title3)
                }
                .accessibilityLabel("Manage terminal tabs")
                Menu {
                    ForEach([TerminalTab.Kind.shell, .server, .test, .log], id: \.rawValue) { kind in
                        Button("New \(kind.rawValue.capitalized) Tab") { Task { await createTab(kind) } }
                    }
                } label: { Image(systemName: "plus.circle.fill").font(.title3) }
                    .accessibilityLabel("New terminal tab")
                    .disabled(!model.network.isConnected)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(.bar)

            if let tab = tabs.first(where: { $0.id == selectedTabID }) {
                TerminalTabHost(
                    api: model.api,
                    offlineCache: model.offlineCache,
                    composerStore: model.composerStore,
                    workspaceID: workspaceID,
                    workspaceLabel: workspaceLabel,
                    tab: tab,
                    preferences: model.userSettings,
                    isOnline: model.network.isConnected
                )
                    .id(tab.id)
            } else if let errorMessage {
                ContentUnavailableView("Terminal Unavailable", systemImage: "terminal", description: Text(errorMessage))
            } else {
                ProgressView("Loading terminal tabs…")
            }
        }
        .task(id: model.network.isConnected) { await loadTabs() }
        .sheet(isPresented: $showsTabManagement) {
            TerminalTabManagementView(
                api: model.api,
                workspaceID: workspaceID,
                isOnline: model.network.isConnected,
                tabs: $tabs,
                selectedTabID: $selectedTabID
            )
        }
    }

    private var workspaceLabel: String {
        guard let workspace = model.workspaces.first(where: { $0.id == workspaceID }) else {
            return "Workspace \(workspaceID)"
        }
        return "\(HostileDisplayText.sanitized(workspace.repositoryFullName)) • \(HostileDisplayText.sanitized(workspace.taskName))"
    }

    private func loadTabs() async {
        guard model.network.isConnected else {
            await loadCachedTabs()
            return
        }
        do {
            errorMessage = nil
            tabs = try await model.api.terminalTabs(workspaceID: workspaceID).sorted { $0.order < $1.order }
            if selectedTabID == nil || !tabs.contains(where: { $0.id == selectedTabID }) {
                selectedTabID = tabs.first?.id
            }
        } catch {
            errorMessage = error.localizedDescription
            await loadCachedTabs()
        }
    }

    private func createTab(_ kind: TerminalTab.Kind) async {
        do {
            let tab = try await model.api.createTerminalTab(workspaceID: workspaceID, kind: kind)
            tabs.append(tab)
            selectedTabID = tab.id
        } catch { errorMessage = error.localizedDescription }
    }

    private func loadCachedTabs() async {
        do {
            let cached = try await model.offlineCache.terminalHistories(workspaceID: workspaceID)
            tabs = cached.enumerated().map { index, value in
                TerminalTab(
                    id: value.tabID,
                    workspaceID: workspaceID,
                    title: "Cached Terminal \(index + 1)",
                    kind: .shell,
                    order: index,
                    isRunning: false
                )
            }
            selectedTabID = selectedTabID ?? tabs.first?.id
            if tabs.isEmpty {
                errorMessage = "No received terminal history is cached for this workspace."
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

@MainActor
private struct TerminalTabHost: View {
    @State private var adapter: SwiftTermAdapter
    @State private var session: TerminalSessionModel
    @State private var showsComposer = false
    @State private var showsSearch = false
    @State private var searchTerm = ""
    @State private var searchSummary = ""
    let isOnline: Bool
    let composerStore: EncryptedComposerStore
    let workspaceID: String
    let workspaceLabel: String
    let tab: TerminalTab

    init(
        api: any CodexMobileAPI,
        offlineCache: EncryptedOfflineCache,
        composerStore: EncryptedComposerStore,
        workspaceID: String,
        workspaceLabel: String,
        tab: TerminalTab,
        preferences: UserSettings?,
        isOnline: Bool
    ) {
        self.isOnline = isOnline
        self.composerStore = composerStore
        self.workspaceID = workspaceID
        self.workspaceLabel = workspaceLabel
        self.tab = tab
        let adapter = SwiftTermAdapter(preferences: preferences)
        _adapter = State(initialValue: adapter)
        _session = State(initialValue: TerminalSessionModel(
            api: api,
            workspaceID: workspaceID,
            tab: tab,
            renderer: adapter,
            offlineCache: offlineCache
        ))
    }

    var body: some View {
        VStack(spacing: 0) {
            if session.state != .connected || !session.holdsInputLease || session.hasReplayGap {
                terminalStatus
            }
            if showsSearch {
                terminalSearch
            }
            SwiftTermSurface(adapter: adapter)
                .background(Color.black)
                .accessibilityIdentifier("terminal.surface")
                .onTapGesture { session.focus() }
            TerminalAccessoryRow(
                send: session.sendAccessory,
                armControl: session.armControlModifier,
                armOption: session.armOptionModifier,
                dismissKeyboard: session.dismissKeyboard,
                showSearch: { showsSearch = true },
                showComposer: { showsComposer = true },
                canCompose: isOnline
            )
        }
        .task {
            await session.restoreCachedHistory()
            if isOnline { session.start() }
        }
        .onChange(of: isOnline) { _, available in session.setNetworkAvailable(available) }
        .onDisappear { session.stop() }
        .sheet(isPresented: $showsComposer) {
            TerminalComposerView(
                workspaceID: workspaceID,
                workspaceLabel: workspaceLabel,
                tab: tab,
                store: composerStore,
                send: { text, attachments in
                    try await session.sendComposer(text: text, attachments: attachments)
                }
            )
            .presentationDetents([.medium, .large])
        }
        .alert("Open terminal link?", isPresented: Binding(
            get: { session.pendingLink != nil },
            set: { if !$0 { session.pendingLink = nil } }
        )) {
            Button("Open") {
                guard let url = session.pendingLink else { return }
                session.pendingLink = nil
                UIApplication.shared.open(url)
            }
            Button("Cancel", role: .cancel) { session.pendingLink = nil }
        } message: {
            Text(HostileDisplayText.sanitized(session.pendingLink?.absoluteString ?? "Unknown link"))
        }
    }

    @ViewBuilder
    private var terminalStatus: some View {
        HStack(spacing: 8) {
            if case .connecting = session.state { ProgressView().controlSize(.small) }
            Label(session.state.title, systemImage: session.state == .connected ? "network" : "network.slash")
                .font(.caption.weight(.semibold))
            if session.hasReplayGap {
                Text("Some earlier output was not retained.").font(.caption)
            }
            Spacer()
            if !session.holdsInputLease && session.mayTakeInputLease {
                Button("Take Control") { session.takeInputLease() }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .accessibilityIdentifier("terminal.take-control")
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(.orange.opacity(0.18))
    }

    private var terminalSearch: some View {
        HStack(spacing: 8) {
            TextField("Search scrollback", text: $searchTerm)
                .textFieldStyle(.roundedBorder)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .onSubmit { searchSummary = session.search(searchTerm) }
                .accessibilityIdentifier("terminal.search-field")
            Text(searchSummary)
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            Button { searchSummary = session.search(searchTerm, backwards: true) } label: {
                Image(systemName: "chevron.up")
            }
            .accessibilityLabel("Previous terminal search result")
            .disabled(searchTerm.isEmpty)
            Button { searchSummary = session.search(searchTerm) } label: {
                Image(systemName: "chevron.down")
            }
            .accessibilityLabel("Next terminal search result")
            .disabled(searchTerm.isEmpty)
            Button {
                session.clearSearch()
                searchTerm = ""
                searchSummary = ""
                showsSearch = false
            } label: {
                Image(systemName: "xmark.circle.fill")
            }
            .accessibilityLabel("Close terminal search")
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(.bar)
    }
}

private struct TerminalAccessoryRow: View {
    let send: ([UInt8]) -> Void
    let armControl: () -> Void
    let armOption: () -> Void
    let dismissKeyboard: () -> Void
    let showSearch: () -> Void
    let showComposer: () -> Void
    let canCompose: Bool

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 4) {
                key("esc") { send([0x1B]) }
                key("ctrl") { armControl() }
                key("⌥") { armOption() }
                key("tab") { send([0x09]) }
                key("←") { send([0x1B, 0x5B, 0x44]) }
                key("↓") { send([0x1B, 0x5B, 0x42]) }
                key("↑") { send([0x1B, 0x5B, 0x41]) }
                key("→") { send([0x1B, 0x5B, 0x43]) }
                key("⌕") { showSearch() }
                key("⌘", disabled: !canCompose) { showComposer() }
                key("⌨︎↓") { dismissKeyboard() }
            }
            .padding(.horizontal, 6)
        }
        .frame(height: 46)
        .background(.bar)
        .accessibilityIdentifier("terminal.accessory")
    }

    private func key(_ title: String, disabled: Bool = false, action: @escaping () -> Void) -> some View {
        Button(title, action: action)
            .font(.caption.monospaced().weight(.semibold))
            .frame(minWidth: 44, minHeight: 38)
            .background(Color(uiColor: .tertiarySystemFill), in: RoundedRectangle(cornerRadius: 7))
            .disabled(disabled)
    }
}
