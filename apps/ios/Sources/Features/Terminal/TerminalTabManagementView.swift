import SwiftUI

/// Native metadata controls for persistent terminal tabs. The control plane is
/// authoritative: local state changes only after an authenticated mutation
/// succeeds, and closing always requires a fresh destructive confirmation.
struct TerminalTabManagementView: View {
    @Environment(\.dismiss) private var dismiss

    let api: any CodexMobileAPI
    let workspaceID: String
    let isOnline: Bool
    @Binding var tabs: [TerminalTab]
    @Binding var selectedTabID: String?

    @State private var renameTarget: TerminalTab?
    @State private var renameTitle = ""
    @State private var closeTarget: TerminalTab?
    @State private var errorMessage: String?
    @State private var isMutating = false

    private var orderedTabs: [TerminalTab] {
        tabs.sorted { lhs, rhs in
            lhs.order == rhs.order ? lhs.id < rhs.id : lhs.order < rhs.order
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(orderedTabs) { tab in
                        row(for: tab)
                    }
                    .onMove(perform: moveTabs)
                    .moveDisabled(!isOnline || isMutating)
                } footer: {
                    Text("The primary Codex tab is authoritative and cannot be closed. Closing another tab terminates its persistent PTY.")
                }
            }
            .navigationTitle("Terminal Tabs")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    EditButton()
                        .disabled(!isOnline || isMutating || tabs.count < 2)
                }
            }
            .overlay {
                if isMutating {
                    ProgressView().controlSize(.large)
                }
            }
        }
        .interactiveDismissDisabled(isMutating)
        .alert("Rename Terminal Tab", isPresented: Binding(
            get: { renameTarget != nil },
            set: { if !$0 { renameTarget = nil } }
        )) {
            TextField("Tab name", text: $renameTitle)
                .textInputAutocapitalization(.sentences)
                .autocorrectionDisabled()
            Button("Rename") {
                guard let target = renameTarget else { return }
                Task { await rename(target) }
            }
            .disabled(!validRenameTitle)
            Button("Cancel", role: .cancel) { renameTarget = nil }
        } message: {
            Text("Use 1–120 characters. Control and bidirectional-override characters are not allowed.")
        }
        .confirmationDialog("Close terminal tab?", isPresented: Binding(
            get: { closeTarget != nil },
            set: { if !$0 { closeTarget = nil } }
        ), titleVisibility: .visible) {
            Button("Close and Terminate PTY", role: .destructive) {
                guard let target = closeTarget else { return }
                Task { await close(target) }
            }
            Button("Cancel", role: .cancel) { closeTarget = nil }
        } message: {
            Text("This disconnects viewers and permanently terminates the selected persistent terminal process.")
        }
        .alert("Terminal Action Failed", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "The terminal tab could not be updated.")
        }
    }

    private func row(for tab: TerminalTab) -> some View {
        HStack(spacing: 12) {
            Image(systemName: tab.kind == .codex ? "sparkles" : "terminal")
                .foregroundStyle(tab.kind == .codex ? Color.accentColor : .secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(HostileDisplayText.sanitized(tab.title)).lineLimit(1)
                Text(tab.kind == .codex ? "Primary Codex TUI" : tab.kind.rawValue.capitalized)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if selectedTabID == tab.id {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(Color.accentColor)
                    .accessibilityLabel("Selected tab")
            }
        }
        .contentShape(Rectangle())
        .onTapGesture { selectedTabID = tab.id }
        .contextMenu {
            Button {
                renameTitle = tab.title
                renameTarget = tab
            } label: {
                Label("Rename", systemImage: "pencil")
            }
            .disabled(!isOnline || isMutating)

            if tab.kind != .codex {
                Button(role: .destructive) {
                    closeTarget = tab
                } label: {
                    Label("Close Tab", systemImage: "xmark.circle")
                }
                .disabled(!isOnline || isMutating)
            }
        }
        .accessibilityIdentifier("terminal.tab-management.\(tab.id)")
    }

    private var validRenameTitle: Bool {
        let value = renameTitle.trimmingCharacters(in: .whitespacesAndNewlines)
        return (1...120).contains(value.count)
            && !value.unicodeScalars.contains(where: { scalar in
                CharacterSet.controlCharacters.contains(scalar)
                    || scalar.value == 0x2028 || scalar.value == 0x2029
                    || (0x202A...0x202E).contains(scalar.value)
                    || (0x2066...0x2069).contains(scalar.value)
            })
    }

    private func rename(_ tab: TerminalTab) async {
        guard isOnline, validRenameTitle else { return }
        isMutating = true
        defer { isMutating = false }
        do {
            let updated = try await api.renameTerminalTab(
                workspaceID: workspaceID,
                tabID: tab.id,
                request: RenameTerminalTabRequest(title: renameTitle)
            )
            if let index = tabs.firstIndex(where: { $0.id == updated.id }) {
                tabs[index] = updated
            }
            renameTarget = nil
            renameTitle = ""
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func moveTabs(from source: IndexSet, to destination: Int) {
        guard isOnline, !isMutating else { return }
        var proposed = orderedTabs
        proposed.move(fromOffsets: source, toOffset: destination)
        Task { await reorder(proposed) }
    }

    private func reorder(_ proposed: [TerminalTab]) async {
        isMutating = true
        defer { isMutating = false }
        do {
            tabs = try await api.reorderTerminalTabs(
                workspaceID: workspaceID,
                request: ReorderTerminalTabsRequest(tabIDs: proposed.map(\.id))
            )
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func close(_ tab: TerminalTab) async {
        guard isOnline, tab.kind != .codex else { return }
        isMutating = true
        defer { isMutating = false }
        do {
            try await api.closeTerminalTab(
                workspaceID: workspaceID,
                tabID: tab.id,
                request: CloseTerminalTabRequest(confirmed: true)
            )
            tabs.removeAll { $0.id == tab.id }
            tabs = tabs.enumerated().map { index, value in
                TerminalTab(
                    id: value.id,
                    workspaceID: value.workspaceID,
                    title: value.title,
                    kind: value.kind,
                    order: index,
                    isRunning: value.isRunning
                )
            }
            if selectedTabID == tab.id {
                selectedTabID = tabs.first?.id
            }
            closeTarget = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
