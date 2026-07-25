import SwiftUI
import UIKit

private final class NoRedirectSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

struct WorkspaceGitView: View {
    @Environment(AppModel.self) private var model
    let workspaceID: String
    let baseBranch: String

    @State private var status: GitStatusDetail?
    @State private var selectedDiffPath: String?
    @State private var showsCommit = false
    @State private var showsPullRequest = false
    @State private var pullRequestResult: PullRequestResult?
    @State private var cachedDiffs: [DiffDocument] = []
    @State private var checkpoints: [CheckpointSummary] = []
    @State private var pendingDiscardPath: String?
    @State private var pendingWorkspaceRestore: CheckpointSummary?
    @State private var fileRestoreCheckpoint: CheckpointSummary?
    @State private var pendingFileRestore: FileRestoreSelection?
    @State private var recoveryCheckpointID: String?
    @State private var errorMessage: String?
    @State private var isWorking = false

    var body: some View {
        Group {
            if let status {
                List {
                    Section("Branch") {
                        LabeledContent("Current", value: HostileDisplayText.sanitized(status.branch))
                        LabeledContent("Upstream", value: HostileDisplayText.sanitized(status.upstream ?? "Not set"))
                        HStack {
                            Label("\(status.ahead) ahead", systemImage: "arrow.up")
                            Spacer()
                            Label("\(status.behind) behind", systemImage: "arrow.down")
                        }
                        if let operation = status.operationInProgress {
                            Label("Git operation in progress: \(HostileDisplayText.sanitized(operation))", systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        }
                    }

                    changesSection("Conflicts", group: .conflicted, status: status)
                    changesSection("Staged", group: .staged, status: status)
                    changesSection("Unstaged", group: .unstaged, status: status)
                    changesSection("Untracked", group: .untracked, status: status)

                    Section("Actions") {
                        Button("Commit Staged Changes") { showsCommit = true }
                            .disabled(!status.changes.contains(where: { $0.group == .staged }) || isWorking || !model.network.isConnected)
                        Button("Pull (Fast-forward Only)") { Task { await run { try await model.api.pull(workspaceID: workspaceID) } } }
                            .disabled(status.operationInProgress != nil || isWorking || !model.network.isConnected)
                        Button("Push Task Branch") { Task { await run { try await model.api.push(workspaceID: workspaceID) } } }
                            .disabled(status.operationInProgress != nil || isWorking || !model.network.isConnected)
                        Button("Create Pull Request") { showsPullRequest = true }
                            .disabled(status.ahead == 0 || isWorking || !model.network.isConnected)
                    }

                    if let recoveryCheckpointID {
                        Section("Recovery Link") {
                            Text(recoveryCheckpointID)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                            Button("Restore from Recovery Checkpoint…") {
                                if let checkpoint = checkpoints.first(where: { $0.id == recoveryCheckpointID }) {
                                    pendingWorkspaceRestore = checkpoint
                                }
                            }
                            .disabled(!checkpoints.contains(where: { $0.id == recoveryCheckpointID && $0.workspaceRestoreSupported && $0.hashStatus == "verified" }))
                        }
                    }

                    Section("Local Checkpoints") {
                        if checkpoints.isEmpty {
                            Text("No local recovery checkpoints yet.")
                                .foregroundStyle(.secondary)
                        }
                        ForEach(checkpoints) { checkpoint in
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Label(
                                        checkpoint.hashStatus == "verified" ? "Verified" : "Hash failed",
                                        systemImage: checkpoint.hashStatus == "verified" ? "checkmark.shield.fill" : "xmark.shield.fill"
                                    )
                                    .foregroundStyle(checkpoint.hashStatus == "verified" ? .green : .red)
                                    Spacer()
                                    Text(checkpoint.createdAt, style: .relative)
                                        .foregroundStyle(.secondary)
                                }
                                Text(checkpoint.reason.replacingOccurrences(of: "-", with: " ").capitalized)
                                    .font(.subheadline.weight(.semibold))
                                Text(checkpoint.id)
                                    .font(.caption2.monospaced())
                                    .textSelection(.enabled)
                                Text("v\(checkpoint.archiveVersion) • \(checkpoint.fileCount) files • \(checkpoint.deletedCount) deletions • \(ByteCountFormatter.string(fromByteCount: checkpoint.expandedBytes, countStyle: .file))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                HStack {
                                    Button("Restore File…") { fileRestoreCheckpoint = checkpoint }
                                        .buttonStyle(.bordered)
                                    Button("Restore Workspace…", role: .destructive) { pendingWorkspaceRestore = checkpoint }
                                        .buttonStyle(.bordered)
                                        .disabled(!checkpoint.workspaceRestoreSupported)
                                }
                                .disabled(checkpoint.hashStatus != "verified" || isWorking || !model.network.isConnected)
                                if !checkpoint.workspaceRestoreSupported {
                                    Text("Legacy checkpoints support file restore only.")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }

                    if let pullRequestResult {
                        Section("Pull Request") {
                            LabeledContent("Status", value: pullRequestResult.state.capitalized)
                            Button("Open #\(pullRequestResult.number) on GitHub") {
                                openPullRequest(pullRequestResult.url)
                            }
                        }
                    }
                    if let errorMessage { Section { Text(errorMessage).foregroundStyle(.red) } }
                }
            } else if !cachedDiffs.isEmpty {
                List(cachedDiffs) { diff in
                    Button {
                        selectedDiffPath = diff.path
                    } label: {
                        Label(HostileDisplayText.sanitized(diff.path), systemImage: "doc.text.magnifyingglass")
                            .font(.subheadline.monospaced())
                    }
                }
                .safeAreaInset(edge: .top, spacing: 0) {
                    Label("Offline cached diffs — read only", systemImage: "lock.fill")
                        .font(.caption.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                        .background(.orange.opacity(0.18))
                }
            } else if let errorMessage {
                ContentUnavailableView("Git Status Unavailable", systemImage: "arrow.triangle.branch", description: Text(errorMessage))
            } else {
                ProgressView("Loading Git status…")
            }
        }
        .refreshable { await load() }
        .task(id: model.network.isConnected) { await load() }
        .sheet(isPresented: Binding(
            get: { selectedDiffPath != nil },
            set: { if !$0 { selectedDiffPath = nil } }
        )) {
            if let path = selectedDiffPath {
                NavigationStack { GitDiffView(workspaceID: workspaceID, path: path) }
            }
        }
        .sheet(isPresented: $showsCommit) {
            CommitSheet { request in
                await run { try await model.api.commit(workspaceID: workspaceID, request: request) }
            }
        }
        .sheet(isPresented: $showsPullRequest) {
            PullRequestSheet(baseBranch: baseBranch) { request in
                do {
                    pullRequestResult = try await model.api.createPullRequest(workspaceID: workspaceID, request: request)
                    errorMessage = nil
                    return true
                } catch {
                    errorMessage = error.localizedDescription
                    return false
                }
            }
        }
        .sheet(item: $fileRestoreCheckpoint) { checkpoint in
            RestoreCheckpointFileSheet(checkpoint: checkpoint) { path in
                pendingFileRestore = FileRestoreSelection(checkpoint: checkpoint, path: path)
            }
        }
        .confirmationDialog(
            "Discard selected tracked path?",
            isPresented: Binding(
                get: { pendingDiscardPath != nil },
                set: { if !$0 { pendingDiscardPath = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let path = pendingDiscardPath {
                Button("Discard \(HostileDisplayText.sanitized(path))", role: .destructive) { Task { await discard(path: path) } }
            }
            Button("Cancel", role: .cancel) { pendingDiscardPath = nil }
        } message: {
            Text("A verified local checkpoint will be created first. Git history is never reset or rewritten.")
        }
        .confirmationDialog(
            "Restore recorded workspace delta?",
            isPresented: Binding(
                get: { pendingWorkspaceRestore != nil },
                set: { if !$0 { pendingWorkspaceRestore = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let checkpoint = pendingWorkspaceRestore {
                Button("Restore Checkpoint", role: .destructive) { Task { await restoreWorkspace(checkpoint) } }
            }
            Button("Cancel", role: .cancel) { pendingWorkspaceRestore = nil }
        } message: {
            Text("A new pre-restore checkpoint will be created. The recorded files and deletions are applied over the current workspace; unrelated paths stay unchanged.")
        }
        .confirmationDialog(
            "Restore one file?",
            isPresented: Binding(
                get: { pendingFileRestore != nil },
                set: { if !$0 { pendingFileRestore = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let selection = pendingFileRestore {
                Button("Restore \(HostileDisplayText.sanitized(selection.path))", role: .destructive) { Task { await restoreFile(selection) } }
            }
            Button("Cancel", role: .cancel) { pendingFileRestore = nil }
        } message: {
            Text("A new pre-restore checkpoint will be created before the file is atomically replaced.")
        }
    }

    @ViewBuilder
    private func changesSection(_ title: String, group: GitChangeGroup, status: GitStatusDetail) -> some View {
        let changes = status.changes.filter { $0.group == group }
        if !changes.isEmpty {
            Section(title) {
                ForEach(changes) { change in
                    HStack {
                        Button {
                            selectedDiffPath = change.path
                        } label: {
                            VStack(alignment: .leading) {
                                Text(HostileDisplayText.sanitized(change.path)).font(.subheadline.monospaced()).foregroundStyle(.primary)
                                Text(HostileDisplayText.sanitized(change.status)).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("git.diff.\(HostileDisplayText.sanitized(change.path))")
                        .accessibilityHint("Opens the read-only diff for this file")
                        Spacer()
                        if group != .conflicted {
                            Button(group == .staged ? "Unstage" : "Stage") {
                                Task { await stage(change, staged: group != .staged) }
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .disabled(isWorking || !model.network.isConnected)
                        }
                        if group == .staged || group == .unstaged {
                            Button("Discard…", role: .destructive) {
                                pendingDiscardPath = change.path
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .disabled(isWorking || !model.network.isConnected)
                        }
                    }
                }
            }
        }
    }

    private func load() async {
        guard model.network.isConnected else {
            await loadCachedDiffs()
            return
        }
        do {
            status = try await model.api.gitStatus(workspaceID: workspaceID)
            checkpoints = try await model.api.checkpoints(workspaceID: workspaceID)
            cachedDiffs = []
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
            await loadCachedDiffs()
        }
    }

    private func stage(_ change: GitFileChange, staged: Bool) async {
        await run { try await model.api.setStaged(workspaceID: workspaceID, path: change.path, staged: staged) }
    }

    private func run(_ operation: () async throws -> GitStatusDetail) async {
        guard model.network.isConnected else {
            errorMessage = ClientError.offline.localizedDescription
            return
        }
        isWorking = true
        defer { isWorking = false }
        do {
            status = try await operation()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func discard(path: String) async {
        pendingDiscardPath = nil
        guard model.network.isConnected else {
            errorMessage = ClientError.offline.localizedDescription
            return
        }
        isWorking = true
        defer { isWorking = false }
        do {
            let result = try await model.api.discardGitChanges(
                workspaceID: workspaceID,
                request: GitDiscardRequest(paths: [path], confirmed: true)
            )
            status = result.status
            recoveryCheckpointID = result.recoveryCheckpointID
            checkpoints = try await model.api.checkpoints(workspaceID: workspaceID)
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func restoreWorkspace(_ checkpoint: CheckpointSummary) async {
        pendingWorkspaceRestore = nil
        isWorking = true
        defer { isWorking = false }
        do {
            let result = try await model.api.restoreCheckpointWorkspace(
                workspaceID: workspaceID,
                checkpointID: checkpoint.id,
                request: CheckpointRestoreWorkspaceRequest(confirmed: true)
            )
            status = result.status ?? status
            recoveryCheckpointID = result.preRestoreCheckpointID
            checkpoints = try await model.api.checkpoints(workspaceID: workspaceID)
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func restoreFile(_ selection: FileRestoreSelection) async {
        pendingFileRestore = nil
        isWorking = true
        defer { isWorking = false }
        do {
            let result = try await model.api.restoreCheckpointFile(
                workspaceID: workspaceID,
                checkpointID: selection.checkpoint.id,
                request: CheckpointRestoreFileRequest(path: selection.path, confirmed: true)
            )
            status = result.status ?? status
            recoveryCheckpointID = result.preRestoreCheckpointID
            checkpoints = try await model.api.checkpoints(workspaceID: workspaceID)
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func openPullRequest(_ url: URL) {
        guard url.scheme?.lowercased() == "https",
              url.host?.lowercased() == "github.com",
              (url.port ?? 443) == 443,
              url.user == nil,
              url.password == nil else {
            errorMessage = "The pull-request URL failed GitHub origin validation."
            return
        }
        UIApplication.shared.open(url)
    }

    private func loadCachedDiffs() async {
        status = nil
        checkpoints = []
        do {
            cachedDiffs = try await model.offlineCache.diffs(workspaceID: workspaceID)
            if cachedDiffs.isEmpty {
                errorMessage = "No recently viewed ordinary diffs are cached for this workspace."
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private struct FileRestoreSelection {
    let checkpoint: CheckpointSummary
    let path: String
}

private struct RestoreCheckpointFileSheet: View {
    @Environment(\.dismiss) private var dismiss
    let checkpoint: CheckpointSummary
    let select: (String) -> Void
    @State private var path = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Verified Checkpoint") {
                    Text(checkpoint.id)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                    LabeledContent("Recorded files", value: "\(checkpoint.fileCount)")
                }
                Section("Workspace-relative path") {
                    TextField("Sources/App.swift", text: $path)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                Section {
                    Text("The server will reject paths that were not recorded, sensitive paths, traversal, and legacy archive hazards.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Restore File")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue") {
                        let selectedPath = path
                        dismiss()
                        select(selectedPath)
                    }
                    .disabled(
                        path.isEmpty || path.count > 4_096 || path.hasPrefix("/")
                            || path.contains("\\") || path.split(separator: "/").contains("..")
                    )
                }
            }
        }
    }
}

private struct CommitSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var message = ""
    @State private var authorName = ""
    @State private var authorEmail = ""
    @State private var isWorking = false
    let commit: (CommitRequest) async -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section("Commit") {
                    TextField("Message", text: $message, axis: .vertical)
                    TextField("Author name", text: $authorName)
                    TextField("Author email", text: $authorEmail)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                }
            }
            .navigationTitle("Commit Changes")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Commit") {
                        isWorking = true
                        Task {
                            await commit(CommitRequest(message: message, authorName: authorName, authorEmail: authorEmail))
                            isWorking = false
                            dismiss()
                        }
                    }
                    .disabled(
                        message.isEmpty || message.count > 10_000
                            || authorName.isEmpty || authorName.count > 200
                            || authorEmail.isEmpty || authorEmail.count > 320 || !authorEmail.contains("@")
                            || isWorking
                    )
                }
            }
        }
    }
}

private struct PullRequestSheet: View {
    @Environment(\.dismiss) private var dismiss
    let baseBranch: String
    let create: (PullRequestRequest) async -> Bool

    @State private var title = ""
    @State private var bodyText = ""
    @State private var base = ""
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            Form {
                TextField("Title", text: $title)
                TextField("Base branch", text: $base)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                TextField("Description", text: $bodyText, axis: .vertical)
                    .lineLimit(4...10)
            }
            .navigationTitle("New Pull Request")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { if base.isEmpty { base = baseBranch } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") {
                        isWorking = true
                        Task {
                            if await create(PullRequestRequest(title: title, body: bodyText, baseBranch: base)) { dismiss() }
                            isWorking = false
                        }
                    }
                    .disabled(
                        title.isEmpty || title.count > 256
                            || bodyText.count > 65_536
                            || base.isEmpty || base.count > 255
                            || isWorking
                    )
                }
            }
        }
    }
}

private struct GitDiffView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let workspaceID: String
    let path: String

    @State private var diff: DiffDocument?
    @State private var isStale = false
    @State private var errorMessage: String?

    var body: some View {
        Group {
            if let diff, let text = diff.unifiedDiff {
                ScrollView([.horizontal, .vertical]) {
                    Text(text)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .safeAreaInset(edge: .top) {
                    if isStale { Text("Offline cached diff").font(.caption).padding(6).frame(maxWidth: .infinity).background(.orange.opacity(0.18)) }
                }
            } else if let diff, diff.imageBeforeURL != nil || diff.imageAfterURL != nil {
                ScrollView {
                    HStack(alignment: .top, spacing: 12) {
                        if let before = diff.imageBeforeURL {
                            EphemeralDiffImage(title: "Before", url: before)
                        }
                        if let after = diff.imageAfterURL {
                            EphemeralDiffImage(title: "After", url: after)
                        }
                    }
                    .padding()
                }
            } else if diff?.isBinary == true {
                ContentUnavailableView("Binary Diff", systemImage: "doc.zipper", description: Text("Open the file with an appropriate image or binary viewer."))
            } else if let errorMessage {
                ContentUnavailableView("Diff Unavailable", systemImage: "doc.text.magnifyingglass", description: Text(errorMessage))
            } else {
                ProgressView("Loading diff…")
            }
        }
        .navigationTitle(HostileDisplayText.sanitized(path))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Close") { dismiss() }
                    .accessibilityIdentifier("git.diff.review.\(HostileDisplayText.sanitized(path)).close")
            }
        }
        .task(id: model.network.isConnected) { await load() }
    }

    private func load() async {
        if model.network.isConnected {
            do {
                let fresh = try await model.api.diff(workspaceID: workspaceID, path: path)
                diff = fresh
                isStale = false
                errorMessage = nil
                if fresh.cacheDirective == .ordinary { try? await model.offlineCache.saveDiff(workspaceID: workspaceID, document: fresh) }
                return
            } catch { errorMessage = error.localizedDescription }
        }
        let cached: DiffDocument?
        do {
            cached = try await model.offlineCache.diff(workspaceID: workspaceID, path: path)
        } catch {
            cached = nil
        }
        if let cached {
            diff = cached
            isStale = true
        } else {
            diff = nil
            isStale = true
            errorMessage = "No cacheable copy of this diff is available offline."
        }
    }
}

private struct EphemeralDiffImage: View {
    @Environment(AppModel.self) private var model
    let title: String
    let url: URL

    @State private var image: UIImage?
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline)
            if let image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .accessibilityLabel("\(title) image diff")
            } else if let errorMessage {
                ContentUnavailableView("Image Unavailable", systemImage: "photo.badge.exclamationmark", description: Text(errorMessage))
            } else {
                ProgressView()
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .task(id: url) { await load() }
    }

    private func load() async {
        guard model.network.isConnected,
              url.scheme?.lowercased() == "https",
              url.host?.lowercased() == model.configuration.apiBaseURL.host?.lowercased(),
              (url.port ?? 443) == (model.configuration.apiBaseURL.port ?? 443),
              url.user == nil,
              url.password == nil else {
            errorMessage = "The image URL failed same-origin validation."
            return
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        do {
            guard let token = try await model.sessionStore.accessToken() else {
                throw ClientError.unauthorized
            }
            var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            request.setValue("image/*", forHTTPHeaderField: "Accept")
            let session = URLSession(
                configuration: configuration,
                delegate: NoRedirectSessionDelegate(),
                delegateQueue: nil
            )
            defer { session.finishTasksAndInvalidate() }
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse,
                  (200..<300).contains(http.statusCode),
                  http.url?.scheme?.lowercased() == "https",
                  http.url?.host?.lowercased() == model.configuration.apiBaseURL.host?.lowercased(),
                  (http.url?.port ?? 443) == (model.configuration.apiBaseURL.port ?? 443),
                  data.count <= 20 * 1_024 * 1_024,
                  let decoded = UIImage(data: data) else {
                throw ClientError.malformedData("The image diff was invalid or exceeded 20 MiB.")
            }
            let width = decoded.size.width * decoded.scale
            let height = decoded.size.height * decoded.scale
            guard width > 0, height > 0, width <= 8_192, height <= 8_192,
                  width * height <= 40_000_000 else {
                throw ClientError.malformedData("The image diff dimensions exceeded the safe rendering limit.")
            }
            image = decoded
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
