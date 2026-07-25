import Observation
import SwiftUI

struct WorkspaceFilesView: View {
    @Environment(AppModel.self) private var model
    let workspaceID: String

    @State private var entries: [FileEntry] = []
    @State private var search = ""
    @State private var results: [FileSearchResult] = []
    @State private var errorMessage: String?
    @State private var isShowingCachedFiles = false

    var body: some View {
        Group {
            if !results.isEmpty {
                List(results) { result in
                    NavigationLink {
                        FileEditorView(workspaceID: workspaceID, path: result.path)
                    } label: {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(HostileDisplayText.sanitized(result.path)).font(.subheadline.monospaced())
                            Text("Line \(result.line): \(HostileDisplayText.sanitized(result.preview))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                        }
                    }
                }
            } else if !entries.isEmpty {
                List {
                    OutlineGroup(entries, children: \.children) { entry in
                        if entry.kind == .text {
                            NavigationLink {
                                FileEditorView(workspaceID: workspaceID, path: entry.path)
                            } label: {
                                FileEntryLabel(entry: entry)
                            }
                        } else {
                            FileEntryLabel(entry: entry)
                                .foregroundStyle(entry.kind == .sensitive ? .tertiary : .primary)
                        }
                    }
                }
            } else if let errorMessage {
                ContentUnavailableView("Files Unavailable", systemImage: "doc.text.magnifyingglass", description: Text(errorMessage))
            } else {
                ProgressView("Loading safe file tree…")
            }
        }
        .safeAreaInset(edge: .top, spacing: 0) {
            if isShowingCachedFiles {
                Label("Offline cached files — read only", systemImage: "lock.fill")
                    .font(.caption.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                    .background(.orange.opacity(0.18))
            }
        }
        .searchable(text: $search, prompt: "Search repository text")
        .onSubmit(of: .search) { Task { await searchFiles() } }
        .onChange(of: search) { _, value in if value.isEmpty { results = [] } }
        .task(id: model.network.isConnected) { await load() }
    }

    private func load() async {
        guard model.network.isConnected else {
            await loadCachedFiles()
            return
        }
        do {
            entries = try await model.api.fileTree(workspaceID: workspaceID)
            isShowingCachedFiles = false
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
            await loadCachedFiles()
        }
    }

    private func searchFiles() async {
        guard !search.isEmpty, model.network.isConnected else { return }
        do { results = try await model.api.searchFiles(workspaceID: workspaceID, query: search) }
        catch { errorMessage = error.localizedDescription }
    }

    private func loadCachedFiles() async {
        do {
            let cached = try await model.offlineCache.files(workspaceID: workspaceID)
            entries = cached.map { document in
                FileEntry(
                    path: document.path,
                    name: document.path,
                    kind: .text,
                    isIgnored: false,
                    sizeBytes: Int64(document.content.utf8.count),
                    children: nil
                )
            }
            isShowingCachedFiles = !entries.isEmpty
            if entries.isEmpty {
                errorMessage = "No recently viewed ordinary text files are cached for this workspace."
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private struct FileEntryLabel: View {
    let entry: FileEntry

    var body: some View {
        HStack {
            Image(systemName: symbol)
            Text(HostileDisplayText.sanitized(entry.name))
            Spacer()
            if entry.isIgnored { Text("ignored").font(.caption2).foregroundStyle(.secondary) }
            if entry.kind == .sensitive { Image(systemName: "lock.fill").accessibilityLabel("Sensitive and unavailable") }
        }
        .accessibilityElement(children: .combine)
    }

    private var symbol: String {
        switch entry.kind {
        case .directory: "folder.fill"
        case .text: "doc.text"
        case .image: "photo"
        case .binary: "doc.zipper"
        case .tooLarge: "doc.badge.ellipsis"
        case .sensitive: "lock.doc.fill"
        }
    }
}

@MainActor
@Observable
private final class FileEditorModel {
    let adapter = RunestoneAdapter()
    private let api: any CodexMobileAPI
    private let cache: EncryptedOfflineCache
    private let workspaceID: String
    private let path: String

    var document: FileDocument?
    var isDirty = false
    var isStale = false
    var isLoading = true
    var errorMessage: String?

    init(api: any CodexMobileAPI, cache: EncryptedOfflineCache, workspaceID: String, path: String) {
        self.api = api
        self.cache = cache
        self.workspaceID = workspaceID
        self.path = path
        adapter.onTextChange = { [weak self] _ in self?.isDirty = true }
    }

    func load(online: Bool) async {
        isLoading = true
        defer { isLoading = false }
        if online {
            do {
                let fresh = try await api.file(workspaceID: workspaceID, path: path)
                guard fresh.kind == .text else {
                    throw ClientError.forbidden("This file is not ordinary repository text and cannot be displayed in the editor.")
                }
                if isDirty, let document, document.etag != fresh.etag {
                    adapter.setEditable(false)
                    errorMessage = "The server copy changed while this local text was unsaved. Copy the visible text before reopening the latest version."
                    return
                }
                document = fresh
                adapter.load(fresh)
                isStale = false
                errorMessage = nil
                if fresh.cacheDirective == .ordinary { try? await cache.saveFile(workspaceID: workspaceID, document: fresh) }
                return
            } catch {
                errorMessage = error.localizedDescription
            }
        }
        let cached: FileDocument?
        do {
            cached = try await cache.file(workspaceID: workspaceID, path: path)
        } catch {
            cached = nil
        }
        if let cached {
            let readOnly = FileDocument(
                path: cached.path,
                content: cached.content,
                etag: cached.etag,
                languageHint: cached.languageHint,
                kind: cached.kind,
                isReadOnly: true,
                cacheDirective: cached.cacheDirective
            )
            document = readOnly
            adapter.load(readOnly)
            isStale = true
            errorMessage = nil
        } else {
            document = nil
            adapter.setEditable(false)
            isStale = true
            errorMessage = "No cacheable copy of this file is available offline."
        }
    }

    func save(online: Bool) async {
        guard online, let document, !document.isReadOnly else {
            errorMessage = ClientError.offline.localizedDescription
            return
        }
        do {
            let saved = try await api.saveFile(
                workspaceID: workspaceID,
                path: document.path,
                request: SaveFileRequest(content: adapter.text, expectedETag: document.etag)
            )
            guard saved.kind == .text else {
                throw ClientError.forbidden("The saved response was not ordinary repository text.")
            }
            self.document = saved
            adapter.load(saved)
            isDirty = false
            errorMessage = nil
            if saved.cacheDirective == .ordinary { try? await cache.saveFile(workspaceID: workspaceID, document: saved) }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private struct FileEditorView: View {
    @Environment(AppModel.self) private var appModel
    let workspaceID: String
    let path: String
    @State private var model: FileEditorModel?

    init(workspaceID: String, path: String) {
        self.workspaceID = workspaceID
        self.path = path
    }

    var body: some View {
        VStack(spacing: 0) {
            if model?.isStale == true {
                Label("Offline cached copy — editing disabled", systemImage: "lock.fill")
                    .font(.caption.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(6)
                    .background(.orange.opacity(0.18))
            }
            if let message = model?.errorMessage, model?.document != nil {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.orange.opacity(0.10))
            }
            if let model, model.document != nil {
                RunestoneSurface(adapter: model.adapter)
                    .accessibilityIdentifier("editor.surface")
            } else if model?.isLoading != false {
                ProgressView("Loading file…")
            } else {
                ContentUnavailableView("File Unavailable", systemImage: "doc.badge.ellipsis", description: Text(model?.errorMessage ?? "This file cannot be displayed."))
            }
        }
        .navigationTitle(HostileDisplayText.sanitized(path.split(separator: "/").last.map(String.init) ?? "Editor"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Save") {
                    guard let model else { return }
                    Task { await model.save(online: appModel.network.isConnected) }
                }
                    .disabled(model?.isDirty != true || model?.document?.isReadOnly != false || !appModel.network.isConnected)
                    .accessibilityIdentifier("editor.save")
            }
        }
        .task(id: appModel.network.isConnected) {
            if model == nil {
                let liveModel = FileEditorModel(
                    api: appModel.api,
                    cache: appModel.offlineCache,
                    workspaceID: workspaceID,
                    path: path
                )
                model = liveModel
            }
            await model?.load(online: appModel.network.isConnected)
        }
    }
}
