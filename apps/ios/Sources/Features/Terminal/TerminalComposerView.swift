import Foundation
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

private struct PendingComposerAttachment: Identifiable {
    let id = UUID()
    let displayName: String
    let mediaType: String
    var content: Data
}

@MainActor
struct TerminalComposerView: View {
    @Environment(\.dismiss) private var dismiss

    let workspaceID: String
    let workspaceLabel: String
    let tab: TerminalTab
    let store: EncryptedComposerStore
    let send: (String, [AttachmentUpload]) async throws -> Void

    @State private var text = ""
    @State private var history: [String] = []
    @State private var attachments: [PendingComposerAttachment] = []
    @State private var photoItems: [PhotosPickerItem] = []
    @State private var showsFileImporter = false
    @State private var isSending = false
    @State private var didRestore = false
    @State private var errorMessage: String?
    @State private var draftSaveTask: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                targetBanner
                TextEditor(text: $text)
                    .font(.body.monospaced())
                    .scrollContentBackground(.hidden)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color(uiColor: .secondarySystemBackground))
                    .accessibilityLabel("Terminal message")
                    .accessibilityHint("Multiline editor. System keyboard dictation is supported.")
                    .accessibilityIdentifier("terminal.composer.editor")
                    .disabled(isSending)

                if !attachments.isEmpty {
                    attachmentStrip
                }
                actionBar
            }
            .navigationTitle("Compose")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismissPreservingDraft() }
                        .disabled(isSending)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Send") { Task { await sendDraft() } }
                        .fontWeight(.semibold)
                        .disabled(isSending || (text.isEmpty && attachments.isEmpty))
                        .accessibilityIdentifier("terminal.composer.send")
                }
            }
            .task { await restore() }
            .onChange(of: text) { _, value in scheduleDraftSave(value) }
            .onChange(of: photoItems.count) { _, count in
                guard count > 0 else { return }
                let items = photoItems
                photoItems = []
                Task { await loadPhotos(items) }
            }
            .fileImporter(
                isPresented: $showsFileImporter,
                allowedContentTypes: [.image, .pdf, .json, .plainText, .text, .commaSeparatedText],
                allowsMultipleSelection: true
            ) { result in
                Task { await loadFiles(result) }
            }
            .alert("Composer", isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            )) {
                Button("OK", role: .cancel) { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "The composer could not continue.")
            }
            .onDisappear {
                draftSaveTask?.cancel()
                let current = text
                Task { try? await store.saveDraft(current, workspaceID: workspaceID, tabID: tab.id) }
                wipeAttachments()
            }
        }
        .interactiveDismissDisabled(isSending)
    }

    private var targetBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: tab.kind == .codex ? "sparkles" : "terminal")
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(workspaceLabel)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Text(HostileDisplayText.sanitized(tab.title))
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
            }
            Spacer()
            if isSending { ProgressView().controlSize(.small) }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .background(.bar)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Target workspace \(HostileDisplayText.sanitized(workspaceLabel)), tab \(HostileDisplayText.sanitized(tab.title))")
    }

    private var attachmentStrip: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(attachments) { item in
                    HStack(spacing: 6) {
                        Image(systemName: item.mediaType.hasPrefix("image/") ? "photo" : "doc")
                        VStack(alignment: .leading, spacing: 1) {
                            Text(HostileDisplayText.sanitized(item.displayName)).lineLimit(1)
                            Text(ByteCountFormatter.string(fromByteCount: Int64(item.content.count), countStyle: .file))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Button {
                            removeAttachment(id: item.id)
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Remove \(HostileDisplayText.sanitized(item.displayName))")
                        .disabled(isSending)
                    }
                    .font(.caption)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 7)
                    .background(Color(uiColor: .tertiarySystemFill), in: RoundedRectangle(cornerRadius: 9))
                }
            }
            .padding(.horizontal, 12)
        }
        .frame(minHeight: 52)
        .background(.bar)
    }

    private var actionBar: some View {
        HStack(spacing: 12) {
            PhotosPicker(
                selection: $photoItems,
                maxSelectionCount: max(1, ComposerAttachmentPolicy.maximumCount - attachments.count),
                matching: .images,
                preferredItemEncoding: .current
            ) {
                Label("Photos", systemImage: "photo.on.rectangle")
            }
            .disabled(isSending || attachments.count >= ComposerAttachmentPolicy.maximumCount)

            Button { showsFileImporter = true } label: {
                Label("Files", systemImage: "folder")
            }
            .disabled(isSending || attachments.count >= ComposerAttachmentPolicy.maximumCount)

            Menu {
                if history.isEmpty {
                    Text("No sent messages yet")
                } else {
                    ForEach(Array(history.enumerated()), id: \.offset) { _, value in
                        Button(String(value.prefix(80))) { text = value }
                    }
                }
            } label: {
                Label("History", systemImage: "clock.arrow.circlepath")
            }
            .disabled(isSending || history.isEmpty)

            Spacer()
            Text("\(attachments.count)/\(ComposerAttachmentPolicy.maximumCount)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .accessibilityLabel("\(attachments.count) of \(ComposerAttachmentPolicy.maximumCount) attachments")
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(.bar)
    }

    private func restore() async {
        guard !didRestore else { return }
        didRestore = true
        do {
            async let restoredDraft = store.draft(workspaceID: workspaceID, tabID: tab.id)
            async let restoredHistory = store.history(workspaceID: workspaceID, tabID: tab.id)
            let values = try await (restoredDraft, restoredHistory)
            text = values.0
            history = values.1
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func scheduleDraftSave(_ value: String) {
        guard didRestore else { return }
        draftSaveTask?.cancel()
        draftSaveTask = Task {
            try? await Task.sleep(for: .milliseconds(350))
            guard !Task.isCancelled else { return }
            try? await store.saveDraft(value, workspaceID: workspaceID, tabID: tab.id)
        }
    }

    private func dismissPreservingDraft() {
        draftSaveTask?.cancel()
        let current = text
        Task {
            do {
                try await store.saveDraft(current, workspaceID: workspaceID, tabID: tab.id)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func sendDraft() async {
        guard !isSending else { return }
        isSending = true
        defer { isSending = false }
        let value = text
        do {
            draftSaveTask?.cancel()
            try await store.saveDraft(value, workspaceID: workspaceID, tabID: tab.id)
            let uploads = attachments.map {
                AttachmentUpload(mediaType: $0.mediaType, contentBase64: $0.content)
            }
            try await send(value, uploads)

            do {
                if value.isEmpty {
                    try await store.saveDraft("", workspaceID: workspaceID, tabID: tab.id)
                } else {
                    try await store.recordSuccessfulSend(value, workspaceID: workspaceID, tabID: tab.id)
                }
            } catch {
                // The terminal send already succeeded, so never invite a duplicate
                // retry. Clear the visible payload and report only the local-history
                // failure; the debounced empty draft write will retry persistence.
                text = ""
                wipeAttachments()
                errorMessage = "The message was sent, but its local draft history could not be updated: \(error.localizedDescription)"
                return
            }
            text = ""
            wipeAttachments()
            dismiss()
        } catch {
            // The encrypted draft and in-memory attachment selection remain
            // intact for a deliberate retry. Nothing clears on a silent drop.
            errorMessage = error.localizedDescription
        }
    }

    private func loadPhotos(_ items: [PhotosPickerItem]) async {
        for (index, item) in items.enumerated() {
            do {
                guard let data = try await item.loadTransferable(type: Data.self) else {
                    throw ClientError.malformedData("A selected photo could not be read.")
                }
                let mediaType = try ComposerAttachmentPolicy.mediaType(
                    data: data,
                    suggestedType: item.supportedContentTypes.first,
                    fileName: "Photo-\(index + 1)"
                )
                try addAttachment(PendingComposerAttachment(
                    displayName: "Photo \(index + 1)", mediaType: mediaType, content: data
                ))
            } catch {
                errorMessage = error.localizedDescription
                return
            }
        }
    }

    private func loadFiles(_ result: Result<[URL], Error>) async {
        do {
            for url in try result.get() {
                let name = url.lastPathComponent
                guard SensitivePathPolicy().permitsAttachment(name: name) else {
                    throw ClientError.forbidden("Credential and secret filenames cannot be attached.")
                }
                let accessed = url.startAccessingSecurityScopedResource()
                defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                let values = try url.resourceValues(forKeys: [
                    .contentTypeKey, .fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey
                ])
                guard values.isRegularFile == true, values.isSymbolicLink != true else {
                    throw ClientError.forbidden("Only regular files can be attached.")
                }
                if let size = values.fileSize, size > ComposerAttachmentPolicy.maximumFileBytes {
                    throw ClientError.malformedData("\(name) exceeds the five MiB attachment limit.")
                }
                let data = try readAttachmentData(at: url, name: name)
                let mediaType = try ComposerAttachmentPolicy.mediaType(
                    data: data, suggestedType: values.contentType, fileName: name
                )
                try addAttachment(PendingComposerAttachment(
                    displayName: name, mediaType: mediaType, content: data
                ))
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func readAttachmentData(at url: URL, name: String) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var result = Data()
        while result.count <= ComposerAttachmentPolicy.maximumFileBytes {
            let remaining = ComposerAttachmentPolicy.maximumFileBytes + 1 - result.count
            guard let chunk = try handle.read(upToCount: min(64 * 1_024, remaining)), !chunk.isEmpty else {
                break
            }
            result.append(chunk)
        }
        guard result.count <= ComposerAttachmentPolicy.maximumFileBytes else {
            result.resetBytes(in: 0..<result.count)
            throw ClientError.malformedData("\(name) exceeds the five MiB attachment limit.")
        }
        return result
    }

    private func addAttachment(_ item: PendingComposerAttachment) throws {
        guard attachments.count < ComposerAttachmentPolicy.maximumCount else {
            throw ClientError.malformedData("Choose at most four attachments.")
        }
        let total = attachments.reduce(item.content.count) { $0 + $1.content.count }
        guard total <= ComposerAttachmentPolicy.maximumTotalBytes else {
            throw ClientError.malformedData("Attachments exceed the eight MiB total limit.")
        }
        attachments.append(item)
    }

    private func removeAttachment(id: UUID) {
        guard let index = attachments.firstIndex(where: { $0.id == id }) else { return }
        var removed = attachments.remove(at: index)
        removed.content.resetBytes(in: 0..<removed.content.count)
    }

    private func wipeAttachments() {
        for index in attachments.indices {
            attachments[index].content.resetBytes(in: 0..<attachments[index].content.count)
        }
        attachments.removeAll(keepingCapacity: false)
        photoItems.removeAll(keepingCapacity: false)
    }
}

enum ComposerAttachmentPolicy {
    static let maximumCount = 4
    static let maximumFileBytes = 5 * 1_024 * 1_024
    static let maximumTotalBytes = 8 * 1_024 * 1_024

    static func mediaType(data: Data, suggestedType: UTType?, fileName: String) throws -> String {
        let displayedFileName = HostileDisplayText.sanitized(fileName)
        guard (1...maximumFileBytes).contains(data.count) else {
            throw ClientError.malformedData("\(displayedFileName) must be between one byte and five MiB.")
        }
        let bytes = [UInt8](data.prefix(64))
        if bytes.starts(with: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) { return "image/png" }
        if bytes.starts(with: [0xFF, 0xD8, 0xFF]) { return "image/jpeg" }
        if isHEIC(data) { return "image/heic" }
        if bytes.starts(with: Array("%PDF-".utf8)) { return "application/pdf" }

        guard let string = String(data: data, encoding: .utf8), !string.contains("\0") else {
            throw ClientError.malformedData("\(displayedFileName) does not match an allowed image, PDF, or UTF-8 text type.")
        }
        let extensionName = (fileName as NSString).pathExtension.lowercased()
        if extensionName == "json" || suggestedType?.conforms(to: .json) == true {
            guard (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) != nil else {
                throw ClientError.malformedData("\(displayedFileName) is not valid JSON.")
            }
            return "application/json"
        }
        if ["md", "markdown"].contains(extensionName) { return "text/markdown" }
        if extensionName == "csv" || suggestedType?.conforms(to: .commaSeparatedText) == true { return "text/csv" }

        let textExtensions = Set([
            "txt", "swift", "go", "rs", "py", "rb", "js", "jsx", "ts", "tsx", "java", "kt",
            "c", "h", "cc", "cpp", "hpp", "cs", "sh", "bash", "zsh", "fish", "yaml", "yml",
            "toml", "xml", "html", "css", "sql", "graphql"
        ])
        guard suggestedType?.conforms(to: .text) == true || textExtensions.contains(extensionName) else {
            throw ClientError.malformedData("\(displayedFileName) has an unsupported attachment type.")
        }
        return "text/plain"
    }

    private static func isHEIC(_ data: Data) -> Bool {
        guard data.count >= 12 else { return false }
        let bytes = [UInt8](data.prefix(min(data.count, 64)))
        guard String(bytes: bytes[4..<8], encoding: .ascii) == "ftyp" else { return false }
        let boxSize = Int(bytes[0]) << 24 | Int(bytes[1]) << 16 | Int(bytes[2]) << 8 | Int(bytes[3])
        guard boxSize >= 12, boxSize <= data.count else { return false }
        let upper = min(boxSize, bytes.count)
        var offset = 8
        while offset + 4 <= upper {
            let brand = String(bytes: bytes[offset..<(offset + 4)], encoding: .ascii)
            if ["heic", "heix", "hevc", "hevx", "mif1"].contains(brand) { return true }
            offset += 4
        }
        return false
    }
}
