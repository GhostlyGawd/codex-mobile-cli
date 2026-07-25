import SwiftUI
import UIKit

struct WorkspacePreviewsView: View {
    @Environment(AppModel.self) private var model
    let workspaceID: String

    @State private var previews: [PreviewEndpoint] = []
    @State private var selected: PreviewEndpoint?
    @State private var errorMessage: String?

    var body: some View {
        Group {
            if model.capabilities?.previewsConfigured == false {
                ContentUnavailableView("Previews Not Configured", systemImage: "safari", description: Text("Wildcard DNS and TLS must be configured before authenticated preview routes are available."))
            } else if previews.isEmpty, errorMessage == nil {
                ContentUnavailableView("No Preview Ports", systemImage: "rectangle.dashed", description: Text("Start a development server in a terminal tab. Raw workspace ports are never public."))
            } else {
                List(previews) { preview in
                    Button {
                        selected = preview
                    } label: {
                        HStack {
                            Image(systemName: "safari.fill")
                            VStack(alignment: .leading) {
                                Text("Port \(preview.port)").font(.headline).foregroundStyle(.primary)
                                Text("\(HostileDisplayText.sanitized(preview.processName)) · \(HostileDisplayText.sanitized(preview.status))").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .disabled(!model.network.isConnected)
                }
            }
            if let errorMessage { Text(errorMessage).foregroundStyle(.red).padding() }
        }
        .task(id: model.network.isConnected) { await load() }
        .sheet(item: $selected) { preview in
            NavigationStack {
                PreviewContainer(workspaceID: workspaceID, preview: preview)
            }
        }
    }

    private func load() async {
        guard model.network.isConnected else { errorMessage = ClientError.offline.localizedDescription; return }
        do {
            previews = try await model.api.previews(workspaceID: workspaceID)
            errorMessage = nil
        }
        catch { errorMessage = error.localizedDescription }
    }
}

private struct PreviewContainer: View {
    @Environment(AppModel.self) private var appModel
    @Environment(\.dismiss) private var dismiss
    let workspaceID: String
    let preview: PreviewEndpoint

    @State private var webModel: PreviewWebViewModel?
    @State private var errorMessage: String?

    var body: some View {
        Group {
            if let webModel {
                HostilePreviewWebView(model: webModel)
                    .overlay(alignment: .top) {
                        if webModel.isLoading { ProgressView().padding(8).background(.regularMaterial, in: Capsule()) }
                    }
                    .alert("Open external link in Safari?", isPresented: Binding(
                        get: { webModel.externalLink != nil },
                        set: { if !$0 { webModel.externalLink = nil } }
                    )) {
                        Button("Open Safari") {
                            guard let url = webModel.externalLink else { return }
                            webModel.externalLink = nil
                            UIApplication.shared.open(url)
                        }
                        Button("Cancel", role: .cancel) { webModel.externalLink = nil }
                    } message: { Text(webModel.externalLink?.host ?? "Unknown host") }
            } else if let errorMessage {
                ContentUnavailableView("Preview Blocked", systemImage: "lock.shield", description: Text(errorMessage))
            } else {
                ProgressView("Creating short-lived preview access…")
            }
        }
        .navigationTitle("\(HostileDisplayText.sanitized(preview.processName)) :\(preview.port)")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            if let url = webModel?.access.url {
                ToolbarItem(placement: .primaryAction) {
                    Button { UIApplication.shared.open(url) } label: { Label("Open in Safari", systemImage: "safari") }
                }
            }
        }
        .task { await createAccess() }
        .onDisappear { Task { try? await appModel.api.revokePreviewAccess(workspaceID: workspaceID, previewID: preview.id) } }
    }

    private func createAccess() async {
        do {
            let access = try await appModel.api.createPreviewAccess(workspaceID: workspaceID, previewID: preview.id)
            let originPolicy = PreviewOriginPolicy(allowedHost: access.allowedHost, allowedPort: 443)
            guard originPolicy.permits(access.url),
                  appModel.configuration.permitsPreviewHost(access.allowedHost),
                  access.expiresAt > Date() else {
                throw ClientError.forbidden("The preview route failed client origin or expiry validation.")
            }
            webModel = PreviewWebViewModel(access: access)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
