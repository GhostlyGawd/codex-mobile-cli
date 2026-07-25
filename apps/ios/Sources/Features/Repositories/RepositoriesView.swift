import SwiftUI

struct RepositoriesView: View {
    private enum Scope: String, CaseIterable, Identifiable {
        case all = "All"
        case favorites = "Favorites"
        case recent = "Recent"

        var id: String { rawValue }
    }

    @Environment(AppModel.self) private var model
    @State private var search = ""
    @State private var scope: Scope = .all
    @State private var newWorkspaceRepositoryID: String?

    var body: some View {
        Group {
            if model.capabilities?.githubConfigured == false {
                ContentUnavailableView {
                    Label("GitHub App Not Configured", systemImage: "shippingbox")
                } description: {
                    Text("The owner must create and install the GitHub App before repositories are available.")
                }
            } else if filteredRepositories.isEmpty {
                ContentUnavailableView(
                    scope == .favorites ? "No Favorite Repositories" : "No Repositories Found",
                    systemImage: scope == .favorites ? "star.slash" : "magnifyingglass",
                    description: Text(scope == .recent ? "Repositories you use appear here." : "Try another repository filter or search.")
                )
            } else {
                List(filteredRepositories) { repository in
                    Button {
                        newWorkspaceRepositoryID = repository.id
                    } label: {
                        HStack {
                            Image(systemName: repository.isPrivate ? "lock.fill" : "globe")
                                .foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(HostileDisplayText.sanitized(repository.fullName)).font(.headline)
                                Text("\(HostileDisplayText.sanitized(repository.installationAccount)) · \(HostileDisplayText.sanitized(repository.defaultBranch))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            if repository.isFavorite {
                                Image(systemName: "star.fill").foregroundStyle(.yellow)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(!model.network.isConnected)
                    .accessibilityHint("Creates a new isolated workspace from this repository")
                    .accessibilityIdentifier("repository.\(repository.id)")
                }
            }
        }
        .navigationTitle("Repositories")
        .safeAreaInset(edge: .bottom, spacing: 0) {
            Text("Only repositories granted to the GitHub App appear. Organization policy may require an administrator to approve access.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal)
                .padding(.vertical, 7)
                .frame(maxWidth: .infinity)
                .background(.bar)
        }
        .safeAreaInset(edge: .top, spacing: 0) {
            Picker("Repository filter", selection: $scope) {
                ForEach(Scope.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(.bar)
            .accessibilityIdentifier("repositories.filter")
        }
        .searchable(text: $search, prompt: "Owner, organization, or repository")
        .onSubmit(of: .search) { Task { await model.refreshRepositories(search: search) } }
        .onChange(of: search) { _, value in
            if value.isEmpty { Task { await model.refreshRepositories() } }
        }
        .refreshable { await model.refreshRepositories(search: search) }
        .task { if model.repositories.isEmpty { await model.refreshRepositories() } }
        .sheet(isPresented: Binding(
            get: { newWorkspaceRepositoryID != nil },
            set: { if !$0 { newWorkspaceRepositoryID = nil } }
        )) {
            if let repositoryID = newWorkspaceRepositoryID {
                NavigationStack { NewWorkspaceView(preselectedRepositoryID: repositoryID) }
            }
        }
    }

    private var filteredRepositories: [RepositorySummary] {
        let scoped: [RepositorySummary]
        switch scope {
        case .all:
            scoped = model.repositories
        case .favorites:
            scoped = model.repositories.filter(\.isFavorite)
        case .recent:
            scoped = model.repositories
                .filter { $0.lastUsedAt != nil }
                .sorted { ($0.lastUsedAt ?? .distantPast) > ($1.lastUsedAt ?? .distantPast) }
        }
        guard !search.isEmpty else { return scoped }
        return scoped.filter { $0.fullName.localizedCaseInsensitiveContains(search) }
    }
}
