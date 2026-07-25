package application

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

func (a *Application) GetConnections(ctx context.Context, principal httpapi.Principal) (httpapi.ConnectionStatus, error) {
	result := httpapi.ConnectionStatus{
		GitHub: httpapi.GitHubConnectionStatus{
			Configured:    a.config.GitHubConfigured,
			Installations: []httpapi.GitHubInstallationConnection{},
		},
		Codex: httpapi.CodexConnectionStatus{Scope: "per_workspace", Workspaces: []httpapi.CodexWorkspaceConnection{}},
	}
	if a.config.GitHubConfigured {
		if a.deps.Connections == nil {
			return httpapi.ConnectionStatus{}, external(errors.New("GitHub connection persistence is unavailable"))
		}
		values, err := a.deps.Connections.ListGitHubInstallations(ctx, principal.OwnerID)
		if err != nil {
			return httpapi.ConnectionStatus{}, err
		}
		for _, value := range values {
			result.GitHub.Installations = append(result.GitHub.Installations, httpapi.GitHubInstallationConnection{
				InstallationID: value.InstallationID, AccountLogin: value.AccountLogin, AccountType: value.AccountType,
				RepositorySelection: value.RepositorySelection, UpdatedAt: value.UpdatedAt,
			})
		}
		result.GitHub.Connected = len(result.GitHub.Installations) != 0
	}

	workspaces, err := a.deps.WorkspaceStore.List(ctx, principal.OwnerID)
	if err != nil {
		return httpapi.ConnectionStatus{}, err
	}
	sort.Slice(workspaces, func(i, j int) bool {
		if workspaces[i].Name == workspaces[j].Name {
			return workspaces[i].ID < workspaces[j].ID
		}
		return workspaces[i].Name < workspaces[j].Name
	})
	for _, value := range workspaces {
		connection, statusErr := a.codexConnection(ctx, value)
		if statusErr != nil {
			return httpapi.ConnectionStatus{}, statusErr
		}
		result.Codex.Workspaces = append(result.Codex.Workspaces, connection)
		switch connection.State {
		case httpapi.CodexConnectionConnected:
			result.Codex.ConnectedWorkspaceCount++
		case httpapi.CodexConnectionAuthenticating:
			result.Codex.AuthenticatingWorkspaceCount++
		case httpapi.CodexConnectionDisconnected:
			result.Codex.DisconnectedWorkspaceCount++
		default:
			result.Codex.UnavailableWorkspaceCount++
		}
	}
	return result, nil
}

func (a *Application) GetCodexConnection(ctx context.Context, principal httpapi.Principal, workspaceID string) (httpapi.CodexWorkspaceConnection, error) {
	value, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.CodexWorkspaceConnection{}, err
	}
	return a.codexConnection(ctx, value)
}

func (a *Application) codexConnection(ctx context.Context, value core.Workspace) (httpapi.CodexWorkspaceConnection, error) {
	result := httpapi.CodexWorkspaceConnection{
		WorkspaceID: value.ID, WorkspaceName: value.Name,
		State: httpapi.CodexConnectionUnavailable, CheckedAt: a.deps.Clock.Now(),
	}
	if !workspaceRuntimeAvailable(value) {
		return result, nil
	}
	response, err := a.runHelper(ctx, value, workspacehelper.Request{
		Version: workspacehelper.Version, Operation: workspacehelper.OpCodexAuthStatus,
	})
	if err != nil {
		if ctx.Err() != nil {
			return httpapi.CodexWorkspaceConnection{}, ctx.Err()
		}
		return result, nil
	}
	switch httpapi.CodexConnectionState(response.CodexAuthState) {
	case httpapi.CodexConnectionConnected, httpapi.CodexConnectionAuthenticating, httpapi.CodexConnectionDisconnected:
		result.State = httpapi.CodexConnectionState(response.CodexAuthState)
	default:
		return httpapi.CodexWorkspaceConnection{}, external(errors.New("workspace helper returned an invalid Codex connection state"))
	}
	return result, nil
}

func (a *Application) DisconnectGitHub(ctx context.Context, principal httpapi.Principal, installationID int64) error {
	if !a.config.GitHubConfigured || a.deps.Connections == nil {
		return fmt.Errorf("%w: GitHub App is not configured", core.ErrPrecondition)
	}
	if err := a.deps.Connections.DisconnectGitHubInstallation(ctx, principal.OwnerID, installationID, a.deps.Clock.Now()); err != nil {
		a.audit(principal, "", "github.connection.disconnect", "failed", "github_installation", fmt.Sprint(installationID), nil)
		return err
	}
	a.audit(principal, "", "github.connection.disconnect", "success", "github_installation", fmt.Sprint(installationID), nil)
	return nil
}

func (a *Application) DisconnectCodex(ctx context.Context, principal httpapi.Principal, workspaceID string, request httpapi.ConfirmConnectionDisconnectRequest) error {
	if !request.Confirmed {
		return invalid(errors.New("Codex disconnect confirmation is required"))
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()

	value, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return err
	}
	if !workspaceRuntimeAvailable(value) {
		return fmt.Errorf("%w: resume the workspace before disconnecting Codex", core.ErrConflict)
	}
	records, err := a.deps.State.ListTerminalTabs(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return err
	}
	tabIDs := make([]string, 0, len(records))
	parsedTabIDs := make([]terminal.TabID, 0, len(records))
	for _, record := range records {
		if record.Kind != string(httpapi.TerminalCodex) {
			continue
		}
		parsed, parseErr := terminal.ParseTabID(record.ID)
		if parseErr != nil {
			return external(errors.New("stored Codex terminal tab has an invalid identity"))
		}
		tabIDs = append(tabIDs, parsed.String())
		parsedTabIDs = append(parsedTabIDs, parsed)
	}

	// Credential deletion is the security commit point. The trusted workspace
	// helper first stops the app-owned Codex sessions and removes both runtime
	// and encrypted credentials. Control-plane bookkeeping happens only after
	// the helper confirms that Codex is disconnected, so a local cleanup error
	// cannot leave usable credentials behind.
	response, err := a.runHelper(ctx, value, workspacehelper.Request{
		Version: workspacehelper.Version, Operation: workspacehelper.OpCodexAuthRevoke,
		Confirmed: true, CodexTerminalTabIDs: tabIDs,
	})
	if err != nil {
		a.audit(principal, workspaceID, "codex.connection.disconnect", "failed", "workspace", workspaceID, map[string]any{"terminal_count": len(tabIDs)})
		return err
	}
	if response.CodexAuthState != string(httpapi.CodexConnectionDisconnected) {
		a.audit(principal, workspaceID, "codex.connection.disconnect", "failed", "workspace", workspaceID, map[string]any{"terminal_count": len(tabIDs)})
		return external(errors.New("workspace helper omitted Codex disconnect confirmation"))
	}

	var cleanupErrors []error
	for index, parsed := range parsedTabIDs {
		a.runtimeMu.Lock()
		delete(a.running, tabIDs[index])
		a.runtimeMu.Unlock()
		if unregisterErr := a.deps.Terminals.Unregister(parsed, "codex_disconnected"); unregisterErr != nil {
			cleanupErrors = append(cleanupErrors, unregisterErr)
		}
	}
	if len(cleanupErrors) != 0 {
		a.audit(principal, workspaceID, "codex.connection.disconnect", "failed", "workspace", workspaceID, map[string]any{
			"credentials_revoked": true, "terminal_count": len(tabIDs), "cleanup_error_count": len(cleanupErrors), "failure_stage": "runtime_cleanup",
		})
		return external(fmt.Errorf("Codex credentials were revoked, but terminal runtime cleanup failed: %w", errors.Join(cleanupErrors...)))
	}
	a.audit(principal, workspaceID, "codex.connection.disconnect", "success", "workspace", workspaceID, map[string]any{"terminal_count": len(tabIDs)})
	return nil
}

func workspaceRuntimeAvailable(value core.Workspace) bool {
	if value.ProviderResourceID == "" {
		return false
	}
	return value.State == core.WorkspaceRunning || value.State == core.WorkspaceReady || value.State == core.WorkspaceIdle || value.State == core.WorkspaceNeedsAttention
}
