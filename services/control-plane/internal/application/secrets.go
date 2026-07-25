package application

import (
	"context"
	"errors"
	"sort"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	secretmodel "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/secrets"
)

func (a *Application) ListSecrets(ctx context.Context, principal httpapi.Principal, repositoryID *string) ([]httpapi.SecretMetadata, error) {
	if repositoryID != nil {
		if _, err := a.deps.Repositories.Get(ctx, principal.OwnerID, *repositoryID); err != nil {
			return nil, external(err)
		}
	}
	values, err := a.deps.State.ListSecrets(ctx, principal.OwnerID, repositoryID)
	if err != nil {
		return nil, external(err)
	}
	result := make([]httpapi.SecretMetadata, 0, len(values))
	for _, value := range values {
		result = append(result, secretMetadata(value))
	}
	return result, nil
}

func (a *Application) CreateSecret(ctx context.Context, principal httpapi.Principal, request httpapi.CreateSecretRequest) (httpapi.SecretMetadata, error) {
	if !secretmodel.ValidName(request.Name) || request.RepositoryID != nil && *request.RepositoryID == "" {
		return httpapi.SecretMetadata{}, invalid(nil)
	}
	if request.RepositoryID != nil {
		if _, err := a.deps.Repositories.Get(ctx, principal.OwnerID, *request.RepositoryID); err != nil {
			return httpapi.SecretMetadata{}, external(err)
		}
	}
	plaintext := []byte(request.Value)
	defer secretmodel.Wipe(plaintext)
	if err := secretmodel.ValidateValue(plaintext); err != nil {
		return httpapi.SecretMetadata{}, invalid(nil)
	}
	id, err := a.newID("secret")
	if err != nil {
		return httpapi.SecretMetadata{}, external(err)
	}
	now := a.deps.Clock.Now()
	value, err := a.deps.State.CreateSecret(ctx, secretmodel.Metadata{
		ID: id, OwnerID: principal.OwnerID, RepositoryID: request.RepositoryID, Name: request.Name,
		CreatedAt: now, UpdatedAt: now,
	}, plaintext, now)
	if err != nil {
		return httpapi.SecretMetadata{}, external(err)
	}
	result := secretMetadata(value)
	a.audit(principal, "", "secret.create", "success", "secret", value.ID, secretAuditDetails(value))
	return result, nil
}

func (a *Application) UpdateSecret(ctx context.Context, principal httpapi.Principal, secretID string, request httpapi.UpdateSecretRequest) (httpapi.SecretMetadata, error) {
	plaintext := []byte(request.Value)
	defer secretmodel.Wipe(plaintext)
	if err := secretmodel.ValidateValue(plaintext); err != nil {
		return httpapi.SecretMetadata{}, invalid(nil)
	}
	releaseSecretMutation := a.acquireSecretMutation(principal.OwnerID, secretID)
	defer releaseSecretMutation()

	workspaces, unlockWorkspaces, err := a.lockSecretWorkspaces(ctx, principal.OwnerID, secretID)
	if err != nil {
		return httpapi.SecretMetadata{}, err
	}
	defer unlockWorkspaces()

	value, err := a.deps.State.UpdateSecret(ctx, principal.OwnerID, secretID, plaintext, a.deps.Clock.Now())
	if err != nil {
		return httpapi.SecretMetadata{}, external(err)
	}
	syncResult, syncErr := a.syncSecretWorkspaces(ctx, workspaces)
	if syncErr != nil {
		details := secretAuditDetails(value)
		addSecretRuntimeSyncAuditDetails(details, syncResult)
		details["failure_stage"] = "runtime_sync"
		a.audit(principal, "", "secret.update", "failed", "secret", secretID, details)
		return httpapi.SecretMetadata{}, syncErr
	}
	a.audit(principal, "", "secret.update", "success", "secret", secretID, secretAuditDetails(value))
	return secretMetadata(value), nil
}

func (a *Application) DeleteSecret(ctx context.Context, principal httpapi.Principal, secretID string) error {
	releaseSecretMutation := a.acquireSecretMutation(principal.OwnerID, secretID)
	defer releaseSecretMutation()

	workspaces, unlockWorkspaces, err := a.lockSecretWorkspaces(ctx, principal.OwnerID, secretID)
	if err != nil {
		return err
	}
	defer unlockWorkspaces()

	if err := a.deps.State.DeleteSecret(ctx, principal.OwnerID, secretID, a.deps.Clock.Now()); err != nil {
		return external(err)
	}
	syncResult, syncErr := a.syncSecretWorkspaces(ctx, workspaces)
	if syncErr != nil {
		details := make(map[string]any)
		addSecretRuntimeSyncAuditDetails(details, syncResult)
		details["failure_stage"] = "runtime_sync"
		a.audit(principal, "", "secret.delete", "failed", "secret", secretID, details)
		return syncErr
	}
	a.audit(principal, "", "secret.delete", "success", "secret", secretID, nil)
	return nil
}

func (a *Application) ListWorkspaceSecretGrants(ctx context.Context, principal httpapi.Principal, workspaceID string) ([]httpapi.WorkspaceSecretGrant, error) {
	if _, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID); err != nil {
		return nil, external(err)
	}
	values, err := a.deps.State.ListWorkspaceSecretGrants(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return nil, external(err)
	}
	result := make([]httpapi.WorkspaceSecretGrant, 0, len(values))
	for _, value := range values {
		result = append(result, httpapi.WorkspaceSecretGrant{
			Secret: secretMetadata(value.Secret), Granted: value.Granted, GrantedAt: value.GrantedAt,
		})
	}
	return result, nil
}

func (a *Application) GrantWorkspaceSecret(ctx context.Context, principal httpapi.Principal, workspaceID, secretID string) error {
	releaseSecretMutation := a.acquireSecretMutation(principal.OwnerID, secretID)
	defer releaseSecretMutation()

	releaseWorkspaceMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseWorkspaceMutation()

	value, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return external(err)
	}
	if err := a.deps.State.GrantWorkspaceSecret(ctx, principal.OwnerID, workspaceID, secretID, a.deps.Clock.Now()); err != nil {
		return external(err)
	}
	disposition, err := a.syncLiveWorkspaceSecretGrants(ctx, value)
	if err != nil {
		a.audit(principal, workspaceID, "secret.grant", "failed", "secret", secretID, map[string]any{
			"database_mutation": "committed", "runtime_sync": disposition, "runtime_sync_scope": "future_processes_only", "failure_stage": "runtime_sync",
		})
		return err
	}
	a.audit(principal, workspaceID, "secret.grant", "success", "secret", secretID, map[string]any{
		"runtime_sync": disposition, "runtime_sync_scope": "future_processes_only",
	})
	return nil
}

func (a *Application) RevokeWorkspaceSecret(ctx context.Context, principal httpapi.Principal, workspaceID, secretID string) error {
	releaseSecretMutation := a.acquireSecretMutation(principal.OwnerID, secretID)
	defer releaseSecretMutation()

	releaseWorkspaceMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseWorkspaceMutation()

	value, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return external(err)
	}
	if err := a.deps.State.RevokeWorkspaceSecret(ctx, principal.OwnerID, workspaceID, secretID, a.deps.Clock.Now()); err != nil {
		return external(err)
	}
	disposition, err := a.syncLiveWorkspaceSecretGrants(ctx, value)
	if err != nil {
		a.audit(principal, workspaceID, "secret.revoke", "failed", "secret", secretID, map[string]any{
			"database_mutation": "committed", "runtime_sync": disposition, "runtime_sync_scope": "future_processes_only", "failure_stage": "runtime_sync",
		})
		return err
	}
	a.audit(principal, workspaceID, "secret.revoke", "success", "secret", secretID, map[string]any{
		"runtime_sync": disposition, "runtime_sync_scope": "future_processes_only",
	})
	return nil
}

func (a *Application) syncLiveWorkspaceSecretGrants(ctx context.Context, value core.Workspace) (string, error) {
	// The tmpfs grant set controls future terminal processes only. Environment
	// inherited by an already-running process cannot be revoked in place; those
	// processes retain their launch-time values until the owner closes them.
	switch value.State {
	case core.WorkspaceReady, core.WorkspaceRunning, core.WorkspaceNeedsAttention, core.WorkspaceIdle:
		if err := a.syncWorkspaceRuntimeSecrets(ctx, value); err != nil {
			return "failed", err
		}
		return "applied", nil
	default:
		// A fresh authoritative sync is mandatory before the next terminal
		// process is launched, so stopped workspaces do not need a live helper.
		return "deferred_until_runtime_launch", nil
	}
}

const maximumSecretWorkspaceMutations = 1000

// lockSecretWorkspaces pins every workspace whose active grant can be affected
// by a rotation or deletion. The caller already holds the secret mutation lock,
// so a concurrent grant cannot appear after discovery. Sorted acquisition gives
// concurrent rotations a single lock order and terminal launches take the same
// workspace locks before performing their mandatory runtime synchronization.
func (a *Application) lockSecretWorkspaces(ctx context.Context, ownerID, secretID string) ([]core.Workspace, func(), error) {
	workspaceIDs, err := a.deps.State.ListSecretWorkspaceIDs(ctx, ownerID, secretID)
	if err != nil {
		return nil, func() {}, external(err)
	}
	if len(workspaceIDs) > maximumSecretWorkspaceMutations {
		return nil, func() {}, external(core.ErrCapacity)
	}
	sort.Strings(workspaceIDs)

	unlockers := make([]func(), 0, len(workspaceIDs))
	uniqueIDs := make([]string, 0, len(workspaceIDs))
	for _, workspaceID := range workspaceIDs {
		if workspaceID == "" {
			for index := len(unlockers) - 1; index >= 0; index-- {
				unlockers[index]()
			}
			return nil, func() {}, external(errors.New("stored secret grant has an invalid workspace identity"))
		}
		if len(uniqueIDs) != 0 && uniqueIDs[len(uniqueIDs)-1] == workspaceID {
			continue
		}
		unlockers = append(unlockers, a.acquireWorkspaceMutation(workspaceID))
		uniqueIDs = append(uniqueIDs, workspaceID)
	}
	unlock := func() {
		for index := len(unlockers) - 1; index >= 0; index-- {
			unlockers[index]()
		}
	}

	workspaces := make([]core.Workspace, 0, len(uniqueIDs))
	for _, workspaceID := range uniqueIDs {
		value, err := a.deps.WorkspaceStore.Get(ctx, ownerID, workspaceID)
		if errors.Is(err, core.ErrNotFound) {
			// The workspace may have been deleted after discovery but before its
			// mutation lock was acquired; it no longer has a live runtime to sync.
			continue
		}
		if err != nil {
			unlock()
			return nil, func() {}, external(err)
		}
		workspaces = append(workspaces, value)
	}
	return workspaces, unlock, nil
}

type secretRuntimeSyncResult struct {
	workspaces int
	applied    int
	deferred   int
	failed     int
}

func (a *Application) syncSecretWorkspaces(ctx context.Context, workspaces []core.Workspace) (secretRuntimeSyncResult, error) {
	result := secretRuntimeSyncResult{workspaces: len(workspaces)}
	var firstErr error
	for _, value := range workspaces {
		disposition, err := a.syncLiveWorkspaceSecretGrants(ctx, value)
		if err != nil {
			result.failed++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		switch disposition {
		case "applied":
			result.applied++
		default:
			result.deferred++
		}
	}
	return result, firstErr
}

func addSecretRuntimeSyncAuditDetails(details map[string]any, result secretRuntimeSyncResult) {
	details["database_mutation"] = "committed"
	details["runtime_sync"] = "failed"
	details["runtime_sync_scope"] = "future_processes_only"
	details["workspace_count"] = result.workspaces
	details["workspace_sync_applied"] = result.applied
	details["workspace_sync_deferred"] = result.deferred
	details["workspace_sync_failed"] = result.failed
}

func secretMetadata(value secretmodel.Metadata) httpapi.SecretMetadata {
	scope := "global"
	if value.RepositoryID != nil {
		scope = "repository"
	}
	return httpapi.SecretMetadata{
		ID: value.ID, Name: value.Name, Scope: scope, RepositoryID: value.RepositoryID,
		ValueBytes: value.ValueBytes, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func secretAuditDetails(value secretmodel.Metadata) map[string]any {
	details := map[string]any{"name": value.Name, "scope": "global"}
	if value.RepositoryID != nil {
		details["scope"] = "repository"
		details["repository_id"] = *value.RepositoryID
	}
	return details
}
