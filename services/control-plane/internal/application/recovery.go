package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

const checkpointRestoreSemantics = "recorded-delta-over-current-workspace"

func (a *Application) ListCheckpoints(ctx context.Context, principal httpapi.Principal, workspaceID string) ([]httpapi.CheckpointSummary, error) {
	if a.deps.Checkpoints == nil {
		return nil, fmt.Errorf("%w: local checkpoint recovery is unavailable", core.ErrPrecondition)
	}
	if _, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID); err != nil {
		return nil, err
	}
	values, err := a.deps.Checkpoints.ListVerified(ctx, workspaceID)
	if err != nil {
		return nil, external(err)
	}
	result := make([]httpapi.CheckpointSummary, 0, len(values))
	for index := len(values) - 1; index >= 0; index-- {
		value := values[index]
		hashStatus := "failed"
		if value.HashVerified {
			hashStatus = "verified"
		}
		result = append(result, httpapi.CheckpointSummary{
			ID: value.ID, Reason: value.Reason, CreatedAt: value.CreatedAt,
			ArchiveSHA256: value.ArchiveSHA256, HashStatus: hashStatus, ArchiveVersion: value.ArchiveVersion,
			WorkspaceRestoreSupported: value.WorkspaceRestoreSupported,
			CompressedBytes:           value.CompressedBytes, ExpandedBytes: value.ExpandedBytes,
			FileCount: value.FileCount, DeletedCount: value.DeletedCount,
			OmittedSensitive: value.OmittedSensitive, OmittedUnsafe: value.OmittedUnsafe, Head: value.Head,
		})
	}
	return result, nil
}

func (a *Application) RestoreCheckpointFile(ctx context.Context, principal httpapi.Principal, workspaceID, checkpointID string, request httpapi.CheckpointRestoreFileRequest) (httpapi.CheckpointRestoreResult, error) {
	if a.deps.Checkpoints == nil {
		return httpapi.CheckpointRestoreResult{}, fmt.Errorf("%w: local checkpoint recovery is unavailable", core.ErrPrecondition)
	}
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.CheckpointRestoreResult{}, err
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	preRestoreID, err := a.deps.Checkpoints.RestoreFileProtected(ctx, workspaceID, value.ProviderResourceID, checkpointID, request.Path, request.Confirmed)
	if err != nil {
		a.audit(principal, workspaceID, "checkpoint.file.restore", "failed", "checkpoint", checkpointID, nil)
		return httpapi.CheckpointRestoreResult{RestoredCheckpointID: checkpointID, PreRestoreCheckpointID: preRestoreID, RestoreSemantics: checkpointRestoreSemantics}, external(err)
	}
	result := httpapi.CheckpointRestoreResult{
		RestoredCheckpointID: checkpointID, PreRestoreCheckpointID: preRestoreID, RestoreSemantics: checkpointRestoreSemantics,
	}
	if status, statusErr := a.gitOperation(ctx, value, workspacehelper.Request{Version: workspacehelper.Version, Operation: workspacehelper.OpGitStatus}); statusErr == nil {
		result.Status = &status
	} else {
		_ = a.touchWorkspace(ctx, value)
	}
	a.audit(principal, workspaceID, "checkpoint.file.restore", "success", "checkpoint", checkpointID, map[string]any{"pre_restore_checkpoint_id": preRestoreID})
	return result, nil
}

func (a *Application) RestoreCheckpointWorkspace(ctx context.Context, principal httpapi.Principal, workspaceID, checkpointID string, request httpapi.CheckpointRestoreWorkspaceRequest) (httpapi.CheckpointRestoreResult, error) {
	if a.deps.Checkpoints == nil {
		return httpapi.CheckpointRestoreResult{}, fmt.Errorf("%w: local checkpoint recovery is unavailable", core.ErrPrecondition)
	}
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.CheckpointRestoreResult{}, err
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	restored, err := a.deps.Checkpoints.RestoreWorkspace(ctx, workspaceID, value.ProviderResourceID, checkpointID, request.Confirmed)
	if err != nil {
		a.audit(principal, workspaceID, "checkpoint.workspace.restore", "failed", "checkpoint", checkpointID, nil)
		return httpapi.CheckpointRestoreResult{RestoredCheckpointID: checkpointID, PreRestoreCheckpointID: restored.PreRestoreCheckpointID, RestoreSemantics: checkpointRestoreSemantics}, external(err)
	}
	if err := a.syncGitState(ctx, value, restored.GitStatus); err != nil {
		return httpapi.CheckpointRestoreResult{}, err
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.CheckpointRestoreResult{}, err
	}
	status := gitStatusDetail(restored.GitStatus)
	a.audit(principal, workspaceID, "checkpoint.workspace.restore", "success", "checkpoint", checkpointID, map[string]any{"pre_restore_checkpoint_id": restored.PreRestoreCheckpointID})
	return httpapi.CheckpointRestoreResult{
		RestoredCheckpointID: restored.RestoredCheckpointID, PreRestoreCheckpointID: restored.PreRestoreCheckpointID,
		RestoreSemantics: checkpointRestoreSemantics, Status: &status,
	}, nil
}

func (a *Application) DiscardGitChanges(ctx context.Context, principal httpapi.Principal, workspaceID string, request httpapi.GitDiscardRequest) (httpapi.GitDiscardResult, error) {
	if a.deps.Checkpoints == nil {
		return httpapi.GitDiscardResult{}, fmt.Errorf("%w: local checkpoint recovery is unavailable", core.ErrPrecondition)
	}
	if !request.Confirmed {
		return httpapi.GitDiscardResult{}, fmt.Errorf("%w: explicit discard confirmation required", core.ErrPrecondition)
	}
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.GitDiscardResult{}, err
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	checkpointID, _, _, err := a.deps.Checkpoints.CreateRequired(ctx, workspaceID, value.ProviderResourceID, "before-git-discard")
	if err != nil || checkpointID == "" {
		if err == nil {
			err = errors.New("checkpoint service returned an empty recovery identity")
		}
		return httpapi.GitDiscardResult{}, fmt.Errorf("checkpoint before discard: %w", external(err))
	}
	response, err := a.runHelper(ctx, value, workspacehelper.Request{
		Version: workspacehelper.Version, Operation: workspacehelper.OpGitDiscard,
		Paths: append([]string(nil), request.Paths...), Confirmed: true, CheckpointID: checkpointID,
	})
	if err != nil {
		a.audit(principal, workspaceID, "git.discard", "failed", "checkpoint", checkpointID, map[string]any{"path_count": len(request.Paths)})
		return httpapi.GitDiscardResult{RecoveryCheckpointID: checkpointID, RestoreURL: checkpointRestoreURL(workspaceID, checkpointID)}, err
	}
	if response.CheckpointID != checkpointID || response.GitStatus == nil {
		return httpapi.GitDiscardResult{RecoveryCheckpointID: checkpointID, RestoreURL: checkpointRestoreURL(workspaceID, checkpointID)}, external(errors.New("workspace helper omitted verified discard result"))
	}
	if err := a.syncGitState(ctx, value, *response.GitStatus); err != nil {
		return httpapi.GitDiscardResult{}, err
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.GitDiscardResult{}, err
	}
	a.audit(principal, workspaceID, "git.discard", "success", "checkpoint", checkpointID, map[string]any{"path_count": len(request.Paths)})
	return httpapi.GitDiscardResult{
		RecoveryCheckpointID: checkpointID, Status: gitStatusDetail(*response.GitStatus), RestoreURL: checkpointRestoreURL(workspaceID, checkpointID),
	}, nil
}

func checkpointRestoreURL(workspaceID, checkpointID string) string {
	return fmt.Sprintf("/v1/workspaces/%s/checkpoints/%s/restore-workspace", workspaceID, checkpointID)
}
