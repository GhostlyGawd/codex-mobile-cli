package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/admission"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspace"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DiskFreeFunc func(context.Context) (int64, error)

type WorkspaceStore struct {
	pool     *pgxpool.Pool
	diskFree DiskFreeFunc
}

var _ workspace.Store = (*WorkspaceStore)(nil)

func NewWorkspaceStore(pool *pgxpool.Pool, diskFree DiskFreeFunc) (*WorkspaceStore, error) {
	if pool == nil || diskFree == nil {
		return nil, errors.New("PostgreSQL pool and disk-free provider are required")
	}
	return &WorkspaceStore{pool: pool, diskFree: diskFree}, nil
}

func (s *WorkspaceStore) Create(ctx context.Context, value core.Workspace) error {
	if err := validateWorkspace(value); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin workspace creation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO workspaces
		    (id, owner_id, repository_id, name, branch, base_branch, worktree_path,
		     state, safety_mode, retention, nested_containers, setup_approved,
		     devcontainer_dir, devcontainer_supported, private_inputs_pending, dirty, unpushed,
		     quota_cpu_milli, quota_memory_mib, quota_disk_gib,
		     requested_disk_gib, provider_resource_id, failure_code, created_at, updated_at, last_activity_at,
		     idle_timeout_minutes, suspended_at)
		VALUES
		    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
		     $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)`,
		value.ID, value.OwnerID, value.Repository.ID, value.Name, value.Branch, value.BaseBranch, value.WorktreePath,
		string(value.State), string(value.SafetyMode), string(value.Retention), value.NestedContainers,
		value.SetupApproved, value.DevcontainerDir, value.DevcontainerSupported, value.PrivateInputsPending, value.Dirty, value.Unpushed,
		value.Quota.CPUMilli, value.Quota.MemoryMiB,
		value.Quota.DiskGiB, value.RequestedDiskGiB, value.ProviderResourceID, value.FailureCode, value.CreatedAt, value.UpdatedAt,
		value.LastActivityAt, nullableIdleTimeout(value.IdleTimeoutMinutes), value.SuspendedAt,
	)
	if err != nil {
		return mapError("create workspace", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspace_state_events
		    (owner_id, workspace_id, from_state, to_state, failure_code, occurred_at)
		VALUES ($1, $2, NULL, $3, $4, $5)`,
		value.OwnerID, value.ID, string(value.State), value.FailureCode, value.CreatedAt,
	); err != nil {
		return mapError("record initial workspace state", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit workspace creation", err)
	}
	return nil
}

func (s *WorkspaceStore) Get(ctx context.Context, ownerID, id string) (core.Workspace, error) {
	value, err := scanWorkspace(s.pool.QueryRow(ctx, workspaceSelect+` WHERE w.owner_id = $1 AND w.id = $2`, ownerID, id))
	if err != nil {
		return core.Workspace{}, mapError("find workspace", err)
	}
	return value, nil
}

func (s *WorkspaceStore) Save(ctx context.Context, value core.Workspace) error {
	if err := validateWorkspace(value); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin workspace save", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var previousState string
	if err := tx.QueryRow(ctx, `
		SELECT state FROM workspaces
		WHERE id = $1 AND owner_id = $2 AND repository_id = $3
		FOR UPDATE`, value.ID, value.OwnerID, value.Repository.ID).Scan(&previousState); err != nil {
		return mapError("lock workspace", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE workspaces SET
		    name = $3, branch = $4, base_branch = $5, worktree_path = $6,
		    state = $7, safety_mode = $8, retention = $9, nested_containers = $10,
		    setup_approved = $11, devcontainer_dir = $12, devcontainer_supported = $13,
		    private_inputs_pending = $14, dirty = $15, unpushed = $16,
		    quota_cpu_milli = $17, quota_memory_mib = $18, quota_disk_gib = $19,
		    requested_disk_gib = $20, provider_resource_id = $21, failure_code = $22,
		    updated_at = $23, last_activity_at = $24,
		    idle_timeout_minutes = $25, suspended_at = $26
		WHERE id = $1 AND owner_id = $2 AND repository_id = $27`,
		value.ID, value.OwnerID, value.Name, value.Branch, value.BaseBranch, value.WorktreePath,
		string(value.State), string(value.SafetyMode), string(value.Retention), value.NestedContainers,
		value.SetupApproved, value.DevcontainerDir, value.DevcontainerSupported, value.PrivateInputsPending, value.Dirty, value.Unpushed,
		value.Quota.CPUMilli, value.Quota.MemoryMiB,
		value.Quota.DiskGiB, value.RequestedDiskGiB, value.ProviderResourceID, value.FailureCode, value.UpdatedAt,
		value.LastActivityAt, nullableIdleTimeout(value.IdleTimeoutMinutes), value.SuspendedAt, value.Repository.ID,
	)
	if err != nil {
		return mapError("save workspace", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("save workspace: %w", core.ErrNotFound)
	}
	if previousState != string(value.State) {
		if _, err := tx.Exec(ctx, `
			INSERT INTO workspace_state_events
			    (owner_id, workspace_id, from_state, to_state, failure_code, occurred_at)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			value.OwnerID, value.ID, previousState, string(value.State), value.FailureCode, value.UpdatedAt,
		); err != nil {
			return mapError("record workspace state", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit workspace save", err)
	}
	return nil
}

// FinalizeDelete removes only the exact owner-scoped workspace that has
// already crossed the durable deleting boundary. PostgreSQL executes all
// reviewed child cascades and audit_events.workspace_id SET NULL in this same
// transaction; a provider acceptance alone never reaches this method.
func (s *WorkspaceStore) FinalizeDelete(ctx context.Context, ownerID, workspaceID string) error {
	if ownerID == "" || workspaceID == "" {
		return fmt.Errorf("finalize workspace delete: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin workspace delete finalization", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var state string
	if err := tx.QueryRow(ctx, `
		SELECT state
		FROM workspaces
		WHERE owner_id = $1 AND id = $2
		FOR UPDATE`, ownerID, workspaceID).Scan(&state); err != nil {
		return mapError("lock workspace delete finalization", err)
	}
	if state != string(core.WorkspaceDeleting) {
		return fmt.Errorf("finalize workspace delete: %w", core.ErrConflict)
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM workspaces
		WHERE owner_id = $1 AND id = $2 AND state = $3`, ownerID, workspaceID, string(core.WorkspaceDeleting))
	if err != nil {
		return mapError("finalize workspace delete", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("finalize workspace delete: %w", core.ErrNotFound)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit workspace delete finalization", err)
	}
	return nil
}

// UpdateGitRisk updates only the live dirty/unpushed observation. Keeping this
// narrow avoids a periodic checkpoint scan overwriting a concurrent lifecycle
// transition with an older full workspace record.
func (s *WorkspaceStore) UpdateGitRisk(ctx context.Context, ownerID, workspaceID string, dirty, unpushed bool, observedAt time.Time) error {
	if ownerID == "" || workspaceID == "" || observedAt.IsZero() {
		return fmt.Errorf("workspace Git risk: %w", core.ErrInvalid)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE workspaces
		SET dirty = $3, unpushed = $4, updated_at = GREATEST(updated_at, $5)
		WHERE owner_id = $1 AND id = $2`, ownerID, workspaceID, dirty, unpushed, observedAt.UTC())
	if err != nil {
		return mapError("update workspace Git risk", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("update workspace Git risk: %w", core.ErrNotFound)
	}
	return nil
}

func (s *WorkspaceStore) List(ctx context.Context, ownerID string) ([]core.Workspace, error) {
	rows, err := s.pool.Query(ctx, workspaceSelect+` WHERE w.owner_id = $1 ORDER BY w.created_at, w.id`, ownerID)
	if err != nil {
		return nil, mapError("list workspaces", err)
	}
	defer rows.Close()
	values := make([]core.Workspace, 0)
	for rows.Next() {
		value, err := scanWorkspace(rows)
		if err != nil {
			return nil, mapError("scan workspace", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate workspaces", err)
	}
	return values, nil
}

// ListAll returns lifecycle candidates in a stable order. It is intentionally
// not exposed through the user-facing application service.
func (s *WorkspaceStore) ListAll(ctx context.Context) ([]core.Workspace, error) {
	rows, err := s.pool.Query(ctx, workspaceSelect+` ORDER BY w.owner_id, w.created_at, w.id`)
	if err != nil {
		return nil, mapError("list all workspaces", err)
	}
	defer rows.Close()
	values := make([]core.Workspace, 0)
	for rows.Next() {
		value, err := scanWorkspace(rows)
		if err != nil {
			return nil, mapError("scan workspace", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate workspaces", err)
	}
	return values, nil
}

// TouchActivity advances the activity clock without allowing an older full
// record to overwrite a concurrent state change. Idle workspaces atomically
// return to running when real activity is observed.
func (s *WorkspaceStore) TouchActivity(ctx context.Context, ownerID, workspaceID string, observedAt time.Time) error {
	if ownerID == "" || workspaceID == "" || observedAt.IsZero() {
		return fmt.Errorf("touch workspace activity: %w", core.ErrInvalid)
	}
	observedAt = observedAt.UTC()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin workspace activity", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var previous string
	err = tx.QueryRow(ctx, `
		SELECT state FROM workspaces
		WHERE owner_id = $1 AND id = $2
		FOR UPDATE`, ownerID, workspaceID).Scan(&previous)
	if err != nil {
		return mapError("lock workspace activity", err)
	}
	state := core.WorkspaceState(previous)
	switch state {
	case core.WorkspaceReady, core.WorkspaceRunning, core.WorkspaceNeedsAttention, core.WorkspaceIdle:
	default:
		return fmt.Errorf("touch workspace activity: %w: state %s", core.ErrConflict, state)
	}
	next := state
	if state == core.WorkspaceIdle {
		next = core.WorkspaceRunning
	}
	_, err = tx.Exec(ctx, `
		UPDATE workspaces
		SET state = $3,
		    last_activity_at = GREATEST(last_activity_at, $4),
		    updated_at = GREATEST(updated_at, $4)
		WHERE owner_id = $1 AND id = $2`, ownerID, workspaceID, string(next), observedAt)
	if err != nil {
		return mapError("touch workspace activity", err)
	}
	if next != state {
		if _, err := tx.Exec(ctx, `
			INSERT INTO workspace_state_events
			    (owner_id, workspace_id, from_state, to_state, failure_code, occurred_at)
			VALUES ($1, $2, $3, $4, '', $5)`,
			ownerID, workspaceID, previous, string(next), observedAt); err != nil {
			return mapError("record workspace activity state", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit workspace activity", err)
	}
	return nil
}

// TransitionIfInactive is the compare-and-swap primitive used by the
// lifecycle coordinator. A concurrent activity touch makes it a no-op.
func (s *WorkspaceStore) TransitionIfInactive(ctx context.Context, ownerID, workspaceID string, from, to core.WorkspaceState, expectedLastActivity, at time.Time) (bool, error) {
	if ownerID == "" || workspaceID == "" || !from.Valid() || !to.Valid() ||
		expectedLastActivity.IsZero() || at.IsZero() || !from.CanTransition(to) {
		return false, fmt.Errorf("transition inactive workspace: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, mapError("begin inactive workspace transition", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	tag, err := tx.Exec(ctx, `
		UPDATE workspaces
		SET state = $5, updated_at = GREATEST(updated_at, $6)
		WHERE owner_id = $1 AND id = $2 AND state = $3 AND last_activity_at = $4`,
		ownerID, workspaceID, string(from), expectedLastActivity.UTC(), string(to), at.UTC())
	if err != nil {
		return false, mapError("transition inactive workspace", err)
	}
	if tag.RowsAffected() == 0 {
		if err := tx.Commit(ctx); err != nil {
			return false, mapError("commit inactive workspace transition", err)
		}
		return false, nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO workspace_state_events
		    (owner_id, workspace_id, from_state, to_state, failure_code, occurred_at)
		VALUES ($1, $2, $3, $4, '', $5)`,
		ownerID, workspaceID, string(from), string(to), at.UTC()); err != nil {
		return false, mapError("record inactive workspace transition", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, mapError("commit inactive workspace transition", err)
	}
	return true, nil
}

func (s *WorkspaceStore) UpdateQuota(ctx context.Context, ownerID, workspaceID string, quota core.Quota, at time.Time) error {
	if ownerID == "" || workspaceID == "" || at.IsZero() || quota.CPUMilli < 0 || quota.MemoryMiB < 0 || quota.DiskGiB < 0 {
		return fmt.Errorf("update workspace quota: %w", core.ErrInvalid)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE workspaces
		SET quota_cpu_milli = $3, quota_memory_mib = $4, quota_disk_gib = $5,
		    updated_at = GREATEST(updated_at, $6)
		WHERE owner_id = $1 AND id = $2`, ownerID, workspaceID, quota.CPUMilli, quota.MemoryMiB, quota.DiskGiB, at.UTC())
	if err != nil {
		return mapError("update workspace quota", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("update workspace quota: %w", core.ErrNotFound)
	}
	return nil
}

func (s *WorkspaceStore) UpdatePolicy(ctx context.Context, ownerID, workspaceID string, retention core.RetentionPolicy, idleTimeoutMinutes int, at time.Time) error {
	if ownerID == "" || workspaceID == "" || !retention.Valid() || at.IsZero() ||
		(idleTimeoutMinutes != 0 && (idleTimeoutMinutes < 5 || idleTimeoutMinutes > 10080)) {
		return fmt.Errorf("update workspace policy: %w", core.ErrInvalid)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE workspaces
		SET retention = $3, idle_timeout_minutes = $4,
		    updated_at = GREATEST(updated_at, $5)
		WHERE owner_id = $1 AND id = $2`, ownerID, workspaceID, string(retention), nullableIdleTimeout(idleTimeoutMinutes), at.UTC())
	if err != nil {
		return mapError("update workspace policy", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("update workspace policy: %w", core.ErrNotFound)
	}
	return nil
}

// UpdateSafetyMode locks and rechecks the lifecycle state so a stale client or
// concurrent transition cannot change the policy of a live workspace. Resume
// is serialized with this operation by workspace.Service's admission gate.
func (s *WorkspaceStore) UpdateSafetyMode(ctx context.Context, ownerID, workspaceID string, mode core.SafetyMode, at time.Time) error {
	if ownerID == "" || workspaceID == "" || !mode.Valid() || at.IsZero() {
		return fmt.Errorf("update workspace safety mode: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin workspace safety mode update", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var state string
	if err := tx.QueryRow(ctx, `
		SELECT state FROM workspaces
		WHERE owner_id = $1 AND id = $2
		FOR UPDATE`, ownerID, workspaceID).Scan(&state); err != nil {
		return mapError("lock workspace safety mode", err)
	}
	if core.WorkspaceState(state) != core.WorkspaceSuspended {
		return fmt.Errorf("update workspace safety mode: %w: workspace must be suspended", core.ErrConflict)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE workspaces
		SET safety_mode = $3, updated_at = GREATEST(updated_at, $4)
		WHERE owner_id = $1 AND id = $2`, ownerID, workspaceID, string(mode), at.UTC()); err != nil {
		return mapError("update workspace safety mode", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit workspace safety mode update", err)
	}
	return nil
}

func (s *WorkspaceStore) Snapshot(ctx context.Context, ownerID string) (admission.Snapshot, error) {
	diskFreeGiB, err := s.diskFree(ctx)
	if err != nil {
		return admission.Snapshot{}, fmt.Errorf("measure workspace disk: %w", err)
	}
	if diskFreeGiB < 0 {
		return admission.Snapshot{}, errors.New("measure workspace disk: negative free space")
	}
	var running, queued, pendingDiskGiB int64
	err = s.pool.QueryRow(ctx, `
		SELECT
		    count(*) FILTER (WHERE state IN (
		        'provisioning', 'ready', 'running', 'needs_attention', 'idle', 'suspending', 'maintenance', 'deleting'
		    )),
		    count(*) FILTER (WHERE state = 'queued'),
		    COALESCE(sum(quota_disk_gib) FILTER (
		        WHERE state = 'provisioning' AND provider_resource_id = ''
		    ), 0)
		FROM workspaces WHERE owner_id = $1`, ownerID).Scan(&running, &queued, &pendingDiskGiB)
	if err != nil {
		return admission.Snapshot{}, mapError("count workspace capacity", err)
	}
	return admission.Snapshot{
		Running: int(running), Queued: int(queued), DiskFreeGiB: diskFreeGiB, PendingDiskGiB: pendingDiskGiB,
	}, nil
}

const workspaceSelect = `
	SELECT
	    w.id, w.owner_id, w.name, w.branch, w.base_branch, w.worktree_path,
	    w.state, w.safety_mode, w.retention, w.nested_containers,
	    w.setup_approved, w.devcontainer_dir, w.devcontainer_supported, w.private_inputs_pending,
	    w.dirty, w.unpushed,
	    w.quota_cpu_milli, w.quota_memory_mib, w.quota_disk_gib,
	    w.requested_disk_gib, w.provider_resource_id, w.failure_code,
	    w.created_at, w.updated_at, w.last_activity_at,
	    w.idle_timeout_minutes, w.suspended_at,
	    r.id, r.installation_id, r.full_name, r.default_branch,
	    r.private, r.organization, r.permission, r.updated_at
	FROM workspaces w
	JOIN repositories r ON r.owner_id = w.owner_id AND r.id = w.repository_id`

func scanWorkspace(row rowScanner) (core.Workspace, error) {
	var value core.Workspace
	var state, safetyMode, retention string
	var idleTimeoutMinutes *int
	if err := row.Scan(
		&value.ID, &value.OwnerID, &value.Name, &value.Branch, &value.BaseBranch, &value.WorktreePath,
		&state, &safetyMode, &retention, &value.NestedContainers,
		&value.SetupApproved, &value.DevcontainerDir, &value.DevcontainerSupported, &value.PrivateInputsPending,
		&value.Dirty, &value.Unpushed,
		&value.Quota.CPUMilli, &value.Quota.MemoryMiB, &value.Quota.DiskGiB,
		&value.RequestedDiskGiB, &value.ProviderResourceID, &value.FailureCode,
		&value.CreatedAt, &value.UpdatedAt, &value.LastActivityAt,
		&idleTimeoutMinutes, &value.SuspendedAt,
		&value.Repository.ID, &value.Repository.InstallationID, &value.Repository.FullName,
		&value.Repository.DefaultBranch, &value.Repository.Private, &value.Repository.Organization,
		&value.Repository.Permission, &value.Repository.UpdatedAt,
	); err != nil {
		return core.Workspace{}, err
	}
	value.State = core.WorkspaceState(state)
	value.SafetyMode = core.SafetyMode(safetyMode)
	value.Retention = core.RetentionPolicy(retention)
	if idleTimeoutMinutes != nil {
		value.IdleTimeoutMinutes = *idleTimeoutMinutes
	}
	if !value.State.Valid() || !value.SafetyMode.Valid() || !value.Retention.Valid() {
		return core.Workspace{}, errors.New("invalid stored workspace policy value")
	}
	return value, nil
}

func validateWorkspace(value core.Workspace) error {
	if value.ID == "" || value.OwnerID == "" || value.Repository.ID == "" || value.Name == "" ||
		value.Branch == "" || value.BaseBranch == "" || value.CreatedAt.IsZero() ||
		value.UpdatedAt.Before(value.CreatedAt) || value.LastActivityAt.Before(value.CreatedAt) ||
		!value.State.Valid() || !value.SafetyMode.Valid() || !value.Retention.Valid() ||
		(value.IdleTimeoutMinutes != 0 && (value.IdleTimeoutMinutes < 5 || value.IdleTimeoutMinutes > 10080)) ||
		(value.State == core.WorkspaceSuspended) != (value.SuspendedAt != nil) ||
		(value.State == core.WorkspaceAwaitingSetupApproval && value.DevcontainerDir == "") ||
		(value.PrivateInputsPending && value.State != core.WorkspaceQueued && value.State != core.WorkspaceProvisioning && value.State != core.WorkspaceFailed && value.State != core.WorkspaceDeleting) ||
		!validStoredDevcontainer(value.DevcontainerDir, value.DevcontainerSupported) ||
		value.Quota.CPUMilli < 0 || value.Quota.MemoryMiB < 0 || value.Quota.DiskGiB < 0 ||
		value.RequestedDiskGiB < core.MinimumWorkspaceDiskGiB || value.RequestedDiskGiB > core.MaximumWorkspaceDiskGiB {
		return fmt.Errorf("workspace record: %w", core.ErrInvalid)
	}
	return nil
}

func validStoredDevcontainer(directory string, supported bool) bool {
	if directory != "" && directory != "." && directory != ".devcontainer" {
		return false
	}
	return !supported || directory != ""
}

func nullableIdleTimeout(value int) any {
	if value == 0 {
		return nil
	}
	return value
}
