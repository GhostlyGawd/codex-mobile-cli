package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspace"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maximumGitHubSharedLeaseConnections    = 8
	maximumGitHubExclusiveLeaseConnections = 2
)

type RepositoryStore struct {
	pool                      *pgxpool.Pool
	githubSharedLeaseSlots    chan struct{}
	githubExclusiveLeaseSlots chan struct{}
}

var _ workspace.RepositorySource = (*RepositoryStore)(nil)
var _ githubapp.TokenUseStore = (*RepositoryStore)(nil)

var githubTokenUseIDPattern = regexp.MustCompile(`^ght_[0-9a-f]{32}$`)

type GitHubInstallation struct {
	OwnerID             string
	InstallationID      int64
	AccountID           int64
	AccountLogin        string
	AccountType         string
	RepositorySelection string
	Permissions         json.RawMessage
	CreatedAt           time.Time
	UpdatedAt           time.Time
	SuspendedAt         *time.Time
}

type RepositoryView struct {
	Repository          core.Repository
	InstallationAccount string
	Favorite            bool
	LastUsedAt          *time.Time
}

type GitHubInstallationConnection struct {
	InstallationID      int64
	AccountLogin        string
	AccountType         string
	RepositorySelection string
	UpdatedAt           time.Time
}

func NewRepositoryStore(pool *pgxpool.Pool) (*RepositoryStore, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL pool is required")
	}
	sharedLimit := min(max(1, int(pool.Config().MaxConns)), maximumGitHubSharedLeaseConnections)
	exclusiveLimit := min(max(1, int(pool.Config().MaxConns)), maximumGitHubExclusiveLeaseConnections)
	return &RepositoryStore{
		pool: pool, githubSharedLeaseSlots: make(chan struct{}, sharedLimit),
		githubExclusiveLeaseSlots: make(chan struct{}, exclusiveLimit),
	}, nil
}

func (s *RepositoryStore) UpsertInstallation(ctx context.Context, installation GitHubInstallation) error {
	return s.upsertInstallation(ctx, installation, false, nil)
}

// UpsertInstallationFromProviderUnsuspend may clear provider suspension only
// after the caller has fetched fresh provider metadata while holding
// WithGitHubInstallationSyncLease. Keeping this as a distinct operation makes
// ordinary webhook/reconciliation refreshes monotonic revocation writes.
func (s *RepositoryStore) UpsertInstallationFromProviderUnsuspend(ctx context.Context, installation GitHubInstallation) error {
	if err := requireGitHubInstallationSyncLease(ctx, installation.OwnerID, installation.InstallationID); err != nil {
		return err
	}
	return s.upsertInstallation(ctx, installation, true, nil)
}

// UpsertInstallationForOwnerReconnect inserts a newly discovered installation
// in a fail-closed state and preserves the disconnect established by
// BeginGitHubInstallationReconnect for an existing row. The caller must hold
// WithGitHubInstallationSyncLease.
func (s *RepositoryStore) UpsertInstallationForOwnerReconnect(ctx context.Context, installation GitHubInstallation, disconnectedAt time.Time) error {
	if err := requireGitHubInstallationSyncLease(ctx, installation.OwnerID, installation.InstallationID); err != nil {
		return err
	}
	if disconnectedAt.IsZero() {
		return fmt.Errorf("GitHub owner reconnect state: %w", core.ErrInvalid)
	}
	if disconnectedAt.Before(installation.CreatedAt) {
		disconnectedAt = installation.CreatedAt
	}
	if installation.UpdatedAt.Before(disconnectedAt) {
		installation.UpdatedAt = disconnectedAt
	}
	return s.upsertInstallation(ctx, installation, false, &disconnectedAt)
}

func (s *RepositoryStore) upsertInstallation(ctx context.Context, installation GitHubInstallation, allowProviderUnsuspend bool, ownerDisconnectedAt *time.Time) error {
	if allowProviderUnsuspend && installation.SuspendedAt != nil {
		return fmt.Errorf("GitHub provider unsuspend state: %w", core.ErrInvalid)
	}
	if installation.OwnerID == "" || installation.InstallationID <= 0 || installation.AccountID <= 0 ||
		installation.AccountLogin == "" || installation.CreatedAt.IsZero() || installation.UpdatedAt.Before(installation.CreatedAt) {
		return fmt.Errorf("GitHub installation: %w", core.ErrInvalid)
	}
	if installation.AccountType != "User" && installation.AccountType != "Organization" && installation.AccountType != "Enterprise" && installation.AccountType != "Bot" {
		return fmt.Errorf("GitHub installation account type: %w", core.ErrInvalid)
	}
	if installation.RepositorySelection != "all" && installation.RepositorySelection != "selected" {
		return fmt.Errorf("GitHub repository selection: %w", core.ErrInvalid)
	}
	permissions := installation.Permissions
	if len(permissions) == 0 {
		permissions = json.RawMessage(`{}`)
	}
	if !json.Valid(permissions) {
		return fmt.Errorf("GitHub installation permissions: %w", core.ErrInvalid)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO github_installations
		    (owner_id, installation_id, account_id, account_login, account_type,
		     repository_selection, permissions, created_at, updated_at, suspended_at,
		     owner_disconnected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (owner_id, installation_id) DO UPDATE SET
		    account_id = EXCLUDED.account_id,
		    account_login = EXCLUDED.account_login,
		    account_type = EXCLUDED.account_type,
		    repository_selection = EXCLUDED.repository_selection,
		    permissions = EXCLUDED.permissions,
		    updated_at = GREATEST(github_installations.updated_at, EXCLUDED.updated_at),
		    -- A metadata refresh is not authority to clear a revocation. Only a
		    -- fresh provider-unsuspend sync holding the exclusive lease may do so.
		    suspended_at = CASE WHEN $12 THEN EXCLUDED.suspended_at
		                        ELSE COALESCE(github_installations.suspended_at, EXCLUDED.suspended_at)
		                   END`,
		installation.OwnerID, installation.InstallationID, installation.AccountID, installation.AccountLogin,
		installation.AccountType, installation.RepositorySelection, permissions, installation.CreatedAt,
		installation.UpdatedAt, installation.SuspendedAt, ownerDisconnectedAt, allowProviderUnsuspend,
	)
	return mapError("upsert GitHub installation", err)
}

func (s *RepositoryStore) Upsert(ctx context.Context, ownerID string, repository core.Repository) error {
	if ownerID == "" {
		return fmt.Errorf("repository owner: %w", core.ErrInvalid)
	}
	if err := repository.Validate(); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO repositories
		    (owner_id, id, installation_id, full_name, default_branch, private,
		     organization, permission, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (owner_id, id) DO UPDATE SET
		    installation_id = EXCLUDED.installation_id,
		    full_name = EXCLUDED.full_name,
		    default_branch = EXCLUDED.default_branch,
		    private = EXCLUDED.private,
		    organization = EXCLUDED.organization,
		    permission = EXCLUDED.permission,
		    available = true,
		    updated_at = EXCLUDED.updated_at`,
		ownerID, repository.ID, repository.InstallationID, repository.FullName, repository.DefaultBranch,
		repository.Private, repository.Organization, repository.Permission, repository.UpdatedAt,
	)
	return mapError("upsert repository", err)
}

func (s *RepositoryStore) Get(ctx context.Context, ownerID, id string) (core.Repository, error) {
	var repository core.Repository
	err := s.pool.QueryRow(ctx, `
		SELECT r.id, r.installation_id, r.full_name, r.default_branch, r.private,
		       r.organization, r.permission, r.updated_at
		FROM repositories r
		JOIN github_installations i
		  ON i.owner_id = r.owner_id AND i.installation_id = r.installation_id
		WHERE r.owner_id = $1 AND r.id = $2 AND r.available
		  AND i.suspended_at IS NULL AND i.owner_disconnected_at IS NULL`, ownerID, id,
	).Scan(&repository.ID, &repository.InstallationID, &repository.FullName, &repository.DefaultBranch,
		&repository.Private, &repository.Organization, &repository.Permission, &repository.UpdatedAt)
	if err != nil {
		return core.Repository{}, mapError("find repository", err)
	}
	return repository, nil
}

func (s *RepositoryStore) List(ctx context.Context, ownerID string) ([]core.Repository, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.installation_id, r.full_name, r.default_branch, r.private,
		       r.organization, r.permission, r.updated_at
		FROM repositories r
		JOIN github_installations i
		  ON i.owner_id = r.owner_id AND i.installation_id = r.installation_id
		WHERE r.owner_id = $1 AND r.available
		  AND i.suspended_at IS NULL AND i.owner_disconnected_at IS NULL
		ORDER BY r.full_name`, ownerID)
	if err != nil {
		return nil, mapError("list repositories", err)
	}
	defer rows.Close()
	repositories := make([]core.Repository, 0)
	for rows.Next() {
		var repository core.Repository
		if err := rows.Scan(&repository.ID, &repository.InstallationID, &repository.FullName, &repository.DefaultBranch,
			&repository.Private, &repository.Organization, &repository.Permission, &repository.UpdatedAt); err != nil {
			return nil, mapError("scan repository", err)
		}
		repositories = append(repositories, repository)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate repositories", err)
	}
	return repositories, nil
}

func (s *RepositoryStore) ListViews(ctx context.Context, ownerID string) ([]RepositoryView, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.installation_id, r.full_name, r.default_branch, r.private,
		       r.organization, r.permission, r.updated_at, i.account_login,
		       COALESCE(p.favorite, false), p.last_used_at
		FROM repositories r
		JOIN github_installations i
		  ON i.owner_id = r.owner_id AND i.installation_id = r.installation_id
		LEFT JOIN repository_preferences p
		  ON p.owner_id = r.owner_id AND p.repository_id = r.id
		WHERE r.owner_id = $1 AND r.available AND i.suspended_at IS NULL AND i.owner_disconnected_at IS NULL
		ORDER BY COALESCE(p.favorite, false) DESC, p.last_used_at DESC NULLS LAST, r.full_name`, ownerID)
	if err != nil {
		return nil, mapError("list repository views", err)
	}
	defer rows.Close()
	values := make([]RepositoryView, 0)
	for rows.Next() {
		var value RepositoryView
		if err := rows.Scan(
			&value.Repository.ID, &value.Repository.InstallationID, &value.Repository.FullName,
			&value.Repository.DefaultBranch, &value.Repository.Private, &value.Repository.Organization,
			&value.Repository.Permission, &value.Repository.UpdatedAt, &value.InstallationAccount,
			&value.Favorite, &value.LastUsedAt,
		); err != nil {
			return nil, mapError("scan repository view", err)
		}
		values = append(values, value)
	}
	return values, mapError("iterate repository views", rows.Err())
}

func (s *RepositoryStore) ListGitHubInstallations(ctx context.Context, ownerID string) ([]GitHubInstallationConnection, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT installation_id, account_login, account_type, repository_selection, updated_at
		FROM github_installations
		WHERE owner_id=$1 AND suspended_at IS NULL AND owner_disconnected_at IS NULL
		ORDER BY account_login, installation_id`, ownerID)
	if err != nil {
		return nil, mapError("list GitHub connections", err)
	}
	defer rows.Close()
	connections := make([]GitHubInstallationConnection, 0)
	for rows.Next() {
		var value GitHubInstallationConnection
		if err := rows.Scan(&value.InstallationID, &value.AccountLogin, &value.AccountType, &value.RepositorySelection, &value.UpdatedAt); err != nil {
			return nil, mapError("scan GitHub connection", err)
		}
		connections = append(connections, value)
	}
	return connections, mapError("iterate GitHub connections", rows.Err())
}

func (s *RepositoryStore) GitHubInstallationActive(ctx context.Context, ownerID string, installationID int64) (bool, error) {
	if ownerID == "" || installationID <= 0 {
		return false, fmt.Errorf("GitHub connection identity: %w", core.ErrInvalid)
	}
	var active bool
	err := s.pool.QueryRow(ctx, `
		SELECT suspended_at IS NULL AND owner_disconnected_at IS NULL FROM github_installations
		WHERE owner_id=$1 AND installation_id=$2`, ownerID, installationID).Scan(&active)
	if err != nil {
		mapped := mapError("find GitHub connection", err)
		if errors.Is(mapped, core.ErrNotFound) {
			return false, nil
		}
		return false, mapped
	}
	return active, nil
}

// GitHubInstallationProviderActive ignores the local owner disconnect. It is
// used only by the explicit owner reconnect flow while that flow holds the
// exclusive synchronization lease and local authority remains disabled.
func (s *RepositoryStore) GitHubInstallationProviderActive(ctx context.Context, ownerID string, installationID int64) (bool, error) {
	if ownerID == "" || installationID <= 0 {
		return false, fmt.Errorf("GitHub provider connection identity: %w", core.ErrInvalid)
	}
	var active bool
	err := s.pool.QueryRow(ctx, `
		SELECT suspended_at IS NULL FROM github_installations
		WHERE owner_id=$1 AND installation_id=$2`, ownerID, installationID).Scan(&active)
	if err != nil {
		mapped := mapError("find GitHub provider connection", err)
		if errors.Is(mapped, core.ErrNotFound) {
			return false, nil
		}
		return false, mapped
	}
	return active, nil
}

// WithGitHubInstallationLease linearizes one installation-token mint and its
// complete use against owner disconnects across every control-plane process.
// The session-level advisory lease is held on a dedicated PostgreSQL
// connection, so provider and workspace calls remain outside a database
// transaction. A crashed process releases the lease when its connection dies.
func (s *RepositoryStore) WithGitHubInstallationLease(ctx context.Context, ownerID string, installationID int64, operation func(context.Context) error) (resultErr error) {
	if ctx == nil || ownerID == "" || installationID <= 0 || operation == nil {
		return fmt.Errorf("GitHub installation lease: %w", core.ErrInvalid)
	}
	lease, err := s.acquireGitHubInstallationLock(ctx, ownerID, installationID, true)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := lease.close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
	}()

	var active bool
	err = lease.conn.QueryRow(ctx, `
		SELECT suspended_at IS NULL AND owner_disconnected_at IS NULL
		FROM github_installations
		WHERE owner_id=$1 AND installation_id=$2`, ownerID, installationID).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !active) {
		return fmt.Errorf("GitHub installation is disconnected: %w", core.ErrPrecondition)
	}
	if err != nil {
		return mapError("authorize GitHub installation lease", err)
	}
	scope := &githubInstallationAuthorityLeaseScope{ownerID: ownerID, installationID: installationID}
	scope.active.Store(true)
	defer scope.active.Store(false)
	return operation(context.WithValue(ctx, githubInstallationAuthorityLeaseContextKey{}, scope))
}

// WithGitHubInstallationSyncLease serializes one complete provider metadata
// and repository synchronization against token users and every authority
// transition. The callback must perform its active-state check directly; it
// must not acquire a nested shared lease for the same installation.
func (s *RepositoryStore) WithGitHubInstallationSyncLease(ctx context.Context, ownerID string, installationID int64, operation func(context.Context) error) (resultErr error) {
	if ctx == nil || ownerID == "" || installationID <= 0 || operation == nil {
		return fmt.Errorf("GitHub synchronization lease: %w", core.ErrInvalid)
	}
	lease, err := s.acquireGitHubInstallationLock(ctx, ownerID, installationID, false)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := lease.close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
	}()
	scope := &githubInstallationSyncLeaseScope{ownerID: ownerID, installationID: installationID}
	scope.active.Store(true)
	defer scope.active.Store(false)
	authorityScope := &githubInstallationAuthorityLeaseScope{ownerID: ownerID, installationID: installationID}
	authorityScope.active.Store(true)
	defer authorityScope.active.Store(false)
	leaseCtx := context.WithValue(ctx, githubInstallationSyncLeaseContextKey{}, scope)
	leaseCtx = context.WithValue(leaseCtx, githubInstallationAuthorityLeaseContextKey{}, authorityScope)
	return operation(leaseCtx)
}

type githubInstallationSyncLeaseContextKey struct{}

type githubInstallationAuthorityLeaseContextKey struct{}

type githubInstallationSyncLeaseScope struct {
	ownerID        string
	installationID int64
	active         atomic.Bool
}

type githubInstallationAuthorityLeaseScope struct {
	ownerID        string
	installationID int64
	active         atomic.Bool
}

func requireGitHubInstallationSyncLease(ctx context.Context, ownerID string, installationID int64) error {
	if ctx == nil {
		return fmt.Errorf("GitHub synchronization lease scope: %w", core.ErrPrecondition)
	}
	scope, ok := ctx.Value(githubInstallationSyncLeaseContextKey{}).(*githubInstallationSyncLeaseScope)
	if !ok || scope == nil || !scope.active.Load() || scope.ownerID != ownerID || scope.installationID != installationID {
		return fmt.Errorf("GitHub synchronization lease scope: %w", core.ErrPrecondition)
	}
	return nil
}

func requireGitHubInstallationAuthorityLease(ctx context.Context, ownerID string, installationID int64) error {
	if ctx == nil {
		return fmt.Errorf("GitHub installation authority lease scope: %w", core.ErrPrecondition)
	}
	scope, ok := ctx.Value(githubInstallationAuthorityLeaseContextKey{}).(*githubInstallationAuthorityLeaseScope)
	if !ok || scope == nil || !scope.active.Load() || scope.ownerID != ownerID || scope.installationID != installationID {
		return fmt.Errorf("GitHub installation authority lease scope: %w", core.ErrPrecondition)
	}
	return nil
}

// BeginGitHubInstallationTokenUse persists a conservative authority record
// before GitHub is asked to mint a token. The random nonce satisfies the
// legacy token_hash uniqueness column but is intentionally unrelated to the
// credential, so no token or token-derived value is persisted.
func (s *RepositoryStore) BeginGitHubInstallationTokenUse(ctx context.Context, value githubapp.TokenUseMetadata) error {
	if !githubTokenUseIDPattern.MatchString(value.ID) || value.OwnerID == "" || value.InstallationID <= 0 ||
		value.CreatedAt.IsZero() || !value.ExpiresAt.After(value.CreatedAt) || value.ExpiresAt.After(value.CreatedAt.Add(2*time.Hour)) {
		return fmt.Errorf("begin GitHub installation token use: %w", core.ErrInvalid)
	}
	if err := requireGitHubInstallationAuthorityLease(ctx, value.OwnerID, value.InstallationID); err != nil {
		return err
	}
	permissions := []byte(`{}`)
	if value.Permissions != nil {
		var err error
		permissions, err = json.Marshal(value.Permissions)
		if err != nil {
			return fmt.Errorf("encode GitHub token permissions: %w", core.ErrInvalid)
		}
	}
	repositories := []byte(`[]`)
	if value.RepositoryIDs != nil {
		var err error
		repositories, err = json.Marshal(value.RepositoryIDs)
		if err != nil {
			return fmt.Errorf("encode GitHub token repositories: %w", core.ErrInvalid)
		}
	}
	// Completed rows are metadata, not an audit log. Opportunistic removal keeps
	// the table bounded by currently active peak token concurrency.
	if _, err := s.pool.Exec(ctx, `
		DELETE FROM github_token_metadata
		WHERE owner_id=$1 AND installation_id=$2
		  AND (revoked_at IS NOT NULL OR expires_at <= clock_timestamp())`, value.OwnerID, value.InstallationID); err != nil {
		return mapError("prune GitHub installation token uses", err)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO github_token_metadata
		    (id, owner_id, installation_id, token_hash, permissions, repository_ids, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8)`,
		value.ID, value.OwnerID, value.InstallationID, value.Nonce[:], permissions, repositories, value.CreatedAt, value.ExpiresAt)
	return mapError("begin GitHub installation token use", err)
}

func (s *RepositoryStore) SetGitHubInstallationTokenUseExpiry(ctx context.Context, ownerID string, installationID int64, useID string, expiresAt time.Time) error {
	if ownerID == "" || installationID <= 0 || !githubTokenUseIDPattern.MatchString(useID) || expiresAt.IsZero() {
		return fmt.Errorf("set GitHub installation token expiry: %w", core.ErrInvalid)
	}
	if err := requireGitHubInstallationAuthorityLease(ctx, ownerID, installationID); err != nil {
		return err
	}
	var found string
	err := s.pool.QueryRow(ctx, `
		UPDATE github_token_metadata SET expires_at=$4
		WHERE owner_id=$1 AND installation_id=$2 AND id=$3
		  AND revoked_at IS NULL AND $4 > created_at
		  AND $4 <= created_at + interval '2 hours'
		RETURNING id`, ownerID, installationID, useID, expiresAt).Scan(&found)
	return mapError("set GitHub installation token expiry", err)
}

func (s *RepositoryStore) RevokeGitHubInstallationTokenUse(ctx context.Context, ownerID string, installationID int64, useID string, at time.Time) error {
	if ownerID == "" || installationID <= 0 || !githubTokenUseIDPattern.MatchString(useID) || at.IsZero() {
		return fmt.Errorf("revoke GitHub installation token use: %w", core.ErrInvalid)
	}
	if err := requireGitHubInstallationAuthorityLease(ctx, ownerID, installationID); err != nil {
		return err
	}
	var found string
	err := s.pool.QueryRow(ctx, `
		UPDATE github_token_metadata
		SET revoked_at=COALESCE(revoked_at, GREATEST(created_at, $4))
		WHERE owner_id=$1 AND installation_id=$2 AND id=$3
		RETURNING id`, ownerID, installationID, useID, at).Scan(&found)
	return mapError("revoke GitHub installation token use", err)
}

func outstandingGitHubTokenUse(ctx context.Context, querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, ownerID string, installationID int64) (bool, error) {
	var pending bool
	err := querier.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM github_token_metadata
			WHERE owner_id=$1 AND installation_id=$2
			  AND revoked_at IS NULL AND expires_at > clock_timestamp()
		)`, ownerID, installationID).Scan(&pending)
	return pending, mapError("check outstanding GitHub installation token uses", err)
}

type githubInstallationLock struct {
	conn        *pgx.Conn
	releaseSlot func()
}

func (s *RepositoryStore) acquireGitHubInstallationLock(ctx context.Context, ownerID string, installationID int64, shared bool) (*githubInstallationLock, error) {
	slots := s.githubExclusiveLeaseSlots
	if shared {
		slots = s.githubSharedLeaseSlots
	}
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	releaseSlot := func() { <-slots }
	config := s.pool.Config().ConnConfig.Copy()
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		releaseSlot()
		return nil, mapError("acquire GitHub installation lease connection", err)
	}
	key := advisoryLockKey("github-installation", ownerID, fmt.Sprintf("%d", installationID))
	query := `SELECT pg_advisory_lock(hashtextextended($1, 0))`
	if shared {
		query = `SELECT pg_advisory_lock_shared(hashtextextended($1, 0))`
	}
	if _, err := conn.Exec(ctx, query, key); err != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = conn.Close(closeCtx)
		cancel()
		releaseSlot()
		return nil, mapError("acquire GitHub installation lease", err)
	}
	return &githubInstallationLock{conn: conn, releaseSlot: releaseSlot}, nil
}

func (l *githubInstallationLock) close() error {
	if l == nil || l.conn == nil {
		return nil
	}
	conn := l.conn
	l.conn = nil
	releaseSlot := l.releaseSlot
	l.releaseSlot = nil
	if releaseSlot != nil {
		defer releaseSlot()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Closing the dedicated session is the authoritative unlock. It prevents a
	// failed explicit-unlock query from ever returning a locked session to the
	// ordinary query pool.
	return mapError("release GitHub installation lease", conn.Close(ctx))
}

// DisconnectGitHubInstallation revokes the control plane's local authority to
// mint new installation tokens. It intentionally does not uninstall or mutate
// the owner's external GitHub App installation.
func (s *RepositoryStore) DisconnectGitHubInstallation(ctx context.Context, ownerID string, installationID int64, at time.Time) (resultErr error) {
	if ownerID == "" || installationID <= 0 || at.IsZero() {
		return fmt.Errorf("GitHub disconnect identity: %w", core.ErrInvalid)
	}
	// The exclusive lease first drains every pre-existing token operation and
	// blocks new ones. Committing the durable disconnect while it is held makes
	// the successful return a strict no-later-mint-or-use boundary.
	lease, err := s.acquireGitHubInstallationLock(ctx, ownerID, installationID, false)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := lease.close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
	}()
	tx, err := lease.conn.Begin(ctx)
	if err != nil {
		return mapError("begin GitHub disconnect", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var found int64
	if err := tx.QueryRow(ctx, `
		UPDATE github_installations
		SET owner_disconnected_at=COALESCE(owner_disconnected_at, $3), updated_at=GREATEST(updated_at, $3)
		WHERE owner_id=$1 AND installation_id=$2
		RETURNING installation_id`, ownerID, installationID, at).Scan(&found); err != nil {
		return mapError("disconnect GitHub installation", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE repositories SET available=false
		WHERE owner_id=$1 AND installation_id=$2`, ownerID, installationID); err != nil {
		return mapError("disconnect GitHub repositories", err)
	}
	pending, err := outstandingGitHubTokenUse(ctx, tx, ownerID, installationID)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit GitHub disconnect", err)
	}
	if pending {
		return fmt.Errorf("GitHub disconnect awaits installation token expiry: %w", core.ErrConflict)
	}
	return nil
}

// BeginGitHubInstallationReconnect disables local authority before any
// provider call. It must run inside WithGitHubInstallationSyncLease. Missing
// rows are allowed because the subsequent metadata upsert inserts them already
// disconnected.
func (s *RepositoryStore) BeginGitHubInstallationReconnect(ctx context.Context, ownerID string, installationID int64, at time.Time) error {
	if ownerID == "" || installationID <= 0 || at.IsZero() {
		return fmt.Errorf("begin GitHub reconnect identity: %w", core.ErrInvalid)
	}
	if err := requireGitHubInstallationSyncLease(ctx, ownerID, installationID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin GitHub reconnect preparation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `
		UPDATE github_installations
		SET owner_disconnected_at=COALESCE(owner_disconnected_at, GREATEST(created_at, $3)),
		    updated_at=GREATEST(updated_at, $3)
		WHERE owner_id=$1 AND installation_id=$2`, ownerID, installationID, at); err != nil {
		return mapError("disable GitHub installation for reconnect", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE repositories SET available=false
		WHERE owner_id=$1 AND installation_id=$2`, ownerID, installationID); err != nil {
		return mapError("disable GitHub repositories for reconnect", err)
	}
	return mapError("commit GitHub reconnect preparation", tx.Commit(ctx))
}

// CompleteGitHubInstallationReconnect is the sole owner-disconnect clear. The
// caller must hold WithGitHubInstallationSyncLease and invoke it only after
// fresh provider validation and every repository synchronization write has
// succeeded.
func (s *RepositoryStore) CompleteGitHubInstallationReconnect(ctx context.Context, ownerID string, installationID int64, at time.Time) error {
	if ownerID == "" || installationID <= 0 || at.IsZero() {
		return fmt.Errorf("complete GitHub reconnect identity: %w", core.ErrInvalid)
	}
	if err := requireGitHubInstallationSyncLease(ctx, ownerID, installationID); err != nil {
		return err
	}
	pending, err := outstandingGitHubTokenUse(ctx, s.pool, ownerID, installationID)
	if err != nil {
		return err
	}
	if pending {
		return fmt.Errorf("complete GitHub installation reconnect awaits old token expiry: %w", core.ErrConflict)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE github_installations
		SET owner_disconnected_at=NULL, updated_at=GREATEST(updated_at, $3)
		WHERE owner_id=$1 AND installation_id=$2 AND suspended_at IS NULL`, ownerID, installationID, at)
	if err != nil {
		return mapError("complete GitHub installation reconnect", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("complete GitHub installation reconnect: %w", core.ErrPrecondition)
	}
	return nil
}

func (s *RepositoryStore) MarkInstallationRepositoriesUnavailable(ctx context.Context, ownerID string, installationID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE repositories SET available=false
		WHERE owner_id=$1 AND installation_id=$2`, ownerID, installationID)
	return mapError("mark GitHub repositories unavailable", err)
}

func (s *RepositoryStore) SuspendInstallation(ctx context.Context, ownerID string, installationID int64, at time.Time) (resultErr error) {
	if ownerID == "" || installationID <= 0 || at.IsZero() {
		return fmt.Errorf("GitHub suspension identity: %w", core.ErrInvalid)
	}
	// Provider suspension/deletion is a revocation boundary just like local
	// disconnect: drain token users before making repository availability false.
	lease, err := s.acquireGitHubInstallationLock(ctx, ownerID, installationID, false)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := lease.close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
	}()
	tx, err := lease.conn.Begin(ctx)
	if err != nil {
		return mapError("begin GitHub installation suspension", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var found int64
	if err := tx.QueryRow(ctx, `
		UPDATE github_installations SET suspended_at=$3, updated_at=GREATEST(updated_at,$3)
		WHERE owner_id=$1 AND installation_id=$2
		RETURNING installation_id`, ownerID, installationID, at).Scan(&found); err != nil {
		return mapError("suspend GitHub installation", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE repositories SET available=false
		WHERE owner_id=$1 AND installation_id=$2`, ownerID, installationID); err != nil {
		return mapError("suspend GitHub repositories", err)
	}
	pending, err := outstandingGitHubTokenUse(ctx, tx, ownerID, installationID)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit GitHub installation suspension", err)
	}
	if pending {
		return fmt.Errorf("GitHub suspension awaits installation token expiry: %w", core.ErrConflict)
	}
	return nil
}

func (s *RepositoryStore) MarkUsed(ctx context.Context, ownerID, repositoryID string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO repository_preferences (owner_id, repository_id, favorite, last_used_at, updated_at)
		VALUES ($1,$2,false,$3,$3)
		ON CONFLICT (owner_id, repository_id) DO UPDATE SET
		    last_used_at=EXCLUDED.last_used_at, updated_at=EXCLUDED.updated_at`,
		ownerID, repositoryID, at)
	return mapError("mark repository used", err)
}
