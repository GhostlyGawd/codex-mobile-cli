package githubsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
)

type GitHub interface {
	Installation(context.Context, int64) (githubapp.Installation, error)
	InstallationToken(context.Context, int64, []int64, map[string]string) (githubapp.InstallationToken, error)
	RevokeInstallationToken(context.Context, string) error
	ListRepositories(context.Context, string, int64) ([]core.Repository, error)
}

type Store interface {
	githubapp.TokenUseStore
	UpsertInstallation(context.Context, postgres.GitHubInstallation) error
	UpsertInstallationFromProviderUnsuspend(context.Context, postgres.GitHubInstallation) error
	UpsertInstallationForOwnerReconnect(context.Context, postgres.GitHubInstallation, time.Time) error
	WithGitHubInstallationSyncLease(context.Context, string, int64, func(context.Context) error) error
	GitHubInstallationActive(context.Context, string, int64) (bool, error)
	GitHubInstallationProviderActive(context.Context, string, int64) (bool, error)
	BeginGitHubInstallationReconnect(context.Context, string, int64, time.Time) error
	CompleteGitHubInstallationReconnect(context.Context, string, int64, time.Time) error
	MarkInstallationRepositoriesUnavailable(context.Context, string, int64) error
	Upsert(context.Context, string, core.Repository) error
	SuspendInstallation(context.Context, string, int64, time.Time) error
}

type syncMode uint8

const (
	syncExistingAuthority syncMode = iota
	syncProviderUnsuspend
	syncOwnerReconnect
)

type Syncer struct {
	github GitHub
	store  Store
	now    func() time.Time
}

func New(github GitHub, store Store) (*Syncer, error) {
	if github == nil || store == nil {
		return nil, errors.New("GitHub client and repository store are required")
	}
	return &Syncer{github: github, store: store, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Syncer) Sync(ctx context.Context, ownerID string, installationID int64) (int, error) {
	return s.sync(ctx, ownerID, installationID, syncExistingAuthority)
}

// SyncProviderUnsuspend handles a signed provider unsuspend event. Fresh
// provider state is validated and any suspension clear is applied inside the
// same exclusive lease that covers token minting and repository writes.
func (s *Syncer) SyncProviderUnsuspend(ctx context.Context, ownerID string, installationID int64) (int, error) {
	return s.sync(ctx, ownerID, installationID, syncProviderUnsuspend)
}

// SyncOwnerReconnect is the explicit owner-authorized reconnect path. It
// disables local authority first and clears the owner disconnect only after
// fresh provider validation and the complete repository sync succeed under a
// single exclusive lease.
func (s *Syncer) SyncOwnerReconnect(ctx context.Context, ownerID string, installationID int64) (int, error) {
	return s.sync(ctx, ownerID, installationID, syncOwnerReconnect)
}

func (s *Syncer) sync(ctx context.Context, ownerID string, installationID int64, mode syncMode) (int, error) {
	if ownerID == "" || installationID <= 0 {
		return 0, fmt.Errorf("GitHub sync identity: %w", core.ErrInvalid)
	}
	count := 0
	err := s.store.WithGitHubInstallationSyncLease(ctx, ownerID, installationID, func(leaseCtx context.Context) error {
		var reconnectStartedAt time.Time
		if mode == syncOwnerReconnect {
			reconnectStartedAt = s.now()
			if beginErr := s.store.BeginGitHubInstallationReconnect(leaseCtx, ownerID, installationID, reconnectStartedAt); beginErr != nil {
				return beginErr
			}
		}
		installation, installationErr := s.github.Installation(leaseCtx, installationID)
		if installationErr != nil {
			return installationErr
		}
		if installation.ID != installationID {
			return fmt.Errorf("GitHub installation identity mismatch: %w", core.ErrInvalid)
		}
		permissions, marshalErr := json.Marshal(installation.Permissions)
		if marshalErr != nil {
			return marshalErr
		}
		createdAt := installation.CreatedAt
		if createdAt.IsZero() {
			createdAt = s.now()
		}
		updatedAt := installation.UpdatedAt
		if updatedAt.Before(createdAt) {
			updatedAt = createdAt
		}
		metadata := postgres.GitHubInstallation{
			OwnerID: ownerID, InstallationID: installation.ID, AccountID: installation.AccountID,
			AccountLogin: installation.AccountLogin, AccountType: installation.AccountType,
			RepositorySelection: installation.RepositorySelection, Permissions: permissions,
			CreatedAt: createdAt, UpdatedAt: updatedAt, SuspendedAt: installation.SuspendedAt,
		}
		upsert := s.store.UpsertInstallation
		if mode == syncProviderUnsuspend && installation.SuspendedAt == nil {
			upsert = s.store.UpsertInstallationFromProviderUnsuspend
		}
		var upsertErr error
		if mode == syncOwnerReconnect {
			upsertErr = s.store.UpsertInstallationForOwnerReconnect(leaseCtx, metadata, reconnectStartedAt)
		} else {
			upsertErr = upsert(leaseCtx, metadata)
		}
		if upsertErr != nil {
			return upsertErr
		}
		activeCheck := s.store.GitHubInstallationActive
		if mode == syncOwnerReconnect {
			activeCheck = s.store.GitHubInstallationProviderActive
		}
		active, activeErr := activeCheck(leaseCtx, ownerID, installationID)
		if activeErr != nil {
			return activeErr
		}
		if !active {
			return fmt.Errorf("GitHub installation is inactive: %w", core.ErrPrecondition)
		}
		var repositories []core.Repository
		tokenErr := githubapp.UseInstallationToken(
			leaseCtx, s.github, s.store, ownerID, installationID, nil,
			map[string]string{"contents": "write", "pull_requests": "write"},
			func(tokenCtx context.Context, token string) error {
				var listErr error
				repositories, listErr = s.github.ListRepositories(tokenCtx, token, installationID)
				return listErr
			},
		)
		if tokenErr != nil {
			return fmt.Errorf("use repository-sync installation token: %w", tokenErr)
		}
		if unavailableErr := s.store.MarkInstallationRepositoriesUnavailable(leaseCtx, ownerID, installationID); unavailableErr != nil {
			return unavailableErr
		}
		for _, repository := range repositories {
			if upsertErr := s.store.Upsert(leaseCtx, ownerID, repository); upsertErr != nil {
				return upsertErr
			}
		}
		if mode == syncOwnerReconnect {
			if completeErr := s.store.CompleteGitHubInstallationReconnect(leaseCtx, ownerID, installationID, s.now()); completeErr != nil {
				return completeErr
			}
		}
		count = len(repositories)
		return nil
	})
	if errors.Is(err, core.ErrPrecondition) && mode != syncOwnerReconnect {
		// Disconnect and suspension own the authoritative unavailable write.
		// Metadata refresh preserves those local revocations, so a stale provider
		// response cannot reactivate the installation or mint a token.
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Syncer) Suspend(ctx context.Context, ownerID string, installationID int64) error {
	if ownerID == "" || installationID <= 0 {
		return fmt.Errorf("GitHub suspension identity: %w", core.ErrInvalid)
	}
	return s.store.SuspendInstallation(ctx, ownerID, installationID, s.now())
}
