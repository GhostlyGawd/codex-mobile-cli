package githubapp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

const (
	installationTokenReservationTTL = 2 * time.Hour
	installationTokenUseTimeout     = 4*time.Minute + 30*time.Second
	installationTokenCleanupTimeout = 20 * time.Second
	maximumInstallationTokenTTL     = 75 * time.Minute
)

var installationTokenUseIDPattern = regexp.MustCompile(`^ght_[0-9a-f]{32}$`)

// TokenUseMetadata is durable authority metadata only. Nonce is fresh random
// uniqueness material required by the legacy token_hash column; it is not a
// token hash and is not derived from the GitHub credential.
type TokenUseMetadata struct {
	ID             string
	OwnerID        string
	InstallationID int64
	Nonce          [32]byte
	Permissions    map[string]string
	RepositoryIDs  []int64
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

type TokenUseStore interface {
	BeginGitHubInstallationTokenUse(context.Context, TokenUseMetadata) error
	SetGitHubInstallationTokenUseExpiry(context.Context, string, int64, string, time.Time) error
	RevokeGitHubInstallationTokenUse(context.Context, string, int64, string, time.Time) error
}

type InstallationTokenService interface {
	InstallationToken(context.Context, int64, []int64, map[string]string) (InstallationToken, error)
	RevokeInstallationToken(context.Context, string) error
}

// tokenUseAmbiguity is implemented by an operation error when the local
// caller cannot prove that a detached remote token user has exited. The
// durable authority record must remain outstanding through SafeAfter even if
// GitHub accepts an explicit token revocation: an already-authorized Git HTTP
// request can still be completing remotely.
type tokenUseAmbiguity interface {
	GitHubTokenUseSafeAfter() time.Time
}

// UseInstallationToken reserves durable metadata before minting, exposes the
// token only to one bounded callback, and revokes it before returning. If the
// process crashes or revocation is ambiguous, the unrevoked metadata remains
// until GitHub's authoritative expiry and blocks a successful disconnect,
// suspension, or reconnect completion.
func UseInstallationToken(
	ctx context.Context,
	github InstallationTokenService,
	store TokenUseStore,
	ownerID string,
	installationID int64,
	repositoryIDs []int64,
	permissions map[string]string,
	operation func(context.Context, string) error,
) error {
	return useInstallationToken(ctx, github, store, ownerID, installationID, repositoryIDs, permissions, operation, rand.Reader, func() time.Time {
		return time.Now().UTC()
	})
}

func useInstallationToken(
	ctx context.Context,
	github InstallationTokenService,
	store TokenUseStore,
	ownerID string,
	installationID int64,
	repositoryIDs []int64,
	permissions map[string]string,
	operation func(context.Context, string) error,
	random io.Reader,
	now func() time.Time,
) (resultErr error) {
	if ctx == nil || github == nil || store == nil || ownerID == "" || installationID <= 0 || operation == nil || random == nil || now == nil {
		return errors.New("GitHub installation token use dependencies are invalid")
	}
	createdAt := now().UTC()
	if createdAt.IsZero() {
		return errors.New("GitHub installation token use clock is invalid")
	}
	var idBytes [16]byte
	var nonce [32]byte
	if _, err := io.ReadFull(random, idBytes[:]); err != nil {
		return errors.New("generate GitHub installation token use identity")
	}
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		clear(idBytes[:])
		return errors.New("generate GitHub installation token use nonce")
	}
	defer clear(idBytes[:])
	defer clear(nonce[:])
	useID := "ght_" + hex.EncodeToString(idBytes[:])
	metadata := TokenUseMetadata{
		ID: useID, OwnerID: ownerID, InstallationID: installationID, Nonce: nonce,
		Permissions: permissions, RepositoryIDs: append([]int64(nil), repositoryIDs...),
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(installationTokenReservationTTL),
	}
	if err := validateTokenUseMetadata(metadata); err != nil {
		return err
	}
	if err := store.BeginGitHubInstallationTokenUse(ctx, metadata); err != nil {
		return fmt.Errorf("reserve GitHub installation token use: %w", err)
	}

	useContext, stopUse := context.WithTimeout(ctx, installationTokenUseTimeout)
	defer stopUse()
	token, err := github.InstallationToken(useContext, installationID, repositoryIDs, permissions)
	if err != nil {
		cleanupContext, cancel := tokenCleanupContext(ctx)
		cleanupErr := store.RevokeGitHubInstallationTokenUse(cleanupContext, ownerID, installationID, useID, now().UTC())
		cancel()
		return errors.Join(err, cleanupErr)
	}
	value := token.Token
	token.Token = ""
	if value == "" {
		cleanupContext, cancel := tokenCleanupContext(ctx)
		cleanupErr := store.RevokeGitHubInstallationTokenUse(cleanupContext, ownerID, installationID, useID, now().UTC())
		cancel()
		return errors.Join(errors.New("GitHub returned an empty installation token"), cleanupErr)
	}

	var preserveAuthorityUntil time.Time
	// Cleanup is deliberately detached from caller cancellation while retaining
	// the active advisory-lease scope in context values. It always completes
	// before the lease callback returns.
	defer func() {
		cleanupContext, cancel := tokenCleanupContext(ctx)
		defer cancel()
		revokeErr := github.RevokeInstallationToken(cleanupContext, value)
		if revokeErr == nil && !preserveAuthorityUntil.After(now().UTC()) {
			revokeErr = store.RevokeGitHubInstallationTokenUse(cleanupContext, ownerID, installationID, useID, now().UTC())
		}
		value = ""
		if revokeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("revoke GitHub installation token: %w", revokeErr))
		}
	}()
	if !token.ExpiresAt.After(createdAt) || token.ExpiresAt.After(createdAt.Add(maximumInstallationTokenTTL)) {
		return errors.New("GitHub returned an invalid installation token lifetime")
	}

	metadataContext, cancelMetadata := tokenCleanupContext(ctx)
	err = store.SetGitHubInstallationTokenUseExpiry(metadataContext, ownerID, installationID, useID, token.ExpiresAt.UTC())
	cancelMetadata()
	if err != nil {
		return fmt.Errorf("record GitHub installation token expiry: %w", err)
	}
	operationErr := operation(useContext, value)
	if operationErr == nil {
		return nil
	}

	// A canceled local SSH process does not prove its remote helper (or an
	// already-authorized Git subprocess) has exited. Keep the authority record
	// live through the independently enforced remote deadline. A generic
	// cancellation conservatively uses the coordinator's own bounded deadline.
	safeAfter := time.Time{}
	var ambiguous tokenUseAmbiguity
	if errors.As(operationErr, &ambiguous) {
		safeAfter = ambiguous.GitHubTokenUseSafeAfter().UTC()
	} else if errors.Is(operationErr, context.Canceled) || errors.Is(operationErr, context.DeadlineExceeded) {
		safeAfter, _ = useContext.Deadline()
		safeAfter = safeAfter.UTC()
	}
	if safeAfter.After(token.ExpiresAt) {
		safeAfter = token.ExpiresAt.UTC()
	}
	if safeAfter.After(now().UTC()) {
		// The exact provider expiry is already durable. If tightening it to the
		// remote safe-after deadline fails, retain that conservative authority
		// record instead of marking the use revoked during deferred cleanup.
		preserveAuthorityUntil = token.ExpiresAt.UTC()
		metadataContext, cancelMetadata = tokenCleanupContext(ctx)
		err = store.SetGitHubInstallationTokenUseExpiry(metadataContext, ownerID, installationID, useID, safeAfter)
		cancelMetadata()
		if err != nil {
			return errors.Join(operationErr, fmt.Errorf("record ambiguous GitHub installation token use deadline: %w", err))
		}
		preserveAuthorityUntil = safeAfter
	}
	return operationErr
}

func tokenCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), installationTokenCleanupTimeout)
}

func validateTokenUseMetadata(value TokenUseMetadata) error {
	if !installationTokenUseIDPattern.MatchString(value.ID) || value.OwnerID == "" || value.InstallationID <= 0 ||
		value.CreatedAt.IsZero() || !value.ExpiresAt.After(value.CreatedAt) || value.ExpiresAt.After(value.CreatedAt.Add(installationTokenReservationTTL)) ||
		len(value.RepositoryIDs) > 500 || len(value.Permissions) > 100 {
		return errors.New("GitHub installation token metadata is invalid")
	}
	for _, id := range value.RepositoryIDs {
		if id <= 0 {
			return errors.New("GitHub installation token repository scope is invalid")
		}
	}
	for name, level := range value.Permissions {
		if name == "" || len(name) > 128 || (level != "read" && level != "write") {
			return errors.New("GitHub installation token permission scope is invalid")
		}
	}
	return nil
}
