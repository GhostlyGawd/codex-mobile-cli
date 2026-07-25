package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/config"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/passkeys"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/migrations"
)

func recoverPasskeys(ctx context.Context, cfg config.Config) error {
	startup, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := openDatabase(startup, cfg, "codex-mobile-passkey-recovery")
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := migrations.Apply(startup, pool); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	var serving bool
	if err := pool.QueryRow(startup, `
		SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database()
			  AND application_name='codex-mobile-control-plane'
			  AND pid <> pg_backend_pid()
		)`).Scan(&serving); err != nil {
		return fmt.Errorf("verify control plane is offline: %w", err)
	}
	if serving {
		return errors.New("stop every control-plane serve process before passkey recovery so no authenticated request can race revocation")
	}
	ownerID, err := singleOwnerID(startup, pool)
	if err != nil {
		return fmt.Errorf("resolve recovery owner: %w", err)
	}
	store, err := postgres.NewBootstrapStore(pool)
	if err != nil {
		return err
	}
	manager, err := passkeys.NewBootstrapManagerWithStore(cfg.SessionPepper, cfg.BootstrapTTL, store)
	if err != nil {
		return err
	}
	token, record, err := manager.NewRecoveryRecord(ownerID)
	if err != nil {
		return fmt.Errorf("generate recovery credential: %w", err)
	}
	summary, err := store.ResetPasskeyEnrollment(startup, record)
	if err != nil {
		return fmt.Errorf("reset passkey enrollment: %w", err)
	}
	// The transaction stores only the keyed hash. This is the one intended
	// plaintext disclosure, after every prior device/session is revoked.
	_, err = fmt.Fprintf(os.Stdout,
		"Recovery bootstrap token: %s\nExpires at: %s\nRevoked: %d passkeys, %d devices, %d session families, %d APNs endpoints, %d preview tokens.\n",
		token, record.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"), summary.PasskeysRevoked,
		summary.DevicesRevoked, summary.SessionFamiliesRevoked, summary.NotificationEndpointsRevoked,
		summary.PreviewTokensRevoked,
	)
	return err
}
