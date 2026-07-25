package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/passkeys"
	"github.com/jackc/pgx/v5"
)

// PasskeyRecoverySummary contains counts only. No credential, token, user
// agent, network, or passkey material is included in operator output or audit.
type PasskeyRecoverySummary struct {
	PasskeysRevoked              int64
	DevicesRevoked               int64
	SessionTokensRevoked         int64
	SessionFamiliesRevoked       int64
	NotificationEndpointsRevoked int64
	PreviewTokensRevoked         int64
}

// ResetPasskeyEnrollment performs the total-loss break-glass mutation in one
// serializable transaction. The caller must print the corresponding plaintext
// token only after this function commits successfully.
func (s *BootstrapStore) ResetPasskeyEnrollment(ctx context.Context, record passkeys.BootstrapRecord) (PasskeyRecoverySummary, error) {
	if record.ID == "" || record.RecoveryOwnerID == "" || record.TokenHash == ([32]byte{}) || record.CreatedAt.IsZero() ||
		!record.ExpiresAt.After(record.CreatedAt) || record.ExpiresAt.Sub(record.CreatedAt) > time.Hour {
		return PasskeyRecoverySummary{}, fmt.Errorf("passkey recovery: %w", core.ErrInvalid)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return PasskeyRecoverySummary{}, mapError("begin passkey recovery", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ownerCreationLock); err != nil {
		return PasskeyRecoverySummary{}, mapError("lock passkey recovery", err)
	}
	var ownerID string
	err = tx.QueryRow(ctx, `
		SELECT id FROM users WHERE id=$1 AND disabled_at IS NULL FOR UPDATE`,
		record.RecoveryOwnerID).Scan(&ownerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return PasskeyRecoverySummary{}, fmt.Errorf("passkey recovery owner: %w", core.ErrNotFound)
	}
	if err != nil {
		return PasskeyRecoverySummary{}, mapError("lock passkey recovery owner", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE bootstrap_tokens SET disabled_at=$1
		WHERE consumed_at IS NULL AND disabled_at IS NULL`, record.CreatedAt); err != nil {
		return PasskeyRecoverySummary{}, mapError("disable bootstrap credentials for recovery", err)
	}

	var summary PasskeyRecoverySummary
	if summary.SessionTokensRevoked, err = affected(tx.Exec(ctx, `
		UPDATE session_tokens SET revoked_at=COALESCE(revoked_at,$2)
		WHERE owner_id=$1 AND revoked_at IS NULL`, ownerID, record.CreatedAt)); err != nil {
		return PasskeyRecoverySummary{}, mapError("revoke session tokens for recovery", err)
	}
	if summary.SessionFamiliesRevoked, err = affected(tx.Exec(ctx, `
		UPDATE session_refresh_families SET revoked_at=COALESCE(revoked_at,$2)
		WHERE owner_id=$1 AND revoked_at IS NULL`, ownerID, record.CreatedAt)); err != nil {
		return PasskeyRecoverySummary{}, mapError("revoke session families for recovery", err)
	}
	if summary.NotificationEndpointsRevoked, err = affected(tx.Exec(ctx, `
		UPDATE notification_endpoints
		SET enabled=false, revoked_at=COALESCE(revoked_at,$2), updated_at=GREATEST(updated_at,$2)
		WHERE owner_id=$1 AND revoked_at IS NULL`, ownerID, record.CreatedAt)); err != nil {
		return PasskeyRecoverySummary{}, mapError("revoke notifications for recovery", err)
	}
	if summary.PreviewTokensRevoked, err = affected(tx.Exec(ctx, `
		UPDATE preview_tokens SET revoked_at=COALESCE(revoked_at,$2)
		WHERE owner_id=$1 AND revoked_at IS NULL`, ownerID, record.CreatedAt)); err != nil {
		return PasskeyRecoverySummary{}, mapError("revoke preview tokens for recovery", err)
	}
	if summary.DevicesRevoked, err = affected(tx.Exec(ctx, `
		UPDATE devices SET revoked_at=COALESCE(revoked_at,$2)
		WHERE owner_id=$1 AND revoked_at IS NULL`, ownerID, record.CreatedAt)); err != nil {
		return PasskeyRecoverySummary{}, mapError("revoke devices for recovery", err)
	}
	if summary.PasskeysRevoked, err = affected(tx.Exec(ctx, `DELETE FROM passkeys WHERE owner_id=$1`, ownerID)); err != nil {
		return PasskeyRecoverySummary{}, mapError("revoke passkeys for recovery", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO bootstrap_tokens
		    (id, token_hash, recovery_owner_id, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5)`,
		record.ID, record.TokenHash[:], ownerID, record.CreatedAt, record.ExpiresAt); err != nil {
		return PasskeyRecoverySummary{}, mapError("insert passkey recovery credential", err)
	}
	details, err := json.Marshal(map[string]int64{
		"passkeys_revoked":               summary.PasskeysRevoked,
		"devices_revoked":                summary.DevicesRevoked,
		"session_tokens_revoked":         summary.SessionTokensRevoked,
		"session_families_revoked":       summary.SessionFamiliesRevoked,
		"notification_endpoints_revoked": summary.NotificationEndpointsRevoked,
		"preview_tokens_revoked":         summary.PreviewTokensRevoked,
	})
	if err != nil {
		return PasskeyRecoverySummary{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events
		    (owner_id, action, result, target_type, target_id, details, created_at)
		VALUES ($1,'administrator.passkey_recovery','success','owner',$1,$2,$3)`,
		ownerID, details, record.CreatedAt); err != nil {
		return PasskeyRecoverySummary{}, mapError("audit passkey recovery", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return PasskeyRecoverySummary{}, mapError("commit passkey recovery", err)
	}
	return summary, nil
}

type commandTag interface{ RowsAffected() int64 }

func affected(tag commandTag, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
