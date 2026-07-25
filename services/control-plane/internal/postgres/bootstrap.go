package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/passkeys"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BootstrapStore persists only keyed token hashes. Replace invalidates all
// previous credentials in the same serializable transaction in which it
// creates the new one, and Consume uses a single conditional update.
type BootstrapStore struct {
	pool *pgxpool.Pool
}

func NewBootstrapStore(pool *pgxpool.Pool) (*BootstrapStore, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL pool is required for bootstrap credentials")
	}
	return &BootstrapStore{pool: pool}, nil
}

func (s *BootstrapStore) Replace(ctx context.Context, record passkeys.BootstrapRecord) error {
	if record.ID == "" || record.RecoveryOwnerID != "" || record.TokenHash == ([32]byte{}) || record.CreatedAt.IsZero() ||
		!record.ExpiresAt.After(record.CreatedAt) || record.ExpiresAt.Sub(record.CreatedAt) > time.Hour {
		return fmt.Errorf("bootstrap record: %w", core.ErrInvalid)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return mapError("begin bootstrap replacement", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ownerCreationLock); err != nil {
		return mapError("lock bootstrap replacement", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE bootstrap_tokens
		SET disabled_at = $1
		WHERE consumed_at IS NULL AND disabled_at IS NULL`, record.CreatedAt); err != nil {
		return mapError("disable previous bootstrap credential", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO bootstrap_tokens (id, token_hash, recovery_owner_id, created_at, expires_at)
		VALUES ($1, $2, NULLIF($3,''), $4, $5)`,
		record.ID, record.TokenHash[:], record.RecoveryOwnerID, record.CreatedAt, record.ExpiresAt,
	); err != nil {
		return mapError("insert bootstrap credential", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit bootstrap replacement", err)
	}
	return nil
}

func (s *BootstrapStore) RecoveryOwner(ctx context.Context, hash [32]byte, now time.Time) (string, error) {
	var ownerID *string
	err := s.pool.QueryRow(ctx, `
		SELECT recovery_owner_id
		FROM bootstrap_tokens
		WHERE token_hash=$1 AND consumed_at IS NULL AND disabled_at IS NULL AND expires_at > $2`,
		hash[:], now).Scan(&ownerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", passkeys.ErrInvalidBootstrap
	}
	if err != nil {
		return "", mapError("load bootstrap binding", err)
	}
	if ownerID == nil {
		return "", nil
	}
	return *ownerID, nil
}

func (s *BootstrapStore) IsValid(ctx context.Context, hash [32]byte, now time.Time) (bool, error) {
	var valid bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM bootstrap_tokens
			WHERE token_hash = $1
			  AND consumed_at IS NULL
			  AND disabled_at IS NULL
			  AND expires_at > $2
		)`, hash[:], now).Scan(&valid)
	if err != nil {
		return false, mapError("validate bootstrap credential", err)
	}
	return valid, nil
}

func (s *BootstrapStore) Consume(ctx context.Context, hash [32]byte, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE bootstrap_tokens
		SET consumed_at = $2
		WHERE token_hash = $1
		  AND consumed_at IS NULL
		  AND disabled_at IS NULL
		  AND expires_at > $2`, hash[:], now)
	if err != nil {
		return mapError("consume bootstrap credential", err)
	}
	if tag.RowsAffected() != 1 {
		return passkeys.ErrInvalidBootstrap
	}
	return nil
}

func (s *BootstrapStore) Disable(ctx context.Context, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE bootstrap_tokens
		SET disabled_at = $1
		WHERE consumed_at IS NULL AND disabled_at IS NULL`, now)
	return mapError("disable bootstrap credentials", err)
}

func (s *BootstrapStore) Available(ctx context.Context, now time.Time) (bool, error) {
	var available bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM bootstrap_tokens
			WHERE consumed_at IS NULL AND disabled_at IS NULL AND expires_at > $1
		)`, now).Scan(&available)
	if err != nil {
		return false, mapError("check bootstrap availability", err)
	}
	return available, nil
}

var _ passkeys.BootstrapStore = (*BootstrapStore)(nil)
