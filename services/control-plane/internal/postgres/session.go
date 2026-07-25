package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionStore struct{ pool *pgxpool.Pool }

var _ session.Store = (*SessionStore)(nil)

func NewSessionStore(pool *pgxpool.Pool) (*SessionStore, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL pool is required")
	}
	return &SessionStore{pool: pool}, nil
}

func (s *SessionStore) CreatePair(ctx context.Context, access, refresh session.Record) error {
	if err := validateSessionPair(access, refresh); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin session pair", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var active bool
	if err := tx.QueryRow(ctx, `
		SELECT revoked_at IS NULL FROM devices
		WHERE owner_id = $1 AND id = $2
		FOR UPDATE`, refresh.OwnerID, refresh.DeviceID).Scan(&active); err != nil {
		return mapError("lock session device", err)
	}
	if !active {
		return fmt.Errorf("insert refresh family: %w", core.ErrUnauthorized)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET last_seen_at=GREATEST(last_seen_at,$3)
		WHERE owner_id=$1 AND id=$2 AND revoked_at IS NULL`,
		refresh.OwnerID, refresh.DeviceID, refresh.CreatedAt); err != nil {
		return mapError("touch session device", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO session_refresh_families
		    (id, owner_id, device_id, created_at, last_rotated_at, expires_at)
		VALUES ($1, $2, $3, $4, $4, $5)`,
		refresh.FamilyID, refresh.OwnerID, refresh.DeviceID, refresh.CreatedAt, refresh.ExpiresAt,
	); err != nil {
		return mapError("insert refresh family", err)
	}
	if err := insertSessionRecord(ctx, tx, access, ""); err != nil {
		return err
	}
	if err := insertSessionRecord(ctx, tx, refresh, ""); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit session pair", err)
	}
	return nil
}

func (s *SessionStore) Get(ctx context.Context, id string) (session.Record, error) {
	record, err := scanSessionRecord(s.pool.QueryRow(ctx, `
		SELECT id, family_id, owner_id, device_id, kind, token_hash,
		       created_at, expires_at, used_at, revoked_at
		FROM session_tokens WHERE id = $1`, id))
	if err != nil {
		return session.Record{}, mapError("find session credential", err)
	}
	return record, nil
}

func (s *SessionStore) ValidatePrincipal(ctx context.Context, principal session.Principal) error {
	if principal.OwnerID == "" || principal.DeviceID == "" || principal.FamilyID == "" {
		return fmt.Errorf("validate session principal: %w", core.ErrInvalid)
	}
	var active bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM session_refresh_families AS family
			JOIN devices AS device
			  ON device.owner_id = family.owner_id
			 AND device.id = family.device_id
			WHERE family.id = $1
			  AND family.owner_id = $2
			  AND family.device_id = $3
			  AND family.revoked_at IS NULL
			  AND device.revoked_at IS NULL
		)`, principal.FamilyID, principal.OwnerID, principal.DeviceID).Scan(&active); err != nil {
		return mapError("validate session principal", err)
	}
	if !active {
		return fmt.Errorf("validate session principal: %w", core.ErrUnauthorized)
	}
	return nil
}

func (s *SessionStore) Rotate(ctx context.Context, previousID string, previousHash [32]byte, now time.Time, access, refresh session.Record) error {
	if err := validateSessionPair(access, refresh); err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return mapError("begin session rotation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	previous, err := scanSessionRecord(tx.QueryRow(ctx, `
		SELECT id, family_id, owner_id, device_id, kind, token_hash,
		       created_at, expires_at, used_at, revoked_at
		FROM session_tokens WHERE id = $1 FOR UPDATE`, previousID))
	if err != nil {
		return mapError("lock refresh credential", err)
	}
	if previous.Kind != session.Refresh || previous.RevokedAt != nil || !now.Before(previous.ExpiresAt) || !hmac.Equal(previous.Hash[:], previousHash[:]) {
		return errors.New("invalid refresh credential")
	}
	if previous.UsedAt != nil {
		if err := revokeFamilyTx(ctx, tx, previous.FamilyID, now, true); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return mapError("commit refresh replay revocation", err)
		}
		return session.ErrReplay
	}
	if access.FamilyID != previous.FamilyID || access.OwnerID != previous.OwnerID || access.DeviceID != previous.DeviceID {
		return fmt.Errorf("session rotation identity: %w", core.ErrInvalid)
	}
	if _, err := tx.Exec(ctx, `UPDATE session_tokens SET used_at = $2 WHERE id = $1`, previousID, now); err != nil {
		return mapError("consume refresh credential", err)
	}
	if err := insertSessionRecord(ctx, tx, access, previousID); err != nil {
		return err
	}
	if err := insertSessionRecord(ctx, tx, refresh, previousID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE session_refresh_families
		SET last_rotated_at = $2, expires_at = $3
		WHERE id = $1 AND revoked_at IS NULL`,
		previous.FamilyID, now, refresh.ExpiresAt,
	)
	if err != nil {
		return mapError("advance refresh family", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("advance refresh family: %w", core.ErrUnauthorized)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit session rotation", err)
	}
	return nil
}

func (s *SessionStore) RevokeFamily(ctx context.Context, familyID string, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin family revocation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := revokeFamilyTx(ctx, tx, familyID, now, false); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit family revocation", err)
	}
	return nil
}

func (s *SessionStore) ListDevices(ctx context.Context, ownerID string) ([]session.Device, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("list devices: %w", core.ErrInvalid)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, owner_id, name, platform, created_at, last_seen_at
		FROM devices
		WHERE owner_id=$1 AND revoked_at IS NULL
		ORDER BY last_seen_at DESC, created_at DESC, id`, ownerID)
	if err != nil {
		return nil, mapError("list devices", err)
	}
	defer rows.Close()
	values := make([]session.Device, 0)
	for rows.Next() {
		var value session.Device
		if err := rows.Scan(&value.ID, &value.OwnerID, &value.Name, &value.Platform, &value.CreatedAt, &value.LastSeenAt); err != nil {
			return nil, mapError("scan device", err)
		}
		values = append(values, value)
	}
	return values, mapError("iterate devices", rows.Err())
}

func (s *SessionStore) RevokeDevice(ctx context.Context, ownerID, deviceID string, now time.Time) error {
	if ownerID == "" || deviceID == "" || now.IsZero() {
		return fmt.Errorf("revoke device: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin device revocation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT true FROM devices WHERE owner_id=$1 AND id=$2 FOR UPDATE`, ownerID, deviceID).Scan(&exists); err != nil {
		return mapError("find device for revocation", err)
	}
	if !exists {
		return fmt.Errorf("revoke device: %w", core.ErrNotFound)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices SET revoked_at = COALESCE(revoked_at, $2)
		WHERE owner_id=$3 AND id = $1`, deviceID, now, ownerID); err != nil {
		return mapError("revoke device", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE session_refresh_families SET revoked_at = COALESCE(revoked_at, $2)
		WHERE owner_id=$3 AND device_id = $1`, deviceID, now, ownerID); err != nil {
		return mapError("revoke device refresh families", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE session_tokens SET revoked_at = COALESCE(revoked_at, $2)
		WHERE owner_id=$3 AND device_id = $1`, deviceID, now, ownerID); err != nil {
		return mapError("revoke device credentials", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE notification_endpoints
		SET enabled=false, revoked_at=COALESCE(revoked_at,$3), updated_at=GREATEST(updated_at,$3)
		WHERE owner_id=$1 AND device_id=$2`, ownerID, deviceID, now); err != nil {
		return mapError("revoke device notification endpoints", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit device revocation", err)
	}
	return nil
}

type rowScanner interface{ Scan(...any) error }

func scanSessionRecord(row rowScanner) (session.Record, error) {
	var record session.Record
	var kind string
	var hash []byte
	if err := row.Scan(&record.ID, &record.FamilyID, &record.OwnerID, &record.DeviceID, &kind, &hash,
		&record.CreatedAt, &record.ExpiresAt, &record.UsedAt, &record.RevokedAt); err != nil {
		return session.Record{}, err
	}
	if len(hash) != len(record.Hash) {
		return session.Record{}, errors.New("invalid stored session hash")
	}
	copy(record.Hash[:], hash)
	record.Kind = session.Kind(kind)
	if record.Kind != session.Access && record.Kind != session.Refresh {
		return session.Record{}, errors.New("invalid stored session kind")
	}
	return record, nil
}

func insertSessionRecord(ctx context.Context, tx pgx.Tx, record session.Record, parentID string) error {
	var parent any
	if parentID != "" {
		parent = parentID
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO session_tokens
		    (id, family_id, owner_id, device_id, kind, token_hash, parent_token_id,
		     created_at, expires_at, used_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		record.ID, record.FamilyID, record.OwnerID, record.DeviceID, string(record.Kind), record.Hash[:], parent,
		record.CreatedAt, record.ExpiresAt, record.UsedAt, record.RevokedAt,
	)
	return mapError("insert session credential", err)
}

func revokeFamilyTx(ctx context.Context, tx pgx.Tx, familyID string, now time.Time, replay bool) error {
	if replay {
		if _, err := tx.Exec(ctx, `
			UPDATE session_refresh_families
			SET revoked_at = COALESCE(revoked_at, $2), replay_detected_at = COALESCE(replay_detected_at, $2)
			WHERE id = $1`, familyID, now); err != nil {
			return mapError("mark refresh replay", err)
		}
	} else if _, err := tx.Exec(ctx, `
		UPDATE session_refresh_families SET revoked_at = COALESCE(revoked_at, $2)
		WHERE id = $1`, familyID, now); err != nil {
		return mapError("revoke refresh family", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE session_tokens SET revoked_at = COALESCE(revoked_at, $2)
		WHERE family_id = $1`, familyID, now); err != nil {
		return mapError("revoke family credentials", err)
	}
	return nil
}

func validateSessionPair(access, refresh session.Record) error {
	if access.Kind != session.Access || refresh.Kind != session.Refresh ||
		access.ID == "" || refresh.ID == "" || access.ID == refresh.ID ||
		access.FamilyID == "" || access.FamilyID != refresh.FamilyID ||
		access.OwnerID == "" || access.OwnerID != refresh.OwnerID ||
		access.DeviceID == "" || access.DeviceID != refresh.DeviceID ||
		access.CreatedAt.IsZero() || refresh.CreatedAt.IsZero() ||
		!access.ExpiresAt.After(access.CreatedAt) || !refresh.ExpiresAt.After(refresh.CreatedAt) {
		return fmt.Errorf("session pair: %w", core.ErrInvalid)
	}
	return nil
}
