package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/passkeys"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const ownerCreationLock int64 = 0x434d4f574e4552

type credentialCipher interface {
	Encrypt([]byte, []byte) (vault.Envelope, error)
	Decrypt(vault.Envelope, []byte) ([]byte, error)
}

// PasskeyStore persists WebAuthn lookup keys in the clear and encrypts the
// credential record itself with the application's envelope-encryption vault.
type PasskeyStore struct {
	pool   *pgxpool.Pool
	cipher credentialCipher
}

var _ passkeys.Store = (*PasskeyStore)(nil)

func NewPasskeyStore(pool *pgxpool.Pool, cipher credentialCipher) (*PasskeyStore, error) {
	if pool == nil || cipher == nil {
		return nil, errors.New("PostgreSQL pool and passkey credential cipher are required")
	}
	return &PasskeyStore{pool: pool, cipher: cipher}, nil
}

func (s *PasskeyStore) HasOwner(ctx context.Context) (bool, error) {
	var exists bool
	// A disabled owner must not silently re-enable first-owner bootstrap. Owner
	// recovery is an explicit administrative operation, not a new enrollment.
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&exists); err != nil {
		return false, mapError("check owner", err)
	}
	return exists, nil
}

func (s *PasskeyStore) CreateOwnerWithCredential(ctx context.Context, owner passkeys.Owner, record passkeys.CredentialRecord) error {
	if err := validateOwnerCredential(owner, record); err != nil {
		return err
	}
	ciphertext, err := s.encryptCredential(record)
	if err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return mapError("begin owner creation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ownerCreationLock); err != nil {
		return mapError("lock owner creation", err)
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&exists); err != nil {
		return mapError("check owner conflict", err)
	}
	if exists {
		return fmt.Errorf("create owner: %w", core.ErrConflict)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, webauthn_handle, username, display_name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5)`,
		owner.ID, owner.Handle, owner.Name, owner.DisplayName, record.CreatedAt,
	); err != nil {
		return mapError("insert owner", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (id, owner_id, name, platform, instance_hash, created_at, last_seen_at)
		VALUES ($1, $2, $3, 'ios', $4, $5, $5)`,
		record.DeviceID, owner.ID, record.DeviceName, record.DeviceInstanceHash[:], record.CreatedAt,
	); err != nil {
		return mapError("insert passkey device", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO passkeys
		    (rp_id, credential_id, owner_id, device_id, credential_ciphertext, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		record.RPID, record.Credential.ID, record.OwnerID, record.DeviceID, ciphertext, record.CreatedAt, record.LastUsedAt,
	); err != nil {
		return mapError("insert passkey", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit owner creation", err)
	}
	return nil
}

func (s *PasskeyStore) OwnerForRecovery(ctx context.Context, rpid, ownerID string) (passkeys.Owner, error) {
	if rpid == "" || ownerID == "" {
		return passkeys.Owner{}, fmt.Errorf("passkey recovery owner: %w", core.ErrInvalid)
	}
	var owner passkeys.Owner
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.webauthn_handle, u.username, u.display_name
		FROM users u
		WHERE u.id=$1 AND u.disabled_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM passkeys p WHERE p.owner_id=u.id)`, ownerID,
	).Scan(&owner.ID, &owner.Handle, &owner.Name, &owner.DisplayName)
	if err != nil {
		return passkeys.Owner{}, mapError("find passkey recovery owner", err)
	}
	if len(owner.Handle) != 64 {
		return passkeys.Owner{}, errors.New("stored passkey recovery owner is invalid")
	}
	return owner, nil
}

func (s *PasskeyStore) CreateCredentialForRecoveredOwner(ctx context.Context, owner passkeys.Owner, record passkeys.CredentialRecord, proof passkeys.RecoveryProof) error {
	if err := validateOwnerCredential(owner, record); err != nil || proof.TokenHash == ([32]byte{}) || proof.At.IsZero() {
		if err == nil {
			err = fmt.Errorf("passkey recovery proof: %w", core.ErrInvalid)
		}
		return err
	}
	ciphertext, err := s.encryptCredential(record)
	if err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return mapError("begin recovered credential creation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ownerCreationLock); err != nil {
		return mapError("lock recovered credential creation", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE bootstrap_tokens SET consumed_at=$3
		WHERE token_hash=$1 AND recovery_owner_id=$2
		  AND consumed_at IS NULL AND disabled_at IS NULL AND expires_at>$3`,
		proof.TokenHash[:], owner.ID, proof.At)
	if err != nil {
		return mapError("consume passkey recovery credential", err)
	}
	if tag.RowsAffected() != 1 {
		return passkeys.ErrInvalidBootstrap
	}
	var storedHandle []byte
	err = tx.QueryRow(ctx, `
		SELECT webauthn_handle FROM users
		WHERE id=$1 AND disabled_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM passkeys WHERE owner_id=$1)
		FOR UPDATE`, owner.ID).Scan(&storedHandle)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("recover passkey credential: %w", core.ErrConflict)
	}
	if err != nil {
		return mapError("lock passkey recovery owner", err)
	}
	if !equalBytes(storedHandle, owner.Handle) {
		return errors.New("passkey recovery owner identity mismatch")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (id, owner_id, name, platform, instance_hash, created_at, last_seen_at)
		VALUES ($1, $2, $3, 'ios', $4, $5, $5)`,
		record.DeviceID, owner.ID, record.DeviceName, record.DeviceInstanceHash[:], record.CreatedAt,
	); err != nil {
		return mapError("insert recovered passkey device", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO passkeys
		    (rp_id, credential_id, owner_id, device_id, credential_ciphertext, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		record.RPID, record.Credential.ID, record.OwnerID, record.DeviceID, ciphertext, record.CreatedAt, record.LastUsedAt,
	); err != nil {
		return mapError("insert recovered passkey", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapError("commit recovered credential creation", err)
	}
	return nil
}

func (s *PasskeyStore) OwnerForAdditionalCredential(ctx context.Context, rpid, ownerID, deviceID string, instanceHash [32]byte) (passkeys.Owner, error) {
	if rpid == "" || ownerID == "" || deviceID == "" || instanceHash == ([32]byte{}) {
		return passkeys.Owner{}, fmt.Errorf("additional passkey owner: %w", core.ErrInvalid)
	}
	var owner passkeys.Owner
	var storedHash []byte
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.webauthn_handle, u.username, u.display_name, d.instance_hash
		FROM users u JOIN devices d ON d.owner_id=u.id
		WHERE u.id=$1 AND u.disabled_at IS NULL AND d.id=$2 AND d.revoked_at IS NULL`,
		ownerID, deviceID).Scan(&owner.ID, &owner.Handle, &owner.Name, &owner.DisplayName, &storedHash)
	if err != nil {
		return passkeys.Owner{}, mapError("find additional passkey owner", err)
	}
	if len(owner.Handle) != 64 || len(storedHash) != 32 || !equalBytes(storedHash, instanceHash[:]) {
		return passkeys.Owner{}, fmt.Errorf("additional passkey device: %w", core.ErrForbidden)
	}
	owner.Credentials, err = s.ownerCredentials(ctx, rpid, ownerID)
	if err != nil {
		return passkeys.Owner{}, err
	}
	if len(owner.Credentials) == 0 {
		return passkeys.Owner{}, fmt.Errorf("additional passkey owner: %w", core.ErrPrecondition)
	}
	return owner, nil
}

func (s *PasskeyStore) CreateAdditionalCredential(ctx context.Context, owner passkeys.Owner, record passkeys.CredentialRecord) error {
	if err := validateOwnerCredential(owner, record); err != nil || record.DeviceInstanceHash == ([32]byte{}) {
		if err == nil {
			err = fmt.Errorf("additional passkey device: %w", core.ErrInvalid)
		}
		return err
	}
	ciphertext, err := s.encryptCredential(record)
	if err != nil {
		return err
	}
	// Read committed takes a fresh snapshot after the advisory lock wait. The
	// lock is the serialization boundary for add/revoke, so a waiter must see
	// the preceding transaction's credential count before enforcing limits.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return mapError("begin additional passkey creation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ownerCreationLock); err != nil {
		return mapError("lock additional passkey creation", err)
	}
	var storedHandle, storedHash []byte
	err = tx.QueryRow(ctx, `
		SELECT u.webauthn_handle, d.instance_hash
		FROM users u JOIN devices d ON d.owner_id=u.id
		WHERE u.id=$1 AND u.disabled_at IS NULL AND d.id=$2 AND d.revoked_at IS NULL
		FOR UPDATE OF u, d`, owner.ID, record.DeviceID).Scan(&storedHandle, &storedHash)
	if err != nil {
		return mapError("lock additional passkey device", err)
	}
	if !equalBytes(storedHandle, owner.Handle) || !equalBytes(storedHash, record.DeviceInstanceHash[:]) {
		return fmt.Errorf("additional passkey identity: %w", core.ErrForbidden)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM passkeys WHERE owner_id=$1 AND rp_id=$2`, owner.ID, record.RPID).Scan(&count); err != nil {
		return mapError("count owner passkeys", err)
	}
	if count < 1 {
		return fmt.Errorf("additional passkey owner: %w", core.ErrPrecondition)
	}
	if count >= 20 {
		return fmt.Errorf("additional passkey limit: %w", core.ErrCapacity)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO passkeys
		    (rp_id, credential_id, owner_id, device_id, credential_ciphertext, created_at, last_used_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		record.RPID, record.Credential.ID, record.OwnerID, record.DeviceID, ciphertext, record.CreatedAt, record.LastUsedAt); err != nil {
		return mapError("insert additional passkey", err)
	}
	return mapError("commit additional passkey creation", tx.Commit(ctx))
}

func (s *PasskeyStore) ListCredentialMetadata(ctx context.Context, rpid, ownerID string) ([]passkeys.CredentialMetadata, error) {
	if rpid == "" || ownerID == "" {
		return nil, fmt.Errorf("list passkeys: %w", core.ErrInvalid)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT p.credential_id, p.device_id, d.name, p.created_at, p.last_used_at
		FROM passkeys p JOIN devices d ON d.owner_id=p.owner_id AND d.id=p.device_id
		JOIN users u ON u.id=p.owner_id
		WHERE p.rp_id=$1 AND p.owner_id=$2 AND u.disabled_at IS NULL
		ORDER BY p.created_at, p.credential_id
		LIMIT 21`, rpid, ownerID)
	if err != nil {
		return nil, mapError("list passkeys", err)
	}
	defer rows.Close()
	values := make([]passkeys.CredentialMetadata, 0)
	for rows.Next() {
		var value passkeys.CredentialMetadata
		if err := rows.Scan(&value.CredentialID, &value.DeviceID, &value.DeviceName, &value.CreatedAt, &value.LastUsedAt); err != nil {
			return nil, mapError("scan passkey metadata", err)
		}
		if len(value.CredentialID) < 1 || len(value.CredentialID) > 1024 || value.DeviceID == "" || value.DeviceName == "" || value.CreatedAt.IsZero() {
			return nil, errors.New("stored passkey metadata is invalid")
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate passkey metadata", err)
	}
	if len(values) > 20 {
		return nil, fmt.Errorf("list passkeys: %w", core.ErrCapacity)
	}
	return values, nil
}

func (s *PasskeyStore) RevokeCredential(ctx context.Context, rpid, ownerID string, credentialID []byte) error {
	if rpid == "" || ownerID == "" || len(credentialID) < 1 || len(credentialID) > 1024 {
		return fmt.Errorf("revoke passkey: %w", core.ErrInvalid)
	}
	// See CreateAdditionalCredential: the post-lock statement must observe the
	// prior add/revoke before deciding whether this is the final credential.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return mapError("begin passkey revocation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, ownerCreationLock); err != nil {
		return mapError("lock passkey revocation", err)
	}
	var ownerExists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM users WHERE id=$1 AND disabled_at IS NULL FOR UPDATE`, ownerID).Scan(&ownerExists); err != nil {
		return mapError("find passkey owner", err)
	}
	var credentialOwner string
	err = tx.QueryRow(ctx, `
		SELECT owner_id FROM passkeys WHERE rp_id=$1 AND credential_id=$2 FOR UPDATE`, rpid, credentialID).Scan(&credentialOwner)
	if errors.Is(err, pgx.ErrNoRows) {
		return mapError("commit idempotent passkey revocation", tx.Commit(ctx))
	}
	if err != nil {
		return mapError("find passkey for revocation", err)
	}
	if credentialOwner != ownerID {
		return fmt.Errorf("revoke passkey: %w", core.ErrNotFound)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM passkeys WHERE owner_id=$1 AND rp_id=$2`, ownerID, rpid).Scan(&count); err != nil {
		return mapError("count passkeys for revocation", err)
	}
	if count <= 1 {
		return fmt.Errorf("revoke final passkey: %w", core.ErrPrecondition)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM passkeys WHERE owner_id=$1 AND rp_id=$2 AND credential_id=$3`, ownerID, rpid, credentialID); err != nil {
		return mapError("revoke passkey", err)
	}
	return mapError("commit passkey revocation", tx.Commit(ctx))
}

func (s *PasskeyStore) OwnerByHandle(ctx context.Context, rpid string, handle []byte) (passkeys.Owner, error) {
	var owner passkeys.Owner
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.webauthn_handle, u.username, u.display_name
		FROM users u
		WHERE u.webauthn_handle = $2
		  AND u.disabled_at IS NULL
		  AND EXISTS (SELECT 1 FROM passkeys p WHERE p.owner_id = u.id AND p.rp_id = $1)`, rpid, handle,
	).Scan(&owner.ID, &owner.Handle, &owner.Name, &owner.DisplayName)
	if err != nil {
		return passkeys.Owner{}, mapError("find owner by handle", err)
	}
	credentials, err := s.ownerCredentials(ctx, rpid, owner.ID)
	if err != nil {
		return passkeys.Owner{}, err
	}
	owner.Credentials = credentials
	return owner, nil
}

func (s *PasskeyStore) OwnerByID(ctx context.Context, rpid, id string) (passkeys.Owner, error) {
	var owner passkeys.Owner
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.webauthn_handle, u.username, u.display_name
		FROM users u
		WHERE u.id = $2
		  AND u.disabled_at IS NULL
		  AND EXISTS (SELECT 1 FROM passkeys p WHERE p.owner_id = u.id AND p.rp_id = $1)`, rpid, id,
	).Scan(&owner.ID, &owner.Handle, &owner.Name, &owner.DisplayName)
	if err != nil {
		return passkeys.Owner{}, mapError("find owner by ID", err)
	}
	credentials, err := s.ownerCredentials(ctx, rpid, owner.ID)
	if err != nil {
		return passkeys.Owner{}, err
	}
	owner.Credentials = credentials
	return owner, nil
}

func (s *PasskeyStore) SaveCredential(ctx context.Context, record passkeys.CredentialRecord) error {
	if err := validateCredentialRecord(record); err != nil {
		return err
	}
	ciphertext, err := s.encryptCredential(record)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE passkeys
		SET credential_ciphertext = $1, last_used_at = $2
		WHERE rp_id = $3 AND credential_id = $4 AND owner_id = $5 AND device_id = $6`,
		ciphertext, record.LastUsedAt, record.RPID, record.Credential.ID, record.OwnerID, record.DeviceID,
	)
	if err != nil {
		return mapError("update passkey", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("update passkey: %w", core.ErrNotFound)
	}
	return nil
}

func (s *PasskeyStore) CredentialRecord(ctx context.Context, rpid string, credentialID []byte) (passkeys.CredentialRecord, error) {
	var record passkeys.CredentialRecord
	var ciphertext []byte
	err := s.pool.QueryRow(ctx, `
		SELECT p.rp_id, p.owner_id, p.device_id, d.name,
		       p.credential_ciphertext, p.created_at, p.last_used_at
		FROM passkeys p
		JOIN users u ON u.id = p.owner_id AND u.disabled_at IS NULL
		JOIN devices d ON d.owner_id = p.owner_id AND d.id = p.device_id
		WHERE p.rp_id = $1 AND p.credential_id = $2`, rpid, credentialID,
	).Scan(&record.RPID, &record.OwnerID, &record.DeviceID, &record.DeviceName,
		&ciphertext, &record.CreatedAt, &record.LastUsedAt)
	if err != nil {
		return passkeys.CredentialRecord{}, mapError("find passkey", err)
	}
	credential, err := s.decryptCredential(record, credentialID, ciphertext)
	if err != nil {
		return passkeys.CredentialRecord{}, err
	}
	record.Credential = credential
	return record, nil
}

func (s *PasskeyStore) ownerCredentials(ctx context.Context, rpid, ownerID string) ([]webauthn.Credential, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.credential_id, p.device_id, p.credential_ciphertext
		FROM passkeys p
		WHERE p.rp_id = $1 AND p.owner_id = $2
		ORDER BY p.created_at, p.credential_id`, rpid, ownerID)
	if err != nil {
		return nil, mapError("list owner passkeys", err)
	}
	defer rows.Close()
	credentials := make([]webauthn.Credential, 0)
	for rows.Next() {
		var credentialID, ciphertext []byte
		var deviceID string
		if err := rows.Scan(&credentialID, &deviceID, &ciphertext); err != nil {
			return nil, mapError("scan owner passkey", err)
		}
		credential, err := s.decryptCredential(passkeys.CredentialRecord{RPID: rpid, OwnerID: ownerID, DeviceID: deviceID}, credentialID, ciphertext)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate owner passkeys", err)
	}
	return credentials, nil
}

func (s *PasskeyStore) ResolveDevice(ctx context.Context, candidate passkeys.Device) (passkeys.Device, error) {
	if err := validateDevice(candidate); err != nil {
		return passkeys.Device{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return passkeys.Device{}, mapError("begin device resolution", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	lockKey := advisoryLockKey("device-instance", candidate.OwnerID, string(candidate.InstanceHash[:]))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return passkeys.Device{}, mapError("lock device instance", err)
	}
	var existing passkeys.Device
	var hash []byte
	err = tx.QueryRow(ctx, `
		SELECT id, owner_id, name, platform, instance_hash, created_at, last_seen_at
		FROM devices
		WHERE owner_id=$1 AND instance_hash=$2 AND revoked_at IS NULL
		FOR UPDATE`, candidate.OwnerID, candidate.InstanceHash[:]).Scan(
		&existing.ID, &existing.OwnerID, &existing.Name, &existing.Platform, &hash,
		&existing.CreatedAt, &existing.LastSeenAt,
	)
	if err == nil {
		if len(hash) != len(existing.InstanceHash) {
			return passkeys.Device{}, errors.New("stored device instance hash is invalid")
		}
		copy(existing.InstanceHash[:], hash)
		existing.Name = candidate.Name
		existing.LastSeenAt = candidate.LastSeenAt
		if _, err := tx.Exec(ctx, `
			UPDATE devices SET name=$3, last_seen_at=GREATEST(last_seen_at,$4)
			WHERE owner_id=$1 AND id=$2 AND revoked_at IS NULL`,
			candidate.OwnerID, existing.ID, candidate.Name, candidate.LastSeenAt); err != nil {
			return passkeys.Device{}, mapError("touch device instance", err)
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		existing = candidate
		if _, err := tx.Exec(ctx, `
			INSERT INTO devices (id, owner_id, name, platform, instance_hash, created_at, last_seen_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			candidate.ID, candidate.OwnerID, candidate.Name, candidate.Platform,
			candidate.InstanceHash[:], candidate.CreatedAt, candidate.LastSeenAt); err != nil {
			return passkeys.Device{}, mapError("insert device instance", err)
		}
	} else {
		return passkeys.Device{}, mapError("find device instance", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return passkeys.Device{}, mapError("commit device resolution", err)
	}
	return existing, nil
}

func (s *PasskeyStore) KnownDeviceInstanceHashes(ctx context.Context, limit int) ([][32]byte, error) {
	if limit < 1 || limit > 65536 {
		return nil, fmt.Errorf("known device instance limit: %w", core.ErrInvalid)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT instance_hash
		FROM devices
		WHERE instance_hash IS NOT NULL
		LIMIT $1`, limit)
	if err != nil {
		return nil, mapError("list known device instances", err)
	}
	defer rows.Close()
	values := make([][32]byte, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, mapError("scan known device instance", err)
		}
		if len(raw) != sha256.Size {
			return nil, errors.New("stored device instance hash is invalid")
		}
		var value [32]byte
		copy(value[:], raw)
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate known device instances", err)
	}
	return values, nil
}

func (s *PasskeyStore) encryptCredential(record passkeys.CredentialRecord) ([]byte, error) {
	plaintext, err := json.Marshal(record.Credential)
	if err != nil {
		return nil, fmt.Errorf("marshal passkey credential: %w", err)
	}
	envelope, err := s.cipher.Encrypt(plaintext, passkeyAAD(record.RPID, record.OwnerID, record.DeviceID, record.Credential.ID))
	if err != nil {
		return nil, fmt.Errorf("encrypt passkey credential: %w", err)
	}
	ciphertext, err := envelope.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal passkey envelope: %w", err)
	}
	return ciphertext, nil
}

func (s *PasskeyStore) decryptCredential(record passkeys.CredentialRecord, credentialID, ciphertext []byte) (webauthn.Credential, error) {
	envelope, err := vault.Parse(ciphertext)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("parse passkey envelope: %w", err)
	}
	plaintext, err := s.cipher.Decrypt(envelope, passkeyAAD(record.RPID, record.OwnerID, record.DeviceID, credentialID))
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("decrypt passkey credential: %w", err)
	}
	var credential webauthn.Credential
	if err := json.Unmarshal(plaintext, &credential); err != nil {
		return webauthn.Credential{}, fmt.Errorf("decode passkey credential: %w", err)
	}
	if !equalBytes(credential.ID, credentialID) {
		return webauthn.Credential{}, errors.New("passkey credential identity mismatch")
	}
	return credential, nil
}

func passkeyAAD(rpid, ownerID, deviceID string, credentialID []byte) []byte {
	return []byte("codex-mobile:passkey:v1:" + rpid + ":" + ownerID + ":" + deviceID + ":" + base64.RawURLEncoding.EncodeToString(credentialID))
}

func validateOwnerCredential(owner passkeys.Owner, record passkeys.CredentialRecord) error {
	if owner.ID == "" || len(owner.Handle) != 64 || owner.Name == "" || owner.DisplayName == "" || record.OwnerID != owner.ID {
		return fmt.Errorf("create owner: %w", core.ErrInvalid)
	}
	return validateCredentialRecord(record)
}

func validateCredentialRecord(record passkeys.CredentialRecord) error {
	if record.RPID == "" || record.OwnerID == "" || record.DeviceID == "" || record.DeviceName == "" || len(record.Credential.ID) < 1 || len(record.Credential.ID) > 1024 || record.CreatedAt.IsZero() {
		return fmt.Errorf("passkey credential: %w", core.ErrInvalid)
	}
	if record.LastUsedAt != nil && record.LastUsedAt.Before(record.CreatedAt) {
		return fmt.Errorf("passkey credential timestamp: %w", core.ErrInvalid)
	}
	return nil
}

func validateDevice(device passkeys.Device) error {
	if device.ID == "" || device.OwnerID == "" || device.Name == "" || len(device.Name) > 120 || device.Platform != "ios" ||
		device.CreatedAt.IsZero() || device.LastSeenAt.Before(device.CreatedAt) {
		return fmt.Errorf("device: %w", core.ErrInvalid)
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for i := range left {
		different |= left[i] ^ right[i]
	}
	return different == 0
}
