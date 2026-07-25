package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	secretmodel "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/secrets"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
	"github.com/jackc/pgx/v5"
)

const userSecretAADVersion = 1

func (s *ApplicationStore) CreateSecret(ctx context.Context, value secretmodel.Metadata, plaintext []byte, now time.Time) (secretmodel.Metadata, error) {
	if !validSecretMetadata(value, true) || value.OwnerID == "" || value.CreatedAt.IsZero() || !value.CreatedAt.Equal(now) ||
		value.UpdatedAt != value.CreatedAt || secretmodel.ValidateValue(plaintext) != nil {
		return secretmodel.Metadata{}, fmt.Errorf("create secret: %w", core.ErrInvalid)
	}
	encoded, hash, err := s.encryptUserSecret(value, plaintext)
	if err != nil {
		return secretmodel.Metadata{}, err
	}
	defer wipeApplicationSecret(encoded)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return secretmodel.Metadata{}, mapError("begin secret creation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, advisoryLockKey("user-secrets", value.OwnerID)); err != nil {
		return secretmodel.Metadata{}, mapError("lock secret collection", err)
	}
	if value.RepositoryID != nil {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT true FROM repositories WHERE owner_id=$1 AND id=$2 AND available`, value.OwnerID, *value.RepositoryID).Scan(&exists); err != nil {
			return secretmodel.Metadata{}, mapError("find secret repository", err)
		}
	}
	var count int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM encrypted_secrets
		WHERE owner_id=$1 AND workspace_id IS NULL AND plaintext_size IS NOT NULL AND deleted_at IS NULL`, value.OwnerID).Scan(&count); err != nil {
		return secretmodel.Metadata{}, mapError("count secrets", err)
	}
	if count >= secretmodel.MaximumSecretsPerOwner {
		return secretmodel.Metadata{}, fmt.Errorf("create secret: %w", core.ErrCapacity)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO encrypted_secrets
		    (id, owner_id, repository_id, workspace_id, name, encrypted_envelope,
		     redaction_hash, aad_version, plaintext_size, created_at, updated_at)
		VALUES ($1,$2,$3,NULL,$4,$5,$6,$7,$8,$9,$9)`,
		value.ID, value.OwnerID, value.RepositoryID, value.Name, encoded, hash[:], userSecretAADVersion, len(plaintext), now)
	if err != nil {
		return secretmodel.Metadata{}, mapError("insert secret", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return secretmodel.Metadata{}, mapError("commit secret creation", err)
	}
	value.ValueBytes = len(plaintext)
	return value, nil
}

func (s *ApplicationStore) ListSecrets(ctx context.Context, ownerID string, repositoryID *string) ([]secretmodel.Metadata, error) {
	if ownerID == "" || (repositoryID != nil && *repositoryID == "") {
		return nil, fmt.Errorf("list secrets: %w", core.ErrInvalid)
	}
	if repositoryID != nil {
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT true FROM repositories WHERE owner_id=$1 AND id=$2 AND available`, ownerID, *repositoryID).Scan(&exists); err != nil {
			return nil, mapError("find secret repository", err)
		}
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, owner_id, repository_id, name, plaintext_size, created_at, updated_at
		FROM encrypted_secrets
		WHERE owner_id=$1 AND workspace_id IS NULL AND plaintext_size IS NOT NULL AND deleted_at IS NULL
		  AND ($2::text IS NULL OR repository_id IS NULL OR repository_id=$2)
		ORDER BY repository_id NULLS FIRST, name, id
		LIMIT 101`, ownerID, repositoryID)
	if err != nil {
		return nil, mapError("list secrets", err)
	}
	defer rows.Close()
	values := make([]secretmodel.Metadata, 0)
	for rows.Next() {
		value, err := scanSecretMetadata(rows)
		if err != nil {
			return nil, mapError("scan secret metadata", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate secrets", err)
	}
	if len(values) > secretmodel.MaximumSecretsPerOwner {
		return nil, fmt.Errorf("list secrets: %w", core.ErrCapacity)
	}
	return values, nil
}

func (s *ApplicationStore) UpdateSecret(ctx context.Context, ownerID, secretID string, plaintext []byte, now time.Time) (secretmodel.Metadata, error) {
	if ownerID == "" || secretID == "" || now.IsZero() || secretmodel.ValidateValue(plaintext) != nil {
		return secretmodel.Metadata{}, fmt.Errorf("update secret: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return secretmodel.Metadata{}, mapError("begin secret update", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	value, err := loadSecretMetadataForUpdate(ctx, tx, ownerID, secretID, false)
	if err != nil {
		return secretmodel.Metadata{}, err
	}
	value.UpdatedAt = now
	encoded, hash, err := s.encryptUserSecret(value, plaintext)
	if err != nil {
		return secretmodel.Metadata{}, err
	}
	defer wipeApplicationSecret(encoded)
	if _, err := tx.Exec(ctx, `
		UPDATE encrypted_secrets
		SET encrypted_envelope=$3, redaction_hash=$4, plaintext_size=$5,
		    updated_at=$6, rotated_at=$6
		WHERE owner_id=$1 AND id=$2 AND deleted_at IS NULL`,
		ownerID, secretID, encoded, hash[:], len(plaintext), now); err != nil {
		return secretmodel.Metadata{}, mapError("update secret", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return secretmodel.Metadata{}, mapError("commit secret update", err)
	}
	value.ValueBytes = len(plaintext)
	return value, nil
}

func (s *ApplicationStore) DeleteSecret(ctx context.Context, ownerID, secretID string, now time.Time) error {
	if ownerID == "" || secretID == "" || now.IsZero() {
		return fmt.Errorf("delete secret: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin secret deletion", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := loadSecretMetadataForUpdate(ctx, tx, ownerID, secretID, true); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE encrypted_secrets SET deleted_at=COALESCE(deleted_at,$3), updated_at=GREATEST(updated_at,$3)
		WHERE owner_id=$1 AND id=$2`, ownerID, secretID, now); err != nil {
		return mapError("delete secret", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE secret_grants SET revoked_at=COALESCE(revoked_at,$3), updated_at=GREATEST(updated_at,$3)
		WHERE owner_id=$1 AND secret_id=$2`, ownerID, secretID, now); err != nil {
		return mapError("revoke deleted secret grants", err)
	}
	return mapError("commit secret deletion", tx.Commit(ctx))
}

// ListSecretWorkspaceIDs returns the live workspaces whose active grants are
// affected by rotating or deleting a secret. The application holds its
// process-wide secret mutation lock across this query, the database mutation,
// and runtime synchronization, while PostgreSQL transactions retain their
// existing row/advisory locks for storage-level integrity.
func (s *ApplicationStore) ListSecretWorkspaceIDs(ctx context.Context, ownerID, secretID string) ([]string, error) {
	if ownerID == "" || secretID == "" {
		return nil, fmt.Errorf("list secret workspaces: %w", core.ErrInvalid)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT g.workspace_id
		FROM encrypted_secrets s
		JOIN secret_grants g ON g.owner_id=s.owner_id AND g.secret_id=s.id AND g.revoked_at IS NULL
		JOIN workspaces w ON w.owner_id=g.owner_id AND w.id=g.workspace_id AND w.state <> 'deleting'
		WHERE s.owner_id=$1 AND s.id=$2 AND s.workspace_id IS NULL
		  AND s.plaintext_size IS NOT NULL AND s.deleted_at IS NULL
		ORDER BY g.workspace_id
		LIMIT 1001`, ownerID, secretID)
	if err != nil {
		return nil, mapError("list secret workspaces", err)
	}
	defer rows.Close()
	workspaceIDs := make([]string, 0)
	for rows.Next() {
		var workspaceID string
		if err := rows.Scan(&workspaceID); err != nil {
			return nil, mapError("scan secret workspace", err)
		}
		if workspaceID == "" {
			return nil, errors.New("stored secret grant has an invalid workspace identity")
		}
		workspaceIDs = append(workspaceIDs, workspaceID)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate secret workspaces", err)
	}
	if len(workspaceIDs) > 1000 {
		return nil, fmt.Errorf("list secret workspaces: %w", core.ErrCapacity)
	}
	return workspaceIDs, nil
}

func (s *ApplicationStore) ListWorkspaceSecretGrants(ctx context.Context, ownerID, workspaceID string) ([]secretmodel.WorkspaceGrant, error) {
	if ownerID == "" || workspaceID == "" {
		return nil, fmt.Errorf("list workspace secret grants: %w", core.ErrInvalid)
	}
	var repositoryID string
	if err := s.pool.QueryRow(ctx, `SELECT repository_id FROM workspaces WHERE owner_id=$1 AND id=$2 AND state <> 'deleting'`, ownerID, workspaceID).Scan(&repositoryID); err != nil {
		return nil, mapError("find secret grant workspace", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, s.owner_id, s.repository_id, s.name, s.plaintext_size, s.created_at, s.updated_at,
		       (g.secret_id IS NOT NULL), g.granted_at
		FROM workspaces w
		JOIN encrypted_secrets s ON s.owner_id=w.owner_id
		  AND s.workspace_id IS NULL AND s.plaintext_size IS NOT NULL AND s.deleted_at IS NULL
		  AND (s.repository_id IS NULL OR s.repository_id=w.repository_id)
		LEFT JOIN secret_grants g ON g.owner_id=w.owner_id AND g.workspace_id=w.id
		  AND g.secret_id=s.id AND g.revoked_at IS NULL
		WHERE w.owner_id=$1 AND w.id=$2 AND w.state <> 'deleting'
		ORDER BY s.repository_id NULLS FIRST, s.name, s.id
		LIMIT 101`, ownerID, workspaceID)
	if err != nil {
		return nil, mapError("list workspace secret grants", err)
	}
	defer rows.Close()
	values := make([]secretmodel.WorkspaceGrant, 0)
	for rows.Next() {
		var value secretmodel.WorkspaceGrant
		if err := rows.Scan(&value.Secret.ID, &value.Secret.OwnerID, &value.Secret.RepositoryID, &value.Secret.Name,
			&value.Secret.ValueBytes, &value.Secret.CreatedAt, &value.Secret.UpdatedAt, &value.Granted, &value.GrantedAt); err != nil {
			return nil, mapError("scan workspace secret grant", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate workspace secret grants", err)
	}
	if len(values) > secretmodel.MaximumSecretsPerOwner {
		return nil, fmt.Errorf("list workspace secret grants: %w", core.ErrCapacity)
	}
	return values, nil
}

func (s *ApplicationStore) GrantWorkspaceSecret(ctx context.Context, ownerID, workspaceID, secretID string, now time.Time) error {
	if ownerID == "" || workspaceID == "" || secretID == "" || now.IsZero() {
		return fmt.Errorf("grant workspace secret: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin workspace secret grant", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, advisoryLockKey("workspace-secrets", ownerID, workspaceID)); err != nil {
		return mapError("lock workspace secret grants", err)
	}
	var name string
	var valueBytes int
	if err := tx.QueryRow(ctx, `
		SELECT s.name, s.plaintext_size
		FROM workspaces w
		JOIN encrypted_secrets s ON s.owner_id=w.owner_id AND s.id=$3
		WHERE w.owner_id=$1 AND w.id=$2 AND w.state <> 'deleting'
		  AND s.workspace_id IS NULL AND s.plaintext_size IS NOT NULL AND s.deleted_at IS NULL
		  AND (s.repository_id IS NULL OR s.repository_id=w.repository_id)
		FOR UPDATE OF s`, ownerID, workspaceID, secretID).Scan(&name, &valueBytes); err != nil {
		return mapError("find workspace secret", err)
	}
	var grantCount, grantedBytes int
	if err := tx.QueryRow(ctx, `
		SELECT count(*), COALESCE(sum(s.plaintext_size),0)
		FROM secret_grants g JOIN encrypted_secrets s ON s.owner_id=g.owner_id AND s.id=g.secret_id
		WHERE g.owner_id=$1 AND g.workspace_id=$2 AND g.revoked_at IS NULL
		  AND s.deleted_at IS NULL AND g.secret_id<>$3`, ownerID, workspaceID, secretID).Scan(&grantCount, &grantedBytes); err != nil {
		return mapError("measure workspace secret grants", err)
	}
	if grantCount >= secretmodel.MaximumGrantsPerWorkspace || grantedBytes+valueBytes > secretmodel.MaximumGrantedBytes {
		return fmt.Errorf("grant workspace secret: %w", core.ErrCapacity)
	}
	var conflicting bool
	err = tx.QueryRow(ctx, `
		SELECT true FROM secret_grants g
		JOIN encrypted_secrets s ON s.owner_id=g.owner_id AND s.id=g.secret_id
		WHERE g.owner_id=$1 AND g.workspace_id=$2 AND g.revoked_at IS NULL
		  AND g.secret_id<>$3 AND s.deleted_at IS NULL AND s.name=$4
		LIMIT 1`, ownerID, workspaceID, secretID, name).Scan(&conflicting)
	if err == nil && conflicting {
		return fmt.Errorf("grant workspace secret: %w", core.ErrConflict)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return mapError("check workspace secret name", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO secret_grants (owner_id, workspace_id, secret_id, granted_at, updated_at)
		VALUES ($1,$2,$3,$4,$4)
		ON CONFLICT (owner_id, workspace_id, secret_id) DO UPDATE
		SET granted_at=CASE WHEN secret_grants.revoked_at IS NULL THEN secret_grants.granted_at ELSE EXCLUDED.granted_at END,
		    updated_at=EXCLUDED.updated_at, revoked_at=NULL`, ownerID, workspaceID, secretID, now); err != nil {
		return mapError("grant workspace secret", err)
	}
	return mapError("commit workspace secret grant", tx.Commit(ctx))
}

func (s *ApplicationStore) RevokeWorkspaceSecret(ctx context.Context, ownerID, workspaceID, secretID string, now time.Time) error {
	if ownerID == "" || workspaceID == "" || secretID == "" || now.IsZero() {
		return fmt.Errorf("revoke workspace secret: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin workspace secret revocation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT true FROM secret_grants
		WHERE owner_id=$1 AND workspace_id=$2 AND secret_id=$3 FOR UPDATE`, ownerID, workspaceID, secretID).Scan(&exists); err != nil {
		return mapError("find workspace secret grant", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE secret_grants SET revoked_at=COALESCE(revoked_at,$4), updated_at=GREATEST(updated_at,$4)
		WHERE owner_id=$1 AND workspace_id=$2 AND secret_id=$3`, ownerID, workspaceID, secretID, now); err != nil {
		return mapError("revoke workspace secret", err)
	}
	return mapError("commit workspace secret revocation", tx.Commit(ctx))
}

// LoadGrantedWorkspaceSecrets is the sole plaintext read boundary. It returns
// only active, explicitly granted values applicable to the workspace's owner
// and repository. Callers must wipe every returned buffer immediately after
// constructing the bounded runtime environment.
func (s *ApplicationStore) LoadGrantedWorkspaceSecrets(ctx context.Context, ownerID, workspaceID string) (map[string][]byte, error) {
	if ownerID == "" || workspaceID == "" {
		return nil, fmt.Errorf("load workspace secrets: %w", core.ErrInvalid)
	}
	var repositoryID string
	if err := s.pool.QueryRow(ctx, `SELECT repository_id FROM workspaces WHERE owner_id=$1 AND id=$2 AND state <> 'deleting'`, ownerID, workspaceID).Scan(&repositoryID); err != nil {
		return nil, mapError("find workspace for secrets", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, s.repository_id, s.name, s.encrypted_envelope, s.aad_version, s.plaintext_size
		FROM workspaces w
		JOIN secret_grants g ON g.owner_id=w.owner_id AND g.workspace_id=w.id AND g.revoked_at IS NULL
		JOIN encrypted_secrets s ON s.owner_id=g.owner_id AND s.id=g.secret_id
		WHERE w.owner_id=$1 AND w.id=$2 AND w.state <> 'deleting'
		  AND s.deleted_at IS NULL AND s.workspace_id IS NULL AND s.plaintext_size IS NOT NULL
		  AND (s.repository_id IS NULL OR s.repository_id=w.repository_id)
		ORDER BY s.name, s.id
		LIMIT 51`, ownerID, workspaceID)
	if err != nil {
		return nil, mapError("load workspace secrets", err)
	}
	defer rows.Close()
	result := make(map[string][]byte)
	total := 0
	fail := func(err error) (map[string][]byte, error) {
		for _, value := range result {
			secretmodel.Wipe(value)
		}
		return nil, err
	}
	for rows.Next() {
		var id, name string
		var repositoryID *string
		var ciphertext []byte
		var aadVersion, plaintextSize int
		if err := rows.Scan(&id, &repositoryID, &name, &ciphertext, &aadVersion, &plaintextSize); err != nil {
			return fail(mapError("scan workspace secret", err))
		}
		if aadVersion != userSecretAADVersion || !secretmodel.ValidName(name) || plaintextSize < secretmodel.MinimumValueBytes || plaintextSize > secretmodel.MaximumValueBytes {
			wipeApplicationSecret(ciphertext)
			return fail(errors.New("stored workspace secret is invalid"))
		}
		if _, duplicate := result[name]; duplicate {
			wipeApplicationSecret(ciphertext)
			return fail(errors.New("workspace secret names conflict"))
		}
		envelope, err := vault.Parse(ciphertext)
		wipeApplicationSecret(ciphertext)
		if err != nil {
			return fail(errors.New("stored workspace secret is invalid"))
		}
		plaintext, err := s.cipher.Decrypt(envelope, userSecretAAD(ownerID, repositoryID, id, name))
		if err != nil || len(plaintext) != plaintextSize || secretmodel.ValidateValue(plaintext) != nil {
			secretmodel.Wipe(plaintext)
			return fail(errors.New("stored workspace secret is invalid"))
		}
		total += len(plaintext)
		if len(result) >= secretmodel.MaximumGrantsPerWorkspace || total > secretmodel.MaximumGrantedBytes {
			secretmodel.Wipe(plaintext)
			return fail(fmt.Errorf("load workspace secrets: %w", core.ErrCapacity))
		}
		result[name] = plaintext
	}
	if err := rows.Err(); err != nil {
		return fail(mapError("iterate workspace secrets", err))
	}
	return result, nil
}

func (s *ApplicationStore) encryptUserSecret(value secretmodel.Metadata, plaintext []byte) ([]byte, [32]byte, error) {
	envelope, err := s.cipher.Encrypt(plaintext, userSecretAAD(value.OwnerID, value.RepositoryID, value.ID, value.Name))
	if err != nil {
		return nil, [32]byte{}, errors.New("secret encryption failed")
	}
	encoded, err := envelope.Marshal()
	if err != nil {
		return nil, [32]byte{}, errors.New("secret encryption failed")
	}
	hash := sha256.Sum256(encoded)
	return encoded, hash, nil
}

func userSecretAAD(ownerID string, repositoryID *string, secretID, name string) []byte {
	scope := "g"
	if repositoryID != nil {
		scope = "r:" + *repositoryID
	}
	return []byte(fmt.Sprintf("codex-mobile:user-secret:v1:%d:%s:%d:%s:%d:%s:%d:%s",
		len(ownerID), ownerID, len(scope), scope, len(secretID), secretID, len(name), name))
}

func validSecretMetadata(value secretmodel.Metadata, requireID bool) bool {
	return (!requireID || value.ID != "") && value.OwnerID != "" && secretmodel.ValidName(value.Name) &&
		(value.RepositoryID == nil || *value.RepositoryID != "")
}

type secretMetadataScanner interface{ Scan(...any) error }

func scanSecretMetadata(row secretMetadataScanner) (secretmodel.Metadata, error) {
	var value secretmodel.Metadata
	err := row.Scan(&value.ID, &value.OwnerID, &value.RepositoryID, &value.Name, &value.ValueBytes, &value.CreatedAt, &value.UpdatedAt)
	if err == nil && !validSecretMetadata(value, true) {
		err = errors.New("stored secret metadata is invalid")
	}
	return value, err
}

func loadSecretMetadataForUpdate(ctx context.Context, tx pgx.Tx, ownerID, secretID string, includeDeleted bool) (secretmodel.Metadata, error) {
	deletedClause := "AND deleted_at IS NULL"
	if includeDeleted {
		deletedClause = ""
	}
	row := tx.QueryRow(ctx, `
		SELECT id, owner_id, repository_id, name, plaintext_size, created_at, updated_at
		FROM encrypted_secrets
		WHERE owner_id=$1 AND id=$2 AND workspace_id IS NULL AND plaintext_size IS NOT NULL `+deletedClause+`
		FOR UPDATE`, ownerID, secretID)
	value, err := scanSecretMetadata(row)
	if err != nil {
		return secretmodel.Metadata{}, mapError("find secret", err)
	}
	return value, nil
}
