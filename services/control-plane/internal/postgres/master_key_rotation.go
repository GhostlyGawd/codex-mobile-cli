package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	secretmodel "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/secrets"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	masterKeyMaintenanceLock     int64 = 0x434d4d4b525750 // CMMKRWP
	maximumRotationRows                = 100_000
	maximumRotationEnvelopeBytes       = 512 << 20
)

var ErrServeProcessesActive = errors.New("control-plane serve processes are active")

// ServeLease holds a session-level shared advisory lock for the entire life of
// a serving control-plane process. The offline rotator takes the corresponding
// exclusive lock, so serving and rewrapping cannot overlap.
type ServeLease struct {
	mu   sync.Mutex
	conn *pgxpool.Conn
}

func AcquireServeLease(ctx context.Context, pool *pgxpool.Pool) (*ServeLease, error) {
	if ctx == nil || pool == nil {
		return nil, errors.New("PostgreSQL pool is required for the serve lease")
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, mapError("acquire serve lease connection", err)
	}
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock_shared($1)`, masterKeyMaintenanceLock).Scan(&acquired); err != nil {
		closeDedicatedConnection(conn)
		return nil, mapError("acquire serve lease", err)
	}
	if !acquired {
		closeDedicatedConnection(conn)
		return nil, errors.New("master-key maintenance is active")
	}
	return &ServeLease{conn: conn}, nil
}

func (l *ServeLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	conn := l.conn
	l.conn = nil
	l.mu.Unlock()
	if conn == nil {
		return nil
	}
	return closeDedicatedConnection(conn)
}

func closeDedicatedConnection(conn *pgxpool.Conn) error {
	if conn == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return conn.Hijack().Close(ctx)
}

type MasterKeyRotationSummary struct {
	Passkeys         int
	EncryptedSecrets int
	APNSTokens       int
}

func (s MasterKeyRotationSummary) Total() int {
	return s.Passkeys + s.EncryptedSecrets + s.APNSTokens
}

type MasterKeyRotator struct {
	pool    *pgxpool.Pool
	current *vault.Vault
}

func NewMasterKeyRotator(pool *pgxpool.Pool, current *vault.Vault) (*MasterKeyRotator, error) {
	if pool == nil || current == nil {
		return nil, errors.New("PostgreSQL pool and current vault are required")
	}
	return &MasterKeyRotator{pool: pool, current: current}, nil
}

// Rotate exclusively locks out serve processes, prepares and authenticates
// every replacement envelope, then applies all updates and the metadata-only
// audit record in one serializable transaction.
func (r *MasterKeyRotator) Rotate(ctx context.Context, newMaster []byte, now time.Time) (MasterKeyRotationSummary, error) {
	if ctx == nil || now.IsZero() {
		return MasterKeyRotationSummary{}, errors.New("master-key rotation context and timestamp are required")
	}
	newVault, err := vault.New(newMaster)
	if err != nil {
		return MasterKeyRotationSummary{}, err
	}
	defer newVault.Destroy()
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return MasterKeyRotationSummary{}, mapError("acquire master-key rotation connection", err)
	}
	defer closeDedicatedConnection(conn)
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, masterKeyMaintenanceLock).Scan(&acquired); err != nil {
		return MasterKeyRotationSummary{}, mapError("acquire master-key rotation lock", err)
	}
	if !acquired {
		return MasterKeyRotationSummary{}, ErrServeProcessesActive
	}
	transaction, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return MasterKeyRotationSummary{}, mapError("begin master-key rotation", err)
	}
	return executeMasterKeyRotation(ctx, &postgresMasterKeyRotationTx{tx: transaction}, r.current, newVault, newMaster, now)
}

type rotationPasskeyRow struct {
	RPID         string
	CredentialID []byte
	OwnerID      string
	DeviceID     string
	Envelope     []byte
}

type rotationSecretRow struct {
	ID            string
	OwnerID       string
	RepositoryID  *string
	WorkspaceID   *string
	Name          string
	Envelope      []byte
	AADVersion    int
	PlaintextSize *int
}

type rotationAPNSRow struct {
	ID          string
	OwnerID     string
	DeviceID    string
	Provider    string
	Environment string
	Envelope    []byte
}

type masterKeyRotationTx interface {
	LoadPasskeys(context.Context) ([]rotationPasskeyRow, error)
	LoadEncryptedSecrets(context.Context) ([]rotationSecretRow, error)
	LoadAPNSTokens(context.Context) ([]rotationAPNSRow, error)
	UpdatePasskey(context.Context, rotationPasskeyRow, []byte) error
	UpdateEncryptedSecret(context.Context, rotationSecretRow, []byte, [32]byte, time.Time) error
	UpdateAPNSToken(context.Context, rotationAPNSRow, []byte, time.Time) error
	InsertAudit(context.Context, MasterKeyRotationSummary, time.Time) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

type preparedPasskey struct {
	row      rotationPasskeyRow
	envelope []byte
}

type preparedSecret struct {
	row      rotationSecretRow
	envelope []byte
	hash     [32]byte
}

type preparedAPNSToken struct {
	row      rotationAPNSRow
	envelope []byte
}

func executeMasterKeyRotation(ctx context.Context, tx masterKeyRotationTx, current, next *vault.Vault, newMaster []byte, now time.Time) (summary MasterKeyRotationSummary, resultErr error) {
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(context.Background())
		}
	}()
	passkeys, err := tx.LoadPasskeys(ctx)
	if err != nil {
		return summary, err
	}
	secrets, err := tx.LoadEncryptedSecrets(ctx)
	if err != nil {
		wipeRotationPasskeys(passkeys)
		return summary, err
	}
	apnsTokens, err := tx.LoadAPNSTokens(ctx)
	if err != nil {
		wipeRotationPasskeys(passkeys)
		wipeRotationSecrets(secrets)
		return summary, err
	}
	defer wipeRotationPasskeys(passkeys)
	defer wipeRotationSecrets(secrets)
	defer wipeRotationAPNS(apnsTokens)
	if err := validateRotationSize(passkeys, secrets, apnsTokens); err != nil {
		return summary, err
	}

	preparedPasskeys := make([]preparedPasskey, 0, len(passkeys))
	preparedSecrets := make([]preparedSecret, 0, len(secrets))
	preparedAPNS := make([]preparedAPNSToken, 0, len(apnsTokens))
	defer func() {
		for index := range preparedPasskeys {
			clear(preparedPasskeys[index].envelope)
		}
		for index := range preparedSecrets {
			clear(preparedSecrets[index].envelope)
		}
		for index := range preparedAPNS {
			clear(preparedAPNS[index].envelope)
		}
	}()

	for _, row := range passkeys {
		if row.RPID == "" || row.OwnerID == "" || row.DeviceID == "" || len(row.CredentialID) == 0 {
			return summary, errors.New("stored passkey row cannot be safely rotated")
		}
		aad := passkeyAAD(row.RPID, row.OwnerID, row.DeviceID, row.CredentialID)
		encoded, err := rewrapAndVerify(current, next, newMaster, row.Envelope, aad)
		clear(aad)
		if err != nil {
			return summary, errors.New("stored passkey envelope cannot be authenticated for rotation")
		}
		preparedPasskeys = append(preparedPasskeys, preparedPasskey{row: row, envelope: encoded})
	}
	for _, row := range secrets {
		aad, err := encryptedSecretRotationAAD(row)
		if err != nil {
			return summary, err
		}
		encoded, err := rewrapAndVerify(current, next, newMaster, row.Envelope, aad)
		clear(aad)
		if err != nil {
			return summary, fmt.Errorf("encrypted secret row %q cannot be authenticated for rotation", row.ID)
		}
		preparedSecrets = append(preparedSecrets, preparedSecret{row: row, envelope: encoded, hash: sha256.Sum256(encoded)})
	}
	for _, row := range apnsTokens {
		if row.ID == "" || row.OwnerID == "" || row.DeviceID == "" || row.Provider != "apns" || (row.Environment != "sandbox" && row.Environment != "production") {
			return summary, errors.New("stored APNs row cannot be safely rotated")
		}
		aad := notificationAAD(row.OwnerID, row.DeviceID, row.Environment)
		encoded, err := rewrapAndVerify(current, next, newMaster, row.Envelope, aad)
		clear(aad)
		if err != nil {
			return summary, errors.New("stored APNs envelope cannot be authenticated for rotation")
		}
		preparedAPNS = append(preparedAPNS, preparedAPNSToken{row: row, envelope: encoded})
	}

	for _, prepared := range preparedPasskeys {
		if err := tx.UpdatePasskey(ctx, prepared.row, prepared.envelope); err != nil {
			return summary, err
		}
	}
	for _, prepared := range preparedSecrets {
		if err := tx.UpdateEncryptedSecret(ctx, prepared.row, prepared.envelope, prepared.hash, now); err != nil {
			return summary, err
		}
	}
	for _, prepared := range preparedAPNS {
		if err := tx.UpdateAPNSToken(ctx, prepared.row, prepared.envelope, now); err != nil {
			return summary, err
		}
	}
	summary = MasterKeyRotationSummary{Passkeys: len(preparedPasskeys), EncryptedSecrets: len(preparedSecrets), APNSTokens: len(preparedAPNS)}
	if err := tx.InsertAudit(ctx, summary, now); err != nil {
		return MasterKeyRotationSummary{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return MasterKeyRotationSummary{}, err
	}
	committed = true
	return summary, nil
}

func encryptedSecretRotationAAD(row rotationSecretRow) ([]byte, error) {
	invalid := func(reason string) ([]byte, error) {
		return nil, fmt.Errorf("encrypted secret row %q cannot be safely rotated: %s", row.ID, reason)
	}
	if row.ID == "" || row.OwnerID == "" || row.AADVersion != 1 {
		return invalid(fmt.Sprintf("unsupported AAD version %d or invalid identity", row.AADVersion))
	}
	if row.PlaintextSize != nil {
		if row.WorkspaceID != nil || *row.PlaintextSize < secretmodel.MinimumValueBytes || *row.PlaintextSize > secretmodel.MaximumValueBytes || !secretmodel.ValidName(row.Name) {
			return invalid("invalid user-secret row shape")
		}
		return userSecretAAD(row.OwnerID, row.RepositoryID, row.ID, row.Name), nil
	}
	if row.RepositoryID == nil || *row.RepositoryID == "" || row.WorkspaceID == nil || *row.WorkspaceID == "" {
		return invalid("unclassifiable legacy row shape")
	}
	workspaceID := *row.WorkspaceID
	repositoryID := *row.RepositoryID
	switch {
	case row.Name == workspaceInitialPromptName(workspaceID):
		return workspaceInitialPromptAAD(row.OwnerID, repositoryID, workspaceID), nil
	case row.Name == workspaceCodexAuthKeyName(workspaceID):
		return workspaceCodexAuthKeyAAD(row.OwnerID, repositoryID, workspaceID), nil
	case strings.HasPrefix(row.Name, workspaceEnvironmentName(workspaceID, "")):
		name := strings.TrimPrefix(row.Name, workspaceEnvironmentName(workspaceID, ""))
		if name == "" || len(name) > 128 {
			return invalid("invalid workspace-environment row shape")
		}
		return workspaceEnvironmentAAD(row.OwnerID, repositoryID, workspaceID, name), nil
	default:
		return invalid("unknown versioned AAD family")
	}
}

func rewrapAndVerify(current, next *vault.Vault, newMaster, encoded, aad []byte) ([]byte, error) {
	envelope, err := vault.Parse(encoded)
	if err != nil {
		return nil, err
	}
	plaintext, err := current.Decrypt(envelope, aad)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	rewrapped, err := current.Rewrap(envelope, aad, newMaster)
	if err != nil {
		return nil, err
	}
	if rewrapped.Version != envelope.Version || rewrapped.Ciphertext != envelope.Ciphertext || rewrapped.DataNonce != envelope.DataNonce {
		return nil, errors.New("rewrap changed encrypted payload")
	}
	verification, err := next.Decrypt(rewrapped, aad)
	if err != nil {
		return nil, err
	}
	defer clear(verification)
	if len(plaintext) != len(verification) || subtle.ConstantTimeCompare(plaintext, verification) != 1 {
		return nil, errors.New("rewrapped envelope verification failed")
	}
	return rewrapped.Marshal()
}

func validateRotationSize(passkeys []rotationPasskeyRow, secrets []rotationSecretRow, apns []rotationAPNSRow) error {
	rows := len(passkeys) + len(secrets) + len(apns)
	if rows > maximumRotationRows {
		return errors.New("master-key rotation row limit exceeded")
	}
	total := 0
	for _, row := range passkeys {
		total += len(row.Envelope)
	}
	for _, row := range secrets {
		total += len(row.Envelope)
	}
	for _, row := range apns {
		total += len(row.Envelope)
	}
	if total > maximumRotationEnvelopeBytes {
		return errors.New("master-key rotation envelope limit exceeded")
	}
	return nil
}

func wipeRotationPasskeys(rows []rotationPasskeyRow) {
	for index := range rows {
		clear(rows[index].CredentialID)
		clear(rows[index].Envelope)
	}
}

func wipeRotationSecrets(rows []rotationSecretRow) {
	for index := range rows {
		clear(rows[index].Envelope)
	}
}

func wipeRotationAPNS(rows []rotationAPNSRow) {
	for index := range rows {
		clear(rows[index].Envelope)
	}
}

type postgresMasterKeyRotationTx struct{ tx pgx.Tx }

func (t *postgresMasterKeyRotationTx) LoadPasskeys(ctx context.Context) ([]rotationPasskeyRow, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT rp_id, credential_id, owner_id, device_id, credential_ciphertext
		FROM passkeys ORDER BY rp_id, credential_id FOR UPDATE`)
	if err != nil {
		return nil, mapError("load passkeys for master-key rotation", err)
	}
	defer rows.Close()
	result := make([]rotationPasskeyRow, 0)
	for rows.Next() {
		var row rotationPasskeyRow
		if err := rows.Scan(&row.RPID, &row.CredentialID, &row.OwnerID, &row.DeviceID, &row.Envelope); err != nil {
			wipeRotationPasskeys(result)
			return nil, mapError("scan passkey for master-key rotation", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		wipeRotationPasskeys(result)
		return nil, mapError("iterate passkeys for master-key rotation", err)
	}
	return result, nil
}

func (t *postgresMasterKeyRotationTx) LoadEncryptedSecrets(ctx context.Context) ([]rotationSecretRow, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT id, owner_id, repository_id, workspace_id, name, encrypted_envelope, aad_version, plaintext_size
		FROM encrypted_secrets ORDER BY owner_id, id FOR UPDATE`)
	if err != nil {
		return nil, mapError("load encrypted secrets for master-key rotation", err)
	}
	defer rows.Close()
	result := make([]rotationSecretRow, 0)
	for rows.Next() {
		var row rotationSecretRow
		if err := rows.Scan(&row.ID, &row.OwnerID, &row.RepositoryID, &row.WorkspaceID, &row.Name, &row.Envelope, &row.AADVersion, &row.PlaintextSize); err != nil {
			wipeRotationSecrets(result)
			return nil, mapError("scan encrypted secret for master-key rotation", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		wipeRotationSecrets(result)
		return nil, mapError("iterate encrypted secrets for master-key rotation", err)
	}
	return result, nil
}

func (t *postgresMasterKeyRotationTx) LoadAPNSTokens(ctx context.Context) ([]rotationAPNSRow, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT id, owner_id, device_id, provider, environment, encrypted_token
		FROM notification_endpoints ORDER BY owner_id, id FOR UPDATE`)
	if err != nil {
		return nil, mapError("load APNs tokens for master-key rotation", err)
	}
	defer rows.Close()
	result := make([]rotationAPNSRow, 0)
	for rows.Next() {
		var row rotationAPNSRow
		if err := rows.Scan(&row.ID, &row.OwnerID, &row.DeviceID, &row.Provider, &row.Environment, &row.Envelope); err != nil {
			wipeRotationAPNS(result)
			return nil, mapError("scan APNs token for master-key rotation", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		wipeRotationAPNS(result)
		return nil, mapError("iterate APNs tokens for master-key rotation", err)
	}
	return result, nil
}

func (t *postgresMasterKeyRotationTx) UpdatePasskey(ctx context.Context, row rotationPasskeyRow, envelope []byte) error {
	tag, err := t.tx.Exec(ctx, `
		UPDATE passkeys SET credential_ciphertext=$5
		WHERE rp_id=$1 AND credential_id=$2 AND owner_id=$3 AND device_id=$4`,
		row.RPID, row.CredentialID, row.OwnerID, row.DeviceID, envelope)
	if err != nil || tag.RowsAffected() != 1 {
		return errors.New("update passkey during master-key rotation failed")
	}
	return nil
}

func (t *postgresMasterKeyRotationTx) UpdateEncryptedSecret(ctx context.Context, row rotationSecretRow, envelope []byte, hash [32]byte, now time.Time) error {
	tag, err := t.tx.Exec(ctx, `
		UPDATE encrypted_secrets
		SET encrypted_envelope=$3, redaction_hash=$4, rotated_at=$5, updated_at=GREATEST(updated_at,$5)
		WHERE owner_id=$1 AND id=$2`, row.OwnerID, row.ID, envelope, hash[:], now)
	if err != nil || tag.RowsAffected() != 1 {
		return fmt.Errorf("update encrypted secret row %q during master-key rotation failed", row.ID)
	}
	return nil
}

func (t *postgresMasterKeyRotationTx) UpdateAPNSToken(ctx context.Context, row rotationAPNSRow, envelope []byte, now time.Time) error {
	tag, err := t.tx.Exec(ctx, `
		UPDATE notification_endpoints SET encrypted_token=$4, updated_at=GREATEST(updated_at,$5)
		WHERE owner_id=$1 AND id=$2 AND provider=$3`, row.OwnerID, row.ID, row.Provider, envelope, now)
	if err != nil || tag.RowsAffected() != 1 {
		return errors.New("update APNs token during master-key rotation failed")
	}
	return nil
}

func (t *postgresMasterKeyRotationTx) InsertAudit(ctx context.Context, summary MasterKeyRotationSummary, now time.Time) error {
	details, err := json.Marshal(map[string]int{
		"apns_tokens": summary.APNSTokens, "encrypted_secrets": summary.EncryptedSecrets,
		"passkeys": summary.Passkeys, "total": summary.Total(),
	})
	if err != nil {
		return errors.New("marshal master-key rotation audit metadata")
	}
	defer clear(details)
	_, err = t.tx.Exec(ctx, `
		INSERT INTO audit_events
		    (owner_id, device_id, workspace_id, action, result, target_type, target_id, details, created_at)
		VALUES (NULL,NULL,NULL,'vault.master_key.rewrap','success','envelope_set','',$1,$2)`, details, now)
	if err != nil {
		return mapError("write master-key rotation audit event", err)
	}
	return nil
}

func (t *postgresMasterKeyRotationTx) Commit(ctx context.Context) error {
	return mapError("commit master-key rotation", t.tx.Commit(ctx))
}

func (t *postgresMasterKeyRotationTx) Rollback(ctx context.Context) error {
	err := t.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}
