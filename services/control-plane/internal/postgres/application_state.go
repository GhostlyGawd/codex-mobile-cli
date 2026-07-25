package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/setupreview"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ApplicationStore struct {
	pool     *pgxpool.Pool
	cipher   credentialCipher
	random   io.Reader
	randomMu sync.Mutex
}

func NewApplicationStore(pool *pgxpool.Pool, cipher credentialCipher, randomSources ...io.Reader) (*ApplicationStore, error) {
	if pool == nil || cipher == nil || len(randomSources) > 1 {
		return nil, errors.New("PostgreSQL pool and application cipher are required")
	}
	randomSource := io.Reader(rand.Reader)
	if len(randomSources) == 1 {
		randomSource = randomSources[0]
	}
	if randomSource == nil {
		return nil, errors.New("application random source is required")
	}
	return &ApplicationStore{pool: pool, cipher: cipher, random: randomSource}, nil
}

type Settings struct {
	AutonomyDefault           string
	RetentionDefault          string
	IdleTimeoutMinutes        int
	TerminalFontSize          float64
	TerminalTheme             string
	TerminalCursorStyle       string
	QuietHoursEnabled         bool
	NotificationDetailEnabled bool
}

func DefaultSettings() Settings {
	return Settings{
		AutonomyDefault: "balanced", RetentionDefault: "30_days", IdleTimeoutMinutes: 30,
		TerminalFontSize: 14, TerminalTheme: "system", TerminalCursorStyle: "block",
	}
}

func (s *ApplicationStore) GetSettings(ctx context.Context, ownerID string) (Settings, error) {
	var value Settings
	err := s.pool.QueryRow(ctx, `
		SELECT autonomy_default, retention_default, idle_timeout_minutes,
		       terminal_font_size, terminal_theme, terminal_cursor_style,
		       quiet_hours_enabled, notification_detail_enabled
		FROM user_settings WHERE owner_id = $1`, ownerID).Scan(
		&value.AutonomyDefault, &value.RetentionDefault, &value.IdleTimeoutMinutes,
		&value.TerminalFontSize, &value.TerminalTheme, &value.TerminalCursorStyle,
		&value.QuietHoursEnabled, &value.NotificationDetailEnabled,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, mapError("get user settings", err)
	}
	return value, nil
}

func (s *ApplicationStore) SaveSettings(ctx context.Context, ownerID string, value Settings, now time.Time) error {
	if ownerID == "" || !validSettings(value) || now.IsZero() {
		return fmt.Errorf("user settings: %w", core.ErrInvalid)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO user_settings
		    (owner_id, autonomy_default, retention_default, idle_timeout_minutes,
		     terminal_font_size, terminal_theme, terminal_cursor_style,
		     quiet_hours_enabled, notification_detail_enabled, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (owner_id) DO UPDATE SET
		    autonomy_default = EXCLUDED.autonomy_default,
		    retention_default = EXCLUDED.retention_default,
		    idle_timeout_minutes = EXCLUDED.idle_timeout_minutes,
		    terminal_font_size = EXCLUDED.terminal_font_size,
		    terminal_theme = EXCLUDED.terminal_theme,
		    terminal_cursor_style = EXCLUDED.terminal_cursor_style,
		    quiet_hours_enabled = EXCLUDED.quiet_hours_enabled,
		    notification_detail_enabled = EXCLUDED.notification_detail_enabled,
		    updated_at = EXCLUDED.updated_at`,
		ownerID, value.AutonomyDefault, value.RetentionDefault, value.IdleTimeoutMinutes,
		value.TerminalFontSize, value.TerminalTheme, value.TerminalCursorStyle,
		value.QuietHoursEnabled, value.NotificationDetailEnabled, now,
	)
	return mapError("save user settings", err)
}

func validSettings(value Settings) bool {
	autonomy := value.AutonomyDefault == "safe" || value.AutonomyDefault == "balanced" || value.AutonomyDefault == "full_access"
	retention := value.RetentionDefault == "7_days" || value.RetentionDefault == "30_days" || value.RetentionDefault == "90_days" || value.RetentionDefault == "keep_forever"
	cursor := value.TerminalCursorStyle == "block" || value.TerminalCursorStyle == "beam" || value.TerminalCursorStyle == "underline"
	return autonomy && retention && cursor && value.IdleTimeoutMinutes >= 5 && value.IdleTimeoutMinutes <= 10080 &&
		value.TerminalFontSize >= 8 && value.TerminalFontSize <= 48 && len(value.TerminalTheme) <= 100
}

func (s *ApplicationStore) SaveWorkspaceEnvironment(ctx context.Context, value core.Workspace) error {
	if value.ID == "" || value.OwnerID == "" || value.Repository.ID == "" || len(value.EnvironmentVariables) > 100 {
		return fmt.Errorf("workspace environment: %w", core.ErrInvalid)
	}
	if len(value.EnvironmentVariables) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin workspace environment save", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	for name, plaintext := range value.EnvironmentVariables {
		if name == "" || len(name) > 128 || len(plaintext) > 8192 || strings.ContainsRune(plaintext, '\x00') {
			return fmt.Errorf("workspace environment: %w", core.ErrInvalid)
		}
		recordName := workspaceEnvironmentName(value.ID, name)
		aad := workspaceEnvironmentAAD(value.OwnerID, value.Repository.ID, value.ID, name)
		envelope, err := s.cipher.Encrypt([]byte(plaintext), aad)
		if err != nil {
			return fmt.Errorf("encrypt workspace environment: %w", err)
		}
		ciphertext, err := envelope.Marshal()
		if err != nil {
			return fmt.Errorf("marshal workspace environment: %w", err)
		}
		redactionHash := sha256.Sum256(ciphertext)
		_, err = tx.Exec(ctx, `
			INSERT INTO encrypted_secrets
			    (id, owner_id, repository_id, workspace_id, name, encrypted_envelope,
			     redaction_hash, aad_version, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$8)
			ON CONFLICT (owner_id, repository_id, name)
			    WHERE repository_id IS NOT NULL AND deleted_at IS NULL
			DO UPDATE SET encrypted_envelope=EXCLUDED.encrypted_envelope,
			    redaction_hash=EXCLUDED.redaction_hash, workspace_id=EXCLUDED.workspace_id,
			    updated_at=EXCLUDED.updated_at, rotated_at=EXCLUDED.updated_at`,
			"env_"+hex.EncodeToString(redactionHash[:16]), value.OwnerID, value.Repository.ID,
			value.ID, recordName, ciphertext, redactionHash[:], value.UpdatedAt,
		)
		if err != nil {
			return mapError("save workspace environment value", err)
		}
	}
	return mapError("commit workspace environment save", tx.Commit(ctx))
}

func (s *ApplicationStore) LoadWorkspaceEnvironment(ctx context.Context, value core.Workspace) (map[string]string, error) {
	prefix := workspaceEnvironmentName(value.ID, "")
	rows, err := s.pool.Query(ctx, `
		SELECT name, encrypted_envelope
		FROM encrypted_secrets
		WHERE owner_id=$1 AND repository_id=$2 AND workspace_id=$3 AND deleted_at IS NULL
		  AND left(name, char_length($4)) = $4
		ORDER BY name`, value.OwnerID, value.Repository.ID, value.ID, prefix)
	if err != nil {
		return nil, mapError("load workspace environment", err)
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var recordName string
		var ciphertext []byte
		if err := rows.Scan(&recordName, &ciphertext); err != nil {
			return nil, mapError("scan workspace environment", err)
		}
		if !strings.HasPrefix(recordName, prefix) {
			return nil, errors.New("workspace environment identity mismatch")
		}
		name := strings.TrimPrefix(recordName, prefix)
		envelope, err := vault.Parse(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("parse workspace environment envelope: %w", err)
		}
		plaintext, err := s.cipher.Decrypt(envelope, workspaceEnvironmentAAD(value.OwnerID, value.Repository.ID, value.ID, name))
		if err != nil {
			return nil, fmt.Errorf("decrypt workspace environment: %w", err)
		}
		result[name] = string(plaintext)
		for index := range plaintext {
			plaintext[index] = 0
		}
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate workspace environment", err)
	}
	return result, nil
}

// LoadOrCreateWorkspaceCodexAuthKey returns the per-workspace key used only by
// the trusted workspace helper to seal Codex's file-backed auth state. The
// unwrapped key is never stored in a workspace volume or application log.
func (s *ApplicationStore) LoadOrCreateWorkspaceCodexAuthKey(ctx context.Context, value core.Workspace) ([]byte, error) {
	if value.ID == "" || value.OwnerID == "" || value.Repository.ID == "" || value.UpdatedAt.IsZero() {
		return nil, fmt.Errorf("workspace Codex auth key: %w", core.ErrInvalid)
	}
	generated := make([]byte, 32)
	defer wipeApplicationSecret(generated)
	s.randomMu.Lock()
	_, randomErr := io.ReadFull(s.random, generated)
	s.randomMu.Unlock()
	if randomErr != nil {
		return nil, fmt.Errorf("generate workspace Codex auth key: %w", randomErr)
	}
	name := workspaceCodexAuthKeyName(value.ID)
	aad := workspaceCodexAuthKeyAAD(value.OwnerID, value.Repository.ID, value.ID)
	envelope, err := s.cipher.Encrypt(generated, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt workspace Codex auth key: %w", err)
	}
	encoded, err := envelope.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal workspace Codex auth key: %w", err)
	}
	hash := sha256.Sum256(encoded)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapError("begin workspace Codex auth key load", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO encrypted_secrets
		    (id, owner_id, repository_id, workspace_id, name, encrypted_envelope,
		     redaction_hash, aad_version, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$8)
		ON CONFLICT (owner_id, repository_id, name)
		    WHERE repository_id IS NOT NULL AND deleted_at IS NULL
		DO NOTHING`,
		"codex_auth_key_"+hex.EncodeToString(hash[:16]), value.OwnerID, value.Repository.ID,
		value.ID, name, encoded, hash[:], value.UpdatedAt,
	)
	if err != nil {
		return nil, mapError("create workspace Codex auth key", err)
	}
	var stored []byte
	if err := tx.QueryRow(ctx, `
		SELECT encrypted_envelope FROM encrypted_secrets
		WHERE owner_id=$1 AND repository_id=$2 AND workspace_id=$3 AND name=$4
		  AND deleted_at IS NULL`, value.OwnerID, value.Repository.ID, value.ID, name).Scan(&stored); err != nil {
		return nil, mapError("load workspace Codex auth key", err)
	}
	storedEnvelope, err := vault.Parse(stored)
	wipeApplicationSecret(stored)
	if err != nil {
		return nil, fmt.Errorf("parse workspace Codex auth key envelope: %w", err)
	}
	plaintext, err := s.cipher.Decrypt(storedEnvelope, aad)
	if err != nil || len(plaintext) != 32 {
		wipeApplicationSecret(plaintext)
		return nil, errors.New("stored workspace Codex auth key is invalid")
	}
	if err := tx.Commit(ctx); err != nil {
		wipeApplicationSecret(plaintext)
		return nil, mapError("commit workspace Codex auth key load", err)
	}
	return plaintext, nil
}

func (s *ApplicationStore) SaveWorkspaceInitialPrompt(ctx context.Context, value core.Workspace) error {
	if value.ID == "" || value.OwnerID == "" || value.Repository.ID == "" || len(value.InitialPrompt) > 100000 || strings.ContainsRune(value.InitialPrompt, '\x00') {
		return fmt.Errorf("workspace initial prompt: %w", core.ErrInvalid)
	}
	if value.InitialPrompt == "" {
		return nil
	}
	name := workspaceInitialPromptName(value.ID)
	aad := workspaceInitialPromptAAD(value.OwnerID, value.Repository.ID, value.ID)
	plaintext := []byte(value.InitialPrompt)
	envelope, err := s.cipher.Encrypt(plaintext, aad)
	for index := range plaintext {
		plaintext[index] = 0
	}
	if err != nil {
		return fmt.Errorf("encrypt workspace initial prompt: %w", err)
	}
	ciphertext, err := envelope.Marshal()
	if err != nil {
		return fmt.Errorf("marshal workspace initial prompt: %w", err)
	}
	hash := sha256.Sum256(ciphertext)
	_, err = s.pool.Exec(ctx, `
		INSERT INTO encrypted_secrets
		    (id, owner_id, repository_id, workspace_id, name, encrypted_envelope,
		     redaction_hash, aad_version, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$8)
		ON CONFLICT (owner_id, repository_id, name)
		    WHERE repository_id IS NOT NULL AND deleted_at IS NULL
		DO UPDATE SET encrypted_envelope=EXCLUDED.encrypted_envelope,
		    redaction_hash=EXCLUDED.redaction_hash, workspace_id=EXCLUDED.workspace_id,
		    updated_at=EXCLUDED.updated_at, rotated_at=EXCLUDED.updated_at`,
		"prompt_"+hex.EncodeToString(hash[:16]), value.OwnerID, value.Repository.ID,
		value.ID, name, ciphertext, hash[:], value.UpdatedAt,
	)
	return mapError("save workspace initial prompt", err)
}

func (s *ApplicationStore) LoadWorkspaceInitialPrompt(ctx context.Context, ownerID, repositoryID, workspaceID string) (string, error) {
	if ownerID == "" || repositoryID == "" || workspaceID == "" {
		return "", fmt.Errorf("workspace initial prompt: %w", core.ErrInvalid)
	}
	var ciphertext []byte
	err := s.pool.QueryRow(ctx, `
		SELECT encrypted_envelope FROM encrypted_secrets
		WHERE owner_id=$1 AND repository_id=$2 AND workspace_id=$3 AND name=$4
		  AND deleted_at IS NULL`, ownerID, repositoryID, workspaceID, workspaceInitialPromptName(workspaceID)).Scan(&ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", mapError("load workspace initial prompt", err)
	}
	envelope, err := vault.Parse(ciphertext)
	if err != nil {
		return "", fmt.Errorf("parse workspace initial prompt envelope: %w", err)
	}
	plaintext, err := s.cipher.Decrypt(envelope, workspaceInitialPromptAAD(ownerID, repositoryID, workspaceID))
	if err != nil {
		return "", fmt.Errorf("decrypt workspace initial prompt: %w", err)
	}
	defer func() {
		for index := range plaintext {
			plaintext[index] = 0
		}
	}()
	if len(plaintext) > 100000 || strings.ContainsRune(string(plaintext), '\x00') {
		return "", errors.New("stored workspace initial prompt is invalid")
	}
	return string(plaintext), nil
}

func (s *ApplicationStore) MarkWorkspaceInitialPromptDelivered(ctx context.Context, ownerID, repositoryID, workspaceID string, now time.Time) error {
	if ownerID == "" || repositoryID == "" || workspaceID == "" || now.IsZero() {
		return fmt.Errorf("workspace initial prompt delivery: %w", core.ErrInvalid)
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE encrypted_secrets SET deleted_at=$5, updated_at=$5
		WHERE owner_id=$1 AND repository_id=$2 AND workspace_id=$3 AND name=$4
		  AND deleted_at IS NULL`, ownerID, repositoryID, workspaceID, workspaceInitialPromptName(workspaceID), now)
	return mapError("mark workspace initial prompt delivered", err)
}

func workspaceInitialPromptName(workspaceID string) string {
	return "workspace_prompt:" + workspaceID
}

func workspaceInitialPromptAAD(ownerID, repositoryID, workspaceID string) []byte {
	return []byte("codex-mobile:workspace-prompt:v1:" + ownerID + ":" + repositoryID + ":" + workspaceID)
}

func workspaceEnvironmentName(workspaceID, name string) string {
	return "workspace_env:" + workspaceID + ":" + name
}

func workspaceEnvironmentAAD(ownerID, repositoryID, workspaceID, name string) []byte {
	return []byte("codex-mobile:workspace-env:v1:" + ownerID + ":" + repositoryID + ":" + workspaceID + ":" + name)
}

func workspaceCodexAuthKeyName(workspaceID string) string {
	return "workspace_codex_auth_key:" + workspaceID
}

func workspaceCodexAuthKeyAAD(ownerID, repositoryID, workspaceID string) []byte {
	return []byte("codex-mobile:workspace-codex-auth-key:v1:" + ownerID + ":" + repositoryID + ":" + workspaceID)
}

func wipeApplicationSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type TerminalTabRecord struct {
	ID               string
	OwnerID          string
	WorkspaceID      string
	Title            string
	Kind             string
	Order            int
	CoderReconnectID string
	CodexThreadID    string
	CreatedAt        time.Time
	LastAttachedAt   *time.Time
	ClosedAt         *time.Time
}

func (s *ApplicationStore) CreateTerminalTab(ctx context.Context, value TerminalTabRecord) (TerminalTabRecord, error) {
	if value.ID == "" || value.OwnerID == "" || value.WorkspaceID == "" || value.Title == "" ||
		value.CoderReconnectID == "" || value.CreatedAt.IsZero() || !validTerminalKind(value.Kind) {
		return TerminalTabRecord{}, fmt.Errorf("terminal tab: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TerminalTabRecord{}, mapError("begin terminal tab creation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, advisoryLockKey("terminal-tab-order", value.OwnerID, value.WorkspaceID)); err != nil {
		return TerminalTabRecord{}, mapError("lock terminal tab order", err)
	}
	var activeCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*), COALESCE(max(sort_order) + 1, 0)
		FROM terminal_tabs
		WHERE owner_id = $1 AND workspace_id = $2 AND closed_at IS NULL`, value.OwnerID, value.WorkspaceID).Scan(&activeCount, &value.Order); err != nil {
		return TerminalTabRecord{}, mapError("choose terminal tab order", err)
	}
	if activeCount >= 64 || value.Order > 999 {
		return TerminalTabRecord{}, fmt.Errorf("terminal tab limit: %w", core.ErrCapacity)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO terminal_tabs
		    (id, owner_id, workspace_id, title, kind, sort_order,
		     coder_reconnect_id, codex_thread_id, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		value.ID, value.OwnerID, value.WorkspaceID, value.Title, value.Kind, value.Order,
		value.CoderReconnectID, value.CodexThreadID, value.CreatedAt,
	)
	if err != nil {
		return TerminalTabRecord{}, mapError("create terminal tab", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return TerminalTabRecord{}, mapError("commit terminal tab", err)
	}
	return value, nil
}

func (s *ApplicationStore) ListTerminalTabs(ctx context.Context, ownerID, workspaceID string) ([]TerminalTabRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, owner_id, workspace_id, title, kind, sort_order,
		       coder_reconnect_id, codex_thread_id, created_at, last_attached_at
		FROM terminal_tabs
		WHERE owner_id = $1 AND workspace_id = $2 AND closed_at IS NULL
		ORDER BY sort_order, created_at, id`, ownerID, workspaceID)
	if err != nil {
		return nil, mapError("list terminal tabs", err)
	}
	defer rows.Close()
	values := make([]TerminalTabRecord, 0)
	for rows.Next() {
		var value TerminalTabRecord
		if err := rows.Scan(&value.ID, &value.OwnerID, &value.WorkspaceID, &value.Title, &value.Kind,
			&value.Order, &value.CoderReconnectID, &value.CodexThreadID, &value.CreatedAt, &value.LastAttachedAt); err != nil {
			return nil, mapError("scan terminal tab", err)
		}
		values = append(values, value)
	}
	return values, mapError("iterate terminal tabs", rows.Err())
}

func (s *ApplicationStore) GetTerminalTab(ctx context.Context, ownerID, workspaceID, tabID string) (TerminalTabRecord, error) {
	var value TerminalTabRecord
	err := s.pool.QueryRow(ctx, `
		SELECT id, owner_id, workspace_id, title, kind, sort_order,
		       coder_reconnect_id, codex_thread_id, created_at, last_attached_at
		FROM terminal_tabs
		WHERE owner_id = $1 AND workspace_id = $2 AND id = $3 AND closed_at IS NULL`,
		ownerID, workspaceID, tabID).Scan(
		&value.ID, &value.OwnerID, &value.WorkspaceID, &value.Title, &value.Kind,
		&value.Order, &value.CoderReconnectID, &value.CodexThreadID, &value.CreatedAt, &value.LastAttachedAt,
	)
	if err != nil {
		return TerminalTabRecord{}, mapError("get terminal tab", err)
	}
	return value, nil
}

func (s *ApplicationStore) RenameTerminalTab(ctx context.Context, ownerID, workspaceID, tabID, title string) (TerminalTabRecord, error) {
	if ownerID == "" || workspaceID == "" || tabID == "" || title == "" {
		return TerminalTabRecord{}, fmt.Errorf("rename terminal tab: %w", core.ErrInvalid)
	}
	var value TerminalTabRecord
	err := s.pool.QueryRow(ctx, `
		UPDATE terminal_tabs SET title = $4
		WHERE owner_id = $1 AND workspace_id = $2 AND id = $3 AND closed_at IS NULL
		RETURNING id, owner_id, workspace_id, title, kind, sort_order,
		          coder_reconnect_id, codex_thread_id, created_at, last_attached_at`,
		ownerID, workspaceID, tabID, title).Scan(
		&value.ID, &value.OwnerID, &value.WorkspaceID, &value.Title, &value.Kind,
		&value.Order, &value.CoderReconnectID, &value.CodexThreadID, &value.CreatedAt, &value.LastAttachedAt,
	)
	if err != nil {
		return TerminalTabRecord{}, mapError("rename terminal tab", err)
	}
	return value, nil
}

// ReorderTerminalTabs validates and rewrites the complete active tab order in
// one transaction. Callers cannot reorder a stale subset or smuggle in a tab
// from another owner/workspace. Temporary free sort positions avoid transient
// conflicts with the active partial unique index while final positions move.
func (s *ApplicationStore) ReorderTerminalTabs(ctx context.Context, ownerID, workspaceID string, orderedIDs []string) ([]TerminalTabRecord, error) {
	if ownerID == "" || workspaceID == "" || !validTerminalTabOrder(orderedIDs) {
		return nil, fmt.Errorf("reorder terminal tabs: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, mapError("begin terminal tab reorder", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, advisoryLockKey("terminal-tab-order", ownerID, workspaceID)); err != nil {
		return nil, mapError("lock terminal tab reorder", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT id, owner_id, workspace_id, title, kind, sort_order,
		       coder_reconnect_id, codex_thread_id, created_at, last_attached_at
		FROM terminal_tabs
		WHERE owner_id = $1 AND workspace_id = $2 AND closed_at IS NULL
		ORDER BY sort_order, created_at, id
		FOR UPDATE`, ownerID, workspaceID)
	if err != nil {
		return nil, mapError("load terminal tabs for reorder", err)
	}
	active := make(map[string]TerminalTabRecord, len(orderedIDs))
	occupied := make(map[int]struct{}, len(orderedIDs))
	for rows.Next() {
		var value TerminalTabRecord
		if err := rows.Scan(&value.ID, &value.OwnerID, &value.WorkspaceID, &value.Title, &value.Kind,
			&value.Order, &value.CoderReconnectID, &value.CodexThreadID, &value.CreatedAt, &value.LastAttachedAt); err != nil {
			rows.Close()
			return nil, mapError("scan terminal tabs for reorder", err)
		}
		active[value.ID] = value
		occupied[value.Order] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate terminal tabs for reorder", err)
	}
	if len(active) != len(orderedIDs) {
		return nil, fmt.Errorf("reorder terminal tabs membership: %w", core.ErrConflict)
	}
	for _, tabID := range orderedIDs {
		if _, exists := active[tabID]; !exists {
			return nil, fmt.Errorf("reorder terminal tabs membership: %w", core.ErrConflict)
		}
	}

	temporary := make([]int, 0, len(orderedIDs))
	for candidate := 999; candidate >= len(orderedIDs) && len(temporary) < len(orderedIDs); candidate-- {
		if _, inUse := occupied[candidate]; !inUse {
			temporary = append(temporary, candidate)
		}
	}
	if len(temporary) != len(orderedIDs) {
		return nil, fmt.Errorf("reorder terminal tabs temporary order: %w", core.ErrCapacity)
	}
	for index, tabID := range orderedIDs {
		tag, err := tx.Exec(ctx, `
			UPDATE terminal_tabs SET sort_order = $4
			WHERE owner_id = $1 AND workspace_id = $2 AND id = $3 AND closed_at IS NULL`,
			ownerID, workspaceID, tabID, temporary[index])
		if err != nil {
			return nil, mapError("stage terminal tab reorder", err)
		}
		if tag.RowsAffected() != 1 {
			return nil, fmt.Errorf("stage terminal tab reorder: %w", core.ErrConflict)
		}
	}
	result := make([]TerminalTabRecord, 0, len(orderedIDs))
	for index, tabID := range orderedIDs {
		tag, err := tx.Exec(ctx, `
			UPDATE terminal_tabs SET sort_order = $4
			WHERE owner_id = $1 AND workspace_id = $2 AND id = $3 AND closed_at IS NULL`,
			ownerID, workspaceID, tabID, index)
		if err != nil {
			return nil, mapError("finish terminal tab reorder", err)
		}
		if tag.RowsAffected() != 1 {
			return nil, fmt.Errorf("finish terminal tab reorder: %w", core.ErrConflict)
		}
		value := active[tabID]
		value.Order = index
		result = append(result, value)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapError("commit terminal tab reorder", err)
	}
	return result, nil
}

// CloseTerminalTab marks one active tab closed and compacts the remaining
// order under the same advisory lock used by create/reorder. The oldest active
// Codex tab is the workspace's primary authoritative TUI and cannot be closed.
// Repeating a completed close is a successful no-op.
func (s *ApplicationStore) CloseTerminalTab(ctx context.Context, ownerID, workspaceID, tabID string, now time.Time) (TerminalTabRecord, bool, error) {
	if ownerID == "" || workspaceID == "" || tabID == "" || now.IsZero() {
		return TerminalTabRecord{}, false, fmt.Errorf("close terminal tab: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TerminalTabRecord{}, false, mapError("begin terminal tab close", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, advisoryLockKey("terminal-tab-order", ownerID, workspaceID)); err != nil {
		return TerminalTabRecord{}, false, mapError("lock terminal tab close", err)
	}
	var value TerminalTabRecord
	err = tx.QueryRow(ctx, `
		SELECT id, owner_id, workspace_id, title, kind, sort_order,
		       coder_reconnect_id, codex_thread_id, created_at, last_attached_at, closed_at
		FROM terminal_tabs
		WHERE owner_id = $1 AND workspace_id = $2 AND id = $3
		FOR UPDATE`, ownerID, workspaceID, tabID).Scan(
		&value.ID, &value.OwnerID, &value.WorkspaceID, &value.Title, &value.Kind,
		&value.Order, &value.CoderReconnectID, &value.CodexThreadID, &value.CreatedAt, &value.LastAttachedAt, &value.ClosedAt,
	)
	if err != nil {
		return TerminalTabRecord{}, false, mapError("get terminal tab for close", err)
	}
	if value.ClosedAt != nil {
		return value, false, nil
	}
	var primaryCodexID string
	err = tx.QueryRow(ctx, `
		SELECT id FROM terminal_tabs
		WHERE owner_id = $1 AND workspace_id = $2 AND kind = 'codex' AND closed_at IS NULL
		ORDER BY created_at, id LIMIT 1`, ownerID, workspaceID).Scan(&primaryCodexID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return TerminalTabRecord{}, false, mapError("identify primary Codex tab", err)
	}
	if primaryCodexID == value.ID {
		return TerminalTabRecord{}, false, fmt.Errorf("close primary Codex tab: %w", core.ErrConflict)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE terminal_tabs SET closed_at = $4
		WHERE owner_id = $1 AND workspace_id = $2 AND id = $3 AND closed_at IS NULL`,
		ownerID, workspaceID, tabID, now); err != nil {
		return TerminalTabRecord{}, false, mapError("close terminal tab", err)
	}
	value.ClosedAt = &now
	rows, err := tx.Query(ctx, `
		SELECT id, sort_order FROM terminal_tabs
		WHERE owner_id = $1 AND workspace_id = $2 AND closed_at IS NULL
		ORDER BY sort_order, created_at, id
		FOR UPDATE`, ownerID, workspaceID)
	if err != nil {
		return TerminalTabRecord{}, false, mapError("load terminal tabs after close", err)
	}
	type activeOrder struct {
		id    string
		order int
	}
	remaining := make([]activeOrder, 0, 64)
	for rows.Next() {
		var entry activeOrder
		if err := rows.Scan(&entry.id, &entry.order); err != nil {
			rows.Close()
			return TerminalTabRecord{}, false, mapError("scan terminal tabs after close", err)
		}
		remaining = append(remaining, entry)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return TerminalTabRecord{}, false, mapError("iterate terminal tabs after close", err)
	}
	for index, entry := range remaining {
		if entry.order == index {
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE terminal_tabs SET sort_order = $4
			WHERE owner_id = $1 AND workspace_id = $2 AND id = $3 AND closed_at IS NULL`,
			ownerID, workspaceID, entry.id, index); err != nil {
			return TerminalTabRecord{}, false, mapError("compact terminal tab order", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return TerminalTabRecord{}, false, mapError("commit terminal tab close", err)
	}
	return value, true, nil
}

func validTerminalTabOrder(orderedIDs []string) bool {
	if len(orderedIDs) < 1 || len(orderedIDs) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(orderedIDs))
	for _, tabID := range orderedIDs {
		if tabID == "" {
			return false
		}
		if _, duplicate := seen[tabID]; duplicate {
			return false
		}
		seen[tabID] = struct{}{}
	}
	return true
}

func (s *ApplicationStore) TouchTerminalTab(ctx context.Context, ownerID, workspaceID, tabID string, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE terminal_tabs SET last_attached_at = $4
		WHERE owner_id = $1 AND workspace_id = $2 AND id = $3 AND closed_at IS NULL`,
		ownerID, workspaceID, tabID, now)
	if err != nil {
		return mapError("touch terminal tab", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("touch terminal tab: %w", core.ErrNotFound)
	}
	return nil
}

func (s *ApplicationStore) SetTerminalCodexThreadID(ctx context.Context, ownerID, workspaceID, tabID, threadID string) (TerminalTabRecord, error) {
	if ownerID == "" || workspaceID == "" || !validUUIDIdentity(tabID) || !validUUIDIdentity(threadID) {
		return TerminalTabRecord{}, fmt.Errorf("set terminal Codex thread: %w", core.ErrInvalid)
	}
	var value TerminalTabRecord
	err := s.pool.QueryRow(ctx, `
		UPDATE terminal_tabs SET codex_thread_id = $4
		WHERE owner_id = $1 AND workspace_id = $2 AND id = $3
		  AND kind = 'codex' AND closed_at IS NULL
		RETURNING id, owner_id, workspace_id, title, kind, sort_order,
		          coder_reconnect_id, codex_thread_id, created_at, last_attached_at`,
		ownerID, workspaceID, tabID, threadID).Scan(
		&value.ID, &value.OwnerID, &value.WorkspaceID, &value.Title, &value.Kind,
		&value.Order, &value.CoderReconnectID, &value.CodexThreadID, &value.CreatedAt, &value.LastAttachedAt,
	)
	if err != nil {
		return TerminalTabRecord{}, mapError("set terminal Codex thread", err)
	}
	return value, nil
}

func validUUIDIdentity(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, part := range decoded {
		if part != 0 {
			return true
		}
	}
	return false
}

func validTerminalKind(value string) bool {
	return value == "codex" || value == "shell" || value == "server" || value == "test" || value == "log"
}

type ActivityRecord struct {
	ID          string
	WorkspaceID *string
	Kind        string
	Summary     string
	Unread      bool
	Metadata    json.RawMessage
	CreatedAt   time.Time
}

func (s *ApplicationStore) ListActivity(ctx context.Context, ownerID string, limit int) ([]ActivityRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, workspace_id, kind, summary, unread, metadata, created_at
		FROM workspace_activity WHERE owner_id = $1
		ORDER BY created_at DESC, id DESC LIMIT $2`, ownerID, limit)
	if err != nil {
		return nil, mapError("list activity", err)
	}
	defer rows.Close()
	values := make([]ActivityRecord, 0)
	for rows.Next() {
		var value ActivityRecord
		if err := rows.Scan(&value.ID, &value.WorkspaceID, &value.Kind, &value.Summary, &value.Unread, &value.Metadata, &value.CreatedAt); err != nil {
			return nil, mapError("scan activity", err)
		}
		values = append(values, value)
	}
	return values, mapError("iterate activity", rows.Err())
}

func (s *ApplicationStore) AddActivity(ctx context.Context, ownerID string, value ActivityRecord) error {
	if ownerID == "" || value.ID == "" || value.Summary == "" || len(value.Summary) > 4096 || value.CreatedAt.IsZero() {
		return fmt.Errorf("activity: %w", core.ErrInvalid)
	}
	if value.Kind != "approval" && value.Kind != "question" && value.Kind != "completed" && value.Kind != "failed" && value.Kind != "maintenance" {
		return fmt.Errorf("activity kind: %w", core.ErrInvalid)
	}
	metadata := value.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO workspace_activity (id, owner_id, workspace_id, kind, summary, unread, metadata, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, value.ID, ownerID, value.WorkspaceID,
		value.Kind, value.Summary, value.Unread, metadata, value.CreatedAt)
	return mapError("add activity", err)
}

type SafetyEvent struct {
	ID            string
	WorkspaceID   string
	WorkspaceName string
	SafetyMode    string
	Action        string
	Decision      string
	Reason        string
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	ResolvedAt    *time.Time
}

// EnsureSetupReview atomically reconciles the durable safety event and its
// linked activity. Locking the workspace row makes concurrent application and
// lifecycle repair attempts converge on one pending review without requiring
// a process-local singleton.
func (s *ApplicationStore) EnsureSetupReview(ctx context.Context, request setupreview.Request) (setupreview.Result, error) {
	if request.OwnerID == "" || request.WorkspaceID == "" || request.ApprovalID == "" || request.ActivityID == "" ||
		request.Reason == "" || len(request.Reason) > 4096 || request.CreatedAt.IsZero() {
		return setupreview.Result{}, fmt.Errorf("ensure setup review: %w", core.ErrInvalid)
	}
	switch core.SafetyMode(request.SafetyMode) {
	case core.SafetySafe, core.SafetyBalanced, core.SafetyFullAccess:
	default:
		return setupreview.Result{}, fmt.Errorf("ensure setup review mode: %w", core.ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return setupreview.Result{}, mapError("begin setup review reconciliation", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var state core.WorkspaceState
	if err := tx.QueryRow(ctx, `
		SELECT state FROM workspaces
		WHERE owner_id = $1 AND id = $2
		FOR UPDATE`, request.OwnerID, request.WorkspaceID).Scan(&state); err != nil {
		return setupreview.Result{}, mapError("lock setup review workspace", err)
	}
	if state != core.WorkspaceAwaitingSetupApproval {
		return setupreview.Result{}, fmt.Errorf("ensure setup review workspace state: %w", core.ErrConflict)
	}

	approvalID := ""
	err = tx.QueryRow(ctx, `
		SELECT id
		FROM workspace_safety_events
		WHERE owner_id = $1 AND workspace_id = $2
		  AND action = 'approve_repository_setup'
		  AND decision = 'requested' AND resolved_at IS NULL
		ORDER BY created_at DESC, id DESC
		LIMIT 1`, request.OwnerID, request.WorkspaceID).Scan(&approvalID)
	if errors.Is(err, pgx.ErrNoRows) {
		approvalID = request.ApprovalID
		_, err = tx.Exec(ctx, `
			INSERT INTO workspace_safety_events
			    (id, owner_id, workspace_id, safety_mode, action, decision, reason, created_at, expires_at)
			VALUES ($1,$2,$3,$4,'approve_repository_setup','requested',$5,$6,NULL)`,
			approvalID, request.OwnerID, request.WorkspaceID, request.SafetyMode, request.Reason, request.CreatedAt)
	} else if err == nil {
		_, err = tx.Exec(ctx, `
			UPDATE workspace_safety_events
			SET safety_mode = $3, reason = $4, expires_at = NULL
			WHERE owner_id = $1 AND id = $2
			  AND action = 'approve_repository_setup'
			  AND decision = 'requested' AND resolved_at IS NULL`,
			request.OwnerID, approvalID, request.SafetyMode, request.Reason)
	}
	if err != nil {
		return setupreview.Result{}, mapError("ensure setup review event", err)
	}

	activityID := ""
	err = tx.QueryRow(ctx, `
		SELECT id
		FROM workspace_activity
		WHERE owner_id = $1 AND workspace_id = $2 AND kind = 'approval'
		  AND metadata ->> 'approval_id' = $3
		ORDER BY created_at DESC, id DESC
		LIMIT 1`, request.OwnerID, request.WorkspaceID, approvalID).Scan(&activityID)
	activityCreated := false
	if errors.Is(err, pgx.ErrNoRows) {
		activityID = request.ActivityID
		metadata, marshalErr := json.Marshal(map[string]string{"approval_id": approvalID})
		if marshalErr != nil {
			return setupreview.Result{}, marshalErr
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO workspace_activity
			    (id, owner_id, workspace_id, kind, summary, unread, metadata, created_at)
			VALUES ($1,$2,$3,'approval','Workspace setup requires approval.',true,$4,$5)`,
			activityID, request.OwnerID, request.WorkspaceID, metadata, request.CreatedAt)
		activityCreated = err == nil
	}
	if err != nil {
		return setupreview.Result{}, mapError("ensure setup review activity", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return setupreview.Result{}, mapError("commit setup review reconciliation", err)
	}
	return setupreview.Result{ApprovalID: approvalID, ActivityID: activityID, ActivityCreated: activityCreated}, nil
}

func (s *ApplicationStore) GetSafetyEvent(ctx context.Context, ownerID, id string) (SafetyEvent, error) {
	var value SafetyEvent
	err := s.pool.QueryRow(ctx, `
		SELECT e.id, e.workspace_id, w.name, e.safety_mode, e.action, e.decision,
		       e.reason, e.created_at, e.expires_at, e.resolved_at
		FROM workspace_safety_events e
		JOIN workspaces w ON w.owner_id = e.owner_id AND w.id = e.workspace_id
		WHERE e.owner_id = $1 AND e.id = $2`, ownerID, id).Scan(
		&value.ID, &value.WorkspaceID, &value.WorkspaceName, &value.SafetyMode,
		&value.Action, &value.Decision, &value.Reason, &value.CreatedAt, &value.ExpiresAt, &value.ResolvedAt,
	)
	if err != nil {
		return SafetyEvent{}, mapError("get safety event", err)
	}
	return value, nil
}

func (s *ApplicationStore) ResolveSafetyEvent(ctx context.Context, ownerID, id, decision, deviceID string, now time.Time) (SafetyEvent, error) {
	if decision != "approved" && decision != "denied" {
		return SafetyEvent{}, fmt.Errorf("approval decision: %w", core.ErrInvalid)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE workspace_safety_events
		SET decision = $3, actor_device_id = $4, resolved_at = $5
		WHERE owner_id = $1 AND id = $2 AND decision = 'requested'
		  AND resolved_at IS NULL
		  AND (action = 'approve_repository_setup' OR expires_at IS NULL OR expires_at > $5)`,
		ownerID, id, decision, deviceID, now)
	if err != nil {
		return SafetyEvent{}, mapError("resolve safety event", err)
	}
	if tag.RowsAffected() != 1 {
		return SafetyEvent{}, fmt.Errorf("resolve safety event: %w", core.ErrConflict)
	}
	return s.GetSafetyEvent(ctx, ownerID, id)
}

type PreviewRouteRecord struct {
	ID, OwnerID, WorkspaceID, ProcessName, WorkspaceHost string
	Port                                                 int
	CreatedAt                                            time.Time
	RevokedAt                                            *time.Time
}

func (s *ApplicationStore) SyncPreviewRoutes(ctx context.Context, ownerID, workspaceID string, routes []PreviewRouteRecord, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin preview route sync", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	ports := make([]int, 0, len(routes))
	for _, route := range routes {
		if route.ID == "" || route.Port < 1024 || route.Port > 65535 || len(route.ProcessName) > 512 {
			return fmt.Errorf("preview route: %w", core.ErrInvalid)
		}
		ports = append(ports, route.Port)
		_, err := tx.Exec(ctx, `
			INSERT INTO preview_routes
			    (id, owner_id, workspace_id, port, process_name, workspace_host, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (workspace_id, port) DO UPDATE SET
			    process_name = EXCLUDED.process_name,
			    workspace_host = EXCLUDED.workspace_host,
			    revoked_at = NULL`, route.ID, ownerID, workspaceID, route.Port,
			route.ProcessName, route.WorkspaceHost, route.CreatedAt)
		if err != nil {
			return mapError("upsert preview route", err)
		}
	}
	if len(ports) == 0 {
		_, err = tx.Exec(ctx, `UPDATE preview_routes SET revoked_at = $3 WHERE owner_id = $1 AND workspace_id = $2 AND revoked_at IS NULL`, ownerID, workspaceID, now)
	} else {
		_, err = tx.Exec(ctx, `UPDATE preview_routes SET revoked_at = $3 WHERE owner_id = $1 AND workspace_id = $2 AND revoked_at IS NULL AND NOT (port = ANY($4))`, ownerID, workspaceID, now, ports)
	}
	if err != nil {
		return mapError("revoke stale preview routes", err)
	}
	return mapError("commit preview route sync", tx.Commit(ctx))
}

func (s *ApplicationStore) ListPreviewRoutes(ctx context.Context, ownerID, workspaceID string) ([]PreviewRouteRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, owner_id, workspace_id, port, process_name, workspace_host, created_at, revoked_at
		FROM preview_routes
		WHERE owner_id = $1 AND workspace_id = $2 AND revoked_at IS NULL
		ORDER BY port`, ownerID, workspaceID)
	if err != nil {
		return nil, mapError("list preview routes", err)
	}
	defer rows.Close()
	values := make([]PreviewRouteRecord, 0)
	for rows.Next() {
		var value PreviewRouteRecord
		if err := rows.Scan(&value.ID, &value.OwnerID, &value.WorkspaceID, &value.Port,
			&value.ProcessName, &value.WorkspaceHost, &value.CreatedAt, &value.RevokedAt); err != nil {
			return nil, mapError("scan preview route", err)
		}
		values = append(values, value)
	}
	return values, mapError("iterate preview routes", rows.Err())
}

func (s *ApplicationStore) GetPreviewRoute(ctx context.Context, ownerID, workspaceID, id string) (PreviewRouteRecord, error) {
	var value PreviewRouteRecord
	err := s.pool.QueryRow(ctx, `
		SELECT id, owner_id, workspace_id, port, process_name, workspace_host, created_at, revoked_at
		FROM preview_routes
		WHERE owner_id=$1 AND workspace_id=$2 AND id=$3 AND revoked_at IS NULL`, ownerID, workspaceID, id).Scan(
		&value.ID, &value.OwnerID, &value.WorkspaceID, &value.Port, &value.ProcessName,
		&value.WorkspaceHost, &value.CreatedAt, &value.RevokedAt)
	if err != nil {
		return PreviewRouteRecord{}, mapError("get preview route", err)
	}
	return value, nil
}

func (s *ApplicationStore) PreviewRouteByID(ctx context.Context, id string) (PreviewRouteRecord, error) {
	var value PreviewRouteRecord
	err := s.pool.QueryRow(ctx, `
		SELECT id, owner_id, workspace_id, port, process_name, workspace_host, created_at, revoked_at
		FROM preview_routes WHERE id=$1 AND revoked_at IS NULL`, id).Scan(
		&value.ID, &value.OwnerID, &value.WorkspaceID, &value.Port, &value.ProcessName,
		&value.WorkspaceHost, &value.CreatedAt, &value.RevokedAt)
	if err != nil {
		return PreviewRouteRecord{}, mapError("resolve preview route", err)
	}
	return value, nil
}

func (s *ApplicationStore) RevokePreviewRoute(ctx context.Context, ownerID, workspaceID, id string, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE preview_routes SET revoked_at = $4
		WHERE owner_id=$1 AND workspace_id=$2 AND id=$3 AND revoked_at IS NULL`, ownerID, workspaceID, id, now)
	if err != nil {
		return mapError("revoke preview route", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("revoke preview route: %w", core.ErrNotFound)
	}
	return nil
}

type NotificationEndpointRecord struct {
	ID          string
	OwnerID     string
	DeviceID    string
	Environment string
	Token       []byte
	Topic       string
}

func (s *ApplicationStore) RegisterNotification(ctx context.Context, ownerID, deviceID, environment, token, topic string, now time.Time) error {
	if ownerID == "" || deviceID == "" || (environment != "sandbox" && environment != "production") ||
		len(token) < 64 || len(token) > 200 || len(token)%2 != 0 || topic == "" || len(topic) > 255 || now.IsZero() {
		return fmt.Errorf("notification endpoint: %w", core.ErrInvalid)
	}
	if _, err := hex.DecodeString(token); err != nil {
		return fmt.Errorf("notification endpoint: %w", core.ErrInvalid)
	}
	hash := sha256.Sum256([]byte(token))
	idHash := sha256.Sum256([]byte("codex-mobile:notification-id:v1:" + ownerID + "\x00" + deviceID + "\x00" + environment + "\x00" + token))
	id := "apns_" + hex.EncodeToString(idHash[:16])
	aad := notificationAAD(ownerID, deviceID, environment)
	plaintext := []byte(token)
	envelope, err := s.cipher.Encrypt(plaintext, aad)
	clear(plaintext)
	if err != nil {
		return fmt.Errorf("encrypt notification token: %w", err)
	}
	ciphertext, err := envelope.Marshal()
	if err != nil {
		return fmt.Errorf("marshal notification token: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapError("begin notification registration", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	// Device authority and endpoint registration share the exact device-row
	// lock used by SessionStore.RevokeDevice. If registration wins, a later
	// revocation waits and sweeps the endpoint; if revocation wins, this request
	// observes the durable revoked state and cannot reactivate notifications.
	var deviceRevokedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT revoked_at
		FROM devices
		WHERE owner_id=$1 AND id=$2
		FOR UPDATE`, ownerID, deviceID).Scan(&deviceRevokedAt); err != nil {
		return mapError("lock notification device", err)
	}
	if deviceRevokedAt != nil {
		return fmt.Errorf("notification device is revoked: %w", core.ErrUnauthorized)
	}
	// APNs tokens rotate. Keep at most the newly registered token enabled for a
	// device/environment so a stale token cannot receive duplicate deliveries.
	if _, err := tx.Exec(ctx, `
		UPDATE notification_endpoints
		SET enabled=false, revoked_at=$5, updated_at=$5
		WHERE owner_id=$1 AND device_id=$2 AND provider='apns' AND environment=$3
		  AND token_hash <> $4 AND enabled AND revoked_at IS NULL`,
		ownerID, deviceID, environment, hash[:], now); err != nil {
		return mapError("revoke rotated notification endpoint", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO notification_endpoints
		    (id, owner_id, device_id, provider, environment, token_hash,
		     encrypted_token, topic, enabled, created_at, updated_at)
		VALUES ($1,$2,$3,'apns',$4,$5,$6,$7,true,$8,$8)
		ON CONFLICT (owner_id, device_id, provider, environment, token_hash) DO UPDATE SET
		    encrypted_token=EXCLUDED.encrypted_token, topic=EXCLUDED.topic,
		    enabled=true, updated_at=EXCLUDED.updated_at, revoked_at=NULL`,
		id, ownerID, deviceID, environment, hash[:], ciphertext, topic, now)
	if err != nil {
		return mapError("register notification endpoint", err)
	}
	return mapError("commit notification registration", tx.Commit(ctx))
}

func (s *ApplicationStore) ListNotificationEndpoints(ctx context.Context, ownerID string) ([]NotificationEndpointRecord, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("notification endpoint owner: %w", core.ErrInvalid)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, owner_id, device_id, environment, encrypted_token, topic
		FROM notification_endpoints
		WHERE owner_id=$1 AND provider='apns' AND enabled AND revoked_at IS NULL
		ORDER BY updated_at DESC, id
		LIMIT 128`, ownerID)
	if err != nil {
		return nil, mapError("list notification endpoints", err)
	}
	defer rows.Close()
	values := make([]NotificationEndpointRecord, 0)
	complete := false
	defer func() {
		if !complete {
			clearNotificationEndpointTokens(values)
		}
	}()
	for rows.Next() {
		var value NotificationEndpointRecord
		var ciphertext []byte
		if err := rows.Scan(&value.ID, &value.OwnerID, &value.DeviceID, &value.Environment, &ciphertext, &value.Topic); err != nil {
			return nil, mapError("scan notification endpoint", err)
		}
		if value.OwnerID != ownerID || (value.Environment != "sandbox" && value.Environment != "production") {
			return nil, errors.New("stored notification endpoint identity is invalid")
		}
		envelope, err := vault.Parse(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("parse notification token envelope: %w", err)
		}
		plaintext, err := s.cipher.Decrypt(envelope, notificationAAD(value.OwnerID, value.DeviceID, value.Environment))
		if err != nil {
			return nil, fmt.Errorf("decrypt notification token: %w", err)
		}
		if len(plaintext) < 64 || len(plaintext) > 200 || len(plaintext)%2 != 0 {
			clear(plaintext)
			return nil, errors.New("stored notification token is invalid")
		}
		if _, err := hex.DecodeString(string(plaintext)); err != nil {
			clear(plaintext)
			return nil, errors.New("stored notification token is invalid")
		}
		value.Token = plaintext
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError("iterate notification endpoints", err)
	}
	complete = true
	return values, nil
}

func clearNotificationEndpointTokens(values []NotificationEndpointRecord) {
	for index := range values {
		clear(values[index].Token)
	}
}

func (s *ApplicationStore) MarkNotificationDelivered(ctx context.Context, ownerID, endpointID string, now time.Time) error {
	if ownerID == "" || endpointID == "" || now.IsZero() {
		return fmt.Errorf("notification delivery status: %w", core.ErrInvalid)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE notification_endpoints
		SET last_success_at=$3, updated_at=$3
		WHERE owner_id=$1 AND id=$2 AND provider='apns' AND enabled AND revoked_at IS NULL`, ownerID, endpointID, now)
	if err != nil {
		return mapError("mark notification delivered", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("mark notification delivered: %w", core.ErrNotFound)
	}
	return nil
}

func (s *ApplicationStore) MarkNotificationFailed(ctx context.Context, ownerID, endpointID string, disable bool, now time.Time) error {
	if ownerID == "" || endpointID == "" || now.IsZero() {
		return fmt.Errorf("notification failure status: %w", core.ErrInvalid)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE notification_endpoints
		SET last_failure_at=$4, updated_at=$4,
		    enabled=CASE WHEN $3 THEN false ELSE enabled END,
		    revoked_at=CASE WHEN $3 THEN $4 ELSE revoked_at END
		WHERE owner_id=$1 AND id=$2 AND provider='apns' AND revoked_at IS NULL`, ownerID, endpointID, disable, now)
	if err != nil {
		return mapError("mark notification failed", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("mark notification failed: %w", core.ErrNotFound)
	}
	return nil
}

func notificationAAD(ownerID, deviceID, environment string) []byte {
	return []byte("codex-mobile:notification:v1:" + ownerID + ":" + deviceID + ":" + environment)
}

func (s *ApplicationStore) Audit(ctx context.Context, ownerID, deviceID, workspaceID, action, result, targetType, targetID string, details json.RawMessage, now time.Time) error {
	if action == "" || (result != "success" && result != "denied" && result != "failed" && result != "cancelled") {
		return fmt.Errorf("audit event: %w", core.ErrInvalid)
	}
	if len(details) == 0 {
		details = json.RawMessage(`{}`)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_events
		    (owner_id, device_id, workspace_id, action, result, target_type, target_id, details, created_at)
		VALUES (NULLIF($1,''),NULLIF($2,''),NULLIF($3,''),$4,$5,$6,$7,$8,$9)`,
		ownerID, deviceID, workspaceID, action, result, targetType, targetID, details, now)
	return mapError("write audit event", err)
}
