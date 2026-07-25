//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/passkeys"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	secretmodel "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/secrets"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/setupreview"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/migrations"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIntegrationPersistence(t *testing.T) {
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN is not set; see migrations/README.md")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := admin.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("codex_mobile_test_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_, _ = admin.Exec(cleanup, `DROP SCHEMA IF EXISTS `+identifier+` CASCADE`)
	})
	pool, err := postgres.Open(ctx, postgres.PoolConfig{URL: dsn, SearchPath: schema, MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("idempotent migration run failed: %v", err)
	}
	var migrationCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&migrationCount); err != nil || migrationCount != 13 {
		t.Fatalf("migration versioning mismatch: count=%d err=%v", migrationCount, err)
	}

	credentialVault, err := vault.New(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	passkeyStore, err := postgres.NewPasskeyStore(pool, credentialVault)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	credential := webauthn.Credential{ID: []byte("credential-1"), PublicKey: []byte("public-key"), Authenticator: webauthn.Authenticator{SignCount: 1}}
	owner := passkeys.Owner{ID: "owner-1", Handle: bytes.Repeat([]byte{0x31}, 64), Name: "owner", DisplayName: "Owner"}
	record := passkeys.CredentialRecord{
		RPID: "codex.example.test", OwnerID: owner.ID, DeviceID: "device-1", DeviceName: "Test Phone",
		DeviceInstanceHash: [32]byte{0x41}, Credential: credential, CreatedAt: now,
	}
	if err := passkeyStore.CreateOwnerWithCredential(ctx, owner, record); err != nil {
		t.Fatal(err)
	}
	loadedOwner, err := passkeyStore.OwnerByHandle(ctx, record.RPID, owner.Handle)
	if err != nil || len(loadedOwner.Credentials) != 1 {
		t.Fatalf("load owner: %#v, %v", loadedOwner, err)
	}
	lastUsed := now.Add(time.Second)
	record.LastUsedAt = &lastUsed
	record.Credential.Authenticator.SignCount = 2
	if err := passkeyStore.SaveCredential(ctx, record); err != nil {
		t.Fatal(err)
	}
	loadedRecord, err := passkeyStore.CredentialRecord(ctx, record.RPID, record.Credential.ID)
	if err != nil || loadedRecord.Credential.Authenticator.SignCount != 2 || loadedRecord.LastUsedAt == nil {
		t.Fatalf("load updated credential: %#v, %v", loadedRecord, err)
	}
	var storedCredential []byte
	if err := pool.QueryRow(ctx, `SELECT credential_ciphertext FROM passkeys`).Scan(&storedCredential); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(storedCredential, credential.PublicKey) {
		t.Fatal("passkey credential was readable in PostgreSQL")
	}

	sessionStore, err := postgres.NewSessionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.New(sessionStore, bytes.Repeat([]byte{0x61}, 32), 5*time.Minute, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := manager.Issue(ctx, owner.ID, record.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	sessionPrincipal, err := manager.Authenticate(ctx, pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ValidatePrincipal(ctx, sessionPrincipal); err != nil {
		t.Fatalf("active durable principal did not validate: %v", err)
	}
	next, err := manager.Rotate(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Rotate(ctx, pair.RefreshToken); !errors.Is(err, session.ErrReplay) {
		t.Fatalf("expected replay revocation, got %v", err)
	}
	if _, err := manager.Authenticate(ctx, next.AccessToken); err == nil {
		t.Fatal("replayed refresh family remained usable")
	}
	if err := manager.ValidatePrincipal(ctx, sessionPrincipal); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("replayed durable principal remained valid: %v", err)
	}
	devicePair, err := manager.Issue(ctx, owner.ID, record.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	devicePrincipal, err := manager.Authenticate(ctx, devicePair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	var storedTokenHash []byte
	if err := pool.QueryRow(ctx, `
		SELECT token_hash FROM session_tokens
		WHERE owner_id = $1 AND id = $2`, owner.ID, tokenID(devicePair.AccessToken)).Scan(&storedTokenHash); err != nil {
		t.Fatal(err)
	}
	if len(storedTokenHash) != 32 || bytes.Contains(storedTokenHash, []byte(devicePair.AccessToken)) {
		t.Fatal("session credential was not persisted as a fixed-length hash")
	}
	applicationStore, err := postgres.NewApplicationStore(pool, credentialVault)
	if err != nil {
		t.Fatal(err)
	}
	if err := applicationStore.RegisterNotification(ctx, owner.ID, record.DeviceID, "production", strings.Repeat("ab", 32), "com.example.CodexMobile", now); err != nil {
		t.Fatal(err)
	}
	if err := manager.RevokeDevice(ctx, owner.ID, record.DeviceID); err != nil {
		t.Fatal(err)
	}
	// Device revocation must be idempotent and owner scoped.
	if err := manager.RevokeDevice(ctx, owner.ID, record.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Authenticate(ctx, devicePair.AccessToken); err == nil {
		t.Fatal("revoked device access credential remained usable")
	}
	if err := manager.ValidatePrincipal(ctx, devicePrincipal); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("revoked device principal remained valid: %v", err)
	}
	if _, err := manager.Issue(ctx, owner.ID, record.DeviceID); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("revoked device received a new session: %v", err)
	}
	if _, err := passkeyStore.CredentialRecord(ctx, record.RPID, record.Credential.ID); err != nil {
		t.Fatalf("device revocation invalidated a synced passkey: %v", err)
	}
	reauthenticated, err := passkeyStore.ResolveDevice(ctx, passkeys.Device{
		ID: "device-2", OwnerID: owner.ID, Name: "Replacement Phone", Platform: "ios",
		InstanceHash: record.DeviceInstanceHash, CreatedAt: now.Add(2 * time.Second), LastSeenAt: now.Add(2 * time.Second),
	})
	if err != nil || reauthenticated.ID == record.DeviceID {
		t.Fatalf("revoked install did not resolve as a new active device: %#v %v", reauthenticated, err)
	}
	devices, err := manager.ListDevices(ctx, owner.ID)
	if err != nil || len(devices) != 1 || devices[0].ID != reauthenticated.ID {
		t.Fatalf("active device list mismatch: %#v %v", devices, err)
	}
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM notification_endpoints WHERE owner_id=$1 AND device_id=$2`, owner.ID, record.DeviceID).Scan(&enabled); err != nil || enabled {
		t.Fatalf("device APNs endpoint was not revoked atomically: enabled=%v err=%v", enabled, err)
	}
	if err := applicationStore.RegisterNotification(ctx, owner.ID, record.DeviceID, "production", strings.Repeat("ac", 32), "com.example.CodexMobile", now.Add(time.Second)); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("revoked device reactivated an APNs endpoint: %v", err)
	}
	testNotificationRegistrationRevocationOrdering(t, ctx, dsn, schema, pool, credentialVault, owner.ID, now.Add(3*time.Second))

	repositoryStore, err := postgres.NewRepositoryStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := repositoryStore.UpsertInstallation(ctx, postgres.GitHubInstallation{
		OwnerID: owner.ID, InstallationID: 42, AccountID: 84, AccountLogin: "owner",
		AccountType: "User", RepositorySelection: "selected", Permissions: json.RawMessage(`{"contents":"write"}`),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	repository := core.Repository{
		ID: "repo-1", InstallationID: 42, FullName: "owner/repo", DefaultBranch: "main",
		Private: true, Permission: "push", UpdatedAt: now,
	}
	if err := repositoryStore.Upsert(ctx, owner.ID, repository); err != nil {
		t.Fatal(err)
	}
	workspaceStore, err := postgres.NewWorkspaceStore(pool, func(context.Context) (int64, error) { return 100, nil })
	if err != nil {
		t.Fatal(err)
	}
	workspaceValue := core.Workspace{
		ID: "ws-1", OwnerID: owner.ID, Repository: repository, Name: "Workspace",
		Branch: "codex-mobile/workspace-1", BaseBranch: "main", State: core.WorkspaceQueued,
		SafetyMode: core.SafetyBalanced, Retention: core.Retention30Days,
		DevcontainerDir: ".", DevcontainerSupported: true,
		RequestedDiskGiB: 12,
		CreatedAt:        now, UpdatedAt: now, LastActivityAt: now,
	}
	workspaceValue.PrivateInputsPending = true
	workspaceValue.EnvironmentVariables = map[string]string{"PRIVATE_BOUNDARY_SENTINEL": "must-not-reach-workspaces-row"}
	workspaceValue.InitialPrompt = "must-not-reach-workspaces-row-prompt"
	if err := workspaceStore.Create(ctx, workspaceValue); err != nil {
		t.Fatal(err)
	}
	loadedWorkspace, err := workspaceStore.Get(ctx, owner.ID, workspaceValue.ID)
	if err != nil || !loadedWorkspace.PrivateInputsPending || len(loadedWorkspace.EnvironmentVariables) != 0 || loadedWorkspace.InitialPrompt != "" {
		t.Fatalf("private input preparation marker did not round trip safely: %#v %v", loadedWorkspace, err)
	}
	var workspaceRowJSON string
	if err := pool.QueryRow(ctx, `SELECT to_jsonb(w)::text FROM workspaces w WHERE owner_id=$1 AND id=$2`, owner.ID, workspaceValue.ID).Scan(&workspaceRowJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(workspaceRowJSON, "must-not-reach-workspaces-row") {
		t.Fatal("workspace row persisted private creation input plaintext")
	}
	loadedWorkspace.PrivateInputsPending = false
	loadedWorkspace.UpdatedAt = now.Add(time.Second)
	if err := workspaceStore.Save(ctx, loadedWorkspace); err != nil {
		t.Fatal(err)
	}
	loadedWorkspace, err = workspaceStore.Get(ctx, owner.ID, workspaceValue.ID)
	if err != nil || loadedWorkspace.PrivateInputsPending {
		t.Fatalf("private input preparation marker did not clear durably: %#v %v", loadedWorkspace, err)
	}
	workspaceValue.PrivateInputsPending = false
	workspaceValue.EnvironmentVariables = nil
	workspaceValue.InitialPrompt = ""
	setupWorkspace := workspaceValue
	setupWorkspace.ID = "ws-setup-review"
	setupWorkspace.Name = "Setup Review"
	setupWorkspace.Branch = "codex-mobile/setup-review"
	setupWorkspace.State = core.WorkspaceAwaitingSetupApproval
	setupWorkspace.PrivateInputsPending = false
	setupWorkspace.EnvironmentVariables = nil
	setupWorkspace.InitialPrompt = ""
	if err := workspaceStore.Create(ctx, setupWorkspace); err != nil {
		t.Fatal(err)
	}
	type setupReviewOutcome struct {
		result setupreview.Result
		err    error
	}
	const setupReviewAttempts = 12
	setupReviewStart := make(chan struct{})
	setupReviewOutcomes := make(chan setupReviewOutcome, setupReviewAttempts)
	var setupReviewWorkers sync.WaitGroup
	for attempt := range setupReviewAttempts {
		setupReviewWorkers.Add(1)
		go func() {
			defer setupReviewWorkers.Done()
			<-setupReviewStart
			result, ensureErr := applicationStore.EnsureSetupReview(ctx, setupreview.Request{
				ApprovalID: fmt.Sprintf("approval-setup-%d", attempt), ActivityID: fmt.Sprintf("activity-setup-%d", attempt), OwnerID: owner.ID,
				WorkspaceID: setupWorkspace.ID, SafetyMode: string(setupWorkspace.SafetyMode),
				Reason: "Review setup", CreatedAt: now,
			})
			setupReviewOutcomes <- setupReviewOutcome{result: result, err: ensureErr}
		}()
	}
	close(setupReviewStart)
	setupReviewWorkers.Wait()
	close(setupReviewOutcomes)
	firstReview := setupreview.Result{}
	createdReviews := 0
	for outcome := range setupReviewOutcomes {
		if outcome.err != nil {
			t.Fatalf("concurrent setup review reconciliation: %v", outcome.err)
		}
		if firstReview.ApprovalID == "" {
			firstReview = outcome.result
		}
		if outcome.result.ApprovalID != firstReview.ApprovalID || outcome.result.ActivityID != firstReview.ActivityID {
			t.Fatalf("concurrent setup reviews diverged: first=%#v outcome=%#v", firstReview, outcome.result)
		}
		if outcome.result.ActivityCreated {
			createdReviews++
		}
	}
	if createdReviews != 1 {
		t.Fatalf("concurrent setup review creation count = %d, want 1", createdReviews)
	}
	secondReview, err := applicationStore.EnsureSetupReview(ctx, setupreview.Request{
		ApprovalID: "approval-setup-late", ActivityID: "activity-setup-late", OwnerID: owner.ID,
		WorkspaceID: setupWorkspace.ID, SafetyMode: string(setupWorkspace.SafetyMode),
		Reason: "Review setup", CreatedAt: now.Add(72 * time.Hour),
	})
	if err != nil || secondReview.ActivityCreated || secondReview.ApprovalID != firstReview.ApprovalID || secondReview.ActivityID != firstReview.ActivityID {
		t.Fatalf("retry setup review: first=%#v second=%#v err=%v", firstReview, secondReview, err)
	}
	var setupReviewCount, setupActivityCount int
	var setupExpiresAt *time.Time
	if err := pool.QueryRow(ctx, `
		SELECT count(*), max(expires_at)
		FROM workspace_safety_events
		WHERE owner_id=$1 AND workspace_id=$2 AND action='approve_repository_setup'`, owner.ID, setupWorkspace.ID).Scan(&setupReviewCount, &setupExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM workspace_activity
		WHERE owner_id=$1 AND workspace_id=$2 AND kind='approval'`, owner.ID, setupWorkspace.ID).Scan(&setupActivityCount); err != nil {
		t.Fatal(err)
	}
	if setupReviewCount != 1 || setupActivityCount != 1 || setupExpiresAt != nil {
		t.Fatalf("setup review was not durable and nonexpiring: events=%d activities=%d expiry=%v", setupReviewCount, setupActivityCount, setupExpiresAt)
	}
	repositoryID := repository.ID
	repositorySecret, err := applicationStore.CreateSecret(ctx, secretmodel.Metadata{
		ID: "secret-repository", OwnerID: owner.ID, RepositoryID: &repositoryID, Name: "DEPLOY_TOKEN",
		CreatedAt: now, UpdatedAt: now,
	}, []byte("repository-secret-value"), now)
	if err != nil || repositorySecret.ValueBytes != len("repository-secret-value") {
		t.Fatalf("create repository secret: %#v %v", repositorySecret, err)
	}
	if _, err := applicationStore.CreateSecret(ctx, secretmodel.Metadata{
		ID: "secret-global", OwnerID: owner.ID, Name: "GLOBAL_TOKEN", CreatedAt: now, UpdatedAt: now,
	}, []byte("global-secret-value"), now); err != nil {
		t.Fatal(err)
	}
	metadata, err := applicationStore.ListSecrets(ctx, owner.ID, nil)
	if err != nil || len(metadata) != 2 {
		t.Fatalf("list secret metadata: %#v %v", metadata, err)
	}
	var secretEnvelope []byte
	if err := pool.QueryRow(ctx, `SELECT encrypted_envelope FROM encrypted_secrets WHERE owner_id=$1 AND id=$2`, owner.ID, repositorySecret.ID).Scan(&secretEnvelope); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(secretEnvelope, []byte("repository-secret-value")) {
		t.Fatal("owner secret was readable in PostgreSQL")
	}
	if err := applicationStore.GrantWorkspaceSecret(ctx, owner.ID, workspaceValue.ID, repositorySecret.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	workspaceGrants, err := applicationStore.ListWorkspaceSecretGrants(ctx, owner.ID, workspaceValue.ID)
	if err != nil || len(workspaceGrants) != 2 {
		t.Fatalf("list workspace secret grants: %#v %v", workspaceGrants, err)
	}
	secretWorkspaceIDs, err := applicationStore.ListSecretWorkspaceIDs(ctx, owner.ID, repositorySecret.ID)
	if err != nil || len(secretWorkspaceIDs) != 1 || secretWorkspaceIDs[0] != workspaceValue.ID {
		t.Fatalf("list active secret workspaces: %#v %v", secretWorkspaceIDs, err)
	}
	otherOwnerWorkspaceIDs, err := applicationStore.ListSecretWorkspaceIDs(ctx, "other-owner", repositorySecret.ID)
	if err != nil || len(otherOwnerWorkspaceIDs) != 0 {
		t.Fatalf("cross-owner secret workspaces were exposed: %#v %v", otherOwnerWorkspaceIDs, err)
	}
	granted, err := applicationStore.LoadGrantedWorkspaceSecrets(ctx, owner.ID, workspaceValue.ID)
	if err != nil || string(granted["DEPLOY_TOKEN"]) != "repository-secret-value" || len(granted) != 1 {
		t.Fatalf("load explicitly granted secret: %#v %v", granted, err)
	}
	for _, plaintext := range granted {
		secretmodel.Wipe(plaintext)
	}
	deletingWorkspace := workspaceValue
	deletingWorkspace.ID = "ws-deleting"
	deletingWorkspace.Name = "Deleting Workspace"
	deletingWorkspace.Branch = "codex-mobile/workspace-deleting"
	if err := workspaceStore.Create(ctx, deletingWorkspace); err != nil {
		t.Fatal(err)
	}
	if err := applicationStore.GrantWorkspaceSecret(ctx, owner.ID, deletingWorkspace.ID, repositorySecret.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	deletingWorkspace.State = core.WorkspaceDeleting
	deletingWorkspace.UpdatedAt = now.Add(2 * time.Second)
	if err := workspaceStore.Save(ctx, deletingWorkspace); err != nil {
		t.Fatal(err)
	}
	secretWorkspaceIDs, err = applicationStore.ListSecretWorkspaceIDs(ctx, owner.ID, repositorySecret.ID)
	if err != nil || len(secretWorkspaceIDs) != 1 || secretWorkspaceIDs[0] != workspaceValue.ID {
		t.Fatalf("deleting workspace remained a live secret consumer: %#v %v", secretWorkspaceIDs, err)
	}
	if _, err := applicationStore.ListWorkspaceSecretGrants(ctx, owner.ID, deletingWorkspace.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("deleting workspace exposed secret grants: %v", err)
	}
	if err := applicationStore.GrantWorkspaceSecret(ctx, owner.ID, deletingWorkspace.ID, repositorySecret.ID, now.Add(3*time.Second)); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("deleting workspace accepted a secret grant: %v", err)
	}
	if _, err := applicationStore.LoadGrantedWorkspaceSecrets(ctx, owner.ID, deletingWorkspace.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("deleting workspace loaded secret plaintext: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO terminal_tabs
		    (id, owner_id, workspace_id, title, kind, sort_order, coder_reconnect_id, created_at)
		VALUES
		    ('11111111-1111-4111-8111-111111111111', $1, $2, 'Delete test', 'shell', 0,
		     '22222222-2222-4222-8222-222222222222', $3)`, owner.ID, deletingWorkspace.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO preview_routes
		    (id, owner_id, workspace_id, port, process_name, workspace_host, created_at)
		VALUES ('preview-delete', $1, $2, 3000, 'test', 'provider-delete', $3)`, owner.ID, deletingWorkspace.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO preview_tokens
		    (id, route_id, owner_id, workspace_id, token_hash, created_at, expires_at)
		VALUES ('preview-token-delete', 'preview-delete', $1, $2, $3, $4, $5)`,
		owner.ID, deletingWorkspace.ID, bytes.Repeat([]byte{0x93}, 32), now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO workspace_activity
		    (id, owner_id, workspace_id, kind, summary, created_at)
		VALUES ('activity-delete', $1, $2, 'maintenance', 'Deletion test activity', $3)`, owner.ID, deletingWorkspace.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO workspace_safety_events
		    (id, owner_id, workspace_id, safety_mode, action, decision, created_at)
		VALUES ('safety-delete', $1, $2, 'balanced', 'delete_test', 'approved', $3)`, owner.ID, deletingWorkspace.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO encrypted_secrets
		    (id, owner_id, repository_id, workspace_id, name, encrypted_envelope, redaction_hash,
		     aad_version, created_at, updated_at)
		VALUES ('workspace-internal-delete', $1, $2, $3, 'workspace_internal_delete', $4, $5, 1, $6, $6)`,
		owner.ID, repository.ID, deletingWorkspace.ID, []byte{0x01}, bytes.Repeat([]byte{0x94}, 32), now); err != nil {
		t.Fatal(err)
	}
	if err := applicationStore.Audit(ctx, owner.ID, "", deletingWorkspace.ID, "workspace.delete.prepared", "success", "workspace", deletingWorkspace.ID, json.RawMessage(`{"phase":"prepared"}`), now); err != nil {
		t.Fatal(err)
	}
	if err := workspaceStore.FinalizeDelete(ctx, "different-owner", deletingWorkspace.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner workspace finalization returned %v", err)
	}
	if err := workspaceStore.FinalizeDelete(ctx, owner.ID, workspaceValue.ID); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("non-deleting workspace finalization returned %v", err)
	}
	if err := workspaceStore.FinalizeDelete(ctx, owner.ID, deletingWorkspace.ID); err != nil {
		t.Fatalf("finalize deleting workspace: %v", err)
	}
	if err := applicationStore.Audit(ctx, owner.ID, "", "", "workspace.delete", "success", "workspace", deletingWorkspace.ID, json.RawMessage(`{"finalized":true}`), now.Add(time.Second)); err != nil {
		t.Fatalf("post-finalization delete audit: %v", err)
	}
	if _, err := workspaceStore.Get(ctx, owner.ID, deletingWorkspace.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("finalized workspace remained readable: %v", err)
	}
	for _, table := range []string{
		"workspace_state_events", "workspace_safety_events", "workspace_activity", "terminal_tabs",
		"preview_routes", "preview_tokens", "secret_grants", "encrypted_secrets",
	} {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE workspace_id=$1`, deletingWorkspace.ID).Scan(&count); err != nil {
			t.Fatalf("count %s cascade: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("workspace finalization retained %d rows in %s", count, table)
		}
	}
	var auditWorkspaceID *string
	var auditTargetID string
	if err := pool.QueryRow(ctx, `
		SELECT workspace_id, target_id
		FROM audit_events
		WHERE owner_id=$1 AND action='workspace.delete.prepared'`, owner.ID).Scan(&auditWorkspaceID, &auditTargetID); err != nil {
		t.Fatal(err)
	}
	if auditWorkspaceID != nil || auditTargetID != deletingWorkspace.ID {
		t.Fatalf("workspace audit did not survive with nullable linkage: workspace=%v target=%q", auditWorkspaceID, auditTargetID)
	}
	if err := pool.QueryRow(ctx, `
		SELECT workspace_id, target_id
		FROM audit_events
		WHERE owner_id=$1 AND action='workspace.delete'`, owner.ID).Scan(&auditWorkspaceID, &auditTargetID); err != nil {
		t.Fatal(err)
	}
	if auditWorkspaceID != nil || auditTargetID != deletingWorkspace.ID {
		t.Fatalf("post-finalization audit lost target/null linkage: workspace=%v target=%q", auditWorkspaceID, auditTargetID)
	}
	recreatedWorkspace := deletingWorkspace
	recreatedWorkspace.ID = "ws-deleting-recreated"
	recreatedWorkspace.Name = "Recreated Workspace"
	recreatedWorkspace.State = core.WorkspaceQueued
	recreatedWorkspace.UpdatedAt = now.Add(4 * time.Second)
	recreatedWorkspace.LastActivityAt = recreatedWorkspace.UpdatedAt
	if err := workspaceStore.Create(ctx, recreatedWorkspace); err != nil {
		t.Fatalf("same-branch workspace recreation after finalization: %v", err)
	}
	recreatedWorkspace.State = core.WorkspaceDeleting
	recreatedWorkspace.UpdatedAt = now.Add(5 * time.Second)
	if err := workspaceStore.Save(ctx, recreatedWorkspace); err != nil {
		t.Fatal(err)
	}
	if err := workspaceStore.FinalizeDelete(ctx, owner.ID, recreatedWorkspace.ID); err != nil {
		t.Fatalf("cleanup recreated workspace: %v", err)
	}
	if _, err := applicationStore.UpdateSecret(ctx, "other-owner", repositorySecret.ID, []byte("wrong-owner"), now.Add(2*time.Second)); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner secret update was not rejected: %v", err)
	}
	if err := applicationStore.RevokeWorkspaceSecret(ctx, owner.ID, workspaceValue.ID, repositorySecret.ID, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := applicationStore.RevokeWorkspaceSecret(ctx, owner.ID, workspaceValue.ID, repositorySecret.ID, now.Add(3*time.Second)); err != nil {
		t.Fatalf("idempotent secret grant revocation failed: %v", err)
	}
	secretWorkspaceIDs, err = applicationStore.ListSecretWorkspaceIDs(ctx, owner.ID, repositorySecret.ID)
	if err != nil || len(secretWorkspaceIDs) != 0 {
		t.Fatalf("revoked secret retained an active workspace: %#v %v", secretWorkspaceIDs, err)
	}
	granted, err = applicationStore.LoadGrantedWorkspaceSecrets(ctx, owner.ID, workspaceValue.ID)
	if err != nil || len(granted) != 0 {
		t.Fatalf("revoked secret remained loadable: %#v %v", granted, err)
	}
	if err := applicationStore.GrantWorkspaceSecret(ctx, owner.ID, workspaceValue.ID, repositorySecret.ID, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	secretWorkspaceIDs, err = applicationStore.ListSecretWorkspaceIDs(ctx, owner.ID, repositorySecret.ID)
	if err != nil || len(secretWorkspaceIDs) != 1 || secretWorkspaceIDs[0] != workspaceValue.ID {
		t.Fatalf("regranted secret workspace was not discoverable: %#v %v", secretWorkspaceIDs, err)
	}
	if err := applicationStore.DeleteSecret(ctx, owner.ID, repositorySecret.ID, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := applicationStore.DeleteSecret(ctx, owner.ID, repositorySecret.ID, now.Add(5*time.Second)); err != nil {
		t.Fatalf("idempotent secret deletion failed: %v", err)
	}
	secretWorkspaceIDs, err = applicationStore.ListSecretWorkspaceIDs(ctx, owner.ID, repositorySecret.ID)
	if err != nil || len(secretWorkspaceIDs) != 0 {
		t.Fatalf("deleted secret retained an active workspace: %#v %v", secretWorkspaceIDs, err)
	}
	granted, err = applicationStore.LoadGrantedWorkspaceSecrets(ctx, owner.ID, workspaceValue.ID)
	if err != nil || len(granted) != 0 {
		t.Fatalf("deleted secret grant remained loadable: %#v %v", granted, err)
	}
	loadedWorkspace, err = workspaceStore.Get(ctx, owner.ID, workspaceValue.ID)
	if err != nil || loadedWorkspace.Repository.FullName != repository.FullName || loadedWorkspace.RequestedDiskGiB != 12 ||
		loadedWorkspace.DevcontainerDir != "." || !loadedWorkspace.DevcontainerSupported {
		t.Fatalf("load workspace: %#v, %v", loadedWorkspace, err)
	}
	workspaceValue.State = core.WorkspaceRunning
	workspaceValue.UpdatedAt = now.Add(time.Second)
	workspaceValue.LastActivityAt = workspaceValue.UpdatedAt
	if err := workspaceStore.Save(ctx, workspaceValue); err != nil {
		t.Fatal(err)
	}
	var stateEventCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM workspace_state_events
		WHERE owner_id = $1 AND workspace_id = $2`, owner.ID, workspaceValue.ID).Scan(&stateEventCount); err != nil {
		t.Fatal(err)
	}
	if stateEventCount != 2 {
		t.Fatalf("workspace state transition count = %d, want 2", stateEventCount)
	}
	capacityDeleting := workspaceValue
	capacityDeleting.ID = "ws-delete-capacity"
	capacityDeleting.Name = "Delete capacity"
	capacityDeleting.Branch = "codex-mobile/delete-capacity"
	capacityDeleting.State = core.WorkspaceQueued
	capacityDeleting.ProviderResourceID = "provider-delete-capacity"
	capacityDeleting.UpdatedAt = now.Add(2 * time.Second)
	if err := workspaceStore.Create(ctx, capacityDeleting); err != nil {
		t.Fatal(err)
	}
	capacityDeleting.State = core.WorkspaceDeleting
	capacityDeleting.UpdatedAt = now.Add(3 * time.Second)
	if err := workspaceStore.Save(ctx, capacityDeleting); err != nil {
		t.Fatal(err)
	}
	snapshot, err := workspaceStore.Snapshot(ctx, owner.ID)
	if err != nil || snapshot.Running != 2 || snapshot.Queued != 0 || snapshot.DiskFreeGiB != 100 {
		t.Fatalf("workspace snapshot: %#v, %v", snapshot, err)
	}
	if err := workspaceStore.FinalizeDelete(ctx, owner.ID, capacityDeleting.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err = workspaceStore.Snapshot(ctx, owner.ID)
	if err != nil || snapshot.Running != 1 {
		t.Fatalf("confirmed deletion did not release capacity: %#v, %v", snapshot, err)
	}
	if err := workspaceStore.UpdateSafetyMode(ctx, owner.ID, workspaceValue.ID, core.SafetySafe, now.Add(2*time.Second)); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("live workspace safety-mode update returned %v", err)
	}
	suspendedAt := now.Add(3 * time.Second)
	workspaceValue.State = core.WorkspaceSuspended
	workspaceValue.SuspendedAt = &suspendedAt
	workspaceValue.UpdatedAt = suspendedAt
	if err := workspaceStore.Save(ctx, workspaceValue); err != nil {
		t.Fatal(err)
	}
	if err := workspaceStore.UpdateSafetyMode(ctx, "other-owner", workspaceValue.ID, core.SafetySafe, now.Add(4*time.Second)); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner workspace safety-mode update returned %v", err)
	}
	if err := workspaceStore.UpdateSafetyMode(ctx, owner.ID, workspaceValue.ID, core.SafetySafe, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	workspaceValue, err = workspaceStore.Get(ctx, owner.ID, workspaceValue.ID)
	if err != nil || workspaceValue.State != core.WorkspaceSuspended || workspaceValue.SafetyMode != core.SafetySafe {
		t.Fatalf("suspended workspace safety-mode update: %#v %v", workspaceValue, err)
	}
	workspaceValue.EnvironmentVariables = map[string]string{"PRIVATE_VALUE": "environment-secret"}
	workspaceValue.InitialPrompt = "start with the failing integration test"
	if err := applicationStore.SaveWorkspaceEnvironment(ctx, workspaceValue); err != nil {
		t.Fatal(err)
	}
	if err := applicationStore.SaveWorkspaceInitialPrompt(ctx, workspaceValue); err != nil {
		t.Fatal(err)
	}
	loadedEnvironment, err := applicationStore.LoadWorkspaceEnvironment(ctx, workspaceValue)
	if err != nil || loadedEnvironment["PRIVATE_VALUE"] != "environment-secret" || len(loadedEnvironment) != 1 {
		t.Fatalf("load encrypted workspace environment: %#v, %v", loadedEnvironment, err)
	}
	codexAuthKey, err := applicationStore.LoadOrCreateWorkspaceCodexAuthKey(ctx, workspaceValue)
	if err != nil || len(codexAuthKey) != 32 {
		t.Fatalf("create workspace Codex auth key: length=%d, %v", len(codexAuthKey), err)
	}
	secondCodexAuthKey, err := applicationStore.LoadOrCreateWorkspaceCodexAuthKey(ctx, workspaceValue)
	if err != nil || !bytes.Equal(codexAuthKey, secondCodexAuthKey) {
		t.Fatalf("workspace Codex auth key was not stable: %v", err)
	}
	var codexAuthKeyEnvelope []byte
	if err := pool.QueryRow(ctx, `
		SELECT encrypted_envelope FROM encrypted_secrets
		WHERE owner_id=$1 AND repository_id=$2 AND workspace_id=$3 AND name=$4
		  AND deleted_at IS NULL`, owner.ID, repository.ID, workspaceValue.ID,
		"workspace_codex_auth_key:"+workspaceValue.ID).Scan(&codexAuthKeyEnvelope); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(codexAuthKeyEnvelope, codexAuthKey) {
		t.Fatal("workspace Codex auth key was stored in plaintext")
	}
	for index := range codexAuthKey {
		codexAuthKey[index] = 0
	}
	for index := range secondCodexAuthKey {
		secondCodexAuthKey[index] = 0
	}
	loadedPrompt, err := applicationStore.LoadWorkspaceInitialPrompt(ctx, owner.ID, repository.ID, workspaceValue.ID)
	if err != nil || loadedPrompt != workspaceValue.InitialPrompt {
		t.Fatalf("load encrypted initial prompt: %q, %v", loadedPrompt, err)
	}
	var promptCiphertext []byte
	if err := pool.QueryRow(ctx, `
		SELECT encrypted_envelope FROM encrypted_secrets
		WHERE owner_id=$1 AND repository_id=$2 AND workspace_id=$3 AND name=$4 AND deleted_at IS NULL`,
		owner.ID, repository.ID, workspaceValue.ID, "workspace_prompt:"+workspaceValue.ID).Scan(&promptCiphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(promptCiphertext, []byte(workspaceValue.InitialPrompt)) {
		t.Fatal("initial prompt was readable in PostgreSQL")
	}
	if err := applicationStore.MarkWorkspaceInitialPromptDelivered(ctx, owner.ID, repository.ID, workspaceValue.ID, workspaceValue.UpdatedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if delivered, err := applicationStore.LoadWorkspaceInitialPrompt(ctx, owner.ID, repository.ID, workspaceValue.ID); err != nil || delivered != "" {
		t.Fatalf("delivered initial prompt remained available: %q, %v", delivered, err)
	}

	bootstrapStore, err := postgres.NewBootstrapStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	recoveryRandom := append(bytes.Repeat([]byte{0x71}, 32), bytes.Repeat([]byte{0x72}, 32)...)
	recoveryManager, err := passkeys.NewBootstrapManagerWithStoreAndDependencies(
		bytes.Repeat([]byte{0x71}, 32), 15*time.Minute, bootstrapStore, bytes.NewReader(recoveryRandom),
		func() time.Time { return now.Add(10 * time.Second) },
	)
	if err != nil {
		t.Fatal(err)
	}
	_, staleRecovery, err := recoveryManager.NewRecoveryRecord(owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := bootstrapStore.ResetPasskeyEnrollment(ctx, staleRecovery)
	if err != nil || summary.PasskeysRevoked != 1 || summary.DevicesRevoked < 1 {
		t.Fatalf("passkey recovery reset: %#v %v", summary, err)
	}
	_, currentRecovery, err := recoveryManager.NewRecoveryRecord(owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapStore.ResetPasskeyEnrollment(ctx, currentRecovery); err != nil {
		t.Fatal(err)
	}
	recoveryOwner, err := passkeyStore.OwnerForRecovery(ctx, record.RPID, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	recoveredRecord := passkeys.CredentialRecord{
		RPID: record.RPID, OwnerID: owner.ID, DeviceID: "device-recovered", DeviceName: "Recovery Phone",
		DeviceInstanceHash: [32]byte{0x52},
		Credential:         webauthn.Credential{ID: []byte("credential-recovered"), PublicKey: []byte("recovered-public-key")},
		CreatedAt:          currentRecovery.CreatedAt,
	}
	if err := passkeyStore.CreateCredentialForRecoveredOwner(ctx, recoveryOwner, recoveredRecord, passkeys.RecoveryProof{
		TokenHash: staleRecovery.TokenHash, At: currentRecovery.CreatedAt,
	}); !errors.Is(err, passkeys.ErrInvalidBootstrap) {
		t.Fatalf("replaced recovery credential won the persistence race: %v", err)
	}
	if err := passkeyStore.CreateCredentialForRecoveredOwner(ctx, recoveryOwner, recoveredRecord, passkeys.RecoveryProof{
		TokenHash: currentRecovery.TokenHash, At: currentRecovery.CreatedAt,
	}); err != nil {
		t.Fatalf("current recovery credential failed atomically: %v", err)
	}
	if valid, err := bootstrapStore.IsValid(ctx, currentRecovery.TokenHash, currentRecovery.CreatedAt); err != nil || valid {
		t.Fatalf("recovery credential was not consumed with passkey creation: valid=%v err=%v", valid, err)
	}
	authenticatedOwner, err := passkeyStore.OwnerForAdditionalCredential(
		ctx, record.RPID, owner.ID, recoveredRecord.DeviceID, recoveredRecord.DeviceInstanceHash,
	)
	if err != nil {
		t.Fatalf("recovered device could not begin authenticated enrollment: %v", err)
	}
	secondCredential := recoveredRecord
	secondCredential.Credential = webauthn.Credential{ID: []byte("credential-second"), PublicKey: []byte("second-public-key")}
	secondCredential.CreatedAt = recoveredRecord.CreatedAt.Add(time.Second)
	if err := passkeyStore.CreateAdditionalCredential(ctx, authenticatedOwner, secondCredential); err != nil {
		t.Fatalf("authenticated second credential enrollment failed: %v", err)
	}
	passkeyMetadata, err := passkeyStore.ListCredentialMetadata(ctx, record.RPID, owner.ID)
	if err != nil || len(passkeyMetadata) != 2 {
		t.Fatalf("additional credential list: len=%d err=%v", len(passkeyMetadata), err)
	}
	thirdCredential := recoveredRecord
	thirdCredential.Credential = webauthn.Credential{ID: []byte("credential-race-add"), PublicKey: []byte("race-public-key")}
	thirdCredential.CreatedAt = secondCredential.CreatedAt.Add(time.Second)
	var raceWait sync.WaitGroup
	raceErrors := make(chan error, 2)
	raceWait.Add(2)
	go func() {
		defer raceWait.Done()
		raceErrors <- passkeyStore.CreateAdditionalCredential(ctx, authenticatedOwner, thirdCredential)
	}()
	go func() {
		defer raceWait.Done()
		raceErrors <- passkeyStore.RevokeCredential(ctx, record.RPID, owner.ID, secondCredential.Credential.ID)
	}()
	raceWait.Wait()
	close(raceErrors)
	for raceErr := range raceErrors {
		if raceErr != nil {
			t.Fatalf("serialized registration/revoke race failed: %v", raceErr)
		}
	}
	passkeyMetadata, err = passkeyStore.ListCredentialMetadata(ctx, record.RPID, owner.ID)
	if err != nil || len(passkeyMetadata) != 2 {
		t.Fatalf("registration/revoke race lost credential invariant: len=%d err=%v", len(passkeyMetadata), err)
	}
	if err := passkeyStore.RevokeCredential(ctx, record.RPID, "different-owner", thirdCredential.Credential.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner credential revoke returned %v", err)
	}
	if err := passkeyStore.RevokeCredential(ctx, record.RPID, owner.ID, thirdCredential.Credential.ID); err != nil {
		t.Fatalf("additional credential revoke failed: %v", err)
	}
	if err := passkeyStore.RevokeCredential(ctx, record.RPID, owner.ID, thirdCredential.Credential.ID); err != nil {
		t.Fatalf("credential revoke was not idempotent: %v", err)
	}
	if err := passkeyStore.RevokeCredential(ctx, record.RPID, owner.ID, recoveredRecord.Credential.ID); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("final credential revoke returned %v", err)
	}

	connections, err := repositoryStore.ListGitHubInstallations(ctx, owner.ID)
	if err != nil || len(connections) != 1 || connections[0].InstallationID != 42 {
		t.Fatalf("active GitHub connection list: %#v %v", connections, err)
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 42); err != nil || !active {
		t.Fatalf("active GitHub installation: active=%v err=%v", active, err)
	}
	if err := repositoryStore.DisconnectGitHubInstallation(ctx, "different-owner", 42, now.Add(time.Minute)); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner GitHub disconnect returned %v", err)
	}
	lowPool, err := postgres.Open(ctx, postgres.PoolConfig{
		URL: dsn, SearchPath: schema, MaxConns: 1, ApplicationName: "github-lease-low-pool-integration",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lowPool.Close()
	lowPoolStore, err := postgres.NewRepositoryStore(lowPool)
	if err != nil {
		t.Fatal(err)
	}
	lowPoolCtx, stopLowPool := context.WithTimeout(ctx, 3*time.Second)
	err = lowPoolStore.WithGitHubInstallationSyncLease(lowPoolCtx, owner.ID, 42, func(leaseCtx context.Context) error {
		if err := lowPoolStore.MarkInstallationRepositoriesUnavailable(leaseCtx, owner.ID, 42); err != nil {
			return err
		}
		return lowPoolStore.Upsert(leaseCtx, owner.ID, repository)
	})
	stopLowPool()
	if err != nil {
		t.Fatalf("MaxConns=1 GitHub lease callback starved its ordinary pool work: %v", err)
	}
	completedTokenUse := githubapp.TokenUseMetadata{
		ID: "ght_11111111111111111111111111111111", OwnerID: owner.ID, InstallationID: 42,
		Permissions: map[string]string{"contents": "read"}, RepositoryIDs: []int64{99},
		CreatedAt: time.Now().UTC(),
	}
	completedTokenUse.ExpiresAt = completedTokenUse.CreatedAt.Add(2 * time.Hour)
	for index := range completedTokenUse.Nonce {
		completedTokenUse.Nonce[index] = 0x7a
	}
	if err := repositoryStore.BeginGitHubInstallationTokenUse(ctx, completedTokenUse); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("token metadata reservation escaped installation authority lease: %v", err)
	}
	err = repositoryStore.WithGitHubInstallationLease(ctx, owner.ID, 42, func(leaseCtx context.Context) error {
		if err := repositoryStore.BeginGitHubInstallationTokenUse(leaseCtx, completedTokenUse); err != nil {
			return err
		}
		if err := repositoryStore.SetGitHubInstallationTokenUseExpiry(leaseCtx, owner.ID, 42, completedTokenUse.ID, completedTokenUse.CreatedAt.Add(time.Hour)); err != nil {
			return err
		}
		return repositoryStore.RevokeGitHubInstallationTokenUse(leaseCtx, owner.ID, 42, completedTokenUse.ID, completedTokenUse.CreatedAt.Add(time.Minute))
	})
	if err != nil {
		t.Fatalf("completed installation-token metadata lifecycle: %v", err)
	}
	var persistedNonce []byte
	var persistedPermissions, persistedRepositories string
	var persistedRevokedAt *time.Time
	if err := pool.QueryRow(ctx, `
		SELECT token_hash, permissions::text, repository_ids::text, revoked_at
		FROM github_token_metadata WHERE id=$1`, completedTokenUse.ID).
		Scan(&persistedNonce, &persistedPermissions, &persistedRepositories, &persistedRevokedAt); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persistedNonce, completedTokenUse.Nonce[:]) || persistedPermissions != `{"contents": "read"}` || persistedRepositories != `[99]` || persistedRevokedAt == nil {
		t.Fatalf("token authority metadata = nonce-match:%t permissions:%s repositories:%s revoked:%v", bytes.Equal(persistedNonce, completedTokenUse.Nonce[:]), persistedPermissions, persistedRepositories, persistedRevokedAt)
	}
	disconnectPool, err := postgres.Open(ctx, postgres.PoolConfig{
		URL: dsn, SearchPath: schema, MaxConns: 2, ApplicationName: "github-disconnect-integration",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer disconnectPool.Close()
	disconnectStore, err := postgres.NewRepositoryStore(disconnectPool)
	if err != nil {
		t.Fatal(err)
	}
	leaseStarted := make(chan struct{})
	leaseRelease := make(chan struct{})
	leaseDone := make(chan error, 1)
	ambiguousSafeAfter := time.Now().UTC().Add(3 * time.Second)
	go func() {
		leaseDone <- repositoryStore.WithGitHubInstallationLease(ctx, owner.ID, 42, func(leaseCtx context.Context) error {
			createdAt := time.Now().UTC()
			ambiguousTokenUse := githubapp.TokenUseMetadata{
				ID: "ght_22222222222222222222222222222222", OwnerID: owner.ID, InstallationID: 42,
				Permissions: map[string]string{"contents": "write"}, RepositoryIDs: []int64{99},
				CreatedAt: createdAt, ExpiresAt: createdAt.Add(2 * time.Hour),
			}
			for index := range ambiguousTokenUse.Nonce {
				ambiguousTokenUse.Nonce[index] = 0x6b
			}
			if err := repositoryStore.BeginGitHubInstallationTokenUse(leaseCtx, ambiguousTokenUse); err != nil {
				return err
			}
			if err := repositoryStore.SetGitHubInstallationTokenUseExpiry(leaseCtx, owner.ID, 42, ambiguousTokenUse.ID, ambiguousSafeAfter); err != nil {
				return err
			}
			refreshed := repository
			refreshed.UpdatedAt = now.Add(30 * time.Second)
			if err := repositoryStore.Upsert(leaseCtx, owner.ID, refreshed); err != nil {
				return err
			}
			close(leaseStarted)
			select {
			case <-leaseRelease:
				return nil
			case <-leaseCtx.Done():
				return leaseCtx.Err()
			}
		})
	}()
	<-leaseStarted
	disconnectDone := make(chan error, 1)
	go func() {
		disconnectDone <- disconnectStore.DisconnectGitHubInstallation(ctx, owner.ID, 42, now.Add(time.Minute))
	}()
	waitDeadline := time.NewTimer(5 * time.Second)
	waitPoll := time.NewTicker(10 * time.Millisecond)
	waiting := false
	for !waiting {
		select {
		case <-waitPoll.C:
			var count int
			if err := pool.QueryRow(ctx, `
				SELECT count(*)
				FROM pg_locks l
				JOIN pg_stat_activity a ON a.pid=l.pid
				WHERE l.locktype='advisory' AND NOT l.granted
				  AND a.application_name='github-disconnect-integration'`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			waiting = count > 0
		case <-waitDeadline.C:
			t.Fatal("GitHub disconnect did not wait on the in-flight cross-pool authority lease")
		}
	}
	waitPoll.Stop()
	if !waitDeadline.Stop() {
		<-waitDeadline.C
	}
	select {
	case err := <-disconnectDone:
		t.Fatalf("GitHub disconnect completed before the authority lease drained: %v", err)
	default:
	}
	close(leaseRelease)
	if err := <-leaseDone; err != nil {
		t.Fatalf("in-flight GitHub authority lease: %v", err)
	}
	if err := <-disconnectDone; !errors.Is(err, core.ErrConflict) {
		t.Fatalf("GitHub disconnect before ambiguous remote deadline: %v", err)
	}
	if !time.Now().Before(ambiguousSafeAfter) {
		t.Fatal("integration test did not exercise disconnect before ambiguous token safe-after")
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 42); err != nil || active {
		t.Fatalf("conflicted disconnect did not durably disable installation: active=%v err=%v", active, err)
	}
	var available bool
	if err := pool.QueryRow(ctx, `SELECT available FROM repositories WHERE owner_id=$1 AND id=$2`, owner.ID, repository.ID).Scan(&available); err != nil || available {
		t.Fatalf("disconnect was not the final repository availability write: available=%v err=%v", available, err)
	}
	if wait := time.Until(ambiguousSafeAfter.Add(50 * time.Millisecond)); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		}
	}
	if err := disconnectStore.DisconnectGitHubInstallation(ctx, owner.ID, 42, now.Add(75*time.Second)); err != nil {
		t.Fatalf("GitHub disconnect after ambiguous token safe-after: %v", err)
	}
	callbackCalled := false
	err = repositoryStore.WithGitHubInstallationLease(ctx, owner.ID, 42, func(context.Context) error {
		callbackCalled = true
		return nil
	})
	if !errors.Is(err, core.ErrPrecondition) || callbackCalled {
		t.Fatalf("post-disconnect token lease = called=%v err=%v", callbackCalled, err)
	}
	callbackCalled = false
	err = repositoryStore.WithGitHubInstallationLease(ctx, "different-owner", 42, func(context.Context) error {
		callbackCalled = true
		return nil
	})
	if !errors.Is(err, core.ErrPrecondition) || callbackCalled {
		t.Fatalf("cross-owner token lease = called=%v err=%v", callbackCalled, err)
	}
	if err := repositoryStore.DisconnectGitHubInstallation(ctx, owner.ID, 42, now.Add(90*time.Second)); err != nil {
		t.Fatalf("idempotent GitHub disconnect: %v", err)
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 42); err != nil || active {
		t.Fatalf("disconnected GitHub installation: active=%v err=%v", active, err)
	}
	if connections, err := repositoryStore.ListGitHubInstallations(ctx, owner.ID); err != nil || len(connections) != 0 {
		t.Fatalf("disconnected GitHub connection remained listed: %#v %v", connections, err)
	}
	if err := repositoryStore.UpsertInstallation(ctx, postgres.GitHubInstallation{
		OwnerID: owner.ID, InstallationID: 42, AccountID: 84, AccountLogin: "owner",
		AccountType: "User", RepositorySelection: "selected", Permissions: json.RawMessage(`{"contents":"write"}`),
		CreatedAt: now, UpdatedAt: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("GitHub webhook metadata refresh: %v", err)
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 42); err != nil || active {
		t.Fatalf("webhook metadata refresh undid owner disconnect: active=%v err=%v", active, err)
	}
	err = repositoryStore.WithGitHubInstallationSyncLease(ctx, owner.ID, 42, func(syncCtx context.Context) error {
		return repositoryStore.UpsertInstallationFromProviderUnsuspend(syncCtx, postgres.GitHubInstallation{
			OwnerID: owner.ID, InstallationID: 42, AccountID: 84, AccountLogin: "owner",
			AccountType: "User", RepositorySelection: "selected", Permissions: json.RawMessage(`{"contents":"write"}`),
			CreatedAt: now, UpdatedAt: now.Add(150 * time.Second), SuspendedAt: nil,
		})
	})
	if err != nil {
		t.Fatalf("provider unsuspend sync while owner-disconnected: %v", err)
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 42); err != nil || active {
		t.Fatalf("provider unsuspend sync undid owner disconnect: active=%v err=%v", active, err)
	}
	reconnectMetadata := postgres.GitHubInstallation{
		OwnerID: owner.ID, InstallationID: 42, AccountID: 84, AccountLogin: "owner",
		AccountType: "User", RepositorySelection: "selected", Permissions: json.RawMessage(`{"contents":"write"}`),
		CreatedAt: now, UpdatedAt: now.Add(3 * time.Minute), SuspendedAt: nil,
	}
	if err := repositoryStore.BeginGitHubInstallationReconnect(ctx, owner.ID, 42, now.Add(3*time.Minute)); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("reconnect preparation escaped synchronization lease: %v", err)
	}
	if err := repositoryStore.UpsertInstallationForOwnerReconnect(ctx, reconnectMetadata, now.Add(3*time.Minute)); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("reconnect metadata escaped synchronization lease: %v", err)
	}
	if err := repositoryStore.CompleteGitHubInstallationReconnect(ctx, owner.ID, 42, now.Add(3*time.Minute)); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("reconnect completion escaped synchronization lease: %v", err)
	}
	reconnectFailure := errors.New("simulated repository synchronization failure")
	err = repositoryStore.WithGitHubInstallationSyncLease(ctx, owner.ID, 42, func(syncCtx context.Context) error {
		if err := repositoryStore.BeginGitHubInstallationReconnect(syncCtx, owner.ID, 42, now.Add(3*time.Minute)); err != nil {
			return err
		}
		if err := repositoryStore.UpsertInstallationForOwnerReconnect(syncCtx, reconnectMetadata, now.Add(3*time.Minute)); err != nil {
			return err
		}
		providerActive, err := repositoryStore.GitHubInstallationProviderActive(syncCtx, owner.ID, 42)
		if err != nil {
			return err
		}
		if !providerActive {
			return errors.New("provider authority was inactive before reconnect synchronization")
		}
		if err := repositoryStore.Upsert(syncCtx, owner.ID, repository); err != nil {
			return err
		}
		return reconnectFailure
	})
	if !errors.Is(err, reconnectFailure) {
		t.Fatalf("failed GitHub reconnect returned %v", err)
	}
	if _, err := repositoryStore.Get(ctx, owner.ID, repository.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("failed reconnect exposed a partially synchronized repository: %v", err)
	}
	if repositories, err := repositoryStore.List(ctx, owner.ID); err != nil || len(repositories) != 0 {
		t.Fatalf("failed reconnect listed partially synchronized repositories: %#v %v", repositories, err)
	}
	callbackCalled = false
	err = repositoryStore.WithGitHubInstallationLease(ctx, owner.ID, 42, func(context.Context) error {
		callbackCalled = true
		return nil
	})
	if !errors.Is(err, core.ErrPrecondition) || callbackCalled {
		t.Fatalf("failed reconnect opened shared token authority: called=%v err=%v", callbackCalled, err)
	}

	reconnectReady := make(chan struct{})
	reconnectRelease := make(chan struct{})
	reconnectDone := make(chan error, 1)
	go func() {
		reconnectDone <- repositoryStore.WithGitHubInstallationSyncLease(ctx, owner.ID, 42, func(syncCtx context.Context) error {
			if err := repositoryStore.BeginGitHubInstallationReconnect(syncCtx, owner.ID, 42, now.Add(3*time.Minute)); err != nil {
				return err
			}
			if err := repositoryStore.UpsertInstallationForOwnerReconnect(syncCtx, reconnectMetadata, now.Add(3*time.Minute)); err != nil {
				return err
			}
			if err := repositoryStore.Upsert(syncCtx, owner.ID, repository); err != nil {
				return err
			}
			close(reconnectReady)
			select {
			case <-reconnectRelease:
			case <-syncCtx.Done():
				return syncCtx.Err()
			}
			return repositoryStore.CompleteGitHubInstallationReconnect(syncCtx, owner.ID, 42, now.Add(3*time.Minute))
		})
	}()
	<-reconnectReady
	sharedCallbackCalled := false
	sharedDone := make(chan error, 1)
	go func() {
		sharedDone <- disconnectStore.WithGitHubInstallationLease(ctx, owner.ID, 42, func(context.Context) error {
			sharedCallbackCalled = true
			return nil
		})
	}()
	sharedWaitDeadline := time.NewTimer(5 * time.Second)
	sharedWaitPoll := time.NewTicker(10 * time.Millisecond)
	sharedWaiting := false
	for !sharedWaiting {
		select {
		case <-sharedWaitPoll.C:
			var count int
			if err := pool.QueryRow(ctx, `
				SELECT count(*)
				FROM pg_locks l
				JOIN pg_stat_activity a ON a.pid=l.pid
				WHERE l.locktype='advisory' AND NOT l.granted
				  AND a.application_name='github-disconnect-integration'`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			sharedWaiting = count > 0
		case <-sharedWaitDeadline.C:
			t.Fatal("shared token user did not wait for the reconnect synchronization lease")
		}
	}
	sharedWaitPoll.Stop()
	if !sharedWaitDeadline.Stop() {
		<-sharedWaitDeadline.C
	}
	select {
	case err := <-sharedDone:
		t.Fatalf("shared token user completed before reconnect synchronization: %v", err)
	default:
	}
	close(reconnectRelease)
	if err := <-reconnectDone; err != nil {
		t.Fatalf("atomic GitHub reconnect: %v", err)
	}
	if err := <-sharedDone; err != nil || !sharedCallbackCalled {
		t.Fatalf("post-reconnect shared token lease: called=%v err=%v", sharedCallbackCalled, err)
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 42); err != nil || !active {
		t.Fatalf("atomic GitHub reconnect did not restore installation: active=%v err=%v", active, err)
	}
	freshMetadata := postgres.GitHubInstallation{
		OwnerID: owner.ID, InstallationID: 43, AccountID: 84, AccountLogin: "owner",
		AccountType: "User", RepositorySelection: "selected", Permissions: json.RawMessage(`{"contents":"write"}`),
		CreatedAt: now, UpdatedAt: now.Add(3 * time.Minute), SuspendedAt: nil,
	}
	freshRepository := repository
	freshRepository.ID = "repo-fresh-install"
	freshRepository.InstallationID = 43
	freshRepository.FullName = "owner/fresh-install"
	freshReconnectSafeAfter := time.Now().UTC().Add(1500 * time.Millisecond)
	err = repositoryStore.WithGitHubInstallationSyncLease(ctx, owner.ID, 43, func(syncCtx context.Context) error {
		if err := repositoryStore.BeginGitHubInstallationReconnect(syncCtx, owner.ID, 43, now.Add(3*time.Minute)); err != nil {
			return err
		}
		if err := repositoryStore.UpsertInstallationForOwnerReconnect(syncCtx, freshMetadata, now.Add(3*time.Minute)); err != nil {
			return err
		}
		active, err := repositoryStore.GitHubInstallationActive(syncCtx, owner.ID, 43)
		if err != nil {
			return err
		}
		if active {
			return errors.New("fresh installation became active before repository sync")
		}
		if err := repositoryStore.Upsert(syncCtx, owner.ID, freshRepository); err != nil {
			return err
		}
		createdAt := time.Now().UTC()
		oldUse := githubapp.TokenUseMetadata{
			ID: "ght_33333333333333333333333333333333", OwnerID: owner.ID, InstallationID: 43,
			Permissions: map[string]string{"contents": "read"}, RepositoryIDs: []int64{99},
			CreatedAt: createdAt, ExpiresAt: createdAt.Add(2 * time.Hour),
		}
		for index := range oldUse.Nonce {
			oldUse.Nonce[index] = 0x5c
		}
		if err := repositoryStore.BeginGitHubInstallationTokenUse(syncCtx, oldUse); err != nil {
			return err
		}
		if err := repositoryStore.SetGitHubInstallationTokenUseExpiry(syncCtx, owner.ID, 43, oldUse.ID, freshReconnectSafeAfter); err != nil {
			return err
		}
		if err := repositoryStore.CompleteGitHubInstallationReconnect(syncCtx, owner.ID, 43, now.Add(3*time.Minute)); !errors.Is(err, core.ErrConflict) {
			return fmt.Errorf("reconnect completion with outstanding old token = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("fresh GitHub reconnect conflict setup: %v", err)
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 43); err != nil || active {
		t.Fatalf("conflicted reconnect completion activated installation: active=%v err=%v", active, err)
	}
	if wait := time.Until(freshReconnectSafeAfter.Add(50 * time.Millisecond)); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		}
	}
	err = repositoryStore.WithGitHubInstallationSyncLease(ctx, owner.ID, 43, func(syncCtx context.Context) error {
		return repositoryStore.CompleteGitHubInstallationReconnect(syncCtx, owner.ID, 43, now.Add(3*time.Minute))
	})
	if err != nil {
		t.Fatalf("fresh atomic GitHub sync after token safe-after: %v", err)
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 43); err != nil || !active {
		t.Fatalf("fresh atomic GitHub sync did not activate installation: active=%v err=%v", active, err)
	}
	if err := repositoryStore.Upsert(ctx, owner.ID, repository); err != nil {
		t.Fatalf("restore repository before suspension: %v", err)
	}
	suspensionSafeAfter := time.Now().UTC().Add(1500 * time.Millisecond)
	err = repositoryStore.WithGitHubInstallationLease(ctx, owner.ID, 42, func(leaseCtx context.Context) error {
		createdAt := time.Now().UTC()
		pendingUse := githubapp.TokenUseMetadata{
			ID: "ght_44444444444444444444444444444444", OwnerID: owner.ID, InstallationID: 42,
			Permissions: map[string]string{"contents": "read"}, RepositoryIDs: []int64{99},
			CreatedAt: createdAt, ExpiresAt: createdAt.Add(2 * time.Hour),
		}
		for index := range pendingUse.Nonce {
			pendingUse.Nonce[index] = 0x4d
		}
		if err := repositoryStore.BeginGitHubInstallationTokenUse(leaseCtx, pendingUse); err != nil {
			return err
		}
		return repositoryStore.SetGitHubInstallationTokenUseExpiry(leaseCtx, owner.ID, 42, pendingUse.ID, suspensionSafeAfter)
	})
	if err != nil {
		t.Fatalf("prepare ambiguous token use before suspension: %v", err)
	}
	if err := repositoryStore.SuspendInstallation(ctx, "different-owner", 42, now.Add(4*time.Minute)); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner GitHub suspension returned %v", err)
	}
	if err := disconnectStore.SuspendInstallation(ctx, owner.ID, 42, now.Add(4*time.Minute)); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("GitHub suspension before token safe-after: %v", err)
	}
	if !time.Now().Before(suspensionSafeAfter) {
		t.Fatal("integration test did not exercise suspension before ambiguous token safe-after")
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 42); err != nil || active {
		t.Fatalf("conflicted suspension did not durably disable installation: active=%v err=%v", active, err)
	}
	if wait := time.Until(suspensionSafeAfter.Add(50 * time.Millisecond)); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		}
	}
	if err := disconnectStore.SuspendInstallation(ctx, owner.ID, 42, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("GitHub suspension after token safe-after: %v", err)
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 42); err != nil || active {
		t.Fatalf("suspended GitHub installation: active=%v err=%v", active, err)
	}
	if err := pool.QueryRow(ctx, `SELECT available FROM repositories WHERE owner_id=$1 AND id=$2`, owner.ID, repository.ID).Scan(&available); err != nil || available {
		t.Fatalf("suspension left repository available: available=%v err=%v", available, err)
	}
	// Simulate a synchronization that starts after suspension but receives stale
	// provider metadata claiming the installation is active. Metadata refresh is
	// inside the exclusive synchronization lease and cannot clear the suspension.
	err = repositoryStore.WithGitHubInstallationSyncLease(ctx, owner.ID, 42, func(syncCtx context.Context) error {
		if err := repositoryStore.UpsertInstallation(syncCtx, postgres.GitHubInstallation{
			OwnerID: owner.ID, InstallationID: 42, AccountID: 84, AccountLogin: "owner",
			AccountType: "User", RepositorySelection: "selected", Permissions: json.RawMessage(`{"contents":"write"}`),
			CreatedAt: now, UpdatedAt: now.Add(5 * time.Minute), SuspendedAt: nil,
		}); err != nil {
			return err
		}
		active, err := repositoryStore.GitHubInstallationActive(syncCtx, owner.ID, 42)
		if err != nil {
			return err
		}
		if active {
			return errors.New("stale provider metadata cleared a completed suspension")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("post-suspension stale metadata sync: %v", err)
	}
	err = repositoryStore.WithGitHubInstallationSyncLease(ctx, owner.ID, 42, func(syncCtx context.Context) error {
		return repositoryStore.UpsertInstallationFromProviderUnsuspend(syncCtx, postgres.GitHubInstallation{
			OwnerID: owner.ID, InstallationID: 42, AccountID: 84, AccountLogin: "owner",
			AccountType: "User", RepositorySelection: "selected", Permissions: json.RawMessage(`{"contents":"write"}`),
			CreatedAt: now, UpdatedAt: now.Add(6 * time.Minute), SuspendedAt: nil,
		})
	})
	if err != nil {
		t.Fatalf("GitHub provider-unsuspend sync: %v", err)
	}
	if active, err := repositoryStore.GitHubInstallationActive(ctx, owner.ID, 42); err != nil || !active {
		t.Fatalf("GitHub provider-unsuspend sync did not restore provider authority: active=%v err=%v", active, err)
	}
}

func testNotificationRegistrationRevocationOrdering(
	t *testing.T,
	ctx context.Context,
	dsn, schema string,
	pool *pgxpool.Pool,
	credentialVault *vault.Vault,
	ownerID string,
	now time.Time,
) {
	t.Helper()
	registerPool, err := postgres.Open(ctx, postgres.PoolConfig{
		URL: dsn, SearchPath: schema, ApplicationName: "codex-mobile-apns-register-race", MaxConns: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registerPool.Close()
	revokePool, err := postgres.Open(ctx, postgres.PoolConfig{
		URL: dsn, SearchPath: schema, ApplicationName: "codex-mobile-apns-revoke-race", MaxConns: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer revokePool.Close()
	registerStore, err := postgres.NewApplicationStore(registerPool, credentialVault)
	if err != nil {
		t.Fatal(err)
	}
	revokeStore, err := postgres.NewSessionStore(revokePool)
	if err != nil {
		t.Fatal(err)
	}

	for index, test := range []struct {
		name          string
		registerFirst bool
	}{
		{name: "registration before revocation is swept", registerFirst: true},
		{name: "revocation before registration is rejected", registerFirst: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			deviceID := fmt.Sprintf("device-apns-race-%d", index)
			at := now.Add(time.Duration(index) * time.Second)
			if _, err := pool.Exec(ctx, `
				INSERT INTO devices (id, owner_id, name, platform, created_at, last_seen_at)
				VALUES ($1,$2,'Race Phone','ios',$3,$3)`, deviceID, ownerID, at); err != nil {
				t.Fatal(err)
			}

			blocker, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback(context.Background()) }()
			var active bool
			if err := blocker.QueryRow(ctx, `
				SELECT revoked_at IS NULL FROM devices
				WHERE owner_id=$1 AND id=$2 FOR UPDATE`, ownerID, deviceID).Scan(&active); err != nil || !active {
				t.Fatalf("lock active race device: active=%v err=%v", active, err)
			}

			register := func() error {
				return registerStore.RegisterNotification(
					ctx, ownerID, deviceID, "production", strings.Repeat(fmt.Sprintf("%x", index+1), 64),
					"com.example.CodexMobile", at,
				)
			}
			revoke := func() error { return revokeStore.RevokeDevice(ctx, ownerID, deviceID, at) }
			firstName, secondName := "register", "revoke"
			first, second := register, revoke
			firstApplication, secondApplication := "codex-mobile-apns-register-race", "codex-mobile-apns-revoke-race"
			if !test.registerFirst {
				firstName, secondName = secondName, firstName
				first, second = second, first
				firstApplication, secondApplication = secondApplication, firstApplication
			}
			firstResult := make(chan error, 1)
			go func() { firstResult <- first() }()
			waitForPostgresLockWait(t, ctx, pool, firstApplication)
			secondResult := make(chan error, 1)
			go func() { secondResult <- second() }()
			waitForPostgresLockWait(t, ctx, pool, secondApplication)
			if err := blocker.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			firstErr, secondErr := <-firstResult, <-secondResult
			results := map[string]error{firstName: firstErr, secondName: secondErr}
			if err := results["revoke"]; err != nil {
				t.Fatalf("device revocation failed: %v", err)
			}
			if test.registerFirst {
				if err := results["register"]; err != nil {
					t.Fatalf("registration ordered before revocation failed: %v", err)
				}
			} else if err := results["register"]; !errors.Is(err, core.ErrUnauthorized) {
				t.Fatalf("registration ordered after revocation = %v", err)
			}
			var total, enabled int
			if err := pool.QueryRow(ctx, `
				SELECT count(*), count(*) FILTER (WHERE enabled AND revoked_at IS NULL)
				FROM notification_endpoints WHERE owner_id=$1 AND device_id=$2`, ownerID, deviceID).Scan(&total, &enabled); err != nil {
				t.Fatal(err)
			}
			wantTotal := 1
			if !test.registerFirst {
				wantTotal = 0
			}
			if total != wantTotal || enabled != 0 {
				t.Fatalf("post-race endpoints: total=%d enabled=%d want total=%d enabled=0", total, enabled, wantTotal)
			}
		})
	}
}

func waitForPostgresLockWait(t *testing.T, ctx context.Context, pool *pgxpool.Pool, applicationName string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE application_name=$1 AND wait_event_type='Lock'
			)`, applicationName).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("PostgreSQL session %q did not wait on the device row lock", applicationName)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func tokenID(token string) string {
	prefix := "cm_access_"
	dot := bytes.IndexByte([]byte(token), '.')
	if dot <= len(prefix) || len(token) <= len(prefix) || token[:len(prefix)] != prefix {
		return ""
	}
	return token[len(prefix):dot]
}
