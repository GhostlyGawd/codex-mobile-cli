//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIntegrationTerminalTabMutations(t *testing.T) {
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN is not set; see migrations/README.md")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("codex_mobile_terminal_tabs_%d", time.Now().UnixNano())
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

	now := time.Date(2026, 7, 16, 20, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, webauthn_handle, username, display_name, created_at, updated_at)
		VALUES ('owner', $1, 'owner', 'Owner', $2, $2)`, bytes.Repeat([]byte{0x31}, 64), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO github_installations
		    (owner_id, installation_id, account_id, account_login, account_type,
		     repository_selection, permissions, created_at, updated_at)
		VALUES ('owner', 1, 1, 'owner', 'User', 'selected', '{}', $1, $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO repositories
		    (owner_id, id, installation_id, full_name, default_branch, private,
		     organization, permission, updated_at)
		VALUES ('owner', 'repo', 1, 'owner/repo', 'main', true, false, 'push', $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO workspaces
		    (id, owner_id, repository_id, name, branch, base_branch, state,
		     safety_mode, retention, created_at, updated_at, last_activity_at)
		VALUES ('workspace', 'owner', 'repo', 'Workspace', 'task', 'main', 'running',
		        'balanced', '30_days', $1, $1, $1)`, now); err != nil {
		t.Fatal(err)
	}
	cipher, err := vault.New(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgres.NewApplicationStore(pool, cipher)
	if err != nil {
		t.Fatal(err)
	}
	create := func(id, reconnect, title, kind string, created time.Time) postgres.TerminalTabRecord {
		t.Helper()
		value, err := store.CreateTerminalTab(ctx, postgres.TerminalTabRecord{
			ID: id, OwnerID: "owner", WorkspaceID: "workspace", Title: title, Kind: kind,
			CoderReconnectID: reconnect, CreatedAt: created,
		})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	primaryID := "11111111-1111-4111-8111-111111111111"
	shellAID := "22222222-2222-4222-8222-222222222222"
	shellBID := "33333333-3333-4333-8333-333333333333"
	create(primaryID, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Codex", "codex", now)
	create(shellAID, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Shell A", "shell", now.Add(time.Second))
	create(shellBID, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "Shell B", "shell", now.Add(2*time.Second))
	threadID := "99999999-9999-4999-8999-999999999999"
	mapped, err := store.SetTerminalCodexThreadID(ctx, "owner", "workspace", primaryID, threadID)
	if err != nil || mapped.CodexThreadID != threadID {
		t.Fatalf("Codex thread mapping mismatch: %#v %v", mapped, err)
	}
	if _, err := store.SetTerminalCodexThreadID(ctx, "owner", "workspace", shellAID, threadID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("shell accepted a Codex thread mapping: %v", err)
	}
	if _, err := store.SetTerminalCodexThreadID(ctx, "other", "workspace", primaryID, threadID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner Codex thread mapping was not hidden: %v", err)
	}
	if _, err := store.SetTerminalCodexThreadID(ctx, "owner", "workspace", primaryID, "unsafe"); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("unsafe Codex thread mapping was accepted: %v", err)
	}

	renamed, err := store.RenameTerminalTab(ctx, "owner", "workspace", shellAID, "Build logs")
	if err != nil || renamed.Title != "Build logs" {
		t.Fatalf("rename mismatch: %#v %v", renamed, err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := store.RenameTerminalTab(cancelled, "owner", "workspace", shellAID, "Cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled rename did not stop: %v", err)
	}
	if _, err := store.RenameTerminalTab(ctx, "other", "workspace", shellAID, "Hidden"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner rename was not hidden: %v", err)
	}
	if _, err := store.ReorderTerminalTabs(ctx, "owner", "workspace", []string{primaryID, shellAID}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("stale subset reorder was accepted: %v", err)
	}
	order := []string{shellBID, primaryID, shellAID}
	values, err := store.ReorderTerminalTabs(ctx, "owner", "workspace", order)
	if err != nil || !slices.Equal(tabRecordIDs(values), order) {
		t.Fatalf("atomic reorder mismatch: %#v %v", values, err)
	}
	if _, _, err := store.CloseTerminalTab(ctx, "owner", "workspace", primaryID, now.Add(time.Hour)); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("primary Codex tab close was accepted: %v", err)
	}
	if _, changed, err := store.CloseTerminalTab(ctx, "owner", "workspace", shellBID, now.Add(time.Hour)); err != nil || !changed {
		t.Fatalf("terminal close failed: changed=%v err=%v", changed, err)
	}
	if _, changed, err := store.CloseTerminalTab(ctx, "owner", "workspace", shellBID, now.Add(2*time.Hour)); err != nil || changed {
		t.Fatalf("idempotent terminal close mismatch: changed=%v err=%v", changed, err)
	}
	values, err = store.ListTerminalTabs(ctx, "owner", "workspace")
	if err != nil || !slices.Equal(tabRecordIDs(values), []string{primaryID, shellAID}) || values[0].Order != 0 || values[1].Order != 1 {
		t.Fatalf("close did not compact active order: %#v %v", values, err)
	}

	for index := 0; index < 62; index++ {
		create(
			fmt.Sprintf("40000000-0000-4000-8000-%012d", index),
			fmt.Sprintf("50000000-0000-4000-8000-%012d", index),
			fmt.Sprintf("Shell %d", index), "shell", now.Add(time.Duration(index+3)*time.Second),
		)
	}
	values, err = store.ListTerminalTabs(ctx, "owner", "workspace")
	if err != nil || len(values) != 64 {
		t.Fatalf("terminal cap setup mismatch: count=%d err=%v", len(values), err)
	}
	fullOrder := tabRecordIDs(values)
	slices.Reverse(fullOrder)
	values, err = store.ReorderTerminalTabs(ctx, "owner", "workspace", fullOrder)
	if err != nil || !slices.Equal(tabRecordIDs(values), fullOrder) || values[63].Order != 63 {
		t.Fatalf("64-tab atomic reorder mismatch: count=%d err=%v", len(values), err)
	}
	_, err = store.CreateTerminalTab(ctx, postgres.TerminalTabRecord{
		ID: "60000000-0000-4000-8000-000000000000", OwnerID: "owner", WorkspaceID: "workspace",
		Title: "Over capacity", Kind: "shell", CoderReconnectID: "70000000-0000-4000-8000-000000000000", CreatedAt: now.Add(10 * time.Minute),
	})
	if !errors.Is(err, core.ErrCapacity) {
		t.Fatalf("65th active terminal tab was accepted: %v", err)
	}
}

func tabRecordIDs(values []postgres.TerminalTabRecord) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.ID
	}
	return result
}
