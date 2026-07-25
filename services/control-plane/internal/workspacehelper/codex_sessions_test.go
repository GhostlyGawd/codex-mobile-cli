package workspacehelper

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLatestCodexThreadIDIsTabScopedBoundedMetadata(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	tabID := "11111111-1111-4111-8111-111111111111"
	home, err := terminalCodexHome(root, tabID)
	if err != nil {
		t.Fatal(err)
	}
	day := filepath.Join(home, "sessions", "2026", "07", "16")
	if err := os.MkdirAll(day, 0o700); err != nil {
		t.Fatal(err)
	}
	older := filepath.Join(day, "rollout-2026-07-16T10-00-00-22222222-2222-4222-8222-222222222222.jsonl")
	newer := filepath.Join(day, "rollout-2026-07-16T11-00-00-33333333-3333-4333-8333-333333333333.jsonl")
	for _, path := range []string{older, newer} {
		if err := os.WriteFile(path, []byte("metadata is deliberately not parsed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := os.Chtimes(older, now.Add(-time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newer, now, now); err != nil {
		t.Fatal(err)
	}
	threadID, err := latestCodexThreadID(home)
	if err != nil || threadID != "33333333-3333-4333-8333-333333333333" {
		t.Fatalf("unexpected latest thread: %q %v", threadID, err)
	}

	helper, err := NewWithTemporaryRoot(root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	response := helper.execute(t.Context(), &Request{Version: Version, Operation: OpCodexThreadLookup, TerminalTabID: tabID})
	if !response.OK || response.CodexThreadID != threadID {
		t.Fatalf("unexpected lookup response: %#v", response)
	}
	response = helper.execute(t.Context(), &Request{Version: Version, Operation: OpCodexThreadLookup, TerminalTabID: tabID, Query: "smuggled"})
	if response.OK || response.ErrorCode != "invalid" {
		t.Fatalf("lookup accepted unrelated helper fields: %#v", response)
	}
}

func TestLatestCodexThreadIDRejectsSymlinkedSessionTree(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, "sessions")); err != nil {
		if os.PathSeparator == '\\' {
			t.Skip("Windows development host does not permit an unprivileged directory symlink")
		}
		t.Fatal(err)
	}
	if _, err := latestCodexThreadID(home); !errors.Is(err, errCodexAuthUnavailable) {
		t.Fatalf("symlinked session tree was accepted: %v", err)
	}
}

func TestPrepareTerminalCodexHomeUsesManagedSharedLinks(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	home, err := prepareTerminalCodexHome(root, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		if os.PathSeparator == '\\' {
			t.Skip("Windows development host does not permit unprivileged managed symlinks")
		}
		t.Fatal(err)
	}
	for name, want := range map[string]string{"config.toml": filepath.Join("..", "..", "config.toml"), "auth.json": filepath.Join("..", "..", "auth.json")} {
		got, err := os.Readlink(filepath.Join(home, name))
		if err != nil || filepath.Clean(got) != filepath.Clean(want) {
			t.Fatalf("managed %s link: %q %v", name, got, err)
		}
	}
	if _, err := prepareTerminalCodexHome(root, "not-a-tab"); err == nil {
		t.Fatal("unsafe terminal identity was accepted")
	}
}
