package postgres

import (
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

func TestScanWorkspaceMapsRepositoryAndPolicy(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	value, err := scanWorkspace(valuesRow{
		"ws-1", "owner-1", "Workspace", "codex-mobile/task-1", "main", "/worktrees/ws-1",
		"running", "balanced", "30_days", false,
		true, ".", true, false, true, false,
		int64(1000), int64(2048), int64(20),
		int64(12),
		"provider-1", "",
		now, now.Add(time.Minute), now.Add(time.Minute),
		(*int)(nil), (*time.Time)(nil),
		"repo-1", int64(42), "owner/repo", "main",
		true, false, "push", now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.State != core.WorkspaceRunning || value.SafetyMode != core.SafetyBalanced ||
		value.Repository.FullName != "owner/repo" || value.Quota.MemoryMiB != 2048 || value.RequestedDiskGiB != 12 || value.PrivateInputsPending {
		t.Fatalf("unexpected workspace mapping: %#v", value)
	}
}

func TestScanWorkspaceRejectsUnknownState(t *testing.T) {
	now := time.Now().UTC()
	_, err := scanWorkspace(valuesRow{
		"ws-1", "owner-1", "Workspace", "branch", "main", "",
		"invented", "balanced", "30_days", false,
		false, "", false, false, false, false,
		int64(0), int64(0), int64(0),
		int64(0),
		"", "", now, now, now, (*int)(nil), (*time.Time)(nil),
		"repo-1", int64(42), "owner/repo", "main", true, false, "push", now,
	})
	if err == nil {
		t.Fatal("accepted an unknown stored workspace state")
	}
}
