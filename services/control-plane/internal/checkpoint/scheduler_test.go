package checkpoint

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

type recordedRisk struct {
	calls                int
	ownerID, workspaceID string
	dirty, unpushed      bool
}

type checkpointRecorder struct{ values []bool }

func (r *checkpointRecorder) RecordCheckpoint(success bool) { r.values = append(r.values, success) }

func (r *recordedRisk) UpdateGitRisk(_ context.Context, ownerID, workspaceID string, dirty, unpushed bool, _ time.Time) error {
	r.calls++
	r.ownerID, r.workspaceID, r.dirty, r.unpushed = ownerID, workspaceID, dirty, unpushed
	return nil
}

func TestSchedulerCreatesPeriodicCheckpointAndRefreshesLiveRisk(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGit(t, repository)
	write(t, filepath.Join(repository, "tracked.txt"), "terminal-side edit\n")
	helper, _ := workspacehelper.New(repository)
	service, err := New(Config{Root: filepath.Join(base, "checkpoints")}, localRunner{helper: helper, providerID: testProviderID})
	if err != nil {
		t.Fatal(err)
	}
	workspace := core.Workspace{
		ID: testWorkspaceID, OwnerID: "owner", ProviderResourceID: testProviderID,
		State: core.WorkspaceRunning,
		// Deliberately stale to prove the scheduler uses helper-derived state.
		Dirty: false, Unpushed: false,
	}
	risk := &recordedRisk{}
	recorder := &checkpointRecorder{}
	scheduler, err := NewScheduler(service, func(context.Context) ([]core.Workspace, error) {
		return []core.Workspace{workspace}, nil
	}, risk, time.Minute, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if risk.calls != 1 || risk.ownerID != "owner" || risk.workspaceID != testWorkspaceID || !risk.dirty || !risk.unpushed {
		t.Fatalf("live risk update = %#v", risk)
	}
	if len(recorder.values) != 1 || !recorder.values[0] {
		t.Fatalf("checkpoint metric = %#v", recorder.values)
	}
	items, err := service.List(testWorkspaceID)
	if err != nil || len(items) != 1 || items[0].Reason != "periodic" {
		t.Fatalf("periodic checkpoints = %#v, %v", items, err)
	}
}
