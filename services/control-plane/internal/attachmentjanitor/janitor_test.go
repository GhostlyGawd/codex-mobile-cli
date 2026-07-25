package attachmentjanitor

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

type recordingRunner struct {
	providers []string
	requests  [][]byte
	err       error
}

func (r *recordingRunner) RunHelper(_ context.Context, provider string, request []byte) ([]byte, error) {
	r.providers = append(r.providers, provider)
	r.requests = append(r.requests, append([]byte(nil), request...))
	if r.err != nil {
		return nil, r.err
	}
	return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true})
}

func TestRunOnceCleansOnlyLiveWorkspaceTmpfs(t *testing.T) {
	runner := &recordingRunner{}
	janitor, err := New(runner, func(context.Context) ([]core.Workspace, error) {
		return []core.Workspace{
			{ID: "running", State: core.WorkspaceRunning, ProviderResourceID: "provider-running"},
			{ID: "suspended", State: core.WorkspaceSuspended, ProviderResourceID: "provider-suspended"},
			{ID: "missing", State: core.WorkspaceRunning},
		}, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := janitor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.providers) != 1 || runner.providers[0] != "provider-running" {
		t.Fatalf("unexpected janitor targets: %#v", runner.providers)
	}
	var request workspacehelper.Request
	if err := json.Unmarshal(runner.requests[0], &request); err != nil || request.Operation != workspacehelper.OpAttachmentCleanup {
		t.Fatalf("unexpected cleanup request: %#v %v", request, err)
	}
}

func TestRunOnceSurfacesRunnerFailure(t *testing.T) {
	runner := &recordingRunner{err: errors.New("provider unavailable")}
	janitor, err := New(runner, func(context.Context) ([]core.Workspace, error) {
		return []core.Workspace{{State: core.WorkspaceRunning, ProviderResourceID: "provider"}}, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := janitor.RunOnce(context.Background()); err == nil {
		t.Fatal("expected cleanup failure")
	}
}
