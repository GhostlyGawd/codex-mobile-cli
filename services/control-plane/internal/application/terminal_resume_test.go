package application

import (
	"context"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
)

type terminalSuspendOperations struct {
	fakeWorkspaceOperations
	result core.Workspace
	hook   func(context.Context) error
}

func (o *terminalSuspendOperations) Suspend(ctx context.Context, _, _ string) (core.Workspace, error) {
	if o.hook != nil {
		if err := o.hook(ctx); err != nil {
			return core.Workspace{}, err
		}
	}
	return o.result, nil
}

func TestWorkspaceSuspendClearsTerminalRuntimeForExactResume(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 21, 0, 0, 0, time.UTC)
	const (
		workspaceID = "ws-resume"
		tabID       = "11111111-1111-4111-8111-111111111111"
	)
	current := core.Workspace{
		ID: workspaceID, OwnerID: "owner", Name: "Resume", State: core.WorkspaceRunning,
		SafetyMode: core.SafetyBalanced, Retention: core.Retention30Days,
		Repository: core.Repository{ID: "repo", FullName: "owner/repo"},
		Branch:     "codex-mobile/resume", BaseBranch: "main",
		CreatedAt: now, UpdatedAt: now, LastActivityAt: now,
	}
	suspended := current
	suspended.State = core.WorkspaceSuspended
	state := &fakeState{tab: postgres.TerminalTabRecord{
		ID: tabID, OwnerID: "owner", WorkspaceID: workspaceID, Title: "Codex", Kind: "codex",
		CoderReconnectID: "22222222-2222-4222-8222-222222222222", CodexThreadID: "33333333-3333-4333-8333-333333333333", CreatedAt: now,
	}}
	terminals := &fakeTerminals{}
	operations := &terminalSuspendOperations{result: suspended}
	application := &Application{
		deps: Dependencies{
			Workspaces: operations, WorkspaceStore: &fakeWorkspaceStore{value: current},
			State: state, Terminals: terminals, Clock: fixedClock{now},
		},
		running: map[string]bool{tabID: true}, starting: make(map[string]chan struct{}),
	}
	operations.hook = func(ctx context.Context) error {
		suspending := current
		suspending.State = core.WorkspaceSuspending
		release, err := application.BeginWorkspaceSuspension(ctx, suspending)
		if err != nil {
			return err
		}
		defer release()
		return nil
	}
	result, err := application.PerformWorkspaceAction(
		context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, workspaceID,
		httpapi.WorkspaceActionRequest{Action: httpapi.ActionSuspend},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Workspace.Summary.Lifecycle != httpapi.WorkspaceSuspended || application.running[tabID] || terminals.unregisterCalls != 1 {
		t.Fatalf("suspend left a stale terminal runtime: lifecycle=%s running=%v unregister=%d", result.Workspace.Summary.Lifecycle, application.running[tabID], terminals.unregisterCalls)
	}
}
