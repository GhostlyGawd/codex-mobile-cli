package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
)

type autonomyWorkspaceOperations struct {
	fakeWorkspaceOperations
	result      core.Workspace
	ownerID     string
	workspaceID string
	mode        core.SafetyMode
	calls       int
}

func (o *autonomyWorkspaceOperations) UpdateSafetyMode(_ context.Context, ownerID, workspaceID string, mode core.SafetyMode) (core.Workspace, error) {
	o.calls++
	o.ownerID, o.workspaceID, o.mode = ownerID, workspaceID, mode
	return o.result, nil
}

func TestWorkspaceAutonomyActionIsOwnerScopedAndReturnsAppliedMode(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 22, 0, 0, 0, time.UTC)
	current := core.Workspace{
		ID: "ws-autonomy", OwnerID: "owner", Name: "Autonomy", State: core.WorkspaceSuspended,
		SafetyMode: core.SafetyBalanced, Retention: core.Retention30Days,
		Repository: core.Repository{ID: "repo", FullName: "owner/repo"},
		Branch:     "codex-mobile/autonomy", BaseBranch: "main", RequestedDiskGiB: 12,
		CreatedAt: now, UpdatedAt: now, LastActivityAt: now, SuspendedAt: &now,
	}
	updated := current
	updated.SafetyMode = core.SafetySafe
	operations := &autonomyWorkspaceOperations{result: updated}
	state := &fakeState{}
	application := &Application{deps: Dependencies{
		Workspaces: operations, WorkspaceStore: &fakeWorkspaceStore{value: current},
		State: state, Clock: fixedClock{now},
	}}
	mode := httpapi.AutonomySafe
	result, err := application.PerformWorkspaceAction(
		context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, current.ID,
		httpapi.WorkspaceActionRequest{Action: httpapi.ActionUpdateAutonomy, Autonomy: &mode},
	)
	if err != nil {
		t.Fatal(err)
	}
	if operations.calls != 1 || operations.ownerID != "owner" || operations.workspaceID != current.ID ||
		operations.mode != core.SafetySafe || result.Workspace.Autonomy != httpapi.AutonomySafe {
		t.Fatalf("autonomy action mapping = operations=%#v result=%#v", operations, result)
	}
	if len(state.audits) != 1 || state.audits[0].action != "workspace.update_autonomy" {
		t.Fatalf("autonomy action audit = %#v", state.audits)
	}

	_, err = application.PerformWorkspaceAction(
		context.Background(), httpapi.Principal{OwnerID: "other-owner", DeviceID: "device"}, current.ID,
		httpapi.WorkspaceActionRequest{Action: httpapi.ActionUpdateAutonomy, Autonomy: &mode},
	)
	if !errors.Is(err, core.ErrNotFound) || operations.calls != 1 {
		t.Fatalf("cross-owner autonomy action was not rejected before mutation: calls=%d err=%v", operations.calls, err)
	}
}

func TestWorkspaceAutonomyActionRequiresMode(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 22, 5, 0, 0, time.UTC)
	current := core.Workspace{
		ID: "ws-autonomy", OwnerID: "owner", Name: "Autonomy", State: core.WorkspaceSuspended,
		SafetyMode: core.SafetyBalanced, Retention: core.Retention30Days,
		Repository: core.Repository{ID: "repo", FullName: "owner/repo"}, Branch: "branch", BaseBranch: "main",
		CreatedAt: now, UpdatedAt: now, LastActivityAt: now, SuspendedAt: &now,
	}
	operations := &autonomyWorkspaceOperations{result: current}
	application := &Application{deps: Dependencies{
		Workspaces: operations, WorkspaceStore: &fakeWorkspaceStore{value: current}, State: &fakeState{},
		Clock: fixedClock{now}, Random: zeroReader{},
	}}
	_, err := application.PerformWorkspaceAction(
		context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, current.ID,
		httpapi.WorkspaceActionRequest{Action: httpapi.ActionUpdateAutonomy},
	)
	if !errors.Is(err, core.ErrInvalid) || operations.calls != 0 {
		t.Fatalf("missing autonomy = calls=%d err=%v", operations.calls, err)
	}
}
