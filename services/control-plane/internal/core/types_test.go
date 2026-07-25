package core

import "testing"

func TestWorkspaceStateTransitions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		from, to WorkspaceState
		want     bool
	}{
		{WorkspaceQueued, WorkspaceProvisioning, true},
		{WorkspaceProvisioning, WorkspaceAwaitingSetupApproval, true},
		{WorkspaceAwaitingSetupApproval, WorkspaceProvisioning, true},
		{WorkspaceRunning, WorkspaceSuspending, true},
		{WorkspaceSuspending, WorkspaceSuspended, true},
		{WorkspaceSuspended, WorkspaceRunning, false},
		{WorkspaceDeleting, WorkspaceRunning, false},
	}
	for _, tc := range cases {
		if got := tc.from.CanTransition(tc.to); got != tc.want {
			t.Errorf("%s -> %s = %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestDirtyWorkspaceCannotAutoDelete(t *testing.T) {
	t.Parallel()
	for _, w := range []Workspace{
		{Dirty: true, Retention: Retention7Days},
		{Unpushed: true, Retention: Retention7Days},
		{Retention: RetentionForever},
	} {
		if w.MayAutoDelete() {
			t.Fatalf("workspace %#v unexpectedly eligible for auto-delete", w)
		}
	}
}

func TestUnconfirmedProviderStatesConsumeRuntimeCapacity(t *testing.T) {
	t.Parallel()
	for _, state := range []WorkspaceState{WorkspaceProvisioning, WorkspaceSuspending, WorkspaceDeleting} {
		if !state.CountsAsRunning() {
			t.Fatalf("%s unexpectedly released runtime capacity", state)
		}
	}
	for _, state := range []WorkspaceState{WorkspaceQueued, WorkspaceAwaitingSetupApproval, WorkspaceSuspended, WorkspaceFailed} {
		if state.CountsAsRunning() {
			t.Fatalf("%s unexpectedly consumed runtime capacity", state)
		}
	}
}

func TestWorkspaceEnvironmentRejectsRuntimeOverrides(t *testing.T) {
	t.Parallel()
	input := CreateWorkspaceInput{
		RepositoryID: "repo", Name: "task", BaseBranch: "main",
		SafetyMode: SafetyBalanced, Retention: Retention30Days,
		RequestedDiskGiB:     DefaultWorkspaceDiskGiB,
		EnvironmentVariables: map[string]string{"PATH": "/hostile"},
	}
	if err := input.Validate(); err == nil {
		t.Fatal("reserved runtime environment override was accepted")
	}
	input.EnvironmentVariables = map[string]string{"EXAMPLE_API_TOKEN": "value"}
	if err := input.Validate(); err != nil {
		t.Fatalf("valid workspace environment rejected: %v", err)
	}
}

func TestWorkspaceDiskDefaultsAndBounds(t *testing.T) {
	t.Parallel()
	input := CreateWorkspaceInput{
		RepositoryID: "repo", Name: "task", SafetyMode: SafetyBalanced, Retention: Retention30Days,
	}
	input.ApplyDefaults("main")
	if input.RequestedDiskGiB != DefaultWorkspaceDiskGiB {
		t.Fatalf("default disk = %d, want %d", input.RequestedDiskGiB, DefaultWorkspaceDiskGiB)
	}
	if err := input.Validate(); err != nil {
		t.Fatalf("default input rejected: %v", err)
	}
	for _, invalid := range []int64{MinimumWorkspaceDiskGiB - 1, MaximumWorkspaceDiskGiB + 1} {
		input.RequestedDiskGiB = invalid
		if err := input.Validate(); err == nil {
			t.Fatalf("invalid disk quota %d GiB accepted", invalid)
		}
	}
}
