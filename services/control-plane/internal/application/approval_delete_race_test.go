package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/admission"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspace"
)

type approvalRaceRepositories struct{ value core.Repository }

func (r approvalRaceRepositories) Get(context.Context, string, string) (core.Repository, error) {
	return r.value, nil
}

type approvalRaceDetector struct{}

func (approvalRaceDetector) Detect(context.Context, string, core.Repository, string) (workspace.Environment, error) {
	return workspace.Environment{HasDevcontainer: true, Supported: true, RequiresTrust: true, ConfigDirectory: ".devcontainer"}, nil
}

type approvalRaceCheckpoint struct{}

func (approvalRaceCheckpoint) Create(context.Context, string, string, string) (string, bool, bool, error) {
	return "checkpoint", false, false, nil
}
func (approvalRaceCheckpoint) Latest(context.Context, string) (string, error) {
	return "checkpoint", nil
}

type approvalRaceWorkspaceStore struct{ *workspace.MemoryStore }

func (s *approvalRaceWorkspaceStore) UpdateGitRisk(ctx context.Context, ownerID, workspaceID string, dirty, unpushed bool, at time.Time) error {
	value, err := s.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return err
	}
	value.Dirty, value.Unpushed = dirty, unpushed
	value.UpdatedAt = at
	return s.Save(ctx, value)
}

type approvalRaceProvider struct {
	deleteStarted chan struct{}
	deleteRelease chan struct{}
}

func (*approvalRaceProvider) LookupProvisioned(context.Context, string) (string, error) {
	return "", core.ErrNotFound
}
func (*approvalRaceProvider) Provision(_ context.Context, request workspace.ProvisionRequest) (string, error) {
	return "provider-" + request.WorkspaceID, nil
}
func (*approvalRaceProvider) Start(context.Context, string, workspace.StartRequest) error { return nil }
func (*approvalRaceProvider) StartWithSetup(context.Context, string, workspace.SetupStartRequest) error {
	return nil
}
func (*approvalRaceProvider) StopAndWait(context.Context, string) error { return nil }
func (*approvalRaceProvider) Stop(context.Context, string) error        { return nil }
func (p *approvalRaceProvider) Delete(ctx context.Context, _ string) error {
	select {
	case <-p.deleteStarted:
	default:
		close(p.deleteStarted)
	}
	select {
	case <-p.deleteRelease:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*approvalRaceProvider) ApplyQuota(context.Context, string, core.Quota) error { return nil }

func TestSetupDecisionNeverDeadlocksOrOverwritesConcurrentDelete(t *testing.T) {
	for _, decision := range []httpapi.ApprovalDecision{httpapi.DecisionApprove, httpapi.DecisionDeny} {
		t.Run(string(decision), func(t *testing.T) {
			now := time.Date(2026, 7, 16, 20, 0, 0, 0, time.UTC)
			store := &approvalRaceWorkspaceStore{MemoryStore: workspace.NewMemoryStore(200)}
			controller, err := admission.New(admission.ReferenceCapacity())
			if err != nil {
				t.Fatal(err)
			}
			provider := &approvalRaceProvider{deleteStarted: make(chan struct{}), deleteRelease: make(chan struct{})}
			repository := core.Repository{ID: "repo", InstallationID: 1, FullName: "owner/repo", DefaultBranch: "main"}
			service, err := workspace.New(store, approvalRaceRepositories{repository}, approvalRaceDetector{}, provider, controller, approvalRaceCheckpoint{})
			if err != nil {
				t.Fatal(err)
			}
			state := &fakeState{}
			application := &Application{deps: Dependencies{
				State: state, Workspaces: service, WorkspaceStore: store, Clock: fixedClock{now}, Random: zeroReader{},
			}}
			if err := service.ConfigureDeletionBoundary(application); err != nil {
				t.Fatal(err)
			}
			if err := service.ConfigureSuspensionBoundary(application); err != nil {
				t.Fatal(err)
			}
			value, err := service.Create(context.Background(), "owner", core.CreateWorkspaceInput{RepositoryID: "repo", Name: "Race setup"})
			if err != nil || value.State != core.WorkspaceAwaitingSetupApproval {
				t.Fatalf("setup workspace = %#v, %v", value, err)
			}
			state.event = postgres.SafetyEvent{
				ID: "approval-race", WorkspaceID: value.ID, WorkspaceName: value.Name, SafetyMode: string(value.SafetyMode),
				Action: "approve_repository_setup", Decision: "requested", Reason: "Review setup", CreatedAt: now,
			}
			deleteDone := make(chan error, 1)
			go func() { deleteDone <- service.Delete(context.Background(), "owner", value.ID, false, true) }()
			select {
			case <-provider.deleteStarted:
			case <-time.After(time.Second):
				t.Fatal("delete did not reach provider")
			}
			decisionDone := make(chan error, 1)
			go func() {
				_, resolveErr := application.ResolveApproval(
					context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, state.event.ID,
					httpapi.ApprovalDecisionRequest{Decision: decision},
				)
				decisionDone <- resolveErr
			}()
			select {
			case err := <-decisionDone:
				t.Fatalf("setup decision escaped in-flight delete with %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			close(provider.deleteRelease)
			if err := <-deleteDone; err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-decisionDone:
				if !errors.Is(err, core.ErrNotFound) {
					t.Fatalf("decision after finalized delete = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("setup decision deadlocked with deletion boundary")
			}
			if _, err := store.Get(context.Background(), "owner", value.ID); !errors.Is(err, core.ErrNotFound) {
				t.Fatalf("setup decision resurrected deleting workspace: %v", err)
			}
		})
	}
}
