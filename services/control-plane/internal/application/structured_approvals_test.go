package application

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/setupreview"
)

type availableBootstrap bool

func (value availableBootstrap) Available(context.Context) (bool, error) {
	return bool(value), nil
}

type recordedActivityNotification struct {
	ownerID, activityID, kind, deepLinkPath string
}

type recordedSetupReviewStore struct {
	requests []setupreview.Request
}

func (s *recordedSetupReviewStore) EnsureSetupReview(_ context.Context, request setupreview.Request) (setupreview.Result, error) {
	s.requests = append(s.requests, request)
	return setupreview.Result{ApprovalID: request.ApprovalID, ActivityID: request.ActivityID, ActivityCreated: true}, nil
}

func (r *recordedActivityNotification) NotifyActivity(ownerID, activityID, kind, deepLinkPath string) bool {
	r.ownerID, r.activityID, r.kind, r.deepLinkPath = ownerID, activityID, kind, deepLinkPath
	return true
}

func TestSetupApprovalsAreAlwaysAdvertisedAndStructured(t *testing.T) {
	t.Parallel()
	application := &Application{deps: Dependencies{
		Bootstrap: availableBootstrap(false),
		Clock:     fixedClock{time.Unix(200, 0)},
	}}
	capabilities, err := application.GetCapabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !capabilities.StructuredApprovalsAvailable {
		t.Fatal("internally generated setup approvals must remain reachable in the native client")
	}

	review := application.approvalReview(postgres.SafetyEvent{
		ID: "approval_1", WorkspaceID: "workspace_1", WorkspaceName: "Workspace",
		Decision: "requested", CreatedAt: time.Unix(100, 0),
	})
	if !review.StructuredDetailAvailable {
		t.Fatal("setup approval review must expose its structured action controls")
	}
}

func TestLegacySetupApprovalDoesNotExpireWhileWorkspaceAwaitsDecision(t *testing.T) {
	t.Parallel()
	created := time.Unix(100, 0).UTC()
	expires := created.Add(24 * time.Hour)
	if state := approvalState(postgres.SafetyEvent{
		Action: "approve_repository_setup", Decision: "requested", CreatedAt: created, ExpiresAt: &expires,
	}, expires.Add(72*time.Hour)); state != httpapi.ActivityPending {
		t.Fatalf("legacy setup approval state = %s, want pending", state)
	}
}

func TestSetupApprovalQueuesGenericAuthenticatedNotificationAfterPersistence(t *testing.T) {
	t.Parallel()
	notifier := &recordedActivityNotification{}
	store := &recordedSetupReviewStore{}
	reviews, err := setupreview.New(store, notifier, bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatal(err)
	}
	application := &Application{deps: Dependencies{
		SetupReviews: reviews, Clock: fixedClock{time.Unix(200, 0)},
	}}
	if err := application.addSetupApproval(context.Background(), core.Workspace{
		ID: "workspace_1", OwnerID: "owner_1", Name: "Hostile repository name",
		State: core.WorkspaceAwaitingSetupApproval, SafetyMode: core.SafetyBalanced,
	}); err != nil {
		t.Fatal(err)
	}
	if len(store.requests) != 1 || notifier.ownerID != "owner_1" || notifier.activityID == "" || notifier.kind != "approval" ||
		!strings.HasPrefix(notifier.deepLinkPath, "/app/approvals/approval_") || strings.Contains(notifier.deepLinkPath, "Hostile") {
		t.Fatalf("setup approval notification was not generic and routable: store=%#v notification=%#v", store, notifier)
	}
}
