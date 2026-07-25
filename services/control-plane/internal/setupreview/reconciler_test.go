package setupreview

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type memoryStore struct {
	approvalID, activityID string
	requests               []Request
}

func (s *memoryStore) EnsureSetupReview(_ context.Context, request Request) (Result, error) {
	s.requests = append(s.requests, request)
	created := s.approvalID == ""
	if created {
		s.approvalID, s.activityID = request.ApprovalID, request.ActivityID
	}
	return Result{ApprovalID: s.approvalID, ActivityID: s.activityID, ActivityCreated: created}, nil
}

type memoryNotifier struct{ calls int }

func (n *memoryNotifier) NotifyActivity(_, _, _, _ string) bool {
	n.calls++
	return true
}

func TestEnsureIsRetryableAndNotifiesOnlyForNewDurableActivity(t *testing.T) {
	store := &memoryStore{}
	notifier := &memoryNotifier{}
	randomBytes := make([]byte, 128)
	for index := range randomBytes {
		randomBytes[index] = byte(index)
	}
	reconciler, err := New(store, notifier, bytes.NewReader(randomBytes))
	if err != nil {
		t.Fatal(err)
	}
	workspace := core.Workspace{
		ID: "workspace-1", OwnerID: "owner-1", State: core.WorkspaceAwaitingSetupApproval,
		SafetyMode: core.SafetyBalanced,
	}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	if err := reconciler.Ensure(context.Background(), workspace, now); err != nil {
		t.Fatal(err)
	}
	// Reconciliation remains valid long after the old 24-hour expiry window.
	if err := reconciler.Ensure(context.Background(), workspace, now.Add(72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(store.requests) != 2 || notifier.calls != 1 {
		t.Fatalf("reconciliation calls=%d notifications=%d", len(store.requests), notifier.calls)
	}
	if store.approvalID == "" || store.activityID == "" {
		t.Fatal("durable identities were not generated")
	}
}
