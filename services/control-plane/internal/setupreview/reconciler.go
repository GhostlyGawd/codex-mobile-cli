// Package setupreview keeps the durable approval event and its user-visible
// activity in sync with a workspace that is stopped at the setup trust
// boundary.
package setupreview

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type Request struct {
	ApprovalID  string
	ActivityID  string
	OwnerID     string
	WorkspaceID string
	SafetyMode  string
	Reason      string
	CreatedAt   time.Time
}

type Result struct {
	ApprovalID      string
	ActivityID      string
	ActivityCreated bool
}

type Store interface {
	EnsureSetupReview(context.Context, Request) (Result, error)
}

type Notifier interface {
	NotifyActivity(ownerID, activityID, kind, deepLinkPath string) bool
}

type Reconciler struct {
	store    Store
	notifier Notifier
	random   io.Reader
	randomMu sync.Mutex
}

func New(store Store, notifier Notifier, randomSource io.Reader) (*Reconciler, error) {
	if store == nil {
		return nil, errors.New("setup review store is required")
	}
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &Reconciler{store: store, notifier: notifier, random: randomSource}, nil
}

// Ensure is idempotent at the persistence boundary. Callers may invoke it
// after every observation of awaiting_setup_approval, including after a crash
// between the workspace transition and review creation.
func (r *Reconciler) Ensure(ctx context.Context, value core.Workspace, now time.Time) error {
	if value.State != core.WorkspaceAwaitingSetupApproval || value.ID == "" || value.OwnerID == "" || now.IsZero() {
		return fmt.Errorf("ensure setup review: %w", core.ErrInvalid)
	}
	approvalID, activityID, err := r.identities()
	if err != nil {
		return err
	}
	reason := "Repository setup files require owner approval before they can run."
	if value.FailureCode == "devcontainer_unsupported_safe_fallback_available" {
		reason = "Repository setup is not fully supported; review the safe fallback before continuing."
	}
	result, err := r.store.EnsureSetupReview(ctx, Request{
		ApprovalID: approvalID, ActivityID: activityID, OwnerID: value.OwnerID,
		WorkspaceID: value.ID, SafetyMode: string(value.SafetyMode), Reason: reason,
		CreatedAt: now.UTC(),
	})
	if err != nil {
		return err
	}
	if result.ApprovalID == "" || result.ActivityID == "" {
		return errors.New("setup review store returned incomplete durable identity")
	}
	if result.ActivityCreated && r.notifier != nil {
		// Notification delivery is best effort only after both durable rows commit.
		r.notifier.NotifyActivity(value.OwnerID, result.ActivityID, "approval", "/app/approvals/"+result.ApprovalID)
	}
	return nil
}

func (r *Reconciler) identities() (string, string, error) {
	r.randomMu.Lock()
	defer r.randomMu.Unlock()
	approvalID, err := randomID(r.random, "approval")
	if err != nil {
		return "", "", err
	}
	activityID, err := randomID(r.random, "activity")
	if err != nil {
		return "", "", err
	}
	return approvalID, activityID, nil
}

func randomID(source io.Reader, prefix string) (string, error) {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(source, buffer); err != nil {
		return "", fmt.Errorf("generate %s identity: %w", prefix, err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}
