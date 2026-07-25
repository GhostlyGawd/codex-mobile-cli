package lifecycle

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
)

type fakeStore struct{ values []core.Workspace }

func (s *fakeStore) ListAll(context.Context) ([]core.Workspace, error) {
	return append([]core.Workspace(nil), s.values...), nil
}

func (s *fakeStore) index(ownerID, workspaceID string) int {
	for i := range s.values {
		if s.values[i].OwnerID == ownerID && s.values[i].ID == workspaceID {
			return i
		}
	}
	return -1
}

type fakeSettings struct{ minutes int }

func (s fakeSettings) GetSettings(context.Context, string) (postgres.Settings, error) {
	value := postgres.DefaultSettings()
	value.IdleTimeoutMinutes = s.minutes
	return value, nil
}

type fakeProber struct {
	busy  map[string]bool
	err   error
	calls []string
}

func (p *fakeProber) Probe(_ context.Context, value core.Workspace) (RuntimeActivity, error) {
	p.calls = append(p.calls, value.ID)
	return RuntimeActivity{Busy: p.busy[value.ID]}, p.err
}

type fakeActivity struct {
	records map[string]postgres.ActivityRecord
}

type fakeSetupReviews struct {
	values []core.Workspace
	err    error
}

func (r *fakeSetupReviews) Ensure(_ context.Context, value core.Workspace, _ time.Time) error {
	r.values = append(r.values, value)
	return r.err
}

func (a *fakeActivity) AddActivity(_ context.Context, _ string, value postgres.ActivityRecord) error {
	if _, ok := a.records[value.ID]; ok {
		return core.ErrConflict
	}
	a.records[value.ID] = value
	return nil
}

type fakeOperations struct {
	store             *fakeStore
	marked            []string
	suspended         []string
	touched           []string
	deleted           []string
	retried           []string
	reconciled        []string
	retryResults      map[string]core.Workspace
	retryErrors       map[string]error
	reconcileFailures map[string][]error
}

func (o *fakeOperations) TouchActivity(_ context.Context, ownerID, workspaceID string, at time.Time) (core.Workspace, error) {
	o.touched = append(o.touched, workspaceID)
	index := o.store.index(ownerID, workspaceID)
	if index < 0 {
		return core.Workspace{}, core.ErrNotFound
	}
	value := o.store.values[index]
	value.LastActivityAt = at
	if value.State == core.WorkspaceIdle {
		value.State = core.WorkspaceRunning
	}
	o.store.values[index] = value
	return value, nil
}

func (o *fakeOperations) MarkIdleIfInactive(_ context.Context, ownerID, workspaceID string, expected time.Time) (bool, error) {
	o.marked = append(o.marked, workspaceID)
	index := o.store.index(ownerID, workspaceID)
	if index < 0 || o.store.values[index].State != core.WorkspaceRunning || !o.store.values[index].LastActivityAt.Equal(expected) {
		return false, nil
	}
	o.store.values[index].State = core.WorkspaceIdle
	return true, nil
}

func (o *fakeOperations) SuspendIfInactive(_ context.Context, ownerID, workspaceID string, expected time.Time) (core.Workspace, bool, error) {
	o.suspended = append(o.suspended, workspaceID)
	index := o.store.index(ownerID, workspaceID)
	if index < 0 {
		return core.Workspace{}, false, nil
	}
	value := o.store.values[index]
	if value.State != core.WorkspaceSuspending && (value.State != core.WorkspaceIdle || !value.LastActivityAt.Equal(expected)) {
		return core.Workspace{}, false, nil
	}
	value.State = core.WorkspaceSuspended
	o.store.values[index] = value
	return value, true, nil
}

func (o *fakeOperations) Retry(_ context.Context, _, workspaceID string) (core.Workspace, error) {
	o.retried = append(o.retried, workspaceID)
	return o.retryResults[workspaceID], o.retryErrors[workspaceID]
}

func (o *fakeOperations) Delete(_ context.Context, _, workspaceID string, automatic, confirmed bool) error {
	if !automatic || confirmed {
		return errors.New("unexpected delete policy")
	}
	o.deleted = append(o.deleted, workspaceID)
	return nil
}

func (o *fakeOperations) ReconcileCapacity(_ context.Context, ownerID string) error {
	o.reconciled = append(o.reconciled, ownerID)
	failures := o.reconcileFailures[ownerID]
	if len(failures) == 0 {
		return nil
	}
	err := failures[0]
	o.reconcileFailures[ownerID] = failures[1:]
	return err
}

func newTestCoordinator(t *testing.T, now time.Time, store *fakeStore, operations *fakeOperations, prober *fakeProber, activity *fakeActivity) *Coordinator {
	t.Helper()
	value, err := New(store, fakeSettings{minutes: 30}, operations, prober, activity, &fakeSetupReviews{}, Config{
		ScanInterval: time.Minute, WarningLead: 24 * time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestScanReconcilesQueuedPromotionAndExistingSetupBoundary(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{values: []core.Workspace{
		{ID: "existing-review", OwnerID: "owner", State: core.WorkspaceAwaitingSetupApproval, CreatedAt: now.Add(-time.Hour)},
		{ID: "queued-review", OwnerID: "owner", State: core.WorkspaceQueued, CreatedAt: now},
	}}
	operations := &fakeOperations{
		store: store,
		retryResults: map[string]core.Workspace{
			"queued-review": {ID: "queued-review", OwnerID: "owner", State: core.WorkspaceAwaitingSetupApproval, SafetyMode: core.SafetyBalanced},
		},
		retryErrors: map[string]error{},
	}
	reviews := &fakeSetupReviews{}
	coordinator, err := New(store, fakeSettings{minutes: 30}, operations, &fakeProber{busy: map[string]bool{}},
		&fakeActivity{records: map[string]postgres.ActivityRecord{}}, reviews,
		Config{ScanInterval: time.Minute, WarningLead: 24 * time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(reviews.values) != 2 || reviews.values[0].ID != "existing-review" || reviews.values[1].ID != "queued-review" {
		t.Fatalf("setup review reconciliation mismatch: %#v", reviews.values)
	}
}

func TestScanReconcilesDurableProvisioningBeforeQueuedPromotion(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{values: []core.Workspace{
		{ID: "cleanup", OwnerID: "owner", State: core.WorkspaceProvisioning, FailureCode: "provider_start_cleanup_pending", CreatedAt: now.Add(-time.Minute)},
		{ID: "queued", OwnerID: "owner", State: core.WorkspaceQueued, CreatedAt: now},
	}}
	operations := &fakeOperations{
		store: store,
		retryResults: map[string]core.Workspace{
			"cleanup": {ID: "cleanup", OwnerID: "owner", State: core.WorkspaceProvisioning, FailureCode: "provider_start_cleanup_pending"},
			"queued":  {ID: "queued", OwnerID: "owner", State: core.WorkspaceQueued},
		},
		retryErrors: map[string]error{"cleanup": errors.New("provider stop remains unconfirmed")},
	}
	coordinator := newTestCoordinator(t, now, store, operations, &fakeProber{busy: map[string]bool{}}, &fakeActivity{records: map[string]postgres.ActivityRecord{}})
	if err := coordinator.Scan(context.Background()); err == nil {
		t.Fatal("unconfirmed provisioning cleanup error was hidden")
	}
	if !slices.Equal(operations.retried, []string{"cleanup", "queued"}) {
		t.Fatalf("lifecycle reconciliation order = %#v", operations.retried)
	}
}

func TestScanRoutesIncompletePrivateInputsThroughFailClosedRetry(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{values: []core.Workspace{
		{ID: "preparing", OwnerID: "owner", State: core.WorkspaceProvisioning, PrivateInputsPending: true, CreatedAt: now.Add(-time.Minute)},
		{ID: "queued-private", OwnerID: "owner", State: core.WorkspaceQueued, PrivateInputsPending: true, CreatedAt: now},
	}}
	operations := &fakeOperations{
		store: store,
		retryResults: map[string]core.Workspace{
			"preparing":      {ID: "preparing", OwnerID: "owner", State: core.WorkspaceFailed, PrivateInputsPending: true, FailureCode: "private_inputs_recreate_required"},
			"queued-private": {ID: "queued-private", OwnerID: "owner", State: core.WorkspaceFailed, PrivateInputsPending: true, FailureCode: "private_inputs_recreate_required"},
		},
		retryErrors: map[string]error{
			"preparing":      core.ErrPrecondition,
			"queued-private": core.ErrPrecondition,
		},
	}
	coordinator := newTestCoordinator(t, now, store, operations, &fakeProber{busy: map[string]bool{}}, &fakeActivity{records: map[string]postgres.ActivityRecord{}})
	if err := coordinator.Scan(context.Background()); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("scan hid incomplete private input quarantine: %v", err)
	}
	if !slices.Equal(operations.retried, []string{"preparing", "queued-private"}) {
		t.Fatalf("scan did not route every incomplete private row through retry: %#v", operations.retried)
	}
}

func TestScanRetriesPerOwnerCapacityReconciliationAfterTransientFailure(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{values: []core.Workspace{
		{ID: "workspace-b", OwnerID: "owner-b", State: core.WorkspaceReady, CreatedAt: now.Add(-time.Hour)},
		{ID: "workspace-a", OwnerID: "owner-a", State: core.WorkspaceReady, CreatedAt: now},
	}}
	operations := &fakeOperations{
		store: store, retryResults: map[string]core.Workspace{}, retryErrors: map[string]error{},
		reconcileFailures: map[string][]error{"owner-a": {errors.New("quota persistence unavailable")}},
	}
	coordinator := newTestCoordinator(t, now, store, operations, &fakeProber{busy: map[string]bool{}}, &fakeActivity{records: map[string]postgres.ActivityRecord{}})

	if err := coordinator.Scan(context.Background()); err == nil {
		t.Fatal("transient capacity reconciliation failure was hidden")
	}
	if !slices.Equal(operations.reconciled, []string{"owner-a", "owner-b"}) {
		t.Fatalf("first reconciliation pass was not deterministic per owner: %#v", operations.reconciled)
	}
	if err := coordinator.Scan(context.Background()); err != nil {
		t.Fatalf("later lifecycle scan did not repair capacity: %v", err)
	}
	if !slices.Equal(operations.reconciled, []string{"owner-a", "owner-b", "owner-a", "owner-b"}) {
		t.Fatalf("capacity reconciliation was not level-triggered: %#v", operations.reconciled)
	}
}

func TestScanRequiresTwoPhaseIdleThenSuspend(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{values: []core.Workspace{{
		ID: "ws-1", OwnerID: "owner", State: core.WorkspaceRunning,
		CreatedAt: now.Add(-time.Hour), LastActivityAt: now.Add(-31 * time.Minute),
	}}}
	operations := &fakeOperations{store: store, retryResults: map[string]core.Workspace{}, retryErrors: map[string]error{}}
	coordinator := newTestCoordinator(t, now, store, operations, &fakeProber{busy: map[string]bool{}}, &fakeActivity{records: map[string]postgres.ActivityRecord{}})

	if err := coordinator.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.values[0].State != core.WorkspaceIdle || len(operations.suspended) != 0 {
		t.Fatalf("first scan skipped idle boundary: %#v", store.values[0])
	}
	if err := coordinator.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.values[0].State != core.WorkspaceSuspended || len(operations.suspended) != 1 {
		t.Fatalf("second inactive scan did not suspend: %#v", store.values[0])
	}
}

func TestScanBusyRuntimeRefreshesActivity(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{values: []core.Workspace{{
		ID: "server", OwnerID: "owner", State: core.WorkspaceRunning,
		CreatedAt: now.Add(-time.Hour), LastActivityAt: now.Add(-31 * time.Minute),
	}}}
	operations := &fakeOperations{store: store, retryResults: map[string]core.Workspace{}, retryErrors: map[string]error{}}
	coordinator := newTestCoordinator(t, now, store, operations, &fakeProber{busy: map[string]bool{"server": true}}, &fakeActivity{records: map[string]postgres.ActivityRecord{}})

	if err := coordinator.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.values[0].State != core.WorkspaceRunning || !store.values[0].LastActivityAt.Equal(now) || len(operations.marked) != 0 {
		t.Fatalf("busy development server was not preserved: %#v", store.values[0])
	}
}

func TestRetentionWarnsOnceAndDeletesOnlyEligibleSuspendedWorkspace(t *testing.T) {
	suspended := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	now := suspended.Add(6*24*time.Hour + time.Hour)
	store := &fakeStore{values: []core.Workspace{
		{ID: "eligible", OwnerID: "owner", State: core.WorkspaceSuspended, Retention: core.Retention7Days, SuspendedAt: &suspended},
		{ID: "dirty", OwnerID: "owner", State: core.WorkspaceSuspended, Retention: core.Retention7Days, SuspendedAt: &suspended, Dirty: true},
		{ID: "forever", OwnerID: "owner", State: core.WorkspaceSuspended, Retention: core.RetentionForever, SuspendedAt: &suspended},
	}}
	operations := &fakeOperations{store: store, retryResults: map[string]core.Workspace{}, retryErrors: map[string]error{}}
	activity := &fakeActivity{records: map[string]postgres.ActivityRecord{}}
	coordinator := newTestCoordinator(t, now, store, operations, &fakeProber{busy: map[string]bool{}}, activity)

	if err := coordinator.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(activity.records) != 1 || len(operations.deleted) != 0 {
		t.Fatalf("unexpected retention warning behavior: records=%d deleted=%v", len(activity.records), operations.deleted)
	}
	coordinator.now = func() time.Time { return suspended.Add(7 * 24 * time.Hour) }
	if err := coordinator.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(operations.deleted) != 1 || operations.deleted[0] != "eligible" {
		t.Fatalf("unsafe retention deletion: %v", operations.deleted)
	}
}

func TestScanRetriesDurableDeletingWorkspace(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{values: []core.Workspace{{
		ID: "delete-retry", OwnerID: "owner", State: core.WorkspaceDeleting,
	}}}
	operations := &fakeOperations{store: store, retryResults: map[string]core.Workspace{}, retryErrors: map[string]error{}}
	coordinator := newTestCoordinator(t, now, store, operations, &fakeProber{busy: map[string]bool{}}, &fakeActivity{records: map[string]postgres.ActivityRecord{}})

	if err := coordinator.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(operations.deleted, []string{"delete-retry"}) {
		t.Fatalf("deleting tombstone was not retried: %v", operations.deleted)
	}
}

func TestScanRetriesDurableSuspendingWorkspace(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{values: []core.Workspace{{
		ID: "suspend-retry", OwnerID: "owner", State: core.WorkspaceSuspending, LastActivityAt: now.Add(-time.Hour),
	}}}
	operations := &fakeOperations{store: store, retryResults: map[string]core.Workspace{}, retryErrors: map[string]error{}}
	coordinator := newTestCoordinator(t, now, store, operations, &fakeProber{busy: map[string]bool{}}, &fakeActivity{records: map[string]postgres.ActivityRecord{}})

	if err := coordinator.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(operations.suspended, []string{"suspend-retry"}) || store.values[0].State != core.WorkspaceSuspended {
		t.Fatalf("suspending authority was not retried: calls=%v workspace=%#v", operations.suspended, store.values[0])
	}
}

func TestQueuePromotionContinuesAfterFailedProvisionInCreatedOrder(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{values: []core.Workspace{
		{ID: "second", OwnerID: "owner", State: core.WorkspaceQueued, CreatedAt: now.Add(-time.Minute)},
		{ID: "first", OwnerID: "owner", State: core.WorkspaceQueued, CreatedAt: now.Add(-time.Hour)},
	}}
	operations := &fakeOperations{
		store: store,
		retryResults: map[string]core.Workspace{
			"first":  {ID: "first", State: core.WorkspaceFailed},
			"second": {ID: "second", State: core.WorkspaceRunning},
		},
		retryErrors: map[string]error{"first": errors.New("provider failed")},
	}
	coordinator := newTestCoordinator(t, now, store, operations, &fakeProber{busy: map[string]bool{}}, &fakeActivity{records: map[string]postgres.ActivityRecord{}})
	if err := coordinator.Scan(context.Background()); err == nil {
		t.Fatal("expected failed provision to be reported")
	}
	if len(operations.retried) != 2 || operations.retried[0] != "first" || operations.retried[1] != "second" {
		t.Fatalf("queue was not promoted fairly: %v", operations.retried)
	}
}
