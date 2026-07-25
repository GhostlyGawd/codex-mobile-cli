package maintenance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type memoryStore struct {
	mu          sync.Mutex
	active      *Run
	failTargets map[State]int
}

func (s *memoryStore) Active(context.Context) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || !s.active.Active() {
		return Run{}, core.ErrNotFound
	}
	return *s.active, nil
}
func (s *memoryStore) Latest(_ context.Context, ownerID string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || s.active.OwnerID != ownerID {
		return Run{}, core.ErrNotFound
	}
	return *s.active, nil
}
func (s *memoryStore) Create(_ context.Context, run Run) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil && s.active.Active() {
		return core.ErrConflict
	}
	copy := run
	s.active = &copy
	return nil
}
func (s *memoryStore) Transition(_ context.Context, run Run, expected State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || s.active.ID != run.ID || s.active.State != expected {
		return core.ErrConflict
	}
	if s.failTargets[run.State] > 0 {
		s.failTargets[run.State]--
		return errors.New("injected transition failure")
	}
	copy := run
	s.active = &copy
	return nil
}

func (s *memoryStore) value() Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return Run{}
	}
	return *s.active
}

type workspaceSource struct {
	mu        sync.Mutex
	values    map[string]core.Workspace
	listCalls int
	failLists int
}

func newWorkspaceSource(values ...core.Workspace) *workspaceSource {
	source := &workspaceSource{values: make(map[string]core.Workspace)}
	for _, value := range values {
		source.values[value.ID] = value
	}
	return source
}

func (s *workspaceSource) ListAll(context.Context) ([]core.Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCalls++
	if s.failLists > 0 {
		s.failLists--
		return nil, errors.New("injected list failure")
	}
	values := make([]core.Workspace, 0, len(s.values))
	for _, value := range s.values {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values, nil
}

func (s *workspaceSource) set(value core.Workspace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[value.ID] = value
}

func (s *workspaceSource) update(workspaceID string, state core.WorkspaceState) (core.Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[workspaceID]
	if !ok {
		return core.Workspace{}, core.ErrNotFound
	}
	value.State = state
	s.values[workspaceID] = value
	return value, nil
}

func (s *workspaceSource) remove(workspaceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.values[workspaceID]; !ok {
		return core.ErrNotFound
	}
	delete(s.values, workspaceID)
	return nil
}

type checkpointFake struct {
	mu       sync.Mutex
	failures map[string]bool
	calls    []string
}

func (f *checkpointFake) CreateRequired(_ context.Context, workspaceID, _ string, reason string) (string, bool, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, workspaceID+":"+reason)
	if f.failures[workspaceID] {
		return "", true, false, errors.New("disk full")
	}
	return "cp", true, false, nil
}

func (f *checkpointFake) setFailure(workspaceID string, failed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[workspaceID] = failed
}

func (f *checkpointFake) callValues() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type operationsFake struct {
	mu             sync.Mutex
	source         *workspaceSource
	calls          []string
	begin          func(context.Context) error
	beginCalls     int
	releaseCalls   int
	suspend        func(context.Context, string) error
	failures       map[string]int
	reconcileSteps map[string][]core.WorkspaceState
}

func (f *operationsFake) BeginMaintenanceDrain(ctx context.Context) (func(), error) {
	f.mu.Lock()
	f.beginCalls++
	begin := f.begin
	f.mu.Unlock()
	if begin != nil {
		if err := begin(ctx); err != nil {
			return nil, err
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			f.releaseCalls++
			f.mu.Unlock()
		})
	}, nil
}

func (f *operationsFake) Suspend(ctx context.Context, ownerID, workspaceID string) (core.Workspace, error) {
	f.mu.Lock()
	f.calls = append(f.calls, workspaceID)
	suspend := f.suspend
	if f.failures["suspend:"+workspaceID] > 0 {
		f.failures["suspend:"+workspaceID]--
		f.mu.Unlock()
		return core.Workspace{}, errors.New("injected suspend failure")
	}
	f.mu.Unlock()
	if suspend != nil {
		if err := suspend(ctx, workspaceID); err != nil {
			return core.Workspace{}, err
		}
	}
	value, err := f.source.update(workspaceID, core.WorkspaceSuspended)
	if err != nil {
		return core.Workspace{}, err
	}
	value.OwnerID = ownerID
	return value, nil
}

func (f *operationsFake) Delete(_ context.Context, _, workspaceID string, _, _ bool) error {
	f.mu.Lock()
	f.calls = append(f.calls, "delete:"+workspaceID)
	if f.failures["delete:"+workspaceID] > 0 {
		f.failures["delete:"+workspaceID]--
		f.mu.Unlock()
		return errors.New("injected delete failure")
	}
	f.mu.Unlock()
	return f.source.remove(workspaceID)
}

func (f *operationsFake) ReconcileMaintenanceDrain(_ context.Context, _, workspaceID string) (core.Workspace, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "reconcile:"+workspaceID)
	if f.failures["reconcile:"+workspaceID] > 0 {
		f.failures["reconcile:"+workspaceID]--
		f.mu.Unlock()
		return core.Workspace{}, errors.New("injected reconcile failure")
	}
	steps := f.reconcileSteps[workspaceID]
	if len(steps) > 0 {
		f.reconcileSteps[workspaceID] = steps[1:]
	}
	f.mu.Unlock()
	state := core.WorkspaceFailed
	if len(steps) > 0 {
		state = steps[0]
	}
	return f.source.update(workspaceID, state)
}

func (f *operationsFake) callValues() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *operationsFake) barrierCounts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.beginCalls, f.releaseCalls
}

type admissionFake struct {
	mu       sync.Mutex
	draining bool
}

func (f *admissionFake) SetMaintenanceDrain(value bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.draining = value
}

func (f *admissionFake) isDraining() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.draining
}

type activityFake struct{ values []Activity }

func (f *activityFake) AddMaintenanceActivity(_ context.Context, value Activity) error {
	f.values = append(f.values, value)
	return nil
}

type healthFake struct{ err error }

func (f healthFake) Ping(context.Context) error { return f.err }

func TestWeeklyWindowWarnsDrainsAndRequiresExplicitUpdateStages(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC) // Monday
	store := &memoryStore{}
	checkpoints := &checkpointFake{failures: map[string]bool{}}
	source := newWorkspaceSource(
		core.Workspace{ID: "ws_b", OwnerID: "owner", ProviderResourceID: "provider_b", State: core.WorkspaceRunning},
		core.Workspace{ID: "ws_a", OwnerID: "owner", ProviderResourceID: "provider_a", State: core.WorkspaceIdle},
	)
	operations := &operationsFake{source: source, failures: map[string]int{}}
	admission := &admissionFake{}
	activity := &activityFake{}
	coordinator, err := New(store, source, checkpoints, operations, admission, activity, healthFake{}, nil, Config{
		Weekday: time.Tuesday, HourUTC: 3, WarningLead: 2 * time.Hour, ScanInterval: time.Second,
		Now: func() time.Time { return now }, Random: bytes.NewReader(make([]byte, 24)),
	})
	if err != nil {
		t.Fatal(err)
	}
	run, err := coordinator.ScheduleWeekly(context.Background(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC); run.ScheduledFor != want {
		t.Fatalf("scheduled %s, want %s", run.ScheduledFor, want)
	}

	now = run.WarningAt
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.value(); got.State != StateWarning || len(activity.values) != 1 {
		t.Fatalf("warning not persisted: %#v %#v", got, activity.values)
	}
	now = run.ScheduledFor
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.value(); got.State != StateReadyForUpdate || !admission.isDraining() {
		t.Fatalf("drain not ready: %#v", got)
	}
	if got := checkpoints.callValues(); len(got) != 2 || got[0] != "ws_a:maintenance" || got[1] != "ws_b:maintenance" {
		t.Fatalf("checkpoint order/calls: %#v", got)
	}

	if _, err := coordinator.BeginUpdate(context.Background(), run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.UpdateApplied(context.Background(), run.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.BeginVerification(context.Background(), run.ID); err != nil {
		t.Fatal(err)
	}
	completed, err := coordinator.Complete(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != StateCompleted || admission.isDraining() {
		t.Fatalf("maintenance not completed: %#v", completed)
	}
}

func TestScheduledMaintenanceFailsClosedBeforeUpdateWhenCheckpointFails(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	store := &memoryStore{active: &Run{
		ID: "maint_1", OwnerID: "owner", State: StateWarning,
		ScheduledFor: now, WarningAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-time.Hour),
	}}
	checkpoint := &checkpointFake{failures: map[string]bool{"ws": true}}
	admission := &admissionFake{}
	source := newWorkspaceSource(core.Workspace{ID: "ws", OwnerID: "owner", ProviderResourceID: "provider", State: core.WorkspaceRunning})
	operations := &operationsFake{source: source, failures: map[string]int{}}
	coordinator, err := New(store, source, checkpoint, operations, admission, &activityFake{}, healthFake{}, nil, Config{
		Weekday: time.Tuesday, HourUTC: 3, WarningLead: time.Hour, ScanInterval: time.Second,
		Now: func() time.Time { return now }, Random: bytes.NewReader(make([]byte, 24)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RunOnce(context.Background()); err == nil {
		t.Fatal("expected checkpoint failure")
	}
	if got := store.value(); got.State != StateDraining || !admission.isDraining() {
		t.Fatalf("failure must preserve the durable fail-closed drain: %#v", got)
	}
	checkpoint.setFailure("ws", false)
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("resume drain: %v", err)
	}
	if got := store.value(); got.State != StateReadyForUpdate || !admission.isDraining() {
		t.Fatalf("resumed drain did not converge: %#v", got)
	}
}

func TestUrgentMaintenanceWarnsAndUsesBestEffortCheckpointing(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	store := &memoryStore{}
	checkpoint := &checkpointFake{failures: map[string]bool{"ws": true}}
	source := newWorkspaceSource(core.Workspace{ID: "ws", OwnerID: "owner", ProviderResourceID: "provider", State: core.WorkspaceRunning})
	operations := &operationsFake{source: source, failures: map[string]int{}}
	coordinator, err := New(store, source, checkpoint, operations, &admissionFake{}, &activityFake{}, healthFake{}, nil, Config{
		Weekday: time.Tuesday, HourUTC: 3, WarningLead: time.Hour, UrgentWarningLead: time.Minute,
		ScanInterval: time.Second, Now: func() time.Time { return now }, Random: bytes.NewReader(make([]byte, 24)),
	})
	if err != nil {
		t.Fatal(err)
	}
	run, err := coordinator.ScheduleUrgent(context.Background(), "owner")
	if err != nil || !run.Urgent || !run.BestEffort || run.ScheduledFor.Sub(run.WarningAt) != time.Minute {
		t.Fatalf("urgent run: %#v, %v", run, err)
	}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = run.ScheduledFor
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.value(); got.State != StateReadyForUpdate || got.FailedWorkspaces != 1 || len(operations.callValues()) != 1 {
		t.Fatalf("best-effort drain: %#v", got)
	}
}

func TestDrainWaitsForPreAdmittedStartAndConfirmedSuspend(t *testing.T) {
	now := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	store := &memoryStore{active: &Run{
		ID: "maint_start", OwnerID: "owner", State: StateWarning,
		ScheduledFor: now, WarningAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-time.Hour),
	}}
	source := newWorkspaceSource(core.Workspace{
		ID: "ws_start", OwnerID: "owner", ProviderResourceID: "provider", State: core.WorkspaceProvisioning,
	})
	beginEntered := make(chan struct{})
	startCompleted := make(chan struct{})
	suspendEntered := make(chan struct{})
	stopConfirmed := make(chan struct{})
	operations := &operationsFake{source: source, failures: map[string]int{}}
	var beginOnce, suspendOnce sync.Once
	operations.begin = func(ctx context.Context) error {
		beginOnce.Do(func() { close(beginEntered) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-startCompleted:
			return nil
		}
	}
	operations.suspend = func(ctx context.Context, _ string) error {
		suspendOnce.Do(func() { close(suspendEntered) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stopConfirmed:
			return nil
		}
	}
	coordinator := mustCoordinator(t, store, source, &checkpointFake{failures: map[string]bool{}}, operations, &admissionFake{}, now)
	done := make(chan error, 1)
	go func() { done <- coordinator.RunOnce(context.Background()) }()

	awaitSignal(t, beginEntered, "maintenance admission barrier")
	if got := store.value(); got.State != StateDraining {
		t.Fatalf("run became ready while provider start was blocked: %#v", got)
	}
	if _, err := source.update("ws_start", core.WorkspaceRunning); err != nil {
		t.Fatal(err)
	}
	close(startCompleted)
	awaitSignal(t, suspendEntered, "workspace suspension")
	if got := store.value(); got.State != StateDraining {
		t.Fatalf("run became ready before provider stop confirmation: %#v", got)
	}
	close(stopConfirmed)
	if err := awaitResult(t, done, "maintenance drain"); err != nil {
		t.Fatal(err)
	}
	if got := store.value(); got.State != StateReadyForUpdate {
		t.Fatalf("confirmed suspension did not complete drain: %#v", got)
	}
}

func TestDrainRetriesSuspendingAndDeletingUntilTombstoned(t *testing.T) {
	now := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	store := drainingRun(now)
	source := newWorkspaceSource(
		core.Workspace{ID: "ws_suspending", OwnerID: "owner", ProviderResourceID: "provider-a", State: core.WorkspaceSuspending},
		core.Workspace{ID: "ws_deleting", OwnerID: "owner", ProviderResourceID: "provider-b", State: core.WorkspaceDeleting},
	)
	operations := &operationsFake{source: source, failures: map[string]int{"delete:ws_deleting": 1}}
	coordinator := mustCoordinator(t, store, source, &checkpointFake{failures: map[string]bool{}}, operations, &admissionFake{}, now)

	if err := coordinator.RunOnce(context.Background()); err == nil {
		t.Fatal("expected first delete confirmation failure")
	}
	if got := store.value(); got.State != StateDraining {
		t.Fatalf("transient delete failure escaped durable draining: %#v", got)
	}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("retry drain: %v", err)
	}
	if got := store.value(); got.State != StateReadyForUpdate {
		t.Fatalf("delete tombstone did not converge: %#v", got)
	}
	values, err := source.ListAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if value.ID == "ws_deleting" {
			t.Fatal("deleting workspace remained after successful retry")
		}
	}
}

func TestDrainIterativelyReconcilesProvisioningAndMaintenanceStates(t *testing.T) {
	now := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	store := drainingRun(now)
	source := newWorkspaceSource(
		core.Workspace{ID: "ws_provisioning", OwnerID: "owner", State: core.WorkspaceProvisioning},
		core.Workspace{ID: "ws_maintenance", OwnerID: "owner", ProviderResourceID: "provider", State: core.WorkspaceMaintenance},
	)
	operations := &operationsFake{
		source: source, failures: map[string]int{},
		reconcileSteps: map[string][]core.WorkspaceState{
			"ws_provisioning": {core.WorkspaceMaintenance, core.WorkspaceFailed},
			"ws_maintenance":  {core.WorkspaceSuspended},
		},
	}
	coordinator := mustCoordinator(t, store, source, &checkpointFake{failures: map[string]bool{}}, operations, &admissionFake{}, now)
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.value(); got.State != StateReadyForUpdate || got.DrainedWorkspaces != 3 {
		t.Fatalf("iterative transitional drain: %#v", got)
	}
	if got := operations.callValues(); fmt.Sprint(got) != "[reconcile:ws_maintenance reconcile:ws_provisioning reconcile:ws_provisioning]" {
		t.Fatalf("unexpected reconciliation order: %v", got)
	}
}

func TestRecoverAndRunOnceResumeCancelledDurableDrain(t *testing.T) {
	now := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	store := drainingRun(now)
	source := newWorkspaceSource(core.Workspace{ID: "ws", OwnerID: "owner", ProviderResourceID: "provider", State: core.WorkspaceRunning})
	admission := &admissionFake{}
	operations := &operationsFake{source: source, failures: map[string]int{}}
	operations.begin = func(ctx context.Context) error { return ctx.Err() }
	coordinator := mustCoordinator(t, store, source, &checkpointFake{failures: map[string]bool{}}, operations, admission, now)

	if err := coordinator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !admission.isDraining() {
		t.Fatal("recover reopened admission for a durable drain")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := coordinator.RunOnce(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled drain error = %v", err)
	}
	if got := store.value(); got.State != StateDraining || !admission.isDraining() {
		t.Fatalf("cancelled drain did not remain fail closed: %#v", got)
	}
	operations.mu.Lock()
	operations.begin = nil
	operations.mu.Unlock()
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("resume after cancellation: %v", err)
	}
	if got := store.value(); got.State != StateReadyForUpdate {
		t.Fatalf("resumed drain did not become ready: %#v", got)
	}
}

func TestFinalReadyTransitionFailureRetriesWithoutRedraining(t *testing.T) {
	now := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	store := drainingRun(now)
	store.failTargets = map[State]int{StateReadyForUpdate: 1}
	source := newWorkspaceSource(core.Workspace{ID: "ws", OwnerID: "owner", ProviderResourceID: "provider", State: core.WorkspaceRunning})
	checkpoint := &checkpointFake{failures: map[string]bool{}}
	operations := &operationsFake{source: source, failures: map[string]int{}}
	coordinator := mustCoordinator(t, store, source, checkpoint, operations, &admissionFake{}, now)

	if err := coordinator.RunOnce(context.Background()); err == nil {
		t.Fatal("expected final transition failure")
	}
	if got := store.value(); got.State != StateDraining {
		t.Fatalf("failed final transition lost draining authority: %#v", got)
	}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("retry final transition: %v", err)
	}
	if got := store.value(); got.State != StateReadyForUpdate {
		t.Fatalf("final transition did not recover: %#v", got)
	}
	if got := checkpoint.callValues(); len(got) != 1 {
		t.Fatalf("already suspended workspace was checkpointed again: %v", got)
	}
	if got := operations.callValues(); len(got) != 1 {
		t.Fatalf("already suspended workspace was drained again: %v", got)
	}
	if begins, releases := operations.barrierCounts(); begins != 2 || releases != 2 {
		t.Fatalf("maintenance barriers wedged: begins=%d releases=%d", begins, releases)
	}
}

func TestInitialSnapshotFailureAlwaysReleasesAdmissionBoundary(t *testing.T) {
	now := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	store := drainingRun(now)
	source := newWorkspaceSource()
	source.failLists = 1
	operations := &operationsFake{source: source, failures: map[string]int{}}
	coordinator := mustCoordinator(t, store, source, &checkpointFake{failures: map[string]bool{}}, operations, &admissionFake{}, now)
	if err := coordinator.RunOnce(context.Background()); err == nil {
		t.Fatal("expected initial snapshot failure")
	}
	if begins, releases := operations.barrierCounts(); begins != 1 || releases != 1 {
		t.Fatalf("failed snapshot wedged admission boundary: begins=%d releases=%d", begins, releases)
	}
	if err := coordinator.RunOnce(context.Background()); err != nil {
		t.Fatalf("retry after snapshot failure: %v", err)
	}
	if got := store.value(); got.State != StateReadyForUpdate {
		t.Fatalf("retry did not complete: %#v", got)
	}
}

func drainingRun(now time.Time) *memoryStore {
	return &memoryStore{active: &Run{
		ID: "maint_drain", OwnerID: "owner", State: StateDraining,
		ScheduledFor: now, WarningAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Hour),
		UpdatedAt: now.Add(-time.Hour), StartedAt: ptrTime(now.Add(-time.Hour)),
	}}
}

func ptrTime(value time.Time) *time.Time { return &value }

func mustCoordinator(t *testing.T, store *memoryStore, source *workspaceSource, checkpoint *checkpointFake, operations *operationsFake, admission *admissionFake, now time.Time) *Coordinator {
	t.Helper()
	coordinator, err := New(store, source, checkpoint, operations, admission, &activityFake{}, healthFake{}, nil, Config{
		Weekday: time.Tuesday, HourUTC: 3, WarningLead: time.Hour, ScanInterval: time.Second,
		Now: func() time.Time { return now }, Random: bytes.NewReader(make([]byte, 24)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func awaitSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func awaitResult(t *testing.T, result <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return nil
	}
}

func TestNextWindowAlwaysUsesFutureUTCWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)
	if got := nextWindow(now, time.Tuesday, 3); got != now.AddDate(0, 0, 7) {
		t.Fatalf("got %s", got)
	}
}
