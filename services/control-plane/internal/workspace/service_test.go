package workspace

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/admission"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type fakeRepos struct{ repo core.Repository }

func (f fakeRepos) Get(context.Context, string, string) (core.Repository, error) { return f.repo, nil }

type fakeDetector struct{ environment Environment }

func (f fakeDetector) Detect(context.Context, string, core.Repository, string) (Environment, error) {
	return f.environment, nil
}

type fakeProvider struct {
	mu               sync.Mutex
	requests         []ProvisionRequest
	starts           int
	startRequests    []StartRequest
	setupStarts      []SetupStartRequest
	fail             bool
	failStart        bool
	failSetupStart   bool
	failStop         bool
	failDelete       bool
	stops            int
	waitStops        int
	deletes          int
	stopStarted      chan<- struct{}
	stopRelease      <-chan struct{}
	startStarted     chan<- struct{}
	startRelease     <-chan struct{}
	deleteStarted    chan<- struct{}
	deleteRelease    <-chan struct{}
	provisionStarted chan<- struct{}
	provisionRelease <-chan struct{}
	lookupErr        error
	lookupID         string
	lookups          int
	applyCalls       []string
	applyQuotas      []core.Quota
	failApply        bool
	applyStarted     chan<- string
	applyRelease     <-chan struct{}
	afterStop        func()
}

func (f *fakeProvider) LookupProvisioned(_ context.Context, workspaceID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if f.lookupErr != nil {
		return "", f.lookupErr
	}
	if f.lookupID != "" {
		return f.lookupID, nil
	}
	return "", core.ErrNotFound
}

func (f *fakeProvider) Provision(ctx context.Context, r ProvisionRequest) (string, error) {
	f.mu.Lock()
	f.requests = append(f.requests, r)
	fail, started, release := f.fail, f.provisionStarted, f.provisionRelease
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if fail {
		return "", errors.New("build failed")
	}
	return "provider-" + r.WorkspaceID, nil
}
func (f *fakeProvider) Start(ctx context.Context, _ string, request StartRequest) error {
	f.mu.Lock()
	f.starts++
	f.startRequests = append(f.startRequests, request)
	fail, started, release := f.failStart, f.startStarted, f.startRelease
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if fail {
		return errors.New("start failed")
	}
	return nil
}
func (f *fakeProvider) StartWithSetup(_ context.Context, _ string, request SetupStartRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setupStarts = append(f.setupStarts, request)
	if f.failSetupStart {
		return errors.New("setup start failed")
	}
	return nil
}
func (f *fakeProvider) StopAndWait(ctx context.Context, id string) error {
	f.mu.Lock()
	f.waitStops++
	started, release := f.stopStarted, f.stopRelease
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.Stop(ctx, id)
}
func (f *fakeProvider) Stop(context.Context, string) error {
	f.mu.Lock()
	f.stops++
	fail, after := f.failStop, f.afterStop
	f.mu.Unlock()
	if after != nil {
		after()
	}
	if fail {
		return errors.New("stop failed")
	}
	return nil
}
func (f *fakeProvider) Delete(ctx context.Context, _ string) error {
	f.mu.Lock()
	f.deletes++
	fail, started, release := f.failDelete, f.deleteStarted, f.deleteRelease
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if fail {
		return errors.New("delete failed")
	}
	return nil
}
func (f *fakeProvider) ApplyQuota(ctx context.Context, id string, quota core.Quota) error {
	f.mu.Lock()
	f.applyCalls = append(f.applyCalls, id)
	f.applyQuotas = append(f.applyQuotas, quota)
	fail, started, release := f.failApply, f.applyStarted, f.applyRelease
	f.mu.Unlock()
	if started != nil {
		started <- id
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if fail {
		return errors.New("quota build failed")
	}
	return nil
}

type fakeDeletionBoundary struct {
	mu                 sync.Mutex
	calls              int
	releases           int
	err                error
	suspensionCalls    int
	suspensionReleases int
	suspensionErr      error
	suspensionSeen     []core.Workspace
	requireSuspending  bool
}

func (f *fakeDeletionBoundary) BeginWorkspaceDeleteFinalization(_ context.Context, _ core.Workspace) (func(), error) {
	f.mu.Lock()
	f.calls++
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			f.releases++
			f.mu.Unlock()
		})
	}, nil
}

func (f *fakeDeletionBoundary) BeginWorkspaceSuspension(_ context.Context, value core.Workspace) (func(), error) {
	f.mu.Lock()
	f.suspensionCalls++
	f.suspensionSeen = append(f.suspensionSeen, value)
	err := f.suspensionErr
	if f.requireSuspending && value.State != core.WorkspaceSuspending {
		err = errors.New("suspension boundary requires suspending state")
	}
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			f.suspensionReleases++
			f.mu.Unlock()
		})
	}, nil
}

type fakeCheckpoint struct {
	calls  int
	dirty  bool
	push   bool
	latest string
	err    error
	after  func()
}

type fakeInitializer struct {
	calls int
	err   error
	seen  []core.Workspace
}

type privateInputInitializer struct {
	mu              sync.Mutex
	prepareCalls    int
	initializeCalls int
	prepareSeen     []core.Workspace
	initializeSeen  []core.Workspace
	prepareErr      error
	prepareStarted  chan struct{}
	prepareRelease  chan struct{}
	startedOnce     sync.Once
}

func (f *privateInputInitializer) PrepareEnvironment(ctx context.Context, value core.Workspace) error {
	copyValue := value
	copyValue.EnvironmentVariables = cloneEnvironment(value.EnvironmentVariables)
	f.mu.Lock()
	f.prepareCalls++
	f.prepareSeen = append(f.prepareSeen, copyValue)
	started, release, prepareErr := f.prepareStarted, f.prepareRelease, f.prepareErr
	f.mu.Unlock()
	if started != nil {
		f.startedOnce.Do(func() { close(started) })
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return prepareErr
}

func (f *privateInputInitializer) Initialize(_ context.Context, value core.Workspace) error {
	copyValue := value
	copyValue.EnvironmentVariables = cloneEnvironment(value.EnvironmentVariables)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.initializeCalls++
	f.initializeSeen = append(f.initializeSeen, copyValue)
	return nil
}

func (f *fakeInitializer) Initialize(_ context.Context, value core.Workspace) error {
	f.calls++
	f.seen = append(f.seen, value)
	return f.err
}

func (f *fakeCheckpoint) Create(context.Context, string, string, string) (string, bool, bool, error) {
	f.calls++
	if f.err != nil {
		return "", false, false, f.err
	}
	f.latest = "checkpoint"
	if f.after != nil {
		f.after()
	}
	return f.latest, f.dirty, f.push, nil
}

func (f *fakeCheckpoint) Latest(context.Context, string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if f.latest == "" {
		return "", core.ErrNotFound
	}
	return f.latest, nil
}

func service(t *testing.T, detector Environment) (*Service, *MemoryStore, *fakeProvider, *fakeCheckpoint) {
	t.Helper()
	controller, _ := admission.New(admission.ReferenceCapacity())
	store := NewMemoryStore(200)
	provider := &fakeProvider{}
	checkpoint := &fakeCheckpoint{}
	repo := core.Repository{ID: "repo-1", InstallationID: 1, FullName: "owner/repo", DefaultBranch: "main"}
	s, err := New(store, fakeRepos{repo}, fakeDetector{detector}, provider, controller, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	boundary := &fakeDeletionBoundary{}
	if err := s.ConfigureDeletionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSuspensionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	randomBytes := make([]byte, 4096)
	for i := range randomBytes {
		randomBytes[i] = byte(i)
	}
	s.random = bytes.NewReader(randomBytes)
	return s, store, provider, checkpoint
}

func input(name string) core.CreateWorkspaceInput {
	return core.CreateWorkspaceInput{RepositoryID: "repo-1", Name: name}
}

// snapshotRaceStore forces two unsynchronized callers to make their decisions
// from the same snapshot. A serialized caller times out, persists its
// reservation, and only then permits the next snapshot.
type snapshotRaceStore struct {
	*MemoryStore
	calls         atomic.Int32
	secondEntered chan struct{}
	secondOnce    sync.Once
}

type suspendSaveBarrierStore struct {
	*MemoryStore
	workspaceID string
	started     chan struct{}
	release     chan struct{}
	once        sync.Once
}

type quotaFailureStore struct {
	*MemoryStore
	mu     sync.Mutex
	calls  int
	failAt int
	err    error
}

type phaseSaveFailureStore struct {
	*MemoryStore
	mu        sync.Mutex
	fail      func(core.Workspace) bool
	remaining int
}

func (s *phaseSaveFailureStore) Save(ctx context.Context, value core.Workspace) error {
	s.mu.Lock()
	shouldFail := s.remaining > 0 && s.fail != nil && s.fail(value)
	if shouldFail {
		s.remaining--
	}
	s.mu.Unlock()
	if shouldFail {
		return errors.New("phase persistence failed")
	}
	return s.MemoryStore.Save(ctx, value)
}

func (s *quotaFailureStore) UpdateQuota(ctx context.Context, ownerID, workspaceID string, quota core.Quota, at time.Time) error {
	s.mu.Lock()
	s.calls++
	call, failAt, err := s.calls, s.failAt, s.err
	s.mu.Unlock()
	if failAt > 0 && call == failAt {
		if err == nil {
			err = errors.New("quota persistence failed")
		}
		return err
	}
	return s.MemoryStore.UpdateQuota(ctx, ownerID, workspaceID, quota, at)
}

func (s *quotaFailureStore) failNext(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAt = s.calls + 1
	s.err = err
}

func (s *suspendSaveBarrierStore) Save(ctx context.Context, value core.Workspace) error {
	if value.ID == s.workspaceID && value.State == core.WorkspaceSuspended {
		s.once.Do(func() { close(s.started) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.MemoryStore.Save(ctx, value)
}

func (s *snapshotRaceStore) Snapshot(ctx context.Context, ownerID string) (admission.Snapshot, error) {
	snapshot, err := s.MemoryStore.Snapshot(ctx, ownerID)
	if err != nil {
		return admission.Snapshot{}, err
	}
	switch s.calls.Add(1) {
	case 1:
		select {
		case <-s.secondEntered:
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
			return admission.Snapshot{}, ctx.Err()
		}
	case 2:
		s.secondOnce.Do(func() { close(s.secondEntered) })
	}
	return snapshot, nil
}

func serviceWithStore(t *testing.T, store Store, provider *fakeProvider) *Service {
	t.Helper()
	controller, err := admission.New(admission.ReferenceCapacity())
	if err != nil {
		t.Fatal(err)
	}
	repo := core.Repository{ID: "repo-1", InstallationID: 1, FullName: "owner/repo", DefaultBranch: "main"}
	s, err := New(store, fakeRepos{repo}, fakeDetector{}, provider, controller, &fakeCheckpoint{})
	if err != nil {
		t.Fatal(err)
	}
	s.random = rand.Reader
	return s
}

func privateInputService(t *testing.T, store Store, provider *fakeProvider, initializer *privateInputInitializer, maxRunning int) *Service {
	t.Helper()
	capacity := admission.ReferenceCapacity()
	capacity.MaxRunning = maxRunning
	controller, err := admission.New(capacity)
	if err != nil {
		t.Fatal(err)
	}
	repo := core.Repository{ID: "repo-1", InstallationID: 1, FullName: "owner/repo", DefaultBranch: "main"}
	s, err := New(store, fakeRepos{repo}, fakeDetector{}, provider, controller, &fakeCheckpoint{}, initializer)
	if err != nil {
		t.Fatal(err)
	}
	boundary := &fakeDeletionBoundary{}
	if err := s.ConfigureDeletionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSuspensionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	s.random = rand.Reader
	return s
}

func privateBoundaryWorkspace(id string, state core.WorkspaceState) core.Workspace {
	now := time.Now().UTC()
	return core.Workspace{
		ID: id, OwnerID: "owner", Repository: core.Repository{ID: "repo-1"}, Name: id,
		Branch: "codex-mobile/" + id, BaseBranch: "main", State: state,
		SafetyMode: core.SafetyBalanced, Retention: core.Retention30Days,
		Quota: core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 12}, RequestedDiskGiB: 12,
		CreatedAt: now, UpdatedAt: now, LastActivityAt: now,
	}
}

func providerPrivateBoundaryCalls(provider *fakeProvider) (lookups, provisions, starts, setupStarts int) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.lookups, len(provider.requests), provider.starts, len(provider.setupStarts)
}

func TestPrivateInputsStayMarkedAndPlaintextFreeWhilePreparationBlocksLifecycleRetry(t *testing.T) {
	store := NewMemoryStore(200)
	provider := &fakeProvider{}
	initializer := &privateInputInitializer{prepareStarted: make(chan struct{}), prepareRelease: make(chan struct{})}
	s := privateInputService(t, store, provider, initializer, 10)

	type outcome struct {
		value core.Workspace
		err   error
	}
	created := make(chan outcome, 1)
	go func() {
		value, err := s.Create(context.Background(), "owner", core.CreateWorkspaceInput{
			RepositoryID: "repo-1", Name: "Private preparation",
			EnvironmentVariables: map[string]string{"PRIVATE_TOKEN": "plaintext-sentinel"},
			InitialPrompt:        "private prompt sentinel",
		})
		created <- outcome{value: value, err: err}
	}()

	select {
	case <-initializer.prepareStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("private input preparation did not begin")
	}
	values, err := store.List(context.Background(), "owner")
	if err != nil || len(values) != 1 {
		t.Fatalf("durable workspace marker missing during preparation: %#v %v", values, err)
	}
	pending := values[0]
	if !pending.PrivateInputsPending || len(pending.EnvironmentVariables) != 0 || pending.InitialPrompt != "" {
		t.Fatalf("private preparation row was not fail-closed and plaintext-free: %#v", pending)
	}

	retried := make(chan outcome, 1)
	go func() {
		value, retryErr := s.Retry(context.Background(), "owner", pending.ID)
		retried <- outcome{value: value, err: retryErr}
	}()
	select {
	case result := <-retried:
		t.Fatalf("lifecycle-equivalent retry crossed an in-flight preparation gate: %#v", result)
	case <-time.After(75 * time.Millisecond):
	}
	if lookups, provisions, starts, setupStarts := providerPrivateBoundaryCalls(provider); lookups != 0 || provisions != 0 || starts != 0 || setupStarts != 0 {
		t.Fatalf("provider called while private preparation was blocked: lookup=%d provision=%d start=%d setup=%d", lookups, provisions, starts, setupStarts)
	}

	close(initializer.prepareRelease)
	createResult := <-created
	if createResult.err != nil || createResult.value.State != core.WorkspaceRunning || createResult.value.PrivateInputsPending {
		t.Fatalf("successful preparation did not provision exactly once: %#v %v", createResult.value, createResult.err)
	}
	retryResult := <-retried
	if !errors.Is(retryResult.err, core.ErrConflict) {
		t.Fatalf("waiting lifecycle retry should observe completed creation, got %#v %v", retryResult.value, retryResult.err)
	}
	if _, provisions, starts, _ := providerPrivateBoundaryCalls(provider); provisions != 1 || starts != 1 {
		t.Fatalf("blocked scan caused duplicate provider work: provision=%d start=%d", provisions, starts)
	}
	initializer.mu.Lock()
	defer initializer.mu.Unlock()
	if initializer.prepareCalls != 1 || initializer.initializeCalls != 1 ||
		initializer.prepareSeen[0].EnvironmentVariables["PRIVATE_TOKEN"] != "plaintext-sentinel" ||
		initializer.prepareSeen[0].InitialPrompt != "private prompt sentinel" ||
		len(initializer.initializeSeen[0].EnvironmentVariables) != 0 || initializer.initializeSeen[0].InitialPrompt != "" {
		t.Fatalf("private input handoff/scrubbing mismatch: prepare=%#v initialize=%#v", initializer.prepareSeen, initializer.initializeSeen)
	}
}

func TestPartialPrivateInputPersistenceFailsClosedAndCannotRetry(t *testing.T) {
	store := NewMemoryStore(200)
	provider := &fakeProvider{}
	initializer := &privateInputInitializer{prepareErr: errors.New("prompt persistence failed after environment commit")}
	s := privateInputService(t, store, provider, initializer, 10)

	value, err := s.Create(context.Background(), "owner", core.CreateWorkspaceInput{
		RepositoryID: "repo-1", Name: "Partial private state",
		EnvironmentVariables: map[string]string{"TOKEN": "never-store-this"}, InitialPrompt: "also private",
	})
	if !errors.Is(err, core.ErrExternal) || value.State != core.WorkspaceFailed ||
		value.FailureCode != failurePrivateInputsRecreate || !value.PrivateInputsPending {
		t.Fatalf("partial persistence was not quarantined: %#v %v", value, err)
	}
	stored, getErr := store.Get(context.Background(), "owner", value.ID)
	if getErr != nil || stored.State != core.WorkspaceFailed || stored.FailureCode != failurePrivateInputsRecreate ||
		!stored.PrivateInputsPending || len(stored.EnvironmentVariables) != 0 || stored.InitialPrompt != "" {
		t.Fatalf("partial persistence durable state is unsafe: %#v %v", stored, getErr)
	}
	retried, retryErr := s.Retry(context.Background(), "owner", value.ID)
	if !errors.Is(retryErr, core.ErrPrecondition) || retried.State != core.WorkspaceFailed || retried.FailureCode != failurePrivateInputsRecreate {
		t.Fatalf("partial persistence became retryable: %#v %v", retried, retryErr)
	}
	if lookups, provisions, starts, setupStarts := providerPrivateBoundaryCalls(provider); lookups != 0 || provisions != 0 || starts != 0 || setupStarts != 0 {
		t.Fatalf("partial private state reached provider: lookup=%d provision=%d start=%d setup=%d", lookups, provisions, starts, setupStarts)
	}
}

func TestCrashMarkerAndLegacyEnvironmentFailureConvergeWithoutProvider(t *testing.T) {
	for _, test := range []struct {
		name    string
		pending bool
		code    string
	}{
		{name: "crash marker", pending: true},
		{name: "legacy persistence failure", code: failureEnvironmentPersistence},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryStore(200)
			provider := &fakeProvider{}
			s := privateInputService(t, store, provider, &privateInputInitializer{}, 10)
			value := privateBoundaryWorkspace("crashed-private", core.WorkspaceProvisioning)
			value.PrivateInputsPending = test.pending
			value.FailureCode = test.code
			if err := store.Create(context.Background(), value); err != nil {
				t.Fatal(err)
			}
			failed, err := s.Retry(context.Background(), value.OwnerID, value.ID)
			if !errors.Is(err, core.ErrPrecondition) || failed.State != core.WorkspaceFailed || failed.FailureCode != failurePrivateInputsRecreate {
				t.Fatalf("crash residue did not converge safely: %#v %v", failed, err)
			}
			if lookups, provisions, starts, setupStarts := providerPrivateBoundaryCalls(provider); lookups != 0 || provisions != 0 || starts != 0 || setupStarts != 0 {
				t.Fatalf("crash residue called provider: lookup=%d provision=%d start=%d setup=%d", lookups, provisions, starts, setupStarts)
			}
		})
	}
}

func TestMaintenanceReconcileQuarantinesPendingPrivateInputsWithoutProvider(t *testing.T) {
	store := NewMemoryStore(200)
	provider := &fakeProvider{}
	s := privateInputService(t, store, provider, &privateInputInitializer{}, 10)
	value := privateBoundaryWorkspace("maintenance-private", core.WorkspaceProvisioning)
	value.PrivateInputsPending = true
	if err := store.Create(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	failed, err := s.ReconcileMaintenanceDrain(context.Background(), value.OwnerID, value.ID)
	if err != nil || failed.State != core.WorkspaceFailed || failed.FailureCode != failurePrivateInputsRecreate {
		t.Fatalf("maintenance did not quarantine incomplete private inputs: %#v %v", failed, err)
	}
	if lookups, provisions, starts, setupStarts := providerPrivateBoundaryCalls(provider); lookups != 0 || provisions != 0 || starts != 0 || setupStarts != 0 {
		t.Fatalf("maintenance touched provider for incomplete private inputs: lookup=%d provision=%d start=%d setup=%d", lookups, provisions, starts, setupStarts)
	}
}

func TestSuccessfulPrivatePreparationClearsQueuedMarkerBeforePromotion(t *testing.T) {
	store := NewMemoryStore(200)
	blocking := privateBoundaryWorkspace("running-slot", core.WorkspaceRunning)
	if err := store.Create(context.Background(), blocking); err != nil {
		t.Fatal(err)
	}
	provider := &fakeProvider{}
	initializer := &privateInputInitializer{}
	s := privateInputService(t, store, provider, initializer, 1)
	queued, err := s.Create(context.Background(), "owner", core.CreateWorkspaceInput{
		RepositoryID: "repo-1", Name: "Queued private", EnvironmentVariables: map[string]string{"TOKEN": "private"},
	})
	if err != nil || queued.State != core.WorkspaceQueued || queued.PrivateInputsPending {
		t.Fatalf("queued private preparation did not commit safely: %#v %v", queued, err)
	}
	durable, err := store.Get(context.Background(), "owner", queued.ID)
	if err != nil || durable.PrivateInputsPending || len(durable.EnvironmentVariables) != 0 {
		t.Fatalf("queued marker was not durably cleared: %#v %v", durable, err)
	}
	blocking.State = core.WorkspaceSuspended
	blockedAt := time.Now().UTC()
	blocking.SuspendedAt = &blockedAt
	blocking.UpdatedAt = blockedAt
	if err := store.Save(context.Background(), blocking); err != nil {
		t.Fatal(err)
	}
	promoted, err := s.Retry(context.Background(), "owner", queued.ID)
	if err != nil || promoted.State != core.WorkspaceRunning || promoted.PrivateInputsPending {
		t.Fatalf("prepared queued workspace did not promote: %#v %v", promoted, err)
	}
	if _, provisions, starts, _ := providerPrivateBoundaryCalls(provider); provisions != 1 || starts != 1 {
		t.Fatalf("queued promotion provider calls = provision %d start %d", provisions, starts)
	}
}

func TestIncompletePrivateWorkspaceCanStillBeExplicitlyDeleted(t *testing.T) {
	store := NewMemoryStore(200)
	provider := &fakeProvider{}
	s := privateInputService(t, store, provider, &privateInputInitializer{}, 10)
	value := privateBoundaryWorkspace("delete-private", core.WorkspaceFailed)
	value.PrivateInputsPending = true
	value.FailureCode = failurePrivateInputsRecreate
	if err := store.Create(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(context.Background(), value.OwnerID, value.ID, false, true); err != nil {
		t.Fatalf("explicit deletion of quarantined workspace failed: %v", err)
	}
	if _, err := store.Get(context.Background(), value.OwnerID, value.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("quarantined workspace remained after delete: %v", err)
	}
}

func TestPendingPrivateInputDeleteTombstoneCannotBeResurrectedByRetry(t *testing.T) {
	store := NewMemoryStore(200)
	provider := &fakeProvider{lookupErr: errors.New("provider lookup unavailable")}
	s := privateInputService(t, store, provider, &privateInputInitializer{}, 10)
	value := privateBoundaryWorkspace("delete-private-retry", core.WorkspaceFailed)
	value.PrivateInputsPending = true
	value.FailureCode = failurePrivateInputsRecreate
	if err := store.Create(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(context.Background(), value.OwnerID, value.ID, false, true); err == nil {
		t.Fatal("ambiguous provider lookup unexpectedly finalized deletion")
	}
	tombstone, err := store.Get(context.Background(), value.OwnerID, value.ID)
	if err != nil || tombstone.State != core.WorkspaceDeleting || !tombstone.PrivateInputsPending {
		t.Fatalf("failed deletion did not retain private-input tombstone: %#v %v", tombstone, err)
	}
	snapshot, err := store.Snapshot(context.Background(), value.OwnerID)
	if err != nil || snapshot.Running != 1 {
		t.Fatalf("deleting private-input tombstone stopped counting as capacity: %#v %v", snapshot, err)
	}
	retried, retryErr := s.Retry(context.Background(), value.OwnerID, value.ID)
	if !errors.Is(retryErr, core.ErrConflict) || retried.State != core.WorkspaceDeleting {
		t.Fatalf("manual retry resurrected deleting private-input row: %#v %v", retried, retryErr)
	}
	tombstone, err = store.Get(context.Background(), value.OwnerID, value.ID)
	if err != nil || tombstone.State != core.WorkspaceDeleting || tombstone.FailureCode != failurePrivateInputsRecreate {
		t.Fatalf("retry mutated deleting private-input tombstone: %#v %v", tombstone, err)
	}

	provider.mu.Lock()
	provider.lookupErr = core.ErrNotFound
	provider.mu.Unlock()
	if err := s.Delete(context.Background(), value.OwnerID, value.ID, false, true); err != nil {
		t.Fatalf("deleting private-input tombstone did not converge: %v", err)
	}
	if _, err := store.Get(context.Background(), value.OwnerID, value.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("private-input tombstone remained after provider absence: %v", err)
	}
}

func TestSimultaneousTenthAndEleventhStartReserveOnlyOneSlot(t *testing.T) {
	store := &snapshotRaceStore{MemoryStore: NewMemoryStore(200), secondEntered: make(chan struct{})}
	for i := 0; i < 9; i++ {
		if err := store.Create(context.Background(), core.Workspace{
			ID: fmt.Sprintf("existing-%d", i), OwnerID: "owner", State: core.WorkspaceRunning,
			ProviderResourceID: fmt.Sprintf("provider-existing-%d", i), RequestedDiskGiB: core.DefaultWorkspaceDiskGiB,
		}); err != nil {
			t.Fatal(err)
		}
	}
	provider := &fakeProvider{}
	s := serviceWithStore(t, store, provider)

	start := make(chan struct{})
	results := make(chan core.Workspace, 2)
	errs := make(chan error, 2)
	for _, name := range []string{"Tenth", "Eleventh"} {
		name := name
		go func() {
			<-start
			value, err := s.Create(context.Background(), "owner", input(name))
			results <- value
			errs <- err
		}()
	}
	close(start)

	running, queued := 0, 0
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		switch value := <-results; value.State {
		case core.WorkspaceRunning:
			running++
		case core.WorkspaceQueued:
			queued++
			if value.FailureCode != "queued_running_workspace_limit_reached" {
				t.Fatalf("eleventh workspace queue reason = %q", value.FailureCode)
			}
		default:
			t.Fatalf("unexpected concurrent start state: %#v", value)
		}
	}
	if running != 1 || queued != 1 {
		t.Fatalf("simultaneous starts = running %d, queued %d; want 1/1", running, queued)
	}
	provider.mu.Lock()
	requestCount := len(provider.requests)
	provider.mu.Unlock()
	if requestCount != 1 {
		t.Fatalf("provider provision calls = %d, want 1", requestCount)
	}
	snapshot, err := store.MemoryStore.Snapshot(context.Background(), "owner")
	if err != nil || snapshot.Running != 10 || snapshot.Queued != 1 {
		t.Fatalf("reserved capacity snapshot = %#v, %v", snapshot, err)
	}
}

func TestConcurrentStartCountsProvisioningDiskReservation(t *testing.T) {
	store := NewMemoryStore(64)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	provider := &fakeProvider{provisionStarted: started, provisionRelease: release}
	s := serviceWithStore(t, store, provider)

	firstResult := make(chan core.Workspace, 1)
	firstErr := make(chan error, 1)
	go func() {
		request := input("First disk reservation")
		request.RequestedDiskGiB = core.MaximumWorkspaceDiskGiB
		value, err := s.Create(context.Background(), "owner", request)
		firstResult <- value
		firstErr <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first provision did not start")
	}

	secondResult := make(chan core.Workspace, 1)
	secondErr := make(chan error, 1)
	go func() {
		value, err := s.Create(context.Background(), "owner", input("Second disk reservation"))
		secondResult <- value
		secondErr <- err
	}()

	select {
	case second := <-secondResult:
		close(release)
		t.Fatalf("second reservation crossed the first pre-start boundary: %#v", second)
	case <-time.After(30 * time.Millisecond):
	}

	snapshot, err := store.Snapshot(context.Background(), "owner")
	if err != nil || snapshot.PendingDiskGiB != core.MaximumWorkspaceDiskGiB {
		close(release)
		<-firstResult
		<-firstErr
		t.Fatalf("in-flight disk reservation = %#v, %v", snapshot, err)
	}
	close(release)
	if err := <-firstErr; err != nil {
		t.Fatal(err)
	}
	if first := <-firstResult; first.State != core.WorkspaceRunning {
		t.Fatalf("first disk start = %#v", first)
	}
	second := <-secondResult
	if err := <-secondErr; err != nil || second.State != core.WorkspaceRunning {
		t.Fatalf("serialized second disk start = %#v, %v", second, err)
	}
}

func TestNewRuntimeDoesNotStartUntilExistingQuotaReductionIsConfirmed(t *testing.T) {
	s, _, provider, _ := service(t, Environment{})
	first, err := s.Create(context.Background(), "owner", input("Existing runtime"))
	if err != nil || first.State != core.WorkspaceRunning {
		t.Fatalf("first runtime = %#v, %v", first, err)
	}
	provider.mu.Lock()
	provider.failApply = true
	startsBefore, provisionsBefore := provider.starts, len(provider.requests)
	provider.mu.Unlock()

	second, err := s.Create(context.Background(), "owner", input("Blocked start"))
	if err == nil || second.State != core.WorkspaceProvisioning || second.FailureCode != failureProviderStartReserved {
		t.Fatalf("quota failure did not retain provisioning: %#v, %v", second, err)
	}
	provider.mu.Lock()
	if provider.starts != startsBefore || len(provider.requests) != provisionsBefore {
		provider.mu.Unlock()
		t.Fatalf("new provider became live before quota confirmation: starts=%d provisions=%d", provider.starts, len(provider.requests))
	}
	provider.failApply = false
	provider.mu.Unlock()

	second, err = s.Retry(context.Background(), "owner", second.ID)
	if err != nil || second.State != core.WorkspaceRunning {
		t.Fatalf("quota retry did not resume provisioning: %#v, %v", second, err)
	}
}

func TestResumeDoesNotStartUntilExistingQuotaReductionIsConfirmed(t *testing.T) {
	s, _, provider, _ := service(t, Environment{})
	resuming, err := s.Create(context.Background(), "owner", input("Resume target"))
	if err != nil {
		t.Fatal(err)
	}
	resuming, err = s.Suspend(context.Background(), "owner", resuming.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(context.Background(), "owner", input("Existing peer")); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.failApply = true
	startsBefore := provider.starts
	provider.mu.Unlock()
	resuming, err = s.Resume(context.Background(), "owner", resuming.ID)
	if err == nil || resuming.State != core.WorkspaceProvisioning || resuming.FailureCode != failureProviderStartReserved {
		t.Fatalf("resume quota failure = %#v, %v", resuming, err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.starts != startsBefore {
		t.Fatalf("resume started provider before quota confirmation: %d -> %d", startsBefore, provider.starts)
	}
}

func TestAmbiguousStopTransitionBlocksAnotherProviderStart(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	if _, err := s.Create(context.Background(), "owner", input("Stable peer")); err != nil {
		t.Fatal(err)
	}
	stopping, err := s.Create(context.Background(), "owner", input("Ambiguous stop"))
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.failStop = true
	provider.mu.Unlock()
	if _, err := s.Suspend(context.Background(), "owner", stopping.ID); err == nil {
		t.Fatal("provider stop unexpectedly became confirmed")
	}
	stopping, err = store.Get(context.Background(), "owner", stopping.ID)
	if err != nil || stopping.State != core.WorkspaceSuspending {
		t.Fatalf("ambiguous stop lost its capacity-counted state: %#v %v", stopping, err)
	}

	provider.mu.Lock()
	provisionsBefore, startsBefore := len(provider.requests), provider.starts
	provider.mu.Unlock()
	blocked, err := s.Create(context.Background(), "owner", input("Must not start"))
	if err == nil || blocked.State != core.WorkspaceProvisioning || blocked.FailureCode != failureProviderStartReserved {
		t.Fatalf("ambiguous transitional runtime did not fail closed: %#v %v", blocked, err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.requests) != provisionsBefore || provider.starts != startsBefore {
		t.Fatalf("new provider started across ambiguous StopAndWait: provisions %d->%d starts %d->%d", provisionsBefore, len(provider.requests), startsBefore, provider.starts)
	}
}

func TestLostProvisionResponseIsNotTreatedAsEmptyPreProviderReservation(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	shares, err := s.admission.Shares(1)
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := privateBoundaryWorkspace("ambiguous-provision", core.WorkspaceProvisioning)
	ambiguous.FailureCode = failureProvisionUnconfirmed
	ambiguous.ProviderResourceID = ""
	ambiguous.Quota = quotaWithinRequest(shares[0], ambiguous.RequestedDiskGiB)
	if err := store.Create(context.Background(), ambiguous); err != nil {
		t.Fatal(err)
	}

	blocked, err := s.Create(context.Background(), "owner", input("Blocked by lost response"))
	if err == nil || blocked.State != core.WorkspaceProvisioning || blocked.FailureCode != failureProviderStartReserved {
		t.Fatalf("lost Provision response was treated as provider absence: %#v %v", blocked, err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.requests) != 0 || provider.starts != 0 {
		t.Fatalf("provider called across ambiguous Provision response: requests=%d starts=%d", len(provider.requests), provider.starts)
	}
}

func TestProvisionDoesNotCrossFailedUnconfirmedMarkerPersistence(t *testing.T) {
	store := &phaseSaveFailureStore{
		MemoryStore: NewMemoryStore(200), remaining: 1,
		fail: func(value core.Workspace) bool { return value.FailureCode == failureProvisionUnconfirmed },
	}
	provider := &fakeProvider{}
	s := serviceWithStore(t, store, provider)
	value, err := s.Create(context.Background(), "owner", input("Marker save failure"))
	if err == nil {
		t.Fatalf("failed unconfirmed marker persistence was hidden: %#v", value)
	}
	provider.mu.Lock()
	if len(provider.requests) != 0 || provider.starts != 0 {
		provider.mu.Unlock()
		t.Fatalf("provider crossed failed unconfirmed marker persistence: requests=%d starts=%d", len(provider.requests), provider.starts)
	}
	provider.mu.Unlock()
	rows, listErr := store.List(context.Background(), "owner")
	if listErr != nil || len(rows) != 1 || rows[0].FailureCode != failureProviderStartReserved || rows[0].ProviderResourceID != "" {
		t.Fatalf("failed marker persistence lost no-provider proof: %#v %v", rows, listErr)
	}
}

func TestProvisionSuccessThenProviderIDSaveFailureRecoversThroughStop(t *testing.T) {
	store := &phaseSaveFailureStore{
		MemoryStore: NewMemoryStore(200), remaining: 1,
		fail: func(value core.Workspace) bool {
			return value.ProviderResourceID != "" && value.FailureCode == failureStartCleanupPending
		},
	}
	provider := &fakeProvider{}
	s := serviceWithStore(t, store, provider)
	if _, err := s.Create(context.Background(), "owner", input("Provider ID save failure")); err == nil {
		t.Fatal("provider-ID persistence failure was hidden")
	}
	rows, err := store.List(context.Background(), "owner")
	if err != nil || len(rows) != 1 || rows[0].ProviderResourceID != "" || rows[0].FailureCode != failureProvisionUnconfirmed {
		t.Fatalf("provider-ID save failure lost ambiguous authority: %#v %v", rows, err)
	}
	provider.mu.Lock()
	if len(provider.requests) != 1 || provider.starts != 0 {
		provider.mu.Unlock()
		t.Fatalf("unexpected provider work before recovery: requests=%d starts=%d", len(provider.requests), provider.starts)
	}
	provider.lookupID = "provider-" + rows[0].ID
	provider.mu.Unlock()
	recovered, err := s.Retry(context.Background(), "owner", rows[0].ID)
	if err != nil || recovered.State != core.WorkspaceFailed || recovered.FailureCode != failureProviderProvision {
		t.Fatalf("ambiguous provider-ID save did not stop before release: %#v %v", recovered, err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.requests) != 1 || provider.starts != 0 || provider.waitStops != 1 {
		t.Fatalf("recovery duplicated provider work or skipped stop: requests=%d starts=%d waitStops=%d", len(provider.requests), provider.starts, provider.waitStops)
	}
}

func TestResumeDoesNotCrossFailedStartPendingPersistence(t *testing.T) {
	store := &phaseSaveFailureStore{MemoryStore: NewMemoryStore(200)}
	provider := &fakeProvider{}
	s := serviceWithStore(t, store, provider)
	boundary := &fakeDeletionBoundary{}
	if err := s.ConfigureDeletionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSuspensionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	value, err := s.Create(context.Background(), "owner", input("Resume marker"))
	if err != nil {
		t.Fatal(err)
	}
	value, err = s.Suspend(context.Background(), "owner", value.ID)
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	startsBefore := provider.starts
	provider.mu.Unlock()
	store.mu.Lock()
	store.remaining = 1
	store.fail = func(value core.Workspace) bool { return value.FailureCode == failureStartCleanupPending }
	store.mu.Unlock()
	if _, err := s.Resume(context.Background(), "owner", value.ID); err == nil {
		t.Fatal("failed start-pending persistence was hidden")
	}
	durable, err := store.Get(context.Background(), "owner", value.ID)
	if err != nil || durable.State != core.WorkspaceProvisioning || durable.FailureCode != failureProviderStartReserved {
		t.Fatalf("resume marker failure lost stopped proof: %#v %v", durable, err)
	}
	provider.mu.Lock()
	if provider.starts != startsBefore {
		provider.mu.Unlock()
		t.Fatalf("resume crossed failed start marker: %d -> %d", startsBefore, provider.starts)
	}
	provider.mu.Unlock()
	durable, err = s.Retry(context.Background(), "owner", value.ID)
	if err != nil || durable.State != core.WorkspaceRunning {
		t.Fatalf("resume marker retry did not converge: %#v %v", durable, err)
	}
}

func TestConcurrentEmptyPreProviderReservationsDoNotBlockEachOther(t *testing.T) {
	store := NewMemoryStore(200)
	provider := &fakeProvider{}
	initializer := &privateInputInitializer{prepareStarted: make(chan struct{}), prepareRelease: make(chan struct{})}
	s := privateInputService(t, store, provider, initializer, 10)
	type outcome struct {
		value core.Workspace
		err   error
	}
	results := make(chan outcome, 2)
	for _, name := range []string{"Prepared first", "Prepared second"} {
		name := name
		go func() {
			value, err := s.Create(context.Background(), "owner", core.CreateWorkspaceInput{
				RepositoryID: "repo-1", Name: name, EnvironmentVariables: map[string]string{"PRIVATE": name},
			})
			results <- outcome{value: value, err: err}
		}()
	}
	var releaseOnce sync.Once
	releasePreparation := func() { releaseOnce.Do(func() { close(initializer.prepareRelease) }) }
	defer releasePreparation()

	select {
	case <-initializer.prepareStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first private preparation did not begin")
	}
	// Admission is continuous from reservation through private preparation and
	// runtime acquisition, so the second create cannot leave another crash-
	// ambiguous provisioning row while the first owns the provider-start right.
	time.Sleep(75 * time.Millisecond)
	initializer.mu.Lock()
	prepareCalls := initializer.prepareCalls
	initializer.mu.Unlock()
	values, err := store.List(context.Background(), "owner")
	if err != nil || prepareCalls != 1 || len(values) != 1 {
		t.Fatalf("continuous admission boundary allowed multiple reservations: calls=%d values=%#v err=%v", prepareCalls, values, err)
	}
	if value := values[0]; value.State != core.WorkspaceProvisioning || value.ProviderResourceID != "" || value.FailureCode != failureProviderStartReserved || !value.PrivateInputsPending {
		t.Fatalf("pre-provider reservation proof was not durable: %#v", value)
	}
	releasePreparation()
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.err != nil || result.value.State != core.WorkspaceRunning {
				t.Fatalf("pre-provider reservations did not converge: %#v %v", result.value, result.err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent pre-provider reservations deadlocked")
		}
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.requests) != 2 || provider.starts != 2 {
		t.Fatalf("provider work was not exactly once per reservation: requests=%d starts=%d", len(provider.requests), provider.starts)
	}
}

func TestRestartNormalizesMultipleLegacyEmptyProvisioningRowsBeforeOrderedStarts(t *testing.T) {
	store := NewMemoryStore(200)
	provider := &fakeProvider{}
	s := serviceWithStore(t, store, provider)
	now := time.Now().UTC()
	rows := []core.Workspace{
		privateBoundaryWorkspace("legacy-first", core.WorkspaceProvisioning),
		privateBoundaryWorkspace("legacy-second", core.WorkspaceProvisioning),
	}
	rows[0].CreatedAt = now.Add(-time.Minute)
	rows[1].CreatedAt = now
	for i := range rows {
		rows[i].FailureCode = ""
		rows[i].ProviderResourceID = ""
		rows[i].Quota = core.Quota{CPUMilli: 3000, MemoryMiB: 9216, DiskGiB: 12}
		if err := store.Create(context.Background(), rows[i]); err != nil {
			t.Fatal(err)
		}
	}

	// An empty historical phase is ambiguous. Deterministic lookup proves each
	// row absent and writes the explicit no-provider marker without starting it.
	for _, row := range rows {
		value, err := s.Retry(context.Background(), row.OwnerID, row.ID)
		if err != nil || value.State != core.WorkspaceProvisioning || value.FailureCode != failureProviderStartReserved {
			t.Fatalf("legacy reservation normalization failed for %s: %#v %v", row.ID, value, err)
		}
	}
	provider.mu.Lock()
	if provider.lookups != 2 || len(provider.requests) != 0 || provider.starts != 0 {
		provider.mu.Unlock()
		t.Fatalf("normalization crossed provider start: lookups=%d requests=%d starts=%d", provider.lookups, len(provider.requests), provider.starts)
	}
	provider.mu.Unlock()

	// Once both proof markers are durable, created order can be started without
	// either empty-ID reservation blocking the other forever.
	for _, row := range rows {
		value, err := s.Retry(context.Background(), row.OwnerID, row.ID)
		if err != nil || value.State != core.WorkspaceRunning {
			t.Fatalf("ordered reservation start failed for %s: %#v %v", row.ID, value, err)
		}
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.requests) != 2 || provider.starts != 2 {
		t.Fatalf("ordered recovery provider work = requests %d starts %d", len(provider.requests), provider.starts)
	}
}

func TestLegacyEmptyProvisioningWithExistingProviderStopsBeforeReleasingCapacity(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	legacy := privateBoundaryWorkspace("legacy-existing-provider", core.WorkspaceProvisioning)
	legacy.FailureCode = ""
	legacy.ProviderResourceID = ""
	legacy.Quota = core.Quota{CPUMilli: 6000, MemoryMiB: 18 * 1024, DiskGiB: 12}
	if err := store.Create(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.lookupID = "provider-recovered"
	provider.failStop = true
	provider.mu.Unlock()

	legacy, err := s.Retry(context.Background(), legacy.OwnerID, legacy.ID)
	if err == nil || legacy.State != core.WorkspaceProvisioning || legacy.ProviderResourceID != "provider-recovered" || legacy.FailureCode != failureProvisionCleanupPending {
		t.Fatalf("existing ambiguous provider did not retain cleanup authority: %#v %v", legacy, err)
	}
	provider.mu.Lock()
	requestsBefore, startsBefore := len(provider.requests), provider.starts
	provider.mu.Unlock()
	blocked, err := s.Create(context.Background(), "owner", input("Blocked during recovered cleanup"))
	if err == nil || blocked.State != core.WorkspaceProvisioning || blocked.FailureCode != failureProviderStartReserved {
		t.Fatalf("new start crossed recovered cleanup authority: %#v %v", blocked, err)
	}
	provider.mu.Lock()
	if len(provider.requests) != requestsBefore || provider.starts != startsBefore {
		provider.mu.Unlock()
		t.Fatalf("provider started during recovered cleanup: requests %d->%d starts %d->%d", requestsBefore, len(provider.requests), startsBefore, provider.starts)
	}
	provider.failStop = false
	provider.mu.Unlock()
	legacy, err = s.Retry(context.Background(), legacy.OwnerID, legacy.ID)
	if err != nil || legacy.State != core.WorkspaceFailed || legacy.FailureCode != failureProviderProvision {
		t.Fatalf("recovered provider cleanup did not converge: %#v %v", legacy, err)
	}
	blocked, err = s.Retry(context.Background(), "owner", blocked.ID)
	if err != nil || blocked.State != core.WorkspaceRunning {
		t.Fatalf("blocked start did not resume after confirmed cleanup: %#v %v", blocked, err)
	}
}

func TestFailedNPlusOneStartImmediatelyRestoresSurvivorShare(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	survivor, err := s.Create(context.Background(), "owner", input("Survivor"))
	if err != nil {
		t.Fatal(err)
	}
	originalQuota := survivor.Quota
	provider.mu.Lock()
	provider.failStart = true
	provider.applyCalls = nil
	provider.applyQuotas = nil
	provider.mu.Unlock()

	failed, err := s.Create(context.Background(), "owner", input("Failed N plus one"))
	if err == nil || failed.State != core.WorkspaceFailed || failed.FailureCode != failureProviderStart {
		t.Fatalf("failed start did not complete confirmed cleanup: %#v %v", failed, err)
	}
	survivor, err = store.Get(context.Background(), "owner", survivor.ID)
	if err != nil || survivor.Quota != originalQuota {
		t.Fatalf("survivor share was not restored immediately: %#v %v", survivor, err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.applyQuotas) < 2 {
		t.Fatalf("expected shrink and restore quota builds, got %#v", provider.applyQuotas)
	}
	last := provider.applyQuotas[len(provider.applyQuotas)-2:]
	if last[0].CPUMilli >= last[1].CPUMilli || last[1] != originalQuota {
		t.Fatalf("failed N+1 quota sequence did not restore the survivor: %#v", last)
	}
}

func TestCreateReturnsCommittedRunningWhenFinalRebalanceFails(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	provider.mu.Lock()
	provider.failApply = true
	provider.mu.Unlock()
	value, err := s.Create(context.Background(), "owner", input("Committed despite quota repair"))
	if err != nil || value.State != core.WorkspaceRunning {
		t.Fatalf("durably running create reported quota repair failure: %#v %v", value, err)
	}
	durable, err := store.Get(context.Background(), "owner", value.ID)
	if err != nil || durable.State != core.WorkspaceRunning {
		t.Fatalf("running create was not durable: %#v %v", durable, err)
	}
	provider.mu.Lock()
	provider.failApply = false
	provider.mu.Unlock()
	if err := s.ReconcileCapacity(context.Background(), "owner"); err != nil {
		t.Fatalf("later running quota repair failed: %v", err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.applyCalls) < 2 {
		t.Fatalf("final failure was not retried by reconciliation: %#v", provider.applyCalls)
	}
}

func TestResumeReturnsCommittedRunningWhenFinalRebalanceFails(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	value, err := s.Create(context.Background(), "owner", input("Resume committed state"))
	if err != nil {
		t.Fatal(err)
	}
	value, err = s.Suspend(context.Background(), "owner", value.ID)
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.failApply = true
	provider.applyCalls = nil
	provider.mu.Unlock()
	value, err = s.Resume(context.Background(), "owner", value.ID)
	if err != nil || value.State != core.WorkspaceRunning {
		t.Fatalf("durably running resume reported quota repair failure: %#v %v", value, err)
	}
	durable, err := store.Get(context.Background(), "owner", value.ID)
	if err != nil || durable.State != core.WorkspaceRunning {
		t.Fatalf("resumed running state was not durable: %#v %v", durable, err)
	}
	provider.mu.Lock()
	provider.failApply = false
	provider.mu.Unlock()
	if err := s.ReconcileCapacity(context.Background(), "owner"); err != nil {
		t.Fatalf("later resumed quota repair failed: %v", err)
	}
}

func TestAwaitingApprovalReturnsCommittedSuccessWhenPeerRebalanceFails(t *testing.T) {
	s, store, provider, _ := service(t, Environment{
		HasDevcontainer: true, Supported: true, RequiresTrust: true, ConfigDirectory: ".devcontainer",
	})
	shares, err := s.admission.Shares(1)
	if err != nil {
		t.Fatal(err)
	}
	peer := privateBoundaryWorkspace("approval-peer", core.WorkspaceRunning)
	peer.ProviderResourceID = "provider-approval-peer"
	peer.Quota = quotaWithinRequest(shares[0], peer.RequestedDiskGiB)
	if err := store.Create(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.afterStop = func() {
		provider.mu.Lock()
		provider.failApply = true
		provider.afterStop = nil
		provider.mu.Unlock()
	}
	provider.mu.Unlock()

	value, err := s.Create(context.Background(), "owner", input("Approval committed state"))
	if err != nil || value.State != core.WorkspaceAwaitingSetupApproval {
		t.Fatalf("durable approval boundary reported peer quota failure: %#v %v", value, err)
	}
	durable, err := store.Get(context.Background(), "owner", value.ID)
	if err != nil || durable.State != core.WorkspaceAwaitingSetupApproval {
		t.Fatalf("approval boundary was not durable: %#v %v", durable, err)
	}
	provider.mu.Lock()
	provider.failApply = false
	provider.mu.Unlock()
	if err := s.ReconcileCapacity(context.Background(), "owner"); err != nil {
		t.Fatalf("later approval-peer quota repair failed: %v", err)
	}
}

func TestDeletingNineOfTenImmediatelyExpandsSurvivor(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	values := make([]core.Workspace, 0, 10)
	for i := 0; i < 10; i++ {
		value, err := s.Create(context.Background(), "owner", input(fmt.Sprintf("Workspace %d", i)))
		if err != nil {
			t.Fatalf("create workspace %d: %v", i, err)
		}
		values = append(values, value)
	}
	for i := 0; i < 9; i++ {
		if err := s.Delete(context.Background(), "owner", values[i].ID, false, true); err != nil {
			t.Fatalf("delete workspace %d: %v", i, err)
		}
	}
	survivor, err := store.Get(context.Background(), "owner", values[9].ID)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := s.admission.Shares(1)
	if err != nil {
		t.Fatal(err)
	}
	want := quotaWithinRequest(shares[0], survivor.RequestedDiskGiB)
	if survivor.Quota != want {
		t.Fatalf("10-to-1 deletion left stale survivor quota: got %#v want %#v", survivor.Quota, want)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.deletes != 9 {
		t.Fatalf("provider delete count = %d, want 9", provider.deletes)
	}
}

func TestCompletedDeleteIgnoresRebalanceFailureAndLaterReconciles(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	deleted, err := s.Create(context.Background(), "owner", input("Delete me"))
	if err != nil {
		t.Fatal(err)
	}
	survivor, err := s.Create(context.Background(), "owner", input("Repair me"))
	if err != nil {
		t.Fatal(err)
	}
	staleQuota := survivor.Quota
	provider.mu.Lock()
	provider.failApply = true
	provider.mu.Unlock()
	if err := s.Delete(context.Background(), "owner", deleted.ID, false, true); err != nil {
		t.Fatalf("completed deletion reported post-finalization rebalance failure: %v", err)
	}
	if _, err := store.Get(context.Background(), "owner", deleted.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("completed deletion retained its row: %v", err)
	}
	survivor, err = store.Get(context.Background(), "owner", survivor.ID)
	shares, shareErr := s.admission.Shares(1)
	if shareErr != nil {
		t.Fatal(shareErr)
	}
	want := quotaWithinRequest(shares[0], survivor.RequestedDiskGiB)
	if err != nil || survivor.Quota != want || survivor.Quota.CPUMilli <= staleQuota.CPUMilli {
		t.Fatalf("failed provider expansion was not conservatively pre-persisted: %#v %v", survivor, err)
	}
	provider.mu.Lock()
	provider.failApply = false
	provider.mu.Unlock()
	if err := s.ReconcileCapacity(context.Background(), "owner"); err != nil {
		t.Fatalf("later capacity reconciliation failed: %v", err)
	}
	survivor, err = store.Get(context.Background(), "owner", survivor.ID)
	if err != nil || survivor.Quota != want {
		t.Fatalf("later reconciliation did not expand survivor: %#v %v", survivor, err)
	}
}

func TestExpansionPrestoreFailureDoesNotMutateProvider(t *testing.T) {
	store := &quotaFailureStore{MemoryStore: NewMemoryStore(200)}
	provider := &fakeProvider{}
	s := serviceWithStore(t, store, provider)
	boundary := &fakeDeletionBoundary{}
	if err := s.ConfigureDeletionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSuspensionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.Create(context.Background(), "owner", input("Delete before prestore failure"))
	if err != nil {
		t.Fatal(err)
	}
	survivor, err := s.Create(context.Background(), "owner", input("Prestore survivor"))
	if err != nil {
		t.Fatal(err)
	}
	staleQuota := survivor.Quota
	provider.mu.Lock()
	provider.applyCalls = nil
	provider.applyQuotas = nil
	provider.mu.Unlock()
	store.failNext(errors.New("prestore unavailable"))

	if err := s.Delete(context.Background(), "owner", deleted.ID, false, true); err != nil {
		t.Fatalf("completed delete reported prestore rebalance failure: %v", err)
	}
	provider.mu.Lock()
	if len(provider.applyCalls) != 0 {
		provider.mu.Unlock()
		t.Fatalf("provider expansion crossed failed conservative prestore: %#v", provider.applyCalls)
	}
	provider.mu.Unlock()
	survivor, err = store.Get(context.Background(), "owner", survivor.ID)
	if err != nil || survivor.Quota != staleQuota {
		t.Fatalf("failed prestore changed durable quota: %#v %v", survivor, err)
	}
	if err := s.ReconcileCapacity(context.Background(), "owner"); err != nil {
		t.Fatal(err)
	}
	survivor, err = store.Get(context.Background(), "owner", survivor.ID)
	if err != nil || survivor.Quota.CPUMilli <= staleQuota.CPUMilli {
		t.Fatalf("later reconciliation did not repair prestore failure: %#v %v", survivor, err)
	}
}

func TestExpansionProviderFailureLeavesHighWaterThatBlocksAmbiguousStopStart(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	deleted, err := s.Create(context.Background(), "owner", input("Delete before provider failure"))
	if err != nil {
		t.Fatal(err)
	}
	survivor, err := s.Create(context.Background(), "owner", input("Provider failure survivor"))
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.failApply = true
	provider.mu.Unlock()
	if err := s.Delete(context.Background(), "owner", deleted.ID, false, true); err != nil {
		t.Fatal(err)
	}
	survivor, err = store.Get(context.Background(), "owner", survivor.ID)
	if err != nil || survivor.Quota.CPUMilli != 6000 || survivor.Quota.MemoryMiB != 18*1024 {
		t.Fatalf("provider failure lost durable expansion high-water: %#v %v", survivor, err)
	}
	provider.mu.Lock()
	provider.failApply = false
	provider.failStop = true
	provider.mu.Unlock()
	if _, err := s.Suspend(context.Background(), "owner", survivor.ID); err == nil {
		t.Fatal("survivor stop unexpectedly became confirmed")
	}
	provider.mu.Lock()
	requestsBefore, startsBefore := len(provider.requests), provider.starts
	provider.mu.Unlock()
	blocked, err := s.Create(context.Background(), "owner", input("Blocked after failed expansion"))
	if err == nil || blocked.State != core.WorkspaceProvisioning || blocked.FailureCode != failureProviderStartReserved {
		t.Fatalf("durable expansion high-water did not block new start: %#v %v", blocked, err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.requests) != requestsBefore || provider.starts != startsBefore {
		t.Fatalf("new provider crossed ambiguous high-water stop: requests %d->%d starts %d->%d", requestsBefore, len(provider.requests), startsBefore, provider.starts)
	}
}

func TestLegacyExpansionPersistenceGapBlocksStartAfterAmbiguousStop(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	survivor, err := s.Create(context.Background(), "owner", input("Legacy expansion gap"))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the historical provider-first expansion crash: the provider may
	// still have the one-workspace 6/18 allocation while durable metadata kept
	// the old two-workspace 3/9 value.
	legacyLow := core.Quota{CPUMilli: 3000, MemoryMiB: 9 * 1024, DiskGiB: survivor.Quota.DiskGiB}
	if err := store.UpdateQuota(context.Background(), survivor.OwnerID, survivor.ID, legacyLow, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.failStop = true
	provider.mu.Unlock()
	if _, err := s.Suspend(context.Background(), survivor.OwnerID, survivor.ID); err == nil {
		t.Fatal("legacy-gap provider stop unexpectedly became confirmed")
	}
	provider.mu.Lock()
	requestsBefore, startsBefore := len(provider.requests), provider.starts
	provider.mu.Unlock()
	blocked, err := s.Create(context.Background(), "owner", input("Blocked by legacy expansion gap"))
	if err == nil || blocked.State != core.WorkspaceProvisioning || blocked.FailureCode != failureProviderStartReserved {
		t.Fatalf("legacy expansion persistence gap admitted another start: %#v %v", blocked, err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.requests) != requestsBefore || provider.starts != startsBefore {
		t.Fatalf("provider crossed legacy expansion gap: requests %d->%d starts %d->%d", requestsBefore, len(provider.requests), startsBefore, provider.starts)
	}
}

func TestShrinkFinalStoreFailureRetainsHighWaterAndBlocksAfterStopAmbiguity(t *testing.T) {
	store := &quotaFailureStore{MemoryStore: NewMemoryStore(200)}
	provider := &fakeProvider{}
	s := serviceWithStore(t, store, provider)
	boundary := &fakeDeletionBoundary{}
	if err := s.ConfigureDeletionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSuspensionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	survivor, err := s.Create(context.Background(), "owner", input("Shrink store survivor"))
	if err != nil {
		t.Fatal(err)
	}
	originalQuota := survivor.Quota
	store.failNext(errors.New("final shrink persistence unavailable"))
	blocked, err := s.Create(context.Background(), "owner", input("Shrink store blocked start"))
	if err == nil || blocked.State != core.WorkspaceProvisioning || blocked.FailureCode != failureProviderStartReserved {
		t.Fatalf("final shrink persistence failure did not retain reservation: %#v %v", blocked, err)
	}
	survivor, err = store.Get(context.Background(), "owner", survivor.ID)
	if err != nil || survivor.Quota != originalQuota {
		t.Fatalf("failed final shrink store lost conservative upper bound: %#v %v", survivor, err)
	}
	provider.mu.Lock()
	provider.failStop = true
	requestsBefore, startsBefore := len(provider.requests), provider.starts
	provider.mu.Unlock()
	if _, err := s.Suspend(context.Background(), "owner", survivor.ID); err == nil {
		t.Fatal("post-shrink stop unexpectedly became confirmed")
	}
	blocked, err = s.Retry(context.Background(), "owner", blocked.ID)
	if err == nil || blocked.State != core.WorkspaceProvisioning || blocked.FailureCode != failureProviderStartReserved {
		t.Fatalf("failed final-store high-water did not block retry: %#v %v", blocked, err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.requests) != requestsBefore || provider.starts != startsBefore {
		t.Fatalf("retry crossed ambiguous stop after final-store failure: requests %d->%d starts %d->%d", requestsBefore, len(provider.requests), startsBefore, provider.starts)
	}
}

func TestRebalanceCannotRestartStoppedWorkspaceBeforeSuspendedSave(t *testing.T) {
	base := NewMemoryStore(200)
	store := &suspendSaveBarrierStore{MemoryStore: base, started: make(chan struct{}), release: make(chan struct{})}
	provider := &fakeProvider{}
	s := serviceWithStore(t, store, provider)
	boundary := &fakeDeletionBoundary{}
	if err := s.ConfigureDeletionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSuspensionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	first, err := s.Create(context.Background(), "owner", input("Will suspend"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(context.Background(), "owner", input("Stable peer")); err != nil {
		t.Fatal(err)
	}
	store.workspaceID = first.ID
	provider.mu.Lock()
	provider.applyCalls = nil
	provider.mu.Unlock()
	suspendDone := make(chan error, 1)
	go func() {
		_, suspendErr := s.Suspend(context.Background(), "owner", first.ID)
		suspendDone <- suspendErr
	}()
	select {
	case <-store.started:
	case <-time.After(time.Second):
		t.Fatal("suspend did not reach the post-stop persistence boundary")
	}
	createDone := make(chan error, 1)
	go func() {
		_, createErr := s.Create(context.Background(), "owner", input("Concurrent start"))
		createDone <- createErr
	}()
	time.Sleep(30 * time.Millisecond)
	provider.mu.Lock()
	for _, id := range provider.applyCalls {
		if id == first.ProviderResourceID {
			provider.mu.Unlock()
			t.Fatal("quota rebalance reached a provider after stop confirmation")
		}
	}
	provider.mu.Unlock()
	close(store.release)
	if err := <-suspendDone; err != nil {
		t.Fatal(err)
	}
	if err := <-createDone; err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	for _, id := range provider.applyCalls {
		if id == first.ProviderResourceID {
			t.Fatalf("suspended provider received a quota start build: %#v", provider.applyCalls)
		}
	}
}

func TestCanceledAdmissionWaitDoesNotPersistReservation(t *testing.T) {
	store := NewMemoryStore(200)
	s := serviceWithStore(t, store, &fakeProvider{})
	<-s.admissionGate
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.Create(ctx, "owner", input("Canceled admission"))
	s.releaseAdmission()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled admission error = %v", err)
	}
	values, listErr := store.List(context.Background(), "owner")
	if listErr != nil || len(values) != 0 {
		t.Fatalf("canceled admission persisted a reservation: %#v, %v", values, listErr)
	}
}

func TestSameRepositorySessionsUseUniqueBranchesAndWorktrees(t *testing.T) {
	t.Parallel()
	s, _, provider, _ := service(t, Environment{})
	one, err := s.Create(context.Background(), "owner", input("Fix login"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := s.Create(context.Background(), "owner", input("Fix login"))
	if err != nil {
		t.Fatal(err)
	}
	if one.Branch == two.Branch || one.ID == two.ID || len(provider.requests) != 2 || provider.requests[0].WorktreeName == provider.requests[1].WorktreeName {
		t.Fatalf("workspaces not isolated: %#v %#v", one, two)
	}
	if one.State != core.WorkspaceRunning || two.State != core.WorkspaceRunning {
		t.Fatalf("unexpected states: %s %s", one.State, two.State)
	}
}

func TestDevcontainerBootstrapClonesPlainThenStopsForExactApproval(t *testing.T) {
	for _, configDirectory := range []string{".", ".devcontainer"} {
		configDirectory := configDirectory
		t.Run(configDirectory, func(t *testing.T) {
			controller, _ := admission.New(admission.ReferenceCapacity())
			store := NewMemoryStore(200)
			provider := &fakeProvider{}
			initializer := &fakeInitializer{}
			repo := core.Repository{ID: "repo-1", InstallationID: 1, FullName: "owner/repo", DefaultBranch: "main"}
			s, err := New(store, fakeRepos{repo}, fakeDetector{Environment{
				HasDevcontainer: true, Supported: true, RequiresTrust: true, ConfigDirectory: configDirectory,
			}}, provider, controller, &fakeCheckpoint{}, initializer)
			if err != nil {
				t.Fatal(err)
			}
			s.random = bytes.NewReader(make([]byte, 64))

			ws, err := s.Create(context.Background(), "owner", input("Trust setup"))
			if err != nil {
				t.Fatal(err)
			}
			if ws.State != core.WorkspaceAwaitingSetupApproval || ws.ProviderResourceID == "" ||
				initializer.calls != 1 || provider.starts != 1 || provider.stops != 1 ||
				len(provider.requests) != 1 || provider.requests[0].DevcontainerDir != configDirectory ||
				len(provider.setupStarts) != 0 {
				t.Fatalf("plain bootstrap did not clone and stop before approval: workspace=%#v provider=%#v initializer=%#v", ws, provider, initializer)
			}

			ws, err = s.ApproveSetup(context.Background(), "owner", ws.ID)
			if err != nil {
				t.Fatal(err)
			}
			if ws.State != core.WorkspaceRunning || initializer.calls != 2 || len(provider.setupStarts) != 1 ||
				provider.setupStarts[0].WorkspaceID != ws.ID ||
				provider.setupStarts[0].ConfigDirectory != configDirectory ||
				!provider.setupStarts[0].UseEnvBuilder {
				t.Fatalf("approved setup did not restart with the exact detected directory: workspace=%#v setup=%#v", ws, provider.setupStarts)
			}
		})
	}
}

func TestDevcontainerDetectionRejectsUntrustedDirectory(t *testing.T) {
	s, store, provider, _ := service(t, Environment{
		HasDevcontainer: true, Supported: true, RequiresTrust: true, ConfigDirectory: "../outside",
	})
	_, err := s.Create(context.Background(), "owner", input("Unsafe setup path"))
	if !errors.Is(err, core.ErrInvalid) || len(provider.requests) != 0 {
		t.Fatalf("unsafe detected setup directory was accepted: err=%v provider=%#v", err, provider)
	}
	values, listErr := store.List(context.Background(), "owner")
	if listErr != nil || len(values) != 0 {
		t.Fatalf("unsafe setup detection persisted a workspace: values=%#v err=%v", values, listErr)
	}
}

func TestUnsupportedDevcontainerApprovalUsesExplicitPlainFallback(t *testing.T) {
	s, _, provider, _ := service(t, Environment{
		HasDevcontainer: true, Supported: false, RequiresTrust: true, ConfigDirectory: ".devcontainer",
	})
	ws, err := s.Create(context.Background(), "owner", input("Safe fallback"))
	if err != nil {
		t.Fatal(err)
	}
	if ws.State != core.WorkspaceAwaitingSetupApproval || ws.FailureCode != "devcontainer_unsupported_safe_fallback_available" {
		t.Fatalf("unsupported setup did not wait on explicit fallback approval: %#v", ws)
	}
	ws, err = s.ApproveSetup(context.Background(), "owner", ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ws.State != core.WorkspaceRunning || len(provider.setupStarts) != 1 || provider.setupStarts[0].UseEnvBuilder {
		t.Fatalf("unsupported setup did not use the safe plain fallback: workspace=%#v setup=%#v", ws, provider.setupStarts)
	}
}

func TestQueuedDevcontainerPreservesDetectionUntilPlainBootstrap(t *testing.T) {
	controller, _ := admission.New(admission.ReferenceCapacity())
	store := NewMemoryStore(55)
	provider := &fakeProvider{}
	repo := core.Repository{ID: "repo-1", InstallationID: 1, FullName: "owner/repo", DefaultBranch: "main"}
	s, err := New(store, fakeRepos{repo}, fakeDetector{Environment{
		HasDevcontainer: true, Supported: true, RequiresTrust: true, ConfigDirectory: ".",
	}}, provider, controller, &fakeCheckpoint{})
	if err != nil {
		t.Fatal(err)
	}
	s.random = bytes.NewReader(make([]byte, 64))
	ws, err := s.Create(context.Background(), "owner", input("Queued setup"))
	if err != nil {
		t.Fatal(err)
	}
	if ws.State != core.WorkspaceQueued || len(provider.requests) != 0 || ws.DevcontainerDir != "." || !ws.DevcontainerSupported {
		t.Fatalf("queued setup lost its detected configuration: %#v", ws)
	}
	store.mu.Lock()
	store.diskFreeGiB = 200
	store.mu.Unlock()
	ws, err = s.Retry(context.Background(), "owner", ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ws.State != core.WorkspaceAwaitingSetupApproval || len(provider.requests) != 1 ||
		provider.requests[0].DevcontainerDir != "." || provider.starts != 1 || provider.stops != 1 {
		t.Fatalf("queued setup did not complete a plain bootstrap: workspace=%#v provider=%#v", ws, provider)
	}
}

func TestDeniedSetupRetryRepeatsPlainBootstrapAndApproval(t *testing.T) {
	s, store, provider, _ := service(t, Environment{
		HasDevcontainer: true, Supported: true, RequiresTrust: true, ConfigDirectory: ".devcontainer",
	})
	ws, err := s.Create(context.Background(), "owner", input("Deny and retry"))
	if err != nil {
		t.Fatal(err)
	}
	ws.State = core.WorkspaceFailed
	ws.FailureCode = "setup_approval_denied"
	ws.UpdatedAt = s.now()
	if err := store.Save(context.Background(), ws); err != nil {
		t.Fatal(err)
	}
	ws, err = s.Retry(context.Background(), "owner", ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ws.State != core.WorkspaceAwaitingSetupApproval || provider.starts != 2 || provider.stops != 2 || len(provider.setupStarts) != 0 {
		t.Fatalf("denied setup retry bypassed plain bootstrap/approval: workspace=%#v provider=%#v", ws, provider)
	}
}

func TestLegacyDevcontainerRetryFailsClosedUntilRecreated(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	now := s.now()
	legacy := core.Workspace{
		ID: "legacy", OwnerID: "owner", Repository: core.Repository{ID: "repo-1"},
		Name: "Legacy setup", Branch: "codex-mobile/legacy", BaseBranch: "main",
		State: core.WorkspaceFailed, FailureCode: "devcontainer_secure_recreate_required",
		SafetyMode: core.SafetyBalanced, Retention: core.Retention30Days, RequestedDiskGiB: 12,
		CreatedAt: now, UpdatedAt: now, LastActivityAt: now,
	}
	if err := store.Create(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	_, err := s.Retry(context.Background(), "owner", legacy.ID)
	if !errors.Is(err, core.ErrPrecondition) || len(provider.requests) != 0 || provider.starts != 0 {
		t.Fatalf("legacy setup retry did not fail closed: err=%v provider=%#v", err, provider)
	}
}

func TestApprovedEnvbuilderFailureRetriesSamePersistedSetup(t *testing.T) {
	s, _, provider, _ := service(t, Environment{
		HasDevcontainer: true, Supported: true, RequiresTrust: true, ConfigDirectory: ".",
	})
	ws, err := s.Create(context.Background(), "owner", input("Retry approved setup"))
	if err != nil {
		t.Fatal(err)
	}
	provider.failSetupStart = true
	ws, err = s.ApproveSetup(context.Background(), "owner", ws.ID)
	if err == nil || ws.State != core.WorkspaceFailed || !ws.SetupApproved {
		t.Fatalf("failed approved setup = %#v, %v", ws, err)
	}
	provider.failSetupStart = false
	ws, err = s.Retry(context.Background(), "owner", ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ws.State != core.WorkspaceRunning || len(provider.setupStarts) != 2 ||
		provider.setupStarts[1].ConfigDirectory != "." || !provider.setupStarts[1].UseEnvBuilder {
		t.Fatalf("approved setup retry lost its exact configuration: workspace=%#v setup=%#v", ws, provider.setupStarts)
	}
}

func TestFailedProvisionCanRetry(t *testing.T) {
	t.Parallel()
	s, _, provider, _ := service(t, Environment{})
	provider.fail = true
	ws, err := s.Create(context.Background(), "owner", input("Failure"))
	if err == nil || ws.State != core.WorkspaceProvisioning || ws.FailureCode != failureProvisionUnconfirmed {
		t.Fatalf("failure = %#v, %v", ws, err)
	}
	provider.fail = false
	ws, err = s.Retry(context.Background(), "owner", ws.ID)
	if err != nil || ws.State != core.WorkspaceProvisioning || ws.FailureCode != failureProviderStartReserved {
		t.Fatalf("absence reconciliation = %#v, %v", ws, err)
	}
	ws, err = s.Retry(context.Background(), "owner", ws.ID)
	if err != nil || ws.State != core.WorkspaceRunning {
		t.Fatalf("retry after confirmed absence = %#v, %v", ws, err)
	}
}

func TestAmbiguousStartCleanupRemainsCountedAndBlocksQueuedPromotion(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	capacity := admission.ReferenceCapacity()
	capacity.MaxRunning = 1
	controller, err := admission.New(capacity)
	if err != nil {
		t.Fatal(err)
	}
	s.admission = controller
	provider.failStart = true
	provider.failStop = true

	failedStart, createErr := s.Create(context.Background(), "owner", input("Ambiguous start"))
	if createErr == nil || failedStart.State != core.WorkspaceProvisioning || failedStart.FailureCode != failureStartCleanupPending {
		t.Fatalf("ambiguous start released its reservation: %#v, %v", failedStart, createErr)
	}
	snapshot, err := store.Snapshot(context.Background(), "owner")
	if err != nil || snapshot.Running != 1 {
		t.Fatalf("cleanup-pending snapshot = %#v, %v", snapshot, err)
	}
	queued, err := s.Create(context.Background(), "owner", input("Must remain queued"))
	if err != nil || queued.State != core.WorkspaceQueued {
		t.Fatalf("cleanup-pending runtime admitted another start: %#v, %v", queued, err)
	}

	provider.failStart = false
	provider.failStop = false
	cleaned, err := s.Retry(context.Background(), "owner", failedStart.ID)
	if err != nil || cleaned.State != core.WorkspaceFailed || cleaned.FailureCode != failureProviderStart {
		t.Fatalf("confirmed cleanup did not fail closed: %#v, %v", cleaned, err)
	}
	promoted, err := s.Retry(context.Background(), "owner", queued.ID)
	if err != nil || promoted.State != core.WorkspaceRunning {
		t.Fatalf("queued workspace did not promote after confirmed cleanup: %#v, %v", promoted, err)
	}
}

func TestInitializerFailureCannotReleaseCapacityUntilStopConfirmed(t *testing.T) {
	controller, _ := admission.New(admission.ReferenceCapacity())
	store := NewMemoryStore(200)
	provider := &fakeProvider{failStop: true}
	initializer := &fakeInitializer{err: errors.New("initializer response lost")}
	repo := core.Repository{ID: "repo-1", InstallationID: 1, FullName: "owner/repo", DefaultBranch: "main"}
	s, err := New(store, fakeRepos{repo}, fakeDetector{}, provider, controller, &fakeCheckpoint{}, initializer)
	if err != nil {
		t.Fatal(err)
	}
	boundary := &fakeDeletionBoundary{}
	if err := s.ConfigureDeletionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSuspensionBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	s.random = bytes.NewReader(make([]byte, 256))

	value, createErr := s.Create(context.Background(), "owner", input("Initializer cleanup"))
	if createErr == nil || value.State != core.WorkspaceProvisioning || value.FailureCode != failureInitializeCleanupPending {
		t.Fatalf("initializer ambiguity was not retained: %#v, %v", value, createErr)
	}
	snapshot, _ := store.Snapshot(context.Background(), "owner")
	if snapshot.Running != 1 {
		t.Fatalf("initializer cleanup released capacity: %#v", snapshot)
	}
	provider.failStop = false
	value, err = s.Retry(context.Background(), "owner", value.ID)
	if err != nil || value.State != core.WorkspaceFailed || value.FailureCode != failureWorkspaceInitialize {
		t.Fatalf("initializer cleanup retry = %#v, %v", value, err)
	}
}

func TestStopBeforeSetupApprovalRemainsCountedUntilRetryConfirmsStop(t *testing.T) {
	s, store, provider, _ := service(t, Environment{
		HasDevcontainer: true, Supported: true, RequiresTrust: true, ConfigDirectory: ".devcontainer",
	})
	provider.failStop = true
	value, createErr := s.Create(context.Background(), "owner", input("Approval stop"))
	if createErr == nil || value.State != core.WorkspaceProvisioning || value.FailureCode != failureSetupStopCleanupPending {
		t.Fatalf("unconfirmed setup stop = %#v, %v", value, createErr)
	}
	snapshot, _ := store.Snapshot(context.Background(), "owner")
	if snapshot.Running != 1 {
		t.Fatalf("unconfirmed setup stop released capacity: %#v", snapshot)
	}
	provider.failStop = false
	value, err := s.Retry(context.Background(), "owner", value.ID)
	if err != nil || value.State != core.WorkspaceAwaitingSetupApproval {
		t.Fatalf("setup stop reconciliation = %#v, %v", value, err)
	}
}

func TestFailedDeleteRemainsCountedAndBlocksAdmission(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	capacity := admission.ReferenceCapacity()
	capacity.MaxRunning = 1
	controller, _ := admission.New(capacity)
	s.admission = controller
	value, err := s.Create(context.Background(), "owner", input("Deleting runtime"))
	if err != nil {
		t.Fatal(err)
	}
	provider.failDelete = true
	if err := s.Delete(context.Background(), "owner", value.ID, false, true); err == nil {
		t.Fatal("provider delete unexpectedly succeeded")
	}
	snapshot, _ := store.Snapshot(context.Background(), "owner")
	if snapshot.Running != 1 {
		t.Fatalf("failed delete released runtime capacity: %#v", snapshot)
	}
	queued, err := s.Create(context.Background(), "owner", input("Blocked by delete"))
	if err != nil || queued.State != core.WorkspaceQueued {
		t.Fatalf("failed delete admitted another runtime: %#v, %v", queued, err)
	}
	provider.failDelete = false
	if err := s.Delete(context.Background(), "owner", value.ID, true, false); err != nil {
		t.Fatal(err)
	}
	promoted, err := s.Retry(context.Background(), "owner", queued.ID)
	if err != nil || promoted.State != core.WorkspaceRunning {
		t.Fatalf("queued workspace did not promote after confirmed delete: %#v, %v", promoted, err)
	}
}

func TestDeleteResolvesAmbiguousCreateBeforeFinalizing(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	provider.fail = true
	value, err := s.Create(context.Background(), "owner", input("Lost create response"))
	if err == nil || value.ProviderResourceID != "" || value.State != core.WorkspaceProvisioning {
		t.Fatalf("ambiguous create setup = %#v, %v", value, err)
	}
	provider.lookupID = "provider-recovered"
	provider.failDelete = false
	if err := s.Delete(context.Background(), "owner", value.ID, false, true); err != nil {
		t.Fatal(err)
	}
	if provider.lookups != 1 || provider.deletes != 1 {
		t.Fatalf("ambiguous create delete boundaries: lookups=%d deletes=%d", provider.lookups, provider.deletes)
	}
	if _, err := store.Get(context.Background(), "owner", value.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("resolved delete retained row: %v", err)
	}
}

func TestMaintenanceDrainBarrierWaitsForPreDrainStartAndClosesAdmission(t *testing.T) {
	s, _, provider, _ := service(t, Environment{})
	started := make(chan struct{}, 1)
	releaseProvider := make(chan struct{})
	provider.provisionStarted, provider.provisionRelease = started, releaseProvider
	createDone := make(chan error, 1)
	go func() {
		_, err := s.Create(context.Background(), "owner", input("Already admitted"))
		createDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("pre-drain start did not reach provider")
	}
	s.admission.SetMaintenanceDrain(true)
	barrierDone := make(chan struct {
		release func()
		err     error
	}, 1)
	go func() {
		release, err := s.BeginMaintenanceDrain(context.Background())
		barrierDone <- struct {
			release func()
			err     error
		}{release: release, err: err}
	}()
	select {
	case <-barrierDone:
		t.Fatal("maintenance barrier crossed a pre-drain provider start")
	case <-time.After(30 * time.Millisecond):
	}
	close(releaseProvider)
	if err := <-createDone; err != nil {
		t.Fatal(err)
	}
	result := <-barrierDone
	if result.err != nil || result.release == nil {
		t.Fatalf("maintenance barrier release_nil=%t, err=%v", result.release == nil, result.err)
	}
	result.release()
	queued, err := s.Create(context.Background(), "owner", input("After drain"))
	if err != nil || queued.State != core.WorkspaceQueued {
		t.Fatalf("maintenance drain admitted a later start: %#v, %v", queued, err)
	}
}

func TestMaintenanceDrainBarrierCancellationDoesNotLeakAdmission(t *testing.T) {
	s, _, _, _ := service(t, Environment{})
	if err := s.acquireAdmission(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if release, err := s.BeginMaintenanceDrain(ctx); !errors.Is(err, context.DeadlineExceeded) || release != nil {
		t.Fatalf("canceled maintenance barrier release_nil=%t, err=%v", release == nil, err)
	}
	s.releaseAdmission()
	if err := s.acquireAdmission(context.Background()); err != nil {
		t.Fatalf("canceled maintenance barrier leaked admission: %v", err)
	}
	s.releaseAdmission()
}

func TestMaintenanceReconcileUsesSuspensionBoundaryAndConfirmsProviderStop(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	value, err := s.Create(context.Background(), "owner", input("Maintenance runtime"))
	if err != nil {
		t.Fatal(err)
	}
	value.State = core.WorkspaceMaintenance
	if err := store.Save(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	boundary := s.suspension.(*fakeDeletionBoundary)
	boundary.requireSuspending = true
	value, err = s.ReconcileMaintenanceDrain(context.Background(), "owner", value.ID)
	if err != nil || value.State != core.WorkspaceSuspended || value.SuspendedAt == nil {
		t.Fatalf("maintenance reconciliation = %#v, %v", value, err)
	}
	if provider.waitStops == 0 || len(boundary.suspensionSeen) == 0 || boundary.suspensionSeen[0].State != core.WorkspaceSuspending {
		t.Fatalf("maintenance stop/boundary was not enforced: stops=%d seen=%#v", provider.waitStops, boundary.suspensionSeen)
	}
}

func TestMaintenanceProvisioningCleanupRemainsCountedUntilStopConfirmed(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	provider.failStart = true
	provider.failStop = true
	value, err := s.Create(context.Background(), "owner", input("Maintenance provisioning"))
	if err == nil || value.State != core.WorkspaceProvisioning {
		t.Fatalf("cleanup setup = %#v, %v", value, err)
	}
	value, err = s.ReconcileMaintenanceDrain(context.Background(), "owner", value.ID)
	if err == nil || value.State != core.WorkspaceProvisioning {
		t.Fatalf("ambiguous maintenance stop released capacity: %#v, %v", value, err)
	}
	snapshot, _ := store.Snapshot(context.Background(), "owner")
	if snapshot.Running != 1 {
		t.Fatalf("ambiguous maintenance cleanup snapshot = %#v", snapshot)
	}
	provider.failStop = false
	value, err = s.ReconcileMaintenanceDrain(context.Background(), "owner", value.ID)
	if err != nil || value.State != core.WorkspaceFailed || value.FailureCode != "maintenance_interrupted_provisioning" {
		t.Fatalf("confirmed maintenance cleanup = %#v, %v", value, err)
	}
}

func TestRequestedDiskIsStableHardAndEqualShareCap(t *testing.T) {
	t.Parallel()
	s, _, provider, _ := service(t, Environment{})
	request := input("Small disk")
	request.RequestedDiskGiB = 8
	value, err := s.Create(context.Background(), "owner", request)
	if err != nil {
		t.Fatal(err)
	}
	if value.RequestedDiskGiB != 8 || value.Quota.DiskGiB != 8 || len(provider.requests) != 1 || provider.requests[0].Quota.DiskGiB != 8 {
		t.Fatalf("requested disk was not enforced as a cap: workspace=%#v requests=%#v", value, provider.requests)
	}
	request = input("Maximum disk")
	request.RequestedDiskGiB = 16
	value, err = s.Create(context.Background(), "owner", request)
	if err != nil {
		t.Fatal(err)
	}
	if value.Quota.DiskGiB != core.MaximumWorkspaceDiskGiB {
		t.Fatalf("maximum persistent quota = %d, want %d", value.Quota.DiskGiB, core.MaximumWorkspaceDiskGiB)
	}
	share := quotaWithinRequest(core.Quota{CPUMilli: 6000, MemoryMiB: 18000, DiskGiB: 160}, 0)
	if share.DiskGiB != core.MaximumWorkspaceDiskGiB {
		t.Fatalf("unrequested equal share exceeded hard volume ceiling: %#v", share)
	}
}

func TestAutomaticDeletionRefusesDirtyOrUnpushed(t *testing.T) {
	t.Parallel()
	s, store, _, checkpoint := service(t, Environment{})
	ws, _ := s.Create(context.Background(), "owner", input("Protect work"))
	ws.Dirty = true
	_ = store.Save(context.Background(), ws)
	if err := s.Delete(context.Background(), "owner", ws.ID, true, false); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("auto-delete error = %v", err)
	}
	if checkpoint.calls != 0 {
		t.Fatal("checkpoint should not run for refused auto-delete")
	}
}

func TestSuspendUsesLiveCheckpointStatusEvenWhenStoredFlagsAreClean(t *testing.T) {
	t.Parallel()
	s, store, _, checkpoint := service(t, Environment{})
	ws, err := s.Create(context.Background(), "owner", input("Live dirty state"))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.dirty, checkpoint.push = true, true
	ws, err = s.Suspend(context.Background(), "owner", ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.calls != 1 || !ws.Dirty || !ws.Unpushed || ws.State != core.WorkspaceSuspended {
		t.Fatalf("suspend did not persist live risk: %#v calls=%d", ws, checkpoint.calls)
	}
	stored, err := store.Get(context.Background(), "owner", ws.ID)
	if err != nil || !stored.Dirty || !stored.Unpushed {
		t.Fatalf("stored risk = %#v, %v", stored, err)
	}
}

func TestManualDeleteFailsClosedWhenCheckpointFails(t *testing.T) {
	t.Parallel()
	s, store, provider, checkpoint := service(t, Environment{})
	ws, err := s.Create(context.Background(), "owner", input("Protect delete"))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.err = errors.New("checkpoint unavailable")
	if err := s.Delete(context.Background(), "owner", ws.ID, false, true); err == nil {
		t.Fatal("manual delete proceeded without a checkpoint boundary")
	}
	stored, _ := store.Get(context.Background(), "owner", ws.ID)
	if stored.State == core.WorkspaceDeleting || len(provider.requests) != 1 || checkpoint.calls != 1 {
		t.Fatalf("destructive transition occurred: %#v calls=%d", stored, checkpoint.calls)
	}
}

func TestDeleteFailureLeavesRetryableTombstoneThenFinalizesIdempotently(t *testing.T) {
	t.Parallel()
	s, store, provider, checkpoint := service(t, Environment{})
	ws, err := s.Create(context.Background(), "owner", input("Retry deletion"))
	if err != nil {
		t.Fatal(err)
	}
	provider.failDelete = true
	if err := s.Delete(context.Background(), "owner", ws.ID, false, true); err == nil {
		t.Fatal("provider deletion failure was hidden")
	}
	stored, err := store.Get(context.Background(), "owner", ws.ID)
	if err != nil || stored.State != core.WorkspaceDeleting {
		t.Fatalf("failed deletion did not retain its retry tombstone: %#v %v", stored, err)
	}
	if checkpoint.calls != 1 || provider.deletes != 1 {
		t.Fatalf("initial delete boundaries: checkpoints=%d provider_deletes=%d", checkpoint.calls, provider.deletes)
	}

	provider.failDelete = false
	if err := s.Delete(context.Background(), "owner", ws.ID, true, false); err != nil {
		t.Fatalf("automatic tombstone retry: %v", err)
	}
	if _, err := store.Get(context.Background(), "owner", ws.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("successful deletion retained workspace row: %v", err)
	}
	if checkpoint.calls != 1 || provider.deletes != 2 {
		t.Fatalf("retry repeated destructive preparation: checkpoints=%d provider_deletes=%d", checkpoint.calls, provider.deletes)
	}
	if err := s.Delete(context.Background(), "owner", ws.ID, false, true); err != nil {
		t.Fatalf("post-finalization delete was not idempotent: %v", err)
	}
	if provider.deletes != 2 {
		t.Fatalf("post-finalization retry reached provider: %d", provider.deletes)
	}
}

func TestDeleteCleanupFailureRetainsTombstoneForAutomaticRetry(t *testing.T) {
	t.Parallel()
	s, store, provider, checkpoint := service(t, Environment{})
	boundary := s.deletion.(*fakeDeletionBoundary)
	boundary.err = errors.New("runtime cleanup failed")
	ws, err := s.Create(context.Background(), "owner", input("Retry cleanup"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(context.Background(), "owner", ws.ID, false, true); err == nil {
		t.Fatal("cleanup failure was hidden")
	}
	stored, err := store.Get(context.Background(), "owner", ws.ID)
	if err != nil || stored.State != core.WorkspaceDeleting {
		t.Fatalf("cleanup failure lost retry tombstone: %#v %v", stored, err)
	}
	boundary.err = nil
	if err := s.Delete(context.Background(), "owner", ws.ID, true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "owner", ws.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cleanup retry did not finalize workspace: %v", err)
	}
	if checkpoint.calls != 1 || provider.deletes != 2 || boundary.calls != 2 || boundary.releases != 1 {
		t.Fatalf("cleanup retry boundaries: checkpoints=%d deletes=%d calls=%d releases=%d", checkpoint.calls, provider.deletes, boundary.calls, boundary.releases)
	}
}

func TestConcurrentDeleteRetriesShareFinalOutcome(t *testing.T) {
	t.Parallel()
	s, store, provider, checkpoint := service(t, Environment{})
	ws, err := s.Create(context.Background(), "owner", input("Concurrent deletion"))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	provider.deleteStarted = started
	provider.deleteRelease = release

	first := make(chan error, 1)
	go func() { first <- s.Delete(context.Background(), "owner", ws.ID, false, true) }()
	<-started
	second := make(chan error, 1)
	go func() { second <- s.Delete(context.Background(), "owner", ws.ID, false, true) }()
	select {
	case <-started:
		t.Fatal("second deletion bypassed the per-workspace mutation gate")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "owner", ws.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("concurrent delete retained workspace: %v", err)
	}
	if checkpoint.calls != 1 || provider.deletes != 1 {
		t.Fatalf("serialized delete repeated side effects: checkpoints=%d deletes=%d", checkpoint.calls, provider.deletes)
	}
	if len(s.mutations) != 0 {
		t.Fatalf("workspace mutation gates leaked after concurrent delete: %d", len(s.mutations))
	}
}

func TestResumeAndDeleteAreSerializedAcrossProviderWork(t *testing.T) {
	t.Parallel()

	t.Run("resume first", func(t *testing.T) {
		s, store, provider, _ := service(t, Environment{})
		ws, err := s.Create(context.Background(), "owner", input("Resume before delete"))
		if err != nil {
			t.Fatal(err)
		}
		ws, err = s.Suspend(context.Background(), "owner", ws.ID)
		if err != nil {
			t.Fatal(err)
		}
		startStarted := make(chan struct{}, 1)
		startRelease := make(chan struct{})
		deleteStarted := make(chan struct{}, 1)
		provider.startStarted, provider.startRelease = startStarted, startRelease
		provider.deleteStarted = deleteStarted
		resumeDone := make(chan error, 1)
		go func() {
			_, resumeErr := s.Resume(context.Background(), "owner", ws.ID)
			resumeDone <- resumeErr
		}()
		<-startStarted
		deleteDone := make(chan error, 1)
		go func() { deleteDone <- s.Delete(context.Background(), "owner", ws.ID, false, true) }()
		select {
		case <-deleteStarted:
			t.Fatal("delete reached provider while resume was in flight")
		case <-time.After(25 * time.Millisecond):
		}
		close(startRelease)
		if err := <-resumeDone; err != nil {
			t.Fatal(err)
		}
		<-deleteStarted
		if err := <-deleteDone; err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(context.Background(), "owner", ws.ID); !errors.Is(err, core.ErrNotFound) {
			t.Fatalf("resume/delete race resurrected workspace: %v", err)
		}
	})

	t.Run("delete first", func(t *testing.T) {
		s, store, provider, _ := service(t, Environment{})
		ws, err := s.Create(context.Background(), "owner", input("Delete before resume"))
		if err != nil {
			t.Fatal(err)
		}
		ws, err = s.Suspend(context.Background(), "owner", ws.ID)
		if err != nil {
			t.Fatal(err)
		}
		deleteStarted := make(chan struct{}, 1)
		deleteRelease := make(chan struct{})
		startStarted := make(chan struct{}, 1)
		provider.deleteStarted, provider.deleteRelease = deleteStarted, deleteRelease
		provider.startStarted = startStarted
		deleteDone := make(chan error, 1)
		go func() { deleteDone <- s.Delete(context.Background(), "owner", ws.ID, false, true) }()
		<-deleteStarted
		resumeDone := make(chan error, 1)
		go func() {
			_, resumeErr := s.Resume(context.Background(), "owner", ws.ID)
			resumeDone <- resumeErr
		}()
		select {
		case <-startStarted:
			t.Fatal("resume reached provider while delete was in flight")
		case <-time.After(25 * time.Millisecond):
		}
		close(deleteRelease)
		if err := <-deleteDone; err != nil {
			t.Fatal(err)
		}
		if err := <-resumeDone; !errors.Is(err, core.ErrNotFound) {
			t.Fatalf("resume after finalized delete returned %v", err)
		}
		if _, err := store.Get(context.Background(), "owner", ws.ID); !errors.Is(err, core.ErrNotFound) {
			t.Fatalf("delete/resume race resurrected workspace: %v", err)
		}
	})
}

func TestInactiveSuspendRechecksActivityAfterCheckpoint(t *testing.T) {
	t.Parallel()
	s, store, provider, checkpoint := service(t, Environment{})
	ws, err := s.Create(context.Background(), "owner", input("Race safe suspend"))
	if err != nil {
		t.Fatal(err)
	}
	expected := ws.LastActivityAt
	claimed, err := s.MarkIdleIfInactive(context.Background(), "owner", ws.ID, expected)
	if err != nil || !claimed {
		t.Fatalf("mark idle = %v, %v", claimed, err)
	}
	checkpoint.after = func() {
		_ = store.TouchActivity(context.Background(), "owner", ws.ID, expected.Add(time.Second))
	}
	value, suspended, err := s.SuspendIfInactive(context.Background(), "owner", ws.ID, expected)
	if err != nil {
		t.Fatal(err)
	}
	if suspended || provider.stops != 0 {
		t.Fatalf("provider stopped after concurrent activity: value=%#v stops=%d", value, provider.stops)
	}
	stored, _ := store.Get(context.Background(), "owner", ws.ID)
	if stored.State != core.WorkspaceRunning || !stored.LastActivityAt.After(expected) {
		t.Fatalf("activity was lost: %#v", stored)
	}
}

func TestWorkspacePolicySupportsOverrideAndInheritance(t *testing.T) {
	t.Parallel()
	s, _, _, _ := service(t, Environment{})
	ws, err := s.Create(context.Background(), "owner", input("Policy"))
	if err != nil {
		t.Fatal(err)
	}
	ws, err = s.UpdatePolicy(context.Background(), "owner", ws.ID, core.Retention90Days, 45)
	if err != nil || ws.Retention != core.Retention90Days || ws.IdleTimeoutMinutes != 45 {
		t.Fatalf("override = %#v, %v", ws, err)
	}
	ws, err = s.UpdatePolicy(context.Background(), "owner", ws.ID, core.Retention30Days, 0)
	if err != nil || ws.IdleTimeoutMinutes != 0 {
		t.Fatalf("inheritance = %#v, %v", ws, err)
	}
}

func TestSuspendIsNotExposedUntilProviderConfirmsStop(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	boundary := s.suspension.(*fakeDeletionBoundary)
	ws, err := s.Create(context.Background(), "owner", input("Confirmed stop"))
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}, 1), make(chan struct{})
	provider.stopStarted, provider.stopRelease = started, release
	type result struct {
		workspace core.Workspace
		err       error
	}
	finished := make(chan result, 1)
	go func() {
		value, suspendErr := s.Suspend(context.Background(), "owner", ws.ID)
		finished <- result{workspace: value, err: suspendErr}
	}()
	<-started
	stored, err := store.Get(context.Background(), "owner", ws.ID)
	if err != nil || stored.State != core.WorkspaceSuspending || stored.SuspendedAt != nil {
		t.Fatalf("workspace was exposed as suspended before provider confirmation: %#v %v", stored, err)
	}
	boundary.mu.Lock()
	if boundary.suspensionCalls != 1 || boundary.suspensionReleases != 0 ||
		len(boundary.suspensionSeen) != 1 || boundary.suspensionSeen[0].State != core.WorkspaceSuspending {
		boundary.mu.Unlock()
		t.Fatalf("runtime boundary ordering = calls %d releases %d seen %#v",
			boundary.suspensionCalls, boundary.suspensionReleases, boundary.suspensionSeen)
	}
	boundary.mu.Unlock()
	close(release)
	completed := <-finished
	if completed.err != nil || completed.workspace.State != core.WorkspaceSuspended || completed.workspace.SuspendedAt == nil {
		t.Fatalf("confirmed suspension = %#v %v", completed.workspace, completed.err)
	}
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if boundary.suspensionReleases != 1 {
		t.Fatalf("runtime boundary release count = %d", boundary.suspensionReleases)
	}
}

func TestSuspendCleanupFailureLeavesRetryableSuspendingAuthority(t *testing.T) {
	t.Parallel()
	s, store, provider, checkpoint := service(t, Environment{})
	boundary := s.suspension.(*fakeDeletionBoundary)
	ws, err := s.Create(context.Background(), "owner", input("Retry cleanup"))
	if err != nil {
		t.Fatal(err)
	}
	boundary.suspensionErr = errors.New("runtime cleanup failed")
	if _, err := s.Suspend(context.Background(), "owner", ws.ID); err == nil {
		t.Fatal("suspend unexpectedly ignored runtime cleanup failure")
	}
	stored, err := store.Get(context.Background(), "owner", ws.ID)
	if err != nil || stored.State != core.WorkspaceSuspending || provider.waitStops != 0 {
		t.Fatalf("cleanup failure did not fail closed: workspace=%#v stops=%d err=%v", stored, provider.waitStops, err)
	}
	boundary.mu.Lock()
	boundary.suspensionErr = nil
	boundary.mu.Unlock()
	resumed, err := s.Suspend(context.Background(), "owner", ws.ID)
	if err != nil || resumed.State != core.WorkspaceSuspended || provider.waitStops != 1 || checkpoint.calls != 1 {
		t.Fatalf("suspension retry = %#v stops=%d checkpoints=%d err=%v", resumed, provider.waitStops, checkpoint.calls, err)
	}
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if boundary.suspensionCalls != 2 || boundary.suspensionReleases != 1 {
		t.Fatalf("suspension retry boundary calls=%d releases=%d", boundary.suspensionCalls, boundary.suspensionReleases)
	}
}

func TestProviderStopFailureLeavesRetryableSuspendingAuthority(t *testing.T) {
	t.Parallel()
	s, store, provider, checkpoint := service(t, Environment{})
	boundary := s.suspension.(*fakeDeletionBoundary)
	ws, err := s.Create(context.Background(), "owner", input("Retry provider stop"))
	if err != nil {
		t.Fatal(err)
	}
	provider.failStop = true
	if _, err := s.Suspend(context.Background(), "owner", ws.ID); err == nil {
		t.Fatal("suspend unexpectedly ignored provider stop failure")
	}
	stored, err := store.Get(context.Background(), "owner", ws.ID)
	if err != nil || stored.State != core.WorkspaceSuspending || provider.waitStops != 1 {
		t.Fatalf("provider failure did not preserve retry authority: workspace=%#v stops=%d err=%v", stored, provider.waitStops, err)
	}
	provider.failStop = false
	resumed, err := s.Suspend(context.Background(), "owner", ws.ID)
	if err != nil || resumed.State != core.WorkspaceSuspended || provider.waitStops != 2 || checkpoint.calls != 1 {
		t.Fatalf("provider stop retry = %#v stops=%d checkpoints=%d err=%v", resumed, provider.waitStops, checkpoint.calls, err)
	}
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if boundary.suspensionCalls != 2 || boundary.suspensionReleases != 2 {
		t.Fatalf("provider retry boundary calls=%d releases=%d", boundary.suspensionCalls, boundary.suspensionReleases)
	}
}

func TestInactiveSuspendUsesSharedRuntimeBoundary(t *testing.T) {
	t.Parallel()
	s, _, provider, _ := service(t, Environment{})
	boundary := s.suspension.(*fakeDeletionBoundary)
	ws, err := s.Create(context.Background(), "owner", input("Automatic suspend"))
	if err != nil {
		t.Fatal(err)
	}
	expected := ws.LastActivityAt
	if claimed, err := s.MarkIdleIfInactive(context.Background(), "owner", ws.ID, expected); err != nil || !claimed {
		t.Fatalf("mark idle = %v, %v", claimed, err)
	}
	value, suspended, err := s.SuspendIfInactive(context.Background(), "owner", ws.ID, expected)
	if err != nil || !suspended || value.State != core.WorkspaceSuspended || provider.waitStops != 1 {
		t.Fatalf("automatic suspend = %#v suspended=%v stops=%d err=%v", value, suspended, provider.waitStops, err)
	}
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if boundary.suspensionCalls != 1 || boundary.suspensionReleases != 1 {
		t.Fatalf("automatic suspension bypassed boundary: calls=%d releases=%d", boundary.suspensionCalls, boundary.suspensionReleases)
	}
}

func TestSafetyModeChangeRequiresSuspensionAndAppliesProviderAndCodexPolicyOnResume(t *testing.T) {
	s, store, provider, _ := service(t, Environment{})
	ws, err := s.Create(context.Background(), "owner", input("Change autonomy"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateSafetyMode(context.Background(), "owner", ws.ID, core.SafetyFullAccess); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("live safety-mode change error = %v, want conflict", err)
	}
	stored, err := store.Get(context.Background(), "owner", ws.ID)
	if err != nil || stored.SafetyMode != core.SafetyBalanced {
		t.Fatalf("rejected change mutated workspace: %#v %v", stored, err)
	}

	ws, err = s.Suspend(context.Background(), "owner", ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	ws, err = s.UpdateSafetyMode(context.Background(), "owner", ws.ID, core.SafetyFullAccess)
	if err != nil || ws.State != core.WorkspaceSuspended || ws.SafetyMode != core.SafetyFullAccess || provider.waitStops != 1 {
		t.Fatalf("suspended safety-mode change = %#v, %v", ws, err)
	}
	initializer := &fakeInitializer{}
	s.initializer = initializer
	ws, err = s.Resume(context.Background(), "owner", ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	lastStart := provider.startRequests[len(provider.startRequests)-1]
	if ws.State != core.WorkspaceRunning || lastStart.SafetyMode != core.SafetyFullAccess ||
		lastStart.Quota != ws.Quota || len(initializer.seen) != 1 || initializer.seen[0].SafetyMode != core.SafetyFullAccess {
		t.Fatalf("resume did not apply one safety mode across provider/config: workspace=%#v start=%#v init=%#v", ws, lastStart, initializer.seen)
	}
}

func TestSafetyModeChangeRejectsMalformedAndCrossOwnerRequests(t *testing.T) {
	s, _, _, _ := service(t, Environment{})
	ws, err := s.Create(context.Background(), "owner", input("Rejected autonomy"))
	if err != nil {
		t.Fatal(err)
	}
	ws, err = s.Suspend(context.Background(), "owner", ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateSafetyMode(context.Background(), "owner", ws.ID, core.SafetyMode("unbounded")); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("invalid safety mode error = %v", err)
	}
	if _, err := s.UpdateSafetyMode(context.Background(), "other-owner", ws.ID, core.SafetySafe); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner safety mode error = %v", err)
	}
}

func TestSafetyModeChangeAndResumeNeverExposeMixedPolicy(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		s, store, provider, _ := service(t, Environment{})
		ws, err := s.Create(context.Background(), "owner", input("Autonomy race"))
		if err != nil {
			t.Fatal(err)
		}
		ws, err = s.Suspend(context.Background(), "owner", ws.ID)
		if err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var updateErr, resumeErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, updateErr = s.UpdateSafetyMode(context.Background(), "owner", ws.ID, core.SafetySafe)
		}()
		go func() {
			defer wait.Done()
			<-start
			_, resumeErr = s.Resume(context.Background(), "owner", ws.ID)
		}()
		close(start)
		wait.Wait()
		if resumeErr != nil {
			t.Fatalf("iteration %d resume error = %v", iteration, resumeErr)
		}
		stored, err := store.Get(context.Background(), "owner", ws.ID)
		if err != nil {
			t.Fatal(err)
		}
		lastStart := provider.startRequests[len(provider.startRequests)-1]
		if updateErr == nil {
			if stored.SafetyMode != core.SafetySafe || lastStart.SafetyMode != core.SafetySafe {
				t.Fatalf("iteration %d accepted update was not applied consistently: stored=%s start=%s", iteration, stored.SafetyMode, lastStart.SafetyMode)
			}
		} else {
			if !errors.Is(updateErr, core.ErrConflict) || stored.SafetyMode != core.SafetyBalanced || lastStart.SafetyMode != core.SafetyBalanced {
				t.Fatalf("iteration %d losing update produced mixed policy: err=%v stored=%s start=%s", iteration, updateErr, stored.SafetyMode, lastStart.SafetyMode)
			}
		}
	}
}

func TestResumeRerunsInitializerForTmpfsRuntimeState(t *testing.T) {
	s, _, _, _ := service(t, Environment{})
	ws, err := s.Create(context.Background(), "owner", input("Resume private state"))
	if err != nil {
		t.Fatal(err)
	}
	ws, err = s.Suspend(context.Background(), "owner", ws.ID)
	if err != nil {
		t.Fatal(err)
	}
	initializer := &fakeInitializer{}
	s.initializer = initializer
	if _, err := s.Resume(context.Background(), "owner", ws.ID); err != nil {
		t.Fatal(err)
	}
	if initializer.calls != 1 {
		t.Fatalf("resume initializer calls = %d, want 1", initializer.calls)
	}
}
