package workspace

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/admission"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type Environment struct {
	HasDevcontainer bool
	Supported       bool
	RequiresTrust   bool
	ConfigDirectory string
	Reason          string
}

type RepositorySource interface {
	Get(context.Context, string, string) (core.Repository, error)
}

type EnvironmentDetector interface {
	Detect(context.Context, string, core.Repository, string) (Environment, error)
}

type ProvisionRequest struct {
	WorkspaceID      string
	Repository       core.Repository
	Branch           string
	BaseBranch       string
	WorktreeName     string
	Quota            core.Quota
	SafetyMode       core.SafetyMode
	NestedContainers bool
	DevcontainerDir  string
}

// StartRequest carries every mutable runtime policy that must be applied by
// the provider before a stopped workspace becomes reachable again. Disk is
// deliberately absent because the persistent volume quota is immutable after
// provisioning.
type StartRequest struct {
	SafetyMode core.SafetyMode
	Quota      core.Quota
}

// SetupStartRequest is the only path that can switch an already-populated
// plain workspace into EnvBuilder mode. ConfigDirectory is persisted from the
// original detection; it is never inferred again when approval is resolved.
type SetupStartRequest struct {
	WorkspaceID     string
	ConfigDirectory string
	UseEnvBuilder   bool
	SafetyMode      core.SafetyMode
	Quota           core.Quota
}

type Provider interface {
	// LookupProvisioned resolves the provider resource for a logical workspace
	// ID without creating it. ErrNotFound is returned only when provider
	// absence was positively confirmed.
	LookupProvisioned(context.Context, string) (string, error)
	Provision(context.Context, ProvisionRequest) (string, error)
	Start(context.Context, string, StartRequest) error
	StartWithSetup(context.Context, string, SetupStartRequest) error
	StopAndWait(context.Context, string) error
	Stop(context.Context, string) error
	Delete(context.Context, string) error
	ApplyQuota(context.Context, string, core.Quota) error
}

type Store interface {
	Create(context.Context, core.Workspace) error
	Get(context.Context, string, string) (core.Workspace, error)
	Save(context.Context, core.Workspace) error
	FinalizeDelete(context.Context, string, string) error
	List(context.Context, string) ([]core.Workspace, error)
	TouchActivity(context.Context, string, string, time.Time) error
	TransitionIfInactive(context.Context, string, string, core.WorkspaceState, core.WorkspaceState, time.Time, time.Time) (bool, error)
	UpdateQuota(context.Context, string, string, core.Quota, time.Time) error
	UpdatePolicy(context.Context, string, string, core.RetentionPolicy, int, time.Time) error
	UpdateSafetyMode(context.Context, string, string, core.SafetyMode, time.Time) error
	Snapshot(context.Context, string) (admission.Snapshot, error)
}

// DeletionBoundary drains process-local authorities immediately before the
// durable workspace row is removed. The returned release function keeps the
// boundary closed through the database delete, so no terminal or preview can
// be recreated between cleanup and the cascading persistence finalization.
type DeletionBoundary interface {
	BeginWorkspaceDeleteFinalization(context.Context, core.Workspace) (release func(), err error)
}

// SuspensionBoundary drains every process-local authority after the durable
// workspace state has become suspending and before the provider is stopped.
// The returned release function keeps new terminal and preview creation
// serialized until the workspace is durably suspended.
type SuspensionBoundary interface {
	BeginWorkspaceSuspension(context.Context, core.Workspace) (release func(), err error)
}

type Checkpoint interface {
	Create(context.Context, string, string, string) (string, bool, bool, error)
	Latest(context.Context, string) (string, error)
}

// Initializer prepares the private repository checkout after the provider is
// running and before the workspace is exposed as ready. Implementations must
// be idempotent for a provider resource that has already been assigned.
type Initializer interface {
	Initialize(context.Context, core.Workspace) error
}

// EnvironmentPreparer is an optional initializer capability used to persist
// every creation-time private value before a workspace waits in a queue or for
// setup approval. A nil result is a durability boundary: all environment
// values and the initial prompt supplied on the Workspace must already be
// encrypted and committed before PrepareEnvironment returns.
type EnvironmentPreparer interface {
	PrepareEnvironment(context.Context, core.Workspace) error
}

type Service struct {
	store        Store
	repos        RepositorySource
	detector     EnvironmentDetector
	provider     Provider
	admission    *admission.Controller
	checkpoint   Checkpoint
	initializer  Initializer
	deletionMu   sync.RWMutex
	deletion     DeletionBoundary
	suspensionMu sync.RWMutex
	suspension   SuspensionBoundary
	mutationMu   sync.Mutex
	mutations    map[string]*workspaceMutationGate
	// admissionGate serializes the snapshot/decision/persistence boundary. The
	// supported deployment runs exactly one control-plane process; the
	// provisioning state persisted before this lock is released is the durable
	// reservation observed after a process restart.
	admissionGate chan struct{}
	// runtimeGate serializes provider starts, stops, deletes, and quota builds
	// across workspaces. It establishes one global provider mutation order, so
	// quota rebalance cannot restart a resource after stop confirmation and
	// cross-workspace per-ID locks can never deadlock while rebalancing.
	runtimeGate chan struct{}
	random      io.Reader
	now         func() time.Time
}

type workspaceMutationGate struct {
	token chan struct{}
	refs  int
}

const (
	failureProvisionUnconfirmed     = "provider_provision_unconfirmed"
	failureProvisionCleanupPending  = "provider_provision_cleanup_pending"
	failureProviderStartReserved    = "provider_start_reserved"
	failureStartCleanupPending      = "provider_start_cleanup_pending"
	failureInitializeCleanupPending = "workspace_initialize_cleanup_pending"
	failureSetupStopCleanupPending  = "provider_stop_before_setup_approval_cleanup_pending"
	failureProviderProvision        = "provider_provision_failed"
	failureProviderStart            = "provider_start_failed"
	failureWorkspaceInitialize      = "workspace_initialize_failed"
	failureStopBeforeSetupApproval  = "provider_stop_before_setup_approval_failed"
	failureCapacityRebalancePending = "capacity_rebalance_pending"
	failureEnvironmentPersistence   = "environment_persistence_failed"
	failurePrivateInputsRecreate    = "private_inputs_recreate_required"
)

func New(store Store, repos RepositorySource, detector EnvironmentDetector, provider Provider, controller *admission.Controller, checkpoint Checkpoint, initializers ...Initializer) (*Service, error) {
	if store == nil || repos == nil || detector == nil || provider == nil || controller == nil || checkpoint == nil {
		return nil, errors.New("workspace dependencies are required")
	}
	if len(initializers) > 1 {
		return nil, errors.New("at most one workspace initializer is allowed")
	}
	var initializer Initializer
	if len(initializers) == 1 {
		initializer = initializers[0]
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	runtimeGate := make(chan struct{}, 1)
	runtimeGate <- struct{}{}
	return &Service{
		store: store, repos: repos, detector: detector, provider: provider, admission: controller,
		checkpoint: checkpoint, initializer: initializer, admissionGate: gate, runtimeGate: runtimeGate,
		mutations: make(map[string]*workspaceMutationGate),
		random:    rand.Reader, now: func() time.Time { return time.Now().UTC() },
	}, nil
}

// ConfigureDeletionBoundary installs the process-local cleanup boundary once,
// before lifecycle workers or HTTP handlers can delete a workspace. Deletion
// fails closed until this dependency has been installed.
func (s *Service) ConfigureDeletionBoundary(boundary DeletionBoundary) error {
	if boundary == nil {
		return errors.New("workspace deletion boundary is required")
	}
	s.deletionMu.Lock()
	defer s.deletionMu.Unlock()
	if s.deletion != nil {
		return errors.New("workspace deletion boundary is already configured")
	}
	s.deletion = boundary
	return nil
}

// ConfigureSuspensionBoundary installs the process-local authority drain once,
// before lifecycle or maintenance workers can suspend a workspace. Suspension
// fails closed until this dependency has been installed.
func (s *Service) ConfigureSuspensionBoundary(boundary SuspensionBoundary) error {
	if boundary == nil {
		return errors.New("workspace suspension boundary is required")
	}
	s.suspensionMu.Lock()
	defer s.suspensionMu.Unlock()
	if s.suspension != nil {
		return errors.New("workspace suspension boundary is already configured")
	}
	s.suspension = boundary
	return nil
}

func (s *Service) Create(ctx context.Context, ownerID string, input core.CreateWorkspaceInput) (core.Workspace, error) {
	repo, err := s.repos.Get(ctx, ownerID, input.RepositoryID)
	if err != nil {
		return core.Workspace{}, err
	}
	input.ApplyDefaults(repo.DefaultBranch)
	if err := input.Validate(); err != nil {
		return core.Workspace{}, err
	}
	id, suffix, err := s.identifiers()
	if err != nil {
		return core.Workspace{}, err
	}
	now := s.now()
	ws := core.Workspace{
		ID: id, OwnerID: ownerID, Repository: repo, Name: strings.TrimSpace(input.Name),
		Branch: branchName(input.Name, suffix), BaseBranch: input.BaseBranch,
		State: core.WorkspaceQueued, SafetyMode: input.SafetyMode, Retention: input.Retention,
		NestedContainers: input.NestedContainers, CreatedAt: now, UpdatedAt: now, LastActivityAt: now,
		EnvironmentVariables: cloneEnvironment(input.EnvironmentVariables),
		InitialPrompt:        input.InitialPrompt, RequestedDiskGiB: input.RequestedDiskGiB,
		PrivateInputsPending: len(input.EnvironmentVariables) != 0 || input.InitialPrompt != "",
	}
	environment, err := s.detector.Detect(ctx, ownerID, repo, input.BaseBranch)
	if err != nil {
		return core.Workspace{}, fmt.Errorf("detect repository environment: %w", err)
	}
	if err := validateEnvironment(environment); err != nil {
		return core.Workspace{}, fmt.Errorf("detect repository environment: %w", err)
	}
	ws.DevcontainerDir = environment.ConfigDirectory
	ws.DevcontainerSupported = environment.HasDevcontainer && environment.Supported
	// Hold the per-workspace mutation gate across reservation and every
	// provider-side effect. Lifecycle recovery and maintenance can therefore
	// wait for an already-admitted create rather than racing a second create,
	// start, initializer, or stop against it.
	releaseMutation, err := s.acquireWorkspaceMutation(ctx, ownerID, ws.ID)
	if err != nil {
		return core.Workspace{}, err
	}
	defer releaseMutation()
	// Admission remains held continuously from the durable reservation through
	// private-input preparation and runtime-gate acquisition. Consequently only
	// one process-local reservation can own the next provider start, and a
	// maintenance drain cannot slip between reservation and provider mutation.
	if err := s.acquireAdmission(ctx); err != nil {
		return core.Workspace{}, err
	}
	defer s.releaseAdmission()
	ws, admitted, err := s.reserveNewStart(ctx, ws)
	if err != nil {
		return core.Workspace{}, err
	}
	ws, err = s.preparePrivateInputs(ctx, ws)
	if err != nil {
		return ws, err
	}
	if !admitted {
		return ws, nil
	}
	if err := s.acquireRuntime(ctx); err != nil {
		return ws, err
	}
	defer s.releaseRuntime()
	ws, err = s.store.Get(ctx, ownerID, ws.ID)
	if err != nil {
		return core.Workspace{}, err
	}
	return s.provision(ctx, ws)
}

func (s *Service) reserveNewStart(ctx context.Context, ws core.Workspace) (core.Workspace, bool, error) {
	snapshot, err := s.store.Snapshot(ctx, ws.OwnerID)
	if err != nil {
		return core.Workspace{}, false, err
	}
	decision := s.admission.PlanStart(snapshot)
	ws.Quota = quotaWithinRequest(decision.Quota, ws.RequestedDiskGiB)
	if decision.Admitted {
		ws.State = core.WorkspaceProvisioning
		ws.FailureCode = failureProviderStartReserved
	} else {
		ws.State = core.WorkspaceQueued
		ws.FailureCode = queueReason(decision.Reason)
	}
	if err := ctx.Err(); err != nil {
		return core.Workspace{}, false, err
	}
	if err := s.store.Create(ctx, ws); err != nil {
		return core.Workspace{}, false, err
	}
	return ws, decision.Admitted, nil
}

func (s *Service) prepareEnvironment(ctx context.Context, value core.Workspace) error {
	if preparer, ok := s.initializer.(EnvironmentPreparer); ok {
		return preparer.PrepareEnvironment(ctx, value)
	}
	if len(value.EnvironmentVariables) != 0 || value.InitialPrompt != "" {
		return errors.New("workspace private state persistence is not configured")
	}
	return nil
}

// preparePrivateInputs persists all creation-time private inputs before a
// queued or provisioning row can become promotable. The durable marker is
// cleared only after the preparer has completed both environment and prompt
// persistence. Any ambiguous or partial outcome is quarantined for explicit
// deletion and recreation; a later worker must never guess which inputs made
// it to storage.
func (s *Service) preparePrivateInputs(ctx context.Context, value core.Workspace) (core.Workspace, error) {
	if !value.PrivateInputsPending {
		clearWorkspacePrivateInputs(&value)
		return value, nil
	}
	prepareErr := s.prepareEnvironment(ctx, value)
	clearWorkspacePrivateInputs(&value)
	if prepareErr != nil {
		failed, saveErr := s.quarantinePrivateInputs(ctx, value)
		if saveErr != nil {
			return failed, saveErr
		}
		if errors.Is(prepareErr, context.Canceled) || errors.Is(prepareErr, context.DeadlineExceeded) {
			return failed, prepareErr
		}
		return failed, fmt.Errorf("%w: %s", core.ErrExternal, failurePrivateInputsRecreate)
	}

	ready := value
	ready.PrivateInputsPending = false
	ready.UpdatedAt = s.now()
	if err := s.store.Save(ctx, ready); err != nil {
		// Return the durable conservative view. A restart or scanner will see the
		// marker and quarantine it; provider work is deliberately not attempted.
		return value, fmt.Errorf("commit private workspace input preparation: %w", err)
	}
	return ready, nil
}

func clearWorkspacePrivateInputs(value *core.Workspace) {
	if value == nil {
		return
	}
	for name := range value.EnvironmentVariables {
		value.EnvironmentVariables[name] = ""
		delete(value.EnvironmentVariables, name)
	}
	value.EnvironmentVariables = nil
	value.InitialPrompt = ""
}

func privateInputsIncomplete(value core.Workspace) bool {
	return value.PrivateInputsPending || value.FailureCode == failureEnvironmentPersistence || value.FailureCode == failurePrivateInputsRecreate
}

func (s *Service) quarantinePrivateInputs(ctx context.Context, value core.Workspace) (core.Workspace, error) {
	clearWorkspacePrivateInputs(&value)
	if value.State == core.WorkspaceDeleting {
		// Deleting is a durable cleanup authority. It must remain counted and
		// lifecycle-retryable until provider absence and local finalization are
		// confirmed, even when the tombstone still carries the fail-closed marker.
		return value, fmt.Errorf("quarantine incomplete private workspace inputs: %w: workspace is deleting", core.ErrConflict)
	}
	if value.State == core.WorkspaceFailed && value.FailureCode == failurePrivateInputsRecreate {
		return value, fmt.Errorf("%w: workspace private inputs require recreation", core.ErrPrecondition)
	}
	value.State = core.WorkspaceFailed
	value.SuspendedAt = nil
	value.FailureCode = failurePrivateInputsRecreate
	value.UpdatedAt = s.now()
	if err := s.store.Save(ctx, value); err != nil {
		return value, fmt.Errorf("quarantine incomplete private workspace inputs: %w", err)
	}
	return value, nil
}

func cloneEnvironment(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]string, len(source))
	for name, value := range source {
		result[name] = value
	}
	return result
}

func validateEnvironment(value Environment) error {
	if !value.HasDevcontainer {
		if value.ConfigDirectory != "" {
			return fmt.Errorf("%w: Dev Container directory without configuration", core.ErrInvalid)
		}
		return nil
	}
	if !value.RequiresTrust || (value.ConfigDirectory != "." && value.ConfigDirectory != ".devcontainer") {
		return fmt.Errorf("%w: unsafe Dev Container detection", core.ErrInvalid)
	}
	return nil
}

func (s *Service) ApproveSetup(ctx context.Context, ownerID, workspaceID string) (core.Workspace, error) {
	release, err := s.acquireWorkspaceMutation(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	defer release()
	current, err := s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	if current.SetupApproved {
		return current, nil
	}
	if err := s.acquireAdmission(ctx); err != nil {
		return core.Workspace{}, err
	}
	defer s.releaseAdmission()

	ws, admitted, err := s.reserveExistingStart(ctx, ownerID, workspaceID, func(value *core.Workspace) error {
		if value.State != core.WorkspaceAwaitingSetupApproval {
			return fmt.Errorf("%w: workspace is not awaiting setup approval", core.ErrConflict)
		}
		if value.DevcontainerDir == "" {
			return fmt.Errorf("%w: approved setup configuration is unavailable", core.ErrPrecondition)
		}
		value.SetupApproved = true
		return nil
	})
	if err != nil || !admitted {
		return ws, err
	}
	if err := s.acquireRuntime(ctx); err != nil {
		return ws, err
	}
	defer s.releaseRuntime()
	ws, err = s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	return s.provision(ctx, ws)
}

// DenySetup persists the stopped trust decision under the same mutation gate
// used by approval, retry, and deletion. It cannot overwrite a deletion
// tombstone or race an approval into restarting repository-controlled setup.
func (s *Service) DenySetup(ctx context.Context, ownerID, workspaceID string) (core.Workspace, error) {
	release, err := s.acquireWorkspaceMutation(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	defer release()
	value, err := s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	if value.State == core.WorkspaceFailed && value.FailureCode == "setup_approval_denied" {
		return value, nil
	}
	if value.State != core.WorkspaceAwaitingSetupApproval || value.SetupApproved {
		return core.Workspace{}, fmt.Errorf("deny workspace setup: %w", core.ErrConflict)
	}
	value.State = core.WorkspaceFailed
	value.FailureCode = "setup_approval_denied"
	value.UpdatedAt = s.now()
	if err := s.store.Save(ctx, value); err != nil {
		return core.Workspace{}, err
	}
	return value, nil
}

func (s *Service) Retry(ctx context.Context, ownerID, workspaceID string) (core.Workspace, error) {
	release, err := s.acquireWorkspaceMutation(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	defer release()

	current, err := s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	if current.State == core.WorkspaceDeleting {
		return current, fmt.Errorf("%w: workspace is deleting", core.ErrConflict)
	}
	if privateInputsIncomplete(current) {
		failed, quarantineErr := s.quarantinePrivateInputs(ctx, current)
		if quarantineErr != nil {
			return failed, quarantineErr
		}
		return failed, fmt.Errorf("%w: workspace private inputs require recreation", core.ErrPrecondition)
	}
	if current.State == core.WorkspaceProvisioning {
		releaseStart, boundaryErr := s.acquireStartBoundary(ctx)
		if boundaryErr != nil {
			return current, boundaryErr
		}
		defer releaseStart()
		current, err = s.store.Get(ctx, ownerID, workspaceID)
		if err != nil {
			return core.Workspace{}, err
		}
		return s.reconcileProvisioning(ctx, current)
	}
	if err := s.acquireAdmission(ctx); err != nil {
		return core.Workspace{}, err
	}
	defer s.releaseAdmission()

	ws, admitted, err := s.reserveExistingStart(ctx, ownerID, workspaceID, func(value *core.Workspace) error {
		if value.State != core.WorkspaceFailed && value.State != core.WorkspaceQueued {
			return fmt.Errorf("%w: workspace cannot be retried", core.ErrConflict)
		}
		if value.FailureCode == "devcontainer_secure_recreate_required" {
			return fmt.Errorf("%w: legacy Dev Container workspace must be recreated", core.ErrPrecondition)
		}
		if privateInputsIncomplete(*value) {
			return fmt.Errorf("%w: workspace private inputs require recreation", core.ErrPrecondition)
		}
		return nil
	})
	if err != nil || !admitted {
		return ws, err
	}
	if err := s.acquireRuntime(ctx); err != nil {
		return ws, err
	}
	defer s.releaseRuntime()
	ws, err = s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	return s.provision(ctx, ws)
}

func (s *Service) reserveExistingStart(ctx context.Context, ownerID, workspaceID string, validate func(*core.Workspace) error) (core.Workspace, bool, error) {
	ws, err := s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, false, err
	}
	if privateInputsIncomplete(ws) {
		failed, quarantineErr := s.quarantinePrivateInputs(ctx, ws)
		if quarantineErr != nil {
			return failed, false, quarantineErr
		}
		return failed, false, fmt.Errorf("%w: workspace private inputs require recreation", core.ErrPrecondition)
	}
	if err := validate(&ws); err != nil {
		return core.Workspace{}, false, err
	}
	snapshot, err := s.store.Snapshot(ctx, ownerID)
	if err != nil {
		return core.Workspace{}, false, err
	}
	decision := s.admission.PlanStart(snapshot)
	ws.Quota = quotaWithinRequest(decision.Quota, ws.RequestedDiskGiB)
	ws.UpdatedAt = s.now()
	ws.LastActivityAt = ws.UpdatedAt
	ws.SuspendedAt = nil
	if decision.Admitted {
		ws.State = core.WorkspaceProvisioning
		ws.FailureCode = failureProviderStartReserved
	} else {
		ws.State = core.WorkspaceQueued
		ws.FailureCode = queueReason(decision.Reason)
	}
	if err := ctx.Err(); err != nil {
		return core.Workspace{}, false, err
	}
	if err := s.store.Save(ctx, ws); err != nil {
		return core.Workspace{}, false, err
	}
	return ws, decision.Admitted, nil
}

func (s *Service) acquireAdmission(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.admissionGate:
		return nil
	}
}

func (s *Service) releaseAdmission() {
	s.admissionGate <- struct{}{}
}

func (s *Service) acquireRuntime(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.runtimeGate:
		return nil
	}
}

func (s *Service) releaseRuntime() {
	s.runtimeGate <- struct{}{}
}

func (s *Service) acquireStartBoundary(ctx context.Context) (func(), error) {
	if err := s.acquireAdmission(ctx); err != nil {
		return nil, err
	}
	if err := s.acquireRuntime(ctx); err != nil {
		s.releaseAdmission()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.releaseRuntime()
			s.releaseAdmission()
		})
	}, nil
}

// BeginMaintenanceDrain closes the admission snapshot boundary after the
// caller has enabled the controller's maintenance drain. Crossing runtimeGate
// waits for every provider mutation admitted before the drain. The returned
// release keeps new reservations out until maintenance has taken its first
// durable workspace snapshot; retries remain closed by the controller flag.
func (s *Service) BeginMaintenanceDrain(ctx context.Context) (func(), error) {
	if err := s.acquireAdmission(ctx); err != nil {
		return nil, err
	}
	if err := s.acquireRuntime(ctx); err != nil {
		s.releaseAdmission()
		return nil, err
	}
	s.releaseRuntime()
	var once sync.Once
	return func() { once.Do(s.releaseAdmission) }, nil
}

// ReconcileMaintenanceDrain stops a provider-bearing transitional workspace
// that the ordinary Suspend contract cannot safely claim. Provisioning is
// failed closed only after deterministic absence or StopAndWait confirmation;
// maintenance state converges to suspended. Any ambiguous provider result
// leaves the original capacity-counted state durable for the next scan.
func (s *Service) ReconcileMaintenanceDrain(ctx context.Context, ownerID, workspaceID string) (core.Workspace, error) {
	releaseMutation, err := s.acquireWorkspaceMutation(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	defer releaseMutation()
	if err := s.acquireRuntime(ctx); err != nil {
		return core.Workspace{}, err
	}
	defer s.releaseRuntime()

	value, err := s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	if privateInputsIncomplete(value) {
		failed, quarantineErr := s.quarantinePrivateInputs(ctx, value)
		if quarantineErr != nil {
			return failed, quarantineErr
		}
		return failed, nil
	}
	if value.State != core.WorkspaceProvisioning && value.State != core.WorkspaceMaintenance {
		return value, nil
	}
	if value.ProviderResourceID == "" {
		providerID, lookupErr := s.provider.LookupProvisioned(ctx, value.ID)
		switch {
		case lookupErr == nil:
			value.ProviderResourceID = providerID
			value.UpdatedAt = s.now()
			if err := s.store.Save(ctx, value); err != nil {
				return core.Workspace{}, err
			}
		case errors.Is(lookupErr, core.ErrNotFound):
			return s.persistMaintenanceDrainResult(ctx, value)
		default:
			return value, fmt.Errorf("resolve provider during maintenance drain: %w", lookupErr)
		}
	}

	s.suspensionMu.RLock()
	boundary := s.suspension
	s.suspensionMu.RUnlock()
	if boundary == nil {
		return value, errors.New("workspace suspension boundary is not configured")
	}
	boundaryValue := value
	boundaryValue.State = core.WorkspaceSuspending
	releaseBoundary, err := boundary.BeginWorkspaceSuspension(ctx, boundaryValue)
	if err != nil {
		return value, err
	}
	if releaseBoundary == nil {
		return value, errors.New("workspace suspension boundary returned no release function")
	}
	defer releaseBoundary()
	if err := s.provider.StopAndWait(ctx, value.ProviderResourceID); err != nil {
		return value, fmt.Errorf("confirm maintenance provider stop: %w", err)
	}
	return s.persistMaintenanceDrainResult(ctx, value)
}

func (s *Service) persistMaintenanceDrainResult(ctx context.Context, value core.Workspace) (core.Workspace, error) {
	value.UpdatedAt = s.now()
	value.SuspendedAt = nil
	if value.State == core.WorkspaceProvisioning {
		value.State = core.WorkspaceFailed
		value.FailureCode = "maintenance_interrupted_provisioning"
	} else {
		value.State = core.WorkspaceSuspended
		value.FailureCode = ""
		value.SuspendedAt = &value.UpdatedAt
	}
	if err := s.store.Save(ctx, value); err != nil {
		return core.Workspace{}, err
	}
	_ = s.rebalance(ctx, value.OwnerID)
	return value, nil
}

// acquireWorkspaceMutation serializes provider lifecycle calls for one
// owner/workspace pair. Entries are reference-counted and removed when the
// last holder or waiter leaves, so hostile identifiers cannot grow a
// process-lifetime lock map.
func (s *Service) acquireWorkspaceMutation(ctx context.Context, ownerID, workspaceID string) (func(), error) {
	if ctx == nil || ownerID == "" || workspaceID == "" {
		return nil, fmt.Errorf("workspace mutation: %w", core.ErrInvalid)
	}
	key := fmt.Sprintf("%d:%s:%s", len(ownerID), ownerID, workspaceID)
	s.mutationMu.Lock()
	gate := s.mutations[key]
	if gate == nil {
		gate = &workspaceMutationGate{token: make(chan struct{}, 1)}
		gate.token <- struct{}{}
		s.mutations[key] = gate
	}
	gate.refs++
	s.mutationMu.Unlock()

	select {
	case <-ctx.Done():
		s.mutationMu.Lock()
		gate.refs--
		if gate.refs == 0 && s.mutations[key] == gate {
			delete(s.mutations, key)
		}
		s.mutationMu.Unlock()
		return nil, ctx.Err()
	case <-gate.token:
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			s.mutationMu.Lock()
			gate.refs--
			gate.token <- struct{}{}
			if gate.refs == 0 && s.mutations[key] == gate {
				delete(s.mutations, key)
			}
			s.mutationMu.Unlock()
		})
	}, nil
}

// TouchActivity is the single keep-alive path for native and terminal
// activity. The store performs a narrow update so a delayed event cannot
// overwrite a lifecycle transition.
func (s *Service) TouchActivity(ctx context.Context, ownerID, workspaceID string, at time.Time) (core.Workspace, error) {
	if at.IsZero() {
		at = s.now()
	}
	if err := s.store.TouchActivity(ctx, ownerID, workspaceID, at.UTC()); err != nil {
		return core.Workspace{}, err
	}
	return s.store.Get(ctx, ownerID, workspaceID)
}

// MarkIdleIfInactive uses the persisted activity timestamp as a compare-and-
// swap guard. It is safe to race terminal output or a native keep-alive.
func (s *Service) MarkIdleIfInactive(ctx context.Context, ownerID, workspaceID string, expectedLastActivity time.Time) (bool, error) {
	return s.store.TransitionIfInactive(ctx, ownerID, workspaceID, core.WorkspaceRunning, core.WorkspaceIdle, expectedLastActivity, s.now())
}

// SuspendIfInactive checkpoints before claiming the idle workspace and then
// revalidates inactivity atomically. No provider stop is issued if activity
// arrived while the checkpoint was being created.
func (s *Service) SuspendIfInactive(ctx context.Context, ownerID, workspaceID string, expectedLastActivity time.Time) (core.Workspace, bool, error) {
	release, err := s.acquireWorkspaceMutation(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, false, err
	}
	defer release()
	if err := s.acquireRuntime(ctx); err != nil {
		return core.Workspace{}, false, err
	}
	defer s.releaseRuntime()

	ws, err := s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, false, err
	}
	// A cleanup, provider-stop, or final persistence failure deliberately leaves
	// the durable authority in suspending. Lifecycle scans retry this idempotent
	// completion path without repeating the checkpoint or inactivity claim.
	if ws.State == core.WorkspaceSuspending {
		value, suspendErr := s.completeSuspension(ctx, ws)
		return value, true, suspendErr
	}
	if ws.State != core.WorkspaceIdle || !ws.LastActivityAt.Equal(expectedLastActivity) {
		return ws, false, nil
	}
	_, _, _, err = s.checkpoint.Create(ctx, ws.ID, ws.ProviderResourceID, "before-idle-suspend")
	if err != nil {
		return core.Workspace{}, false, fmt.Errorf("checkpoint before idle suspend: %w", err)
	}
	claimed, err := s.store.TransitionIfInactive(ctx, ownerID, workspaceID, core.WorkspaceIdle, core.WorkspaceSuspending, expectedLastActivity, s.now())
	if err != nil || !claimed {
		return ws, false, err
	}
	ws, err = s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, false, err
	}
	value, suspendErr := s.completeSuspension(ctx, ws)
	return value, true, suspendErr
}

func (s *Service) UpdatePolicy(ctx context.Context, ownerID, workspaceID string, retention core.RetentionPolicy, idleTimeoutMinutes int) (core.Workspace, error) {
	if !retention.Valid() || (idleTimeoutMinutes != 0 && (idleTimeoutMinutes < 5 || idleTimeoutMinutes > 10080)) {
		return core.Workspace{}, fmt.Errorf("workspace policy: %w", core.ErrInvalid)
	}
	if err := s.store.UpdatePolicy(ctx, ownerID, workspaceID, retention, idleTimeoutMinutes, s.now()); err != nil {
		return core.Workspace{}, err
	}
	return s.store.Get(ctx, ownerID, workspaceID)
}

// UpdateSafetyMode accepts changes only at the stopped, suspended boundary.
// The admission gate serializes this write with Resume, ensuring a start can
// never observe an older mode and overwrite the newly selected policy. On the
// next resume the provider applies network egress before the initializer
// rewrites the managed Codex configuration and the workspace becomes running.
func (s *Service) UpdateSafetyMode(ctx context.Context, ownerID, workspaceID string, mode core.SafetyMode) (core.Workspace, error) {
	if !mode.Valid() {
		return core.Workspace{}, fmt.Errorf("workspace safety mode: %w", core.ErrInvalid)
	}
	if err := s.acquireAdmission(ctx); err != nil {
		return core.Workspace{}, err
	}
	defer s.releaseAdmission()

	value, err := s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	if value.State != core.WorkspaceSuspended {
		return core.Workspace{}, fmt.Errorf("%w: workspace must be suspended before changing autonomy", core.ErrConflict)
	}
	if value.SafetyMode == mode {
		return value, nil
	}
	if err := s.store.UpdateSafetyMode(ctx, ownerID, workspaceID, mode, s.now()); err != nil {
		return core.Workspace{}, err
	}
	return s.store.Get(ctx, ownerID, workspaceID)
}

func (s *Service) Suspend(ctx context.Context, ownerID, workspaceID string) (core.Workspace, error) {
	release, err := s.acquireWorkspaceMutation(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	defer release()
	if err := s.acquireRuntime(ctx); err != nil {
		return core.Workspace{}, err
	}
	defer s.releaseRuntime()

	ws, err := s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	if ws.State == core.WorkspaceSuspending {
		return s.completeSuspension(ctx, ws)
	}
	if !ws.State.CanTransition(core.WorkspaceSuspending) {
		return core.Workspace{}, fmt.Errorf("%w: workspace cannot suspend from %s", core.ErrConflict, ws.State)
	}
	_, dirty, unpushed, err := s.checkpoint.Create(ctx, ws.ID, ws.ProviderResourceID, "before-suspend")
	if err != nil {
		return core.Workspace{}, fmt.Errorf("checkpoint before suspend: %w", err)
	}
	// The helper's live Git inspection is authoritative here. This prevents a
	// terminal-side edit made after the last native status refresh from skipping
	// the recovery boundary.
	ws.Dirty, ws.Unpushed = dirty, unpushed
	ws.State = core.WorkspaceSuspending
	ws.SuspendedAt = nil
	ws.UpdatedAt = s.now()
	if err := s.store.Save(ctx, ws); err != nil {
		return core.Workspace{}, err
	}
	return s.completeSuspension(ctx, ws)
}

func (s *Service) completeSuspension(ctx context.Context, ws core.Workspace) (core.Workspace, error) {
	if ws.State != core.WorkspaceSuspending {
		return core.Workspace{}, fmt.Errorf("%w: workspace is not suspending", core.ErrConflict)
	}
	s.suspensionMu.RLock()
	boundary := s.suspension
	s.suspensionMu.RUnlock()
	if boundary == nil {
		return core.Workspace{}, errors.New("workspace suspension boundary is not configured")
	}
	release, err := boundary.BeginWorkspaceSuspension(ctx, ws)
	if err != nil {
		return core.Workspace{}, err
	}
	if release == nil {
		return core.Workspace{}, errors.New("workspace suspension boundary returned no release function")
	}
	defer release()

	if err := s.provider.StopAndWait(ctx, ws.ProviderResourceID); err != nil {
		// Stop failures are ambiguous: the provider may still be stopping or may
		// already be stopped even though confirmation failed. Keep the durable
		// suspending authority closed and let lifecycle/manual retry the
		// idempotent drain-and-confirm path.
		return core.Workspace{}, fmt.Errorf("stop workspace provider: %w", err)
	}
	ws.State = core.WorkspaceSuspended
	ws.UpdatedAt = s.now()
	ws.SuspendedAt = &ws.UpdatedAt
	if err := s.store.Save(ctx, ws); err != nil {
		return core.Workspace{}, err
	}
	_ = s.rebalance(ctx, ws.OwnerID)
	return ws, nil
}

func (s *Service) Resume(ctx context.Context, ownerID, workspaceID string) (core.Workspace, error) {
	release, err := s.acquireWorkspaceMutation(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	defer release()
	if err := s.acquireAdmission(ctx); err != nil {
		return core.Workspace{}, err
	}
	defer s.releaseAdmission()

	ws, admitted, err := s.reserveExistingStart(ctx, ownerID, workspaceID, func(value *core.Workspace) error {
		if value.State != core.WorkspaceSuspended {
			return fmt.Errorf("%w: workspace is not suspended", core.ErrConflict)
		}
		return nil
	})
	if err != nil || !admitted {
		return ws, err
	}
	if err := s.acquireRuntime(ctx); err != nil {
		return ws, err
	}
	defer s.releaseRuntime()
	ws, err = s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	if ws, err = s.prepareCapacityForStart(ctx, ws); err != nil {
		// Retain the durable proof that no provider start crossed this
		// reservation. The returned error carries the capacity diagnosis; changing
		// the marker would make an older crash-era row indistinguishable from a
		// provider that may already be live.
		ws.UpdatedAt = s.now()
		_ = s.store.Save(ctx, ws)
		return ws, fmt.Errorf("%w: %s: %v", core.ErrExternal, failureCapacityRebalancePending, err)
	}
	ws, err = s.markProviderStartPending(ctx, ws)
	if err != nil {
		return core.Workspace{}, err
	}
	if err := s.startProvider(ctx, ws); err != nil {
		return s.cleanupFailedRuntime(ctx, ws, failureStartCleanupPending, failureProviderStart, err)
	}
	// The trusted Codex credential key exists only on container tmpfs. Re-run
	// the idempotent initializer after every provider start so a resumed
	// workspace receives the key through the fixed helper channel before any
	// terminal can launch Codex.
	if s.initializer != nil {
		if err := s.initializer.Initialize(ctx, ws); err != nil {
			return s.cleanupFailedRuntime(ctx, ws, failureInitializeCleanupPending, failureWorkspaceInitialize, err)
		}
	}
	ws.State = core.WorkspaceRunning
	ws.FailureCode = ""
	ws.UpdatedAt = s.now()
	if err := s.store.Save(ctx, ws); err != nil {
		return core.Workspace{}, err
	}
	// Running is already committed and reachable. A quota repair failure must
	// not make the caller retry the logical start; lifecycle reconciliation is
	// level-triggered and will converge the conservative durable allocation.
	_ = s.rebalance(ctx, ownerID)
	return ws, nil
}

func (s *Service) Delete(ctx context.Context, ownerID, workspaceID string, automatic, confirmed bool) error {
	releaseMutation, err := s.acquireWorkspaceMutation(ctx, ownerID, workspaceID)
	if err != nil {
		return err
	}
	defer releaseMutation()
	if err := s.acquireRuntime(ctx); err != nil {
		return err
	}
	defer s.releaseRuntime()

	s.deletionMu.RLock()
	deletion := s.deletion
	s.deletionMu.RUnlock()
	if deletion == nil {
		return errors.New("workspace deletion boundary is not configured")
	}

	ws, err := s.store.Get(ctx, ownerID, workspaceID)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil
		}
		return err
	}
	retrying := ws.State == core.WorkspaceDeleting
	if !retrying {
		if automatic && ws.State != core.WorkspaceSuspended {
			return fmt.Errorf("%w: only a suspended workspace can be auto-deleted", core.ErrPrecondition)
		}
		if automatic && !ws.MayAutoDelete() {
			return fmt.Errorf("%w: dirty, unpushed, or keep-forever workspace cannot be auto-deleted", core.ErrPrecondition)
		}
		if !automatic && !confirmed {
			return fmt.Errorf("%w: explicit delete confirmation required", core.ErrPrecondition)
		}
		if !automatic {
			if checkpointLiveState(ws.State) {
				_, dirty, unpushed, err := s.checkpoint.Create(ctx, ws.ID, ws.ProviderResourceID, "before-delete")
				if err != nil {
					return fmt.Errorf("checkpoint before delete: %w", err)
				}
				ws.Dirty, ws.Unpushed = dirty, unpushed
			} else if ws.Dirty || ws.Unpushed {
				// A suspended workspace cannot be inspected without starting it. Its
				// filesystem is immutable while stopped, so require the checkpoint made
				// synchronously before suspension rather than silently deleting legacy
				// or otherwise unprotected work.
				if _, err := s.checkpoint.Latest(ctx, ws.ID); err != nil {
					return fmt.Errorf("checkpoint before delete: %w", err)
				}
			}
		}
		ws.State = core.WorkspaceDeleting
		ws.SuspendedAt = nil
		ws.UpdatedAt = s.now()
		if err := s.store.Save(ctx, ws); err != nil {
			return err
		}
	}
	if ws.ProviderResourceID == "" {
		// A provisioning create may have committed at Coder while its response
		// was lost before the provider ID reached persistence. Resolve the stable
		// logical name before finalization so delete can never orphan that runtime.
		providerID, lookupErr := s.provider.LookupProvisioned(ctx, ws.ID)
		switch {
		case lookupErr == nil:
			ws.ProviderResourceID = providerID
			ws.UpdatedAt = s.now()
			if err := s.store.Save(ctx, ws); err != nil {
				return err
			}
		case errors.Is(lookupErr, core.ErrNotFound):
			// Confirmed provider absence permits local finalization.
		default:
			return fmt.Errorf("resolve provider before workspace deletion: %w", lookupErr)
		}
	}
	if ws.ProviderResourceID != "" {
		if err := s.provider.Delete(ctx, ws.ProviderResourceID); err != nil {
			return err
		}
	}
	releaseFinalization, err := deletion.BeginWorkspaceDeleteFinalization(ctx, ws)
	if err != nil {
		return err
	}
	if releaseFinalization == nil {
		return errors.New("workspace deletion boundary returned no release function")
	}
	defer releaseFinalization()
	if err := s.store.FinalizeDelete(ctx, ownerID, workspaceID); err != nil && !errors.Is(err, core.ErrNotFound) {
		return err
	}
	// The workspace no longer consumes provider capacity. Expand the remaining
	// stable runtimes immediately when possible, but never turn an already
	// completed deletion into an API failure. Lifecycle reconciliation retries
	// this idempotent operation after transient provider or store failures.
	_ = s.rebalance(ctx, ownerID)
	return nil
}

func checkpointLiveState(state core.WorkspaceState) bool {
	switch state {
	case core.WorkspaceReady, core.WorkspaceRunning, core.WorkspaceNeedsAttention, core.WorkspaceIdle:
		return true
	default:
		return false
	}
}

func (s *Service) provision(ctx context.Context, ws core.Workspace) (core.Workspace, error) {
	if privateInputsIncomplete(ws) {
		failed, err := s.quarantinePrivateInputs(ctx, ws)
		if err != nil {
			return failed, err
		}
		return failed, fmt.Errorf("%w: workspace private inputs require recreation", core.ErrPrecondition)
	}
	var err error
	if ws, err = s.prepareCapacityForStart(ctx, ws); err != nil {
		// Preserve provider_start_reserved. It is the durable proof that this
		// reservation did not cross a provider call; capacity_rebalance_pending
		// from older releases cannot carry that proof because an ambiguous
		// Provision retry could overwrite it.
		ws.State = core.WorkspaceProvisioning
		ws.UpdatedAt = s.now()
		_ = s.store.Save(ctx, ws)
		return ws, fmt.Errorf("%w: %s: %v", core.ErrExternal, failureCapacityRebalancePending, err)
	}
	if ws.ProviderResourceID == "" {
		// Flip the durable proof marker before the first provider call. A crash or
		// response loss after this Save is capacity-ambiguous until deterministic
		// lookup proves absence or cleanup confirms a stop.
		ws.FailureCode = failureProvisionUnconfirmed
		ws.UpdatedAt = s.now()
		if err := s.store.Save(ctx, ws); err != nil {
			return core.Workspace{}, err
		}
		providerID, err := s.provider.Provision(ctx, ProvisionRequest{
			WorkspaceID: ws.ID, Repository: ws.Repository, Branch: ws.Branch, BaseBranch: ws.BaseBranch,
			WorktreeName: ws.ID, Quota: ws.Quota, SafetyMode: ws.SafetyMode,
			NestedContainers: ws.NestedContainers, DevcontainerDir: ws.DevcontainerDir,
		})
		if err != nil {
			// The pre-call marker already records this ambiguity even if the
			// provider response and a subsequent persistence attempt are both lost.
			return ws, fmt.Errorf("%w: %s: %v", core.ErrExternal, failureProvisionUnconfirmed, err)
		}
		ws.ProviderResourceID = providerID
		// Provision may have launched an initial build. Persist a cleanup marker
		// with the recovered ID before proceeding toward the explicit start.
		ws.FailureCode = failureStartCleanupPending
		ws.UpdatedAt = s.now()
		if err := s.store.Save(ctx, ws); err != nil {
			return core.Workspace{}, err
		}
	} else {
		ws, err = s.markProviderStartPending(ctx, ws)
		if err != nil {
			return core.Workspace{}, err
		}
	}
	if err := s.startProvider(ctx, ws); err != nil {
		return s.cleanupFailedRuntime(ctx, ws, failureStartCleanupPending, failureProviderStart, err)
	}
	if s.initializer != nil {
		if err := s.initializer.Initialize(ctx, ws); err != nil {
			return s.cleanupFailedRuntime(ctx, ws, failureInitializeCleanupPending, failureWorkspaceInitialize, err)
		}
	}
	if ws.DevcontainerDir != "" && !ws.SetupApproved {
		// The repository now exists on its persistent private volume, but no
		// repository-controlled setup has run. Stop the plain container before
		// exposing the structured approval so a denial leaves no live runtime.
		if err := s.provider.StopAndWait(ctx, ws.ProviderResourceID); err != nil {
			ws.State = core.WorkspaceProvisioning
			ws.FailureCode = failureSetupStopCleanupPending
			ws.UpdatedAt = s.now()
			_ = s.store.Save(ctx, ws)
			return ws, fmt.Errorf("%w: %s: %v", core.ErrExternal, failureStopBeforeSetupApproval, err)
		}
		ws.State = core.WorkspaceAwaitingSetupApproval
		ws.FailureCode = ""
		if !ws.DevcontainerSupported {
			ws.FailureCode = "devcontainer_unsupported_safe_fallback_available"
		}
		ws.UpdatedAt = s.now()
		if err := s.store.Save(ctx, ws); err != nil {
			return core.Workspace{}, err
		}
		// The provider stop and approval state are already durable. Do not report
		// this successful trust-boundary transition as failed solely because a
		// surviving peer's quota repair needs a lifecycle retry.
		_ = s.rebalance(ctx, ws.OwnerID)
		return ws, nil
	}
	ws.State = core.WorkspaceRunning
	ws.FailureCode = ""
	ws.UpdatedAt = s.now()
	ws.LastActivityAt = ws.UpdatedAt
	ws.SuspendedAt = nil
	if err := s.store.Save(ctx, ws); err != nil {
		return core.Workspace{}, err
	}
	_ = s.rebalance(ctx, ws.OwnerID)
	return ws, nil
}

// reconcileProvisioning resumes each durable provisioning crash point. It is
// called by manual retry and the lifecycle scanner while the reservation still
// consumes capacity.
func (s *Service) reconcileProvisioning(ctx context.Context, ws core.Workspace) (core.Workspace, error) {
	switch ws.FailureCode {
	case failureProvisionUnconfirmed:
		return s.reconcileAmbiguousProvision(ctx, ws)
	case failureProvisionCleanupPending:
		return s.finishFailedRuntimeCleanup(ctx, ws, failureProviderProvision)
	case failureStartCleanupPending:
		return s.finishFailedRuntimeCleanup(ctx, ws, failureProviderStart)
	case failureInitializeCleanupPending:
		return s.finishFailedRuntimeCleanup(ctx, ws, failureWorkspaceInitialize)
	case failureSetupStopCleanupPending:
		if err := s.provider.StopAndWait(ctx, ws.ProviderResourceID); err != nil {
			return ws, fmt.Errorf("confirm provider stop before setup approval: %w", err)
		}
		ws.State = core.WorkspaceAwaitingSetupApproval
		ws.FailureCode = ""
		if !ws.DevcontainerSupported {
			ws.FailureCode = "devcontainer_unsupported_safe_fallback_available"
		}
		ws.UpdatedAt = s.now()
		if err := s.store.Save(ctx, ws); err != nil {
			return core.Workspace{}, err
		}
		_ = s.rebalance(ctx, ws.OwnerID)
		return ws, nil
	case failureProviderStartReserved:
		return s.provision(ctx, ws)
	case failureCapacityRebalancePending:
		// Older releases could overwrite an ambiguous create marker with this
		// code. Re-establish provider absence/stop before treating it as a fresh
		// reservation.
		return s.reconcileLegacyProvisioning(ctx, ws)
	case "":
		// Empty was the historical provisioning phase, including the crash window
		// after Coder create success and before provider-ID persistence.
		return s.reconcileLegacyProvisioning(ctx, ws)
	default:
		return ws, fmt.Errorf("reconcile unknown provisioning phase %q: %w", ws.FailureCode, core.ErrPrecondition)
	}
}

func (s *Service) reconcileLegacyProvisioning(ctx context.Context, ws core.Workspace) (core.Workspace, error) {
	if ws.ProviderResourceID == "" {
		return s.reconcileAmbiguousProvision(ctx, ws)
	}
	ws.FailureCode = failureStartCleanupPending
	ws.UpdatedAt = s.now()
	if err := s.store.Save(ctx, ws); err != nil {
		return core.Workspace{}, err
	}
	return s.finishFailedRuntimeCleanup(ctx, ws, failureProviderStart)
}

func (s *Service) reconcileAmbiguousProvision(ctx context.Context, ws core.Workspace) (core.Workspace, error) {
	if ws.ProviderResourceID != "" {
		ws.FailureCode = failureProvisionCleanupPending
		ws.UpdatedAt = s.now()
		if err := s.store.Save(ctx, ws); err != nil {
			return core.Workspace{}, err
		}
		return s.finishFailedRuntimeCleanup(ctx, ws, failureProviderProvision)
	}
	providerID, err := s.provider.LookupProvisioned(ctx, ws.ID)
	switch {
	case err == nil:
		ws.ProviderResourceID = providerID
		ws.FailureCode = failureProvisionCleanupPending
		ws.UpdatedAt = s.now()
		if err := s.store.Save(ctx, ws); err != nil {
			return core.Workspace{}, err
		}
		return s.finishFailedRuntimeCleanup(ctx, ws, failureProviderProvision)
	case errors.Is(err, core.ErrNotFound):
		// Absence was proved while runtimeGate excludes every local provider
		// start. Persist a fresh proof marker and defer actual provisioning to the
		// next retry. This lets a scanner normalize several legacy empty-ID rows
		// in one pass without any row blocking another forever.
		ws.FailureCode = failureProviderStartReserved
		ws.UpdatedAt = s.now()
		if err := s.store.Save(ctx, ws); err != nil {
			return core.Workspace{}, err
		}
		return ws, nil
	default:
		return ws, fmt.Errorf("resolve ambiguous provider provisioning: %w", err)
	}
}

func (s *Service) cleanupFailedRuntime(ctx context.Context, ws core.Workspace, pendingCode, finalCode string, cause error) (core.Workspace, error) {
	ws.State = core.WorkspaceProvisioning
	ws.FailureCode = pendingCode
	ws.SuspendedAt = nil
	ws.UpdatedAt = s.now()
	if err := s.store.Save(ctx, ws); err != nil {
		return core.Workspace{}, errors.Join(fmt.Errorf("%w: %s: %v", core.ErrExternal, finalCode, cause), err)
	}
	if err := s.provider.StopAndWait(ctx, ws.ProviderResourceID); err != nil {
		return ws, fmt.Errorf("%w: %s: %v (cleanup unconfirmed: %v)", core.ErrExternal, finalCode, cause, err)
	}
	ws.State = core.WorkspaceFailed
	ws.FailureCode = finalCode
	ws.UpdatedAt = s.now()
	if err := s.store.Save(ctx, ws); err != nil {
		return core.Workspace{}, errors.Join(fmt.Errorf("%w: %s: %v", core.ErrExternal, finalCode, cause), err)
	}
	// The failed N+1 runtime is now durably stopped and no longer contributes
	// to the fair share. Restore surviving peers without hiding the original
	// start/initialization failure if the best-effort rebalance also fails.
	_ = s.rebalance(ctx, ws.OwnerID)
	return ws, fmt.Errorf("%w: %s: %v", core.ErrExternal, finalCode, cause)
}

func (s *Service) finishFailedRuntimeCleanup(ctx context.Context, ws core.Workspace, finalCode string) (core.Workspace, error) {
	if ws.ProviderResourceID == "" {
		return ws, errors.New("provider cleanup is pending without a durable provider resource ID")
	}
	if err := s.provider.StopAndWait(ctx, ws.ProviderResourceID); err != nil {
		return ws, fmt.Errorf("confirm failed provider cleanup: %w", err)
	}
	ws.State = core.WorkspaceFailed
	ws.FailureCode = finalCode
	ws.SuspendedAt = nil
	ws.UpdatedAt = s.now()
	if err := s.store.Save(ctx, ws); err != nil {
		return core.Workspace{}, err
	}
	_ = s.rebalance(ctx, ws.OwnerID)
	return ws, nil
}

func (s *Service) startProvider(ctx context.Context, ws core.Workspace) error {
	if ws.SetupApproved && ws.DevcontainerDir != "" {
		return s.provider.StartWithSetup(ctx, ws.ProviderResourceID, SetupStartRequest{
			WorkspaceID: ws.ID, ConfigDirectory: ws.DevcontainerDir,
			UseEnvBuilder: ws.DevcontainerSupported, SafetyMode: ws.SafetyMode, Quota: ws.Quota,
		})
	}
	return s.provider.Start(ctx, ws.ProviderResourceID, StartRequest{SafetyMode: ws.SafetyMode, Quota: ws.Quota})
}

func (s *Service) markProviderStartPending(ctx context.Context, ws core.Workspace) (core.Workspace, error) {
	if ws.ProviderResourceID == "" {
		return core.Workspace{}, errors.New("provider start is missing its durable resource ID")
	}
	ws.FailureCode = failureStartCleanupPending
	ws.UpdatedAt = s.now()
	if err := s.store.Save(ctx, ws); err != nil {
		return core.Workspace{}, err
	}
	return ws, nil
}

func (s *Service) fail(ctx context.Context, ws core.Workspace, code string, cause error) (core.Workspace, error) {
	ws.State = core.WorkspaceFailed
	ws.SuspendedAt = nil
	ws.FailureCode = code
	ws.UpdatedAt = s.now()
	_ = s.store.Save(ctx, ws)
	return ws, fmt.Errorf("%w: %s: %v", core.ErrExternal, code, cause)
}

func (s *Service) rebalance(ctx context.Context, ownerID string) error {
	return s.reconcileStableQuotas(ctx, ownerID, "")
}

// ReconcileCapacity is the lifecycle/background repair boundary for fair-share
// quotas. Provider quota builds are serialized with starts, stops, and deletes
// so a restart-time repair cannot resize a runtime concurrently with another
// provider transition.
func (s *Service) ReconcileCapacity(ctx context.Context, ownerID string) error {
	if ownerID == "" {
		return fmt.Errorf("reconcile workspace capacity: %w", core.ErrInvalid)
	}
	if err := s.acquireRuntime(ctx); err != nil {
		return err
	}
	defer s.releaseRuntime()
	return s.rebalance(ctx, ownerID)
}

// prepareCapacityForStart lowers every existing live runtime to its N+1 share
// before a provider create/start can make the new runtime live. A partial
// failure is safe (some runtimes are merely underallocated) and leaves the new
// provisioning reservation durable for retry.
func (s *Service) prepareCapacityForStart(ctx context.Context, starting core.Workspace) (core.Workspace, error) {
	quota, found, err := s.reconcileCapacityQuotas(ctx, starting.OwnerID, starting.ID)
	if err != nil {
		return starting, err
	}
	if !found {
		return starting, errors.New("starting workspace lost its capacity reservation")
	}
	starting.Quota = quota
	return starting, nil
}

func (s *Service) reconcileStableQuotas(ctx context.Context, ownerID, startingID string) error {
	_, _, err := s.reconcileCapacityQuotas(ctx, ownerID, startingID)
	return err
}

func (s *Service) reconcileCapacityQuotas(ctx context.Context, ownerID, startingID string) (core.Quota, bool, error) {
	workspaces, err := s.store.List(ctx, ownerID)
	if err != nil {
		return core.Quota{}, false, err
	}
	consumers := make([]core.Workspace, 0)
	for _, ws := range workspaces {
		if ws.State.CountsAsRunning() {
			consumers = append(consumers, ws)
		}
	}
	shares, err := s.admission.Shares(len(consumers))
	if err != nil {
		return core.Quota{}, false, err
	}
	type capacityTarget struct {
		workspace core.Workspace
		quota     core.Quota
	}
	targets := make([]capacityTarget, 0, len(consumers))
	var startingQuota core.Quota
	foundStarting := false
	for i, ws := range consumers {
		target := quotaWithinRequest(shares[i], ws.RequestedDiskGiB)
		targets = append(targets, capacityTarget{workspace: ws, quota: target})
		if ws.ID == startingID {
			startingQuota = target
			foundStarting = true
		}
	}

	// Preflight every non-stable consumer before changing a stable provider. A
	// transitional runtime may still be live at its last durable allocation but
	// cannot safely receive an ApplyQuota build while its start/stop/delete
	// outcome is unresolved. Plain pre-provider reservations are the exception:
	// they are definitely not live, so several creates may prepare concurrently
	// without deadlocking each other. A lost Provision response is explicitly
	// ambiguous and is never classified as a plain reservation.
	for _, target := range targets {
		ws := target.workspace
		if ws.ID == startingID || stableLiveProviderState(ws.State) || definitelyStoppedStartReservation(ws) {
			continue
		}
		// Never trust the last persisted quota to describe an unresolved
		// transitional provider. Older crash ordering could leave the provider
		// expanded while persistence retained a smaller value; only a durable
		// no-start proof marker is sufficient to admit another provider or expand
		// a stable peer in the background.
		return core.Quota{}, false, fmt.Errorf("%w: transitional workspace %s in %s has unresolved provider capacity", core.ErrCapacity, ws.ID, ws.State)
	}

	for _, target := range targets {
		ws := target.workspace
		if ws.ID == startingID {
			continue
		}
		if !stableLiveProviderState(ws.State) {
			continue
		}
		if ws.ProviderResourceID == "" {
			return core.Quota{}, false, errors.New("live workspace is missing its provider resource ID")
		}
		// Keep persistence as a conservative upper bound across every crash
		// window. Expanding dimensions are recorded before the provider build;
		// shrinking dimensions are recorded only after it succeeds. Mixed changes
		// use a component-wise high-water value around the exact provider target.
		upper := quotaUpperBound(ws.Quota, target.quota)
		if upper != ws.Quota {
			if err := s.store.UpdateQuota(ctx, ws.OwnerID, ws.ID, upper, s.now()); err != nil {
				return core.Quota{}, false, err
			}
		}
		if err := s.provider.ApplyQuota(ctx, ws.ProviderResourceID, target.quota); err != nil {
			return core.Quota{}, false, err
		}
		if target.quota != upper {
			if err := s.store.UpdateQuota(ctx, ws.OwnerID, ws.ID, target.quota, s.now()); err != nil {
				return core.Quota{}, false, err
			}
		}
	}
	if foundStarting {
		if err := s.store.UpdateQuota(ctx, ownerID, startingID, startingQuota, s.now()); err != nil {
			return core.Quota{}, false, err
		}
	}
	return startingQuota, foundStarting, nil
}

func definitelyStoppedStartReservation(value core.Workspace) bool {
	// This phase is written while admission is held and is replaced durably
	// before every provider call. Unlike an empty historical phase or a generic
	// capacity error, it is proof that a new provider cannot yet be live. For an
	// existing provider it follows a previously confirmed stopped state.
	return value.State == core.WorkspaceProvisioning && value.FailureCode == failureProviderStartReserved
}

func quotaUpperBound(current, target core.Quota) core.Quota {
	return core.Quota{
		CPUMilli:  max(current.CPUMilli, target.CPUMilli),
		MemoryMiB: max(current.MemoryMiB, target.MemoryMiB),
		DiskGiB:   max(current.DiskGiB, target.DiskGiB),
	}
}

func stableLiveProviderState(state core.WorkspaceState) bool {
	switch state {
	case core.WorkspaceReady, core.WorkspaceRunning, core.WorkspaceNeedsAttention, core.WorkspaceIdle:
		return true
	default:
		return false
	}
}

// Requested disk is a voluntary upper bound only. It can reduce a workspace's
// writable allocation but can never buy priority or exceed the equal share.
// The hard ceiling keeps every persistent volume stable as the running count
// changes: 10 workspaces * 16 GiB consumes the 160 GiB workspace pool while
// preserving the host's 40 GiB reserve.
func quotaWithinRequest(equalShare core.Quota, requestedDiskGiB int64) core.Quota {
	if equalShare.DiskGiB > core.MaximumWorkspaceDiskGiB {
		equalShare.DiskGiB = core.MaximumWorkspaceDiskGiB
	}
	if requestedDiskGiB >= core.MinimumWorkspaceDiskGiB && requestedDiskGiB < equalShare.DiskGiB {
		equalShare.DiskGiB = requestedDiskGiB
	}
	return equalShare
}

func (s *Service) identifiers() (string, string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(s.random, b); err != nil {
		return "", "", err
	}
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	return "ws_" + encoded, encoded[:8], nil
}

var unsafeSlug = regexp.MustCompile(`[^a-z0-9]+`)

func branchName(name, suffix string) string {
	slug := strings.Trim(unsafeSlug.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if slug == "" {
		slug = "task"
	}
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	return "codex-mobile/" + slug + "-" + suffix
}

func queueReason(reason string) string {
	return "queued_" + strings.Trim(unsafeSlug.ReplaceAllString(strings.ToLower(reason), "_"), "_")
}
