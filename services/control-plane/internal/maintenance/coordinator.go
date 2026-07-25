// Package maintenance coordinates the safe application-facing half of host
// maintenance. It warns, closes admission, checkpoints, and drains workspaces.
// Root-owned host update/reboot tooling advances the persisted state explicitly;
// the control plane never shells out to a package manager or reboots the host.
package maintenance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type State string

const (
	StateScheduled      State = "scheduled"
	StateWarning        State = "warning"
	StateDraining       State = "draining"
	StateReadyForUpdate State = "ready_for_update"
	StateUpdating       State = "updating"
	StateRebootRequired State = "reboot_required"
	StateVerifying      State = "verifying"
	StateCompleted      State = "completed"
	StateFailed         State = "failed"
	StateCancelled      State = "cancelled"
)

type Run struct {
	ID                     string
	OwnerID                string
	State                  State
	Urgent                 bool
	BestEffort             bool
	ScheduledFor           time.Time
	WarningAt              time.Time
	CreatedAt              time.Time
	UpdatedAt              time.Time
	StartedAt              *time.Time
	CompletedAt            *time.Time
	CheckpointedWorkspaces int
	DrainedWorkspaces      int
	FailedWorkspaces       int
	RebootRequired         bool
	Message                string
}

func (r Run) Active() bool {
	switch r.State {
	case StateCompleted, StateFailed, StateCancelled:
		return false
	default:
		return true
	}
}

type Store interface {
	Active(context.Context) (Run, error)
	Latest(context.Context, string) (Run, error)
	Create(context.Context, Run) error
	Transition(context.Context, Run, State) error
}

func (c *Coordinator) Status(ctx context.Context, ownerID string) (Run, error) {
	if ownerID == "" {
		return Run{}, fmt.Errorf("%w: owner is required", core.ErrInvalid)
	}
	run, err := c.store.Active(ctx)
	if err == nil {
		if run.OwnerID != ownerID {
			return Run{}, core.ErrNotFound
		}
		return run, nil
	}
	if !errors.Is(err, core.ErrNotFound) {
		return Run{}, err
	}
	return c.store.Latest(ctx, ownerID)
}

type WorkspaceSource interface {
	ListAll(context.Context) ([]core.Workspace, error)
}

type Checkpointer interface {
	CreateRequired(context.Context, string, string, string) (string, bool, bool, error)
}

type WorkspaceOperations interface {
	// BeginMaintenanceDrain is called only after admission has been closed. It
	// waits for starts admitted before that close to become durably visible and
	// keeps the admission snapshot boundary closed until release is called.
	BeginMaintenanceDrain(context.Context) (release func(), err error)
	Suspend(context.Context, string, string) (core.Workspace, error)
	Delete(context.Context, string, string, bool, bool) error
	ReconcileMaintenanceDrain(context.Context, string, string) (core.Workspace, error)
}

type Admission interface {
	SetMaintenanceDrain(bool)
}

type Activity struct {
	ID        string
	OwnerID   string
	Summary   string
	RunID     string
	CreatedAt time.Time
}

type ActivitySink interface {
	AddMaintenanceActivity(context.Context, Activity) error
}

type HealthChecker interface {
	Ping(context.Context) error
}

type Recorder interface {
	RecordMaintenance(bool)
}

type Config struct {
	Weekday           time.Weekday
	HourUTC           int
	WarningLead       time.Duration
	UrgentWarningLead time.Duration
	ScanInterval      time.Duration
	Now               func() time.Time
	Random            io.Reader
}

type Coordinator struct {
	store      Store
	workspaces WorkspaceSource
	checkpoint Checkpointer
	operations WorkspaceOperations
	admission  Admission
	activity   ActivitySink
	health     HealthChecker
	recorder   Recorder
	config     Config
}

func New(store Store, workspaces WorkspaceSource, checkpoint Checkpointer, operations WorkspaceOperations, admission Admission, activity ActivitySink, health HealthChecker, recorder Recorder, config Config) (*Coordinator, error) {
	if store == nil || workspaces == nil || checkpoint == nil || operations == nil || admission == nil || activity == nil || health == nil {
		return nil, errors.New("maintenance dependencies are required")
	}
	if config.Weekday < time.Sunday || config.Weekday > time.Saturday || config.HourUTC < 0 || config.HourUTC > 23 {
		return nil, errors.New("maintenance weekday or UTC hour is invalid")
	}
	if config.WarningLead == 0 {
		config.WarningLead = 24 * time.Hour
	}
	if config.UrgentWarningLead == 0 {
		config.UrgentWarningLead = 5 * time.Minute
	}
	if config.ScanInterval == 0 {
		config.ScanInterval = time.Minute
	}
	if config.WarningLead < time.Hour || config.WarningLead > 6*24*time.Hour ||
		config.UrgentWarningLead < time.Minute || config.UrgentWarningLead > time.Hour ||
		config.ScanInterval < time.Second || config.ScanInterval > time.Hour {
		return nil, errors.New("maintenance timing is invalid")
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	return &Coordinator{
		store: store, workspaces: workspaces, checkpoint: checkpoint, operations: operations,
		admission: admission, activity: activity, health: health, recorder: recorder, config: config,
	}, nil
}

// Recover restores admission state after a process restart. Host maintenance
// remains fail-closed until verification completes or an operator cancels it.
func (c *Coordinator) Recover(ctx context.Context) error {
	run, err := c.store.Active(ctx)
	if errors.Is(err, core.ErrNotFound) {
		c.admission.SetMaintenanceDrain(false)
		return nil
	}
	if err != nil {
		return err
	}
	switch run.State {
	case StateDraining, StateReadyForUpdate, StateUpdating, StateRebootRequired, StateVerifying:
		c.admission.SetMaintenanceDrain(true)
	default:
		c.admission.SetMaintenanceDrain(false)
	}
	return nil
}

func (c *Coordinator) ScheduleWeekly(ctx context.Context, ownerID string) (Run, error) {
	if ownerID == "" {
		return Run{}, fmt.Errorf("%w: owner is required", core.ErrInvalid)
	}
	if existing, err := c.store.Active(ctx); err == nil {
		if existing.OwnerID != ownerID {
			return Run{}, core.ErrConflict
		}
		return existing, nil
	} else if !errors.Is(err, core.ErrNotFound) {
		return Run{}, err
	}
	now := c.config.Now().UTC()
	scheduled := nextWindow(now, c.config.Weekday, c.config.HourUTC)
	run, err := c.newRun(ownerID, false, false, scheduled, scheduled.Add(-c.config.WarningLead), now)
	if err != nil {
		return Run{}, err
	}
	if err := c.store.Create(ctx, run); err != nil {
		return Run{}, err
	}
	return run, nil
}

// ScheduleUrgent permits a shorter warning and best-effort checkpointing for a
// security emergency. It never skips the warning or checkpoint attempt.
func (c *Coordinator) ScheduleUrgent(ctx context.Context, ownerID string) (Run, error) {
	if ownerID == "" {
		return Run{}, fmt.Errorf("%w: owner is required", core.ErrInvalid)
	}
	if existing, err := c.store.Active(ctx); err == nil {
		if existing.OwnerID != ownerID || (existing.State != StateScheduled && existing.State != StateWarning) {
			return Run{}, fmt.Errorf("%w: maintenance is already active", core.ErrConflict)
		}
		cancelledAt := c.config.Now().UTC()
		previous := existing.State
		existing.State, existing.UpdatedAt, existing.CompletedAt = StateCancelled, cancelledAt, &cancelledAt
		existing.Message = "Superseded by urgent security maintenance."
		if err := c.store.Transition(ctx, existing, previous); err != nil {
			return Run{}, err
		}
	} else if !errors.Is(err, core.ErrNotFound) {
		return Run{}, err
	}
	now := c.config.Now().UTC()
	scheduled := now.Add(c.config.UrgentWarningLead)
	run, err := c.newRun(ownerID, true, true, scheduled, now, now)
	if err != nil {
		return Run{}, err
	}
	if err := c.store.Create(ctx, run); err != nil {
		return Run{}, err
	}
	return run, nil
}

func (c *Coordinator) Run(ctx context.Context, report func(error)) error {
	if err := c.Recover(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(c.config.ScanInterval)
	defer ticker.Stop()
	for {
		if err := c.RunOnce(ctx); err != nil && report != nil && ctx.Err() == nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Coordinator) RunOnce(ctx context.Context) error {
	run, err := c.store.Active(ctx)
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	now := c.config.Now().UTC()
	if run.State == StateScheduled && !now.Before(run.WarningAt) {
		previous := run.State
		run.State = StateWarning
		run.UpdatedAt = now
		if err := c.store.Transition(ctx, run, previous); err != nil {
			return err
		}
		if err := c.activity.AddMaintenanceActivity(ctx, Activity{
			ID: "maintenance-warning-" + run.ID, OwnerID: run.OwnerID,
			Summary: "Server maintenance is scheduled soon. Running workspaces will be checkpointed and suspended.",
			RunID:   run.ID, CreatedAt: now,
		}); err != nil && !errors.Is(err, core.ErrConflict) {
			return err
		}
	}
	if (run.State == StateScheduled || run.State == StateWarning) && !now.Before(run.ScheduledFor) {
		previous := run.State
		run.State = StateDraining
		run.UpdatedAt = now
		if run.StartedAt == nil {
			run.StartedAt = &now
		}
		if err := c.store.Transition(ctx, run, previous); err != nil {
			return err
		}
	}
	if run.State == StateDraining {
		return c.drain(ctx, run)
	}
	return nil
}

const maximumDrainConvergencePasses = 64

// drain resumes exclusively from the durable draining state. Admission stays
// closed across every error and process restart: only successful post-update
// verification reopens it. BeginMaintenanceDrain linearizes the first
// snapshot with workspace admission so a start accepted immediately before
// the drain cannot be missed by a stale ListAll result.
func (c *Coordinator) drain(ctx context.Context, run Run) error {
	c.admission.SetMaintenanceDrain(true)

	release, err := c.operations.BeginMaintenanceDrain(ctx)
	if err != nil {
		return fmt.Errorf("begin workspace maintenance drain: %w", err)
	}
	if release == nil {
		return errors.New("workspace maintenance drain returned no release function")
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()

	values, err := c.workspaces.ListAll(ctx)
	release()
	released = true
	if err != nil {
		return fmt.Errorf("list workspaces during maintenance drain: %w", err)
	}

	for pass := 0; pass < maximumDrainConvergencePasses; pass++ {
		unsafe := unsafeWorkspaces(values)
		if len(unsafe) == 0 {
			return c.markReady(ctx, run)
		}

		checkpointed, drained, failed := 0, 0, 0
		var passErr error
		for _, value := range unsafe {
			if err := ctx.Err(); err != nil {
				return err
			}
			switch value.State {
			case core.WorkspaceReady, core.WorkspaceRunning, core.WorkspaceNeedsAttention, core.WorkspaceIdle:
				if value.ProviderResourceID == "" {
					failed++
					passErr = errors.Join(passErr, fmt.Errorf("workspace %s is live without a provider resource ID", value.ID))
					continue
				}
				_, _, _, checkpointErr := c.checkpoint.CreateRequired(ctx, value.ID, value.ProviderResourceID, "maintenance")
				if checkpointErr != nil {
					failed++
					passErr = errors.Join(passErr, fmt.Errorf("checkpoint workspace %s: %w", value.ID, checkpointErr))
					if !run.BestEffort {
						continue
					}
				} else {
					checkpointed++
				}
				if _, suspendErr := c.operations.Suspend(ctx, value.OwnerID, value.ID); suspendErr != nil {
					failed++
					passErr = errors.Join(passErr, fmt.Errorf("suspend workspace %s: %w", value.ID, suspendErr))
				} else {
					drained++
				}
			case core.WorkspaceSuspending:
				if _, suspendErr := c.operations.Suspend(ctx, value.OwnerID, value.ID); suspendErr != nil {
					failed++
					passErr = errors.Join(passErr, fmt.Errorf("finish suspending workspace %s: %w", value.ID, suspendErr))
				} else {
					drained++
				}
			case core.WorkspaceDeleting:
				if deleteErr := c.operations.Delete(ctx, value.OwnerID, value.ID, false, true); deleteErr != nil {
					failed++
					passErr = errors.Join(passErr, fmt.Errorf("finish deleting workspace %s: %w", value.ID, deleteErr))
				} else {
					drained++
				}
			case core.WorkspaceProvisioning, core.WorkspaceMaintenance:
				if _, reconcileErr := c.operations.ReconcileMaintenanceDrain(ctx, value.OwnerID, value.ID); reconcileErr != nil {
					failed++
					passErr = errors.Join(passErr, fmt.Errorf("reconcile workspace %s during maintenance: %w", value.ID, reconcileErr))
				} else {
					drained++
				}
			}
		}

		run.CheckpointedWorkspaces += checkpointed
		run.DrainedWorkspaces += drained
		run.FailedWorkspaces += failed
		if checkpointed != 0 || drained != 0 || failed != 0 {
			run.UpdatedAt = c.config.Now().UTC()
			if err := c.store.Transition(ctx, run, StateDraining); err != nil {
				return errors.Join(passErr, fmt.Errorf("persist maintenance drain progress: %w", err))
			}
		}

		values, err = c.workspaces.ListAll(ctx)
		if err != nil {
			return errors.Join(passErr, fmt.Errorf("re-list workspaces during maintenance drain: %w", err))
		}
		if passErr != nil && len(unsafeWorkspaces(values)) != 0 {
			return passErr
		}
	}
	return errors.New("workspace maintenance drain did not converge")
}

func (c *Coordinator) markReady(ctx context.Context, run Run) error {
	previous := run.State
	run.State = StateReadyForUpdate
	run.UpdatedAt = c.config.Now().UTC()
	run.Message = "Workspace drain complete; root-owned update tooling may proceed."
	if run.FailedWorkspaces > 0 {
		run.Message = "Urgent best-effort drain completed with workspace failures; operator review is required."
	}
	if err := c.store.Transition(ctx, run, previous); err != nil {
		return err
	}
	if err := c.activity.AddMaintenanceActivity(ctx, Activity{
		ID: "maintenance-ready-" + run.ID, OwnerID: run.OwnerID,
		Summary: "Workspace drain is complete. Host maintenance is ready to proceed.",
		RunID:   run.ID, CreatedAt: run.UpdatedAt,
	}); err != nil && !errors.Is(err, core.ErrConflict) {
		return err
	}
	return nil
}

func unsafeWorkspaces(values []core.Workspace) []core.Workspace {
	result := make([]core.Workspace, 0, len(values))
	for _, value := range values {
		if providerUnsafe(value.State) {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ID == result[j].ID {
			return result[i].OwnerID < result[j].OwnerID
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func (c *Coordinator) BeginUpdate(ctx context.Context, runID string) (Run, error) {
	return c.transition(ctx, runID, StateReadyForUpdate, StateUpdating, false, "Host update is in progress.")
}

func (c *Coordinator) UpdateApplied(ctx context.Context, runID string, rebootRequired bool) (Run, error) {
	target := StateVerifying
	message := "Updates applied; post-update health verification is required."
	if rebootRequired {
		target, message = StateRebootRequired, "Updates applied; a host reboot is required before verification."
	}
	return c.transition(ctx, runID, StateUpdating, target, rebootRequired, message)
}

func (c *Coordinator) BeginVerification(ctx context.Context, runID string) (Run, error) {
	return c.transition(ctx, runID, StateRebootRequired, StateVerifying, true, "Host restarted; verifying control-plane health.")
}

func (c *Coordinator) Complete(ctx context.Context, runID string) (Run, error) {
	run, err := c.store.Active(ctx)
	if err != nil {
		return Run{}, err
	}
	if run.ID != runID || run.State != StateVerifying {
		return Run{}, fmt.Errorf("%w: maintenance is not awaiting verification", core.ErrConflict)
	}
	if err := c.health.Ping(ctx); err != nil {
		return Run{}, c.fail(ctx, run, fmt.Errorf("post-maintenance health: %w", err))
	}
	now := c.config.Now().UTC()
	previous := run.State
	run.State, run.UpdatedAt, run.CompletedAt, run.Message = StateCompleted, now, &now, "Maintenance completed and health checks passed."
	if err := c.store.Transition(ctx, run, previous); err != nil {
		return Run{}, err
	}
	c.admission.SetMaintenanceDrain(false)
	if c.recorder != nil {
		c.recorder.RecordMaintenance(true)
	}
	if err := c.activity.AddMaintenanceActivity(ctx, Activity{
		ID: "maintenance-complete-" + run.ID, OwnerID: run.OwnerID,
		Summary: "Server maintenance completed and health checks passed.", RunID: run.ID, CreatedAt: now,
	}); err != nil && !errors.Is(err, core.ErrConflict) {
		return Run{}, err
	}
	return run, nil
}

func (c *Coordinator) Cancel(ctx context.Context, ownerID, runID string) (Run, error) {
	run, err := c.store.Active(ctx)
	if err != nil {
		return Run{}, err
	}
	if run.OwnerID != ownerID || run.ID != runID || (run.State != StateScheduled && run.State != StateWarning) {
		return Run{}, fmt.Errorf("%w: maintenance cannot be cancelled in this state", core.ErrConflict)
	}
	now := c.config.Now().UTC()
	previous := run.State
	run.State, run.UpdatedAt, run.CompletedAt, run.Message = StateCancelled, now, &now, "Maintenance cancelled by the owner."
	if err := c.store.Transition(ctx, run, previous); err != nil {
		return Run{}, err
	}
	c.admission.SetMaintenanceDrain(false)
	return run, nil
}

func (c *Coordinator) transition(ctx context.Context, runID string, expected, target State, reboot bool, message string) (Run, error) {
	run, err := c.store.Active(ctx)
	if err != nil {
		return Run{}, err
	}
	if run.ID != runID || run.State != expected {
		return Run{}, fmt.Errorf("%w: invalid maintenance transition", core.ErrConflict)
	}
	previous := run.State
	run.State, run.UpdatedAt, run.RebootRequired, run.Message = target, c.config.Now().UTC(), reboot, message
	if err := c.store.Transition(ctx, run, previous); err != nil {
		return Run{}, err
	}
	return run, nil
}

func (c *Coordinator) fail(ctx context.Context, run Run, cause error) error {
	previous := run.State
	now := c.config.Now().UTC()
	run.State, run.UpdatedAt, run.CompletedAt = StateFailed, now, &now
	run.Message = "Maintenance stopped before host updates; review metadata-only service logs."
	transitionErr := c.store.Transition(ctx, run, previous)
	c.admission.SetMaintenanceDrain(false)
	if c.recorder != nil {
		c.recorder.RecordMaintenance(false)
	}
	return errors.Join(cause, transitionErr)
}

func (c *Coordinator) newRun(ownerID string, urgent, bestEffort bool, scheduled, warning, now time.Time) (Run, error) {
	random := make([]byte, 12)
	if _, err := io.ReadFull(c.config.Random, random); err != nil {
		return Run{}, fmt.Errorf("generate maintenance run ID: %w", err)
	}
	return Run{
		ID: "maint_" + hex.EncodeToString(random), OwnerID: ownerID, State: StateScheduled,
		Urgent: urgent, BestEffort: bestEffort, ScheduledFor: scheduled.UTC(), WarningAt: warning.UTC(),
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func nextWindow(now time.Time, weekday time.Weekday, hourUTC int) time.Time {
	now = now.UTC()
	days := (int(weekday) - int(now.Weekday()) + 7) % 7
	candidate := time.Date(now.Year(), now.Month(), now.Day()+days, hourUTC, 0, 0, 0, time.UTC)
	if !candidate.After(now) {
		candidate = candidate.AddDate(0, 0, 7)
	}
	return candidate
}

func providerUnsafe(state core.WorkspaceState) bool {
	switch state {
	case core.WorkspaceProvisioning, core.WorkspaceReady, core.WorkspaceRunning,
		core.WorkspaceNeedsAttention, core.WorkspaceIdle, core.WorkspaceSuspending,
		core.WorkspaceMaintenance, core.WorkspaceDeleting:
		return true
	default:
		return false
	}
}
