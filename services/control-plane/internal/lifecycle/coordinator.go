package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
)

const (
	DefaultScanInterval = time.Minute
	DefaultWarningLead  = 24 * time.Hour
)

type WorkspaceStore interface {
	ListAll(context.Context) ([]core.Workspace, error)
}

type SettingsStore interface {
	GetSettings(context.Context, string) (postgres.Settings, error)
}

type Operations interface {
	TouchActivity(context.Context, string, string, time.Time) (core.Workspace, error)
	MarkIdleIfInactive(context.Context, string, string, time.Time) (bool, error)
	SuspendIfInactive(context.Context, string, string, time.Time) (core.Workspace, bool, error)
	Retry(context.Context, string, string) (core.Workspace, error)
	Delete(context.Context, string, string, bool, bool) error
	ReconcileCapacity(context.Context, string) error
}

type RuntimeProber interface {
	Probe(context.Context, core.Workspace) (RuntimeActivity, error)
}

type ActivityStore interface {
	AddActivity(context.Context, string, postgres.ActivityRecord) error
}

type RuntimeActivity struct {
	Busy               bool
	ActiveProcessCount int
	ListeningPortCount int
}

type ActivityEvent struct {
	OwnerID     string
	WorkspaceID string
	At          time.Time
}

type Config struct {
	ScanInterval time.Duration
	WarningLead  time.Duration
	Now          func() time.Time
}

type Coordinator struct {
	store      WorkspaceStore
	settings   SettingsStore
	operations Operations
	prober     RuntimeProber
	activity   ActivityStore
	reviews    SetupReviewReconciler
	interval   time.Duration
	warning    time.Duration
	now        func() time.Time

	pendingMu sync.Mutex
	pending   map[string]ActivityEvent
	wake      chan struct{}
}

func New(store WorkspaceStore, settings SettingsStore, operations Operations, prober RuntimeProber, activity ActivityStore, reviews SetupReviewReconciler, config Config) (*Coordinator, error) {
	if store == nil || settings == nil || operations == nil || prober == nil || activity == nil || reviews == nil {
		return nil, errors.New("lifecycle dependencies are required")
	}
	if config.ScanInterval == 0 {
		config.ScanInterval = DefaultScanInterval
	}
	if config.WarningLead == 0 {
		config.WarningLead = DefaultWarningLead
	}
	if config.ScanInterval < time.Second || config.WarningLead < time.Minute {
		return nil, errors.New("invalid lifecycle timing")
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Coordinator{
		store: store, settings: settings, operations: operations, prober: prober, activity: activity, reviews: reviews,
		interval: config.ScanInterval, warning: config.WarningLead, now: config.Now,
		pending: make(map[string]ActivityEvent), wake: make(chan struct{}, 1),
	}, nil
}

// RecordActivity is suitable for terminal callbacks: it performs no I/O,
// coalesces bursts by workspace, and never blocks the PTY read loop.
func (c *Coordinator) RecordActivity(event ActivityEvent) {
	if event.OwnerID == "" || event.WorkspaceID == "" {
		return
	}
	if event.At.IsZero() {
		event.At = c.now()
	}
	key := event.OwnerID + "\x00" + event.WorkspaceID
	c.pendingMu.Lock()
	if current, ok := c.pending[key]; !ok || event.At.After(current.At) {
		c.pending[key] = event
	}
	c.pendingMu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Coordinator) Run(ctx context.Context, onError func(error)) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.wake:
			if err := c.flushActivity(ctx); err != nil && onError != nil {
				onError(err)
			}
		case <-ticker.C:
			if err := c.flushActivity(ctx); err != nil && onError != nil {
				onError(err)
			}
			if err := c.Scan(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

func (c *Coordinator) flushActivity(ctx context.Context) error {
	c.pendingMu.Lock()
	pending := c.pending
	c.pending = make(map[string]ActivityEvent)
	c.pendingMu.Unlock()
	var result error
	for _, event := range pending {
		if _, err := c.operations.TouchActivity(ctx, event.OwnerID, event.WorkspaceID, event.At); err != nil &&
			!errors.Is(err, core.ErrConflict) && !errors.Is(err, core.ErrNotFound) {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (c *Coordinator) Scan(ctx context.Context) error {
	values, err := c.store.ListAll(ctx)
	if err != nil {
		return err
	}
	sort.SliceStable(values, func(i, j int) bool {
		if values[i].CreatedAt.Equal(values[j].CreatedAt) {
			return values[i].ID < values[j].ID
		}
		return values[i].CreatedAt.Before(values[j].CreatedAt)
	})
	now := c.now().UTC()
	settings := make(map[string]postgres.Settings)
	owners := make(map[string]struct{})
	queued := make([]core.Workspace, 0)
	var result error
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		owners[value.OwnerID] = struct{}{}
		switch value.State {
		case core.WorkspaceQueued:
			queued = append(queued, value)
		case core.WorkspaceProvisioning:
			// Provision/create response loss, provider start, initializer, and
			// stop-before-approval cleanup all leave a durable capacity
			// reservation. Retry is idempotent and may either resume provisioning
			// or prove the runtime stopped before releasing the reservation.
			updated, retryErr := c.operations.Retry(ctx, value.OwnerID, value.ID)
			result = errors.Join(result, retryErr)
			if updated.State == core.WorkspaceAwaitingSetupApproval {
				result = errors.Join(result, c.reviews.Ensure(ctx, updated, now))
			}
		case core.WorkspaceAwaitingSetupApproval:
			// Repair a crash or transient store failure after the workspace-side
			// trust boundary was committed. Ensure is transactionally idempotent.
			result = errors.Join(result, c.reviews.Ensure(ctx, value, now))
		case core.WorkspaceRunning, core.WorkspaceIdle:
			ownerSettings, ok := settings[value.OwnerID]
			if !ok {
				ownerSettings, err = c.settings.GetSettings(ctx, value.OwnerID)
				if err != nil {
					result = errors.Join(result, fmt.Errorf("load lifecycle settings: %w", err))
					continue
				}
				settings[value.OwnerID] = ownerSettings
			}
			minutes := value.IdleTimeoutMinutes
			if minutes == 0 {
				minutes = ownerSettings.IdleTimeoutMinutes
			}
			if minutes < 5 || minutes > 10080 || now.Before(value.LastActivityAt.Add(time.Duration(minutes)*time.Minute)) {
				continue
			}
			observed, probeErr := c.prober.Probe(ctx, value)
			if probeErr != nil {
				// Failure to prove inactivity is fail-safe: preserve the runtime.
				result = errors.Join(result, fmt.Errorf("probe workspace runtime: %w", probeErr))
				continue
			}
			if observed.Busy {
				_, touchErr := c.operations.TouchActivity(ctx, value.OwnerID, value.ID, now)
				if touchErr != nil && !errors.Is(touchErr, core.ErrConflict) {
					result = errors.Join(result, touchErr)
				}
				continue
			}
			if value.State == core.WorkspaceRunning {
				_, transitionErr := c.operations.MarkIdleIfInactive(ctx, value.OwnerID, value.ID, value.LastActivityAt)
				result = errors.Join(result, transitionErr)
				continue
			}
			_, _, suspendErr := c.operations.SuspendIfInactive(ctx, value.OwnerID, value.ID, value.LastActivityAt)
			result = errors.Join(result, suspendErr)
		case core.WorkspaceSuspending:
			// Cleanup, provider-stop, and final persistence failures leave a
			// durable suspending authority. Retry the idempotent completion path
			// so an automatic suspension cannot strand the workspace forever.
			_, _, suspendErr := c.operations.SuspendIfInactive(ctx, value.OwnerID, value.ID, value.LastActivityAt)
			result = errors.Join(result, suspendErr)
		case core.WorkspaceSuspended:
			result = errors.Join(result, c.applyRetention(ctx, value, now))
		case core.WorkspaceDeleting:
			// Provider deletion and process-local cleanup are retryable. A failed
			// attempt deliberately leaves this durable tombstone for the next scan;
			// the workspace service skips policy/checkpoint preparation on retries.
			result = errors.Join(result, c.operations.Delete(ctx, value.OwnerID, value.ID, true, false))
		}
	}
	result = errors.Join(result, c.promoteQueued(ctx, queued))
	// Quota updates are intentionally level-triggered rather than remembered in
	// process memory. Every scan derives owners from durable workspace rows and
	// retries fair-share convergence, including after a process restart or an
	// earlier best-effort rebalance failure.
	ownerIDs := make([]string, 0, len(owners))
	for ownerID := range owners {
		ownerIDs = append(ownerIDs, ownerID)
	}
	sort.Strings(ownerIDs)
	for _, ownerID := range ownerIDs {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		result = errors.Join(result, c.operations.ReconcileCapacity(ctx, ownerID))
	}
	return result
}

func (c *Coordinator) promoteQueued(ctx context.Context, values []core.Workspace) error {
	blockedOwners := make(map[string]bool)
	var result error
	for _, value := range values {
		if blockedOwners[value.OwnerID] {
			continue
		}
		updated, err := c.operations.Retry(ctx, value.OwnerID, value.ID)
		if updated.State == core.WorkspaceAwaitingSetupApproval {
			// The initial scan snapshot contained a queued row, so do not wait a
			// full interval before making its newly reached review durable.
			result = errors.Join(result, c.reviews.Ensure(ctx, updated, c.now().UTC()))
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("promote queued workspace: %w", err))
			// Failed is reached only after provider absence/stop was confirmed, so
			// the next queued workspace for the owner receives a fair attempt.
			if updated.State == core.WorkspaceFailed {
				continue
			}
			blockedOwners[value.OwnerID] = true
			continue
		}
		if updated.State == core.WorkspaceQueued {
			blockedOwners[value.OwnerID] = true
		}
	}
	return result
}

func (c *Coordinator) applyRetention(ctx context.Context, value core.Workspace, now time.Time) error {
	if value.Retention == core.RetentionForever || !value.MayAutoDelete() {
		return nil
	}
	duration, ok := retentionDuration(value.Retention)
	if !ok || value.SuspendedAt == nil {
		return fmt.Errorf("invalid suspended retention state for %s", value.ID)
	}
	expiresAt := value.SuspendedAt.Add(duration)
	if !now.Before(expiresAt) {
		return c.operations.Delete(ctx, value.OwnerID, value.ID, true, false)
	}
	warningLead := c.warning
	if warningLead >= duration {
		warningLead = duration / 2
	}
	if now.Before(expiresAt.Add(-warningLead)) {
		return nil
	}
	metadata, err := json.Marshal(map[string]string{
		"event":      "workspace_retention_warning",
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	workspaceID := value.ID
	record := postgres.ActivityRecord{
		ID:          "retention-warning-" + value.ID + "-" + strconvUnix(value.SuspendedAt.UTC()),
		WorkspaceID: &workspaceID,
		Kind:        "maintenance", Summary: "Workspace retention period is nearing expiry.",
		Unread: true, Metadata: metadata, CreatedAt: now,
	}
	err = c.activity.AddActivity(ctx, value.OwnerID, record)
	if errors.Is(err, core.ErrConflict) {
		return nil
	}
	return err
}

func retentionDuration(value core.RetentionPolicy) (time.Duration, bool) {
	switch value {
	case core.Retention7Days:
		return 7 * 24 * time.Hour, true
	case core.Retention30Days:
		return 30 * 24 * time.Hour, true
	case core.Retention90Days:
		return 90 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func strconvUnix(value time.Time) string {
	return fmt.Sprintf("%d", value.Unix())
}
