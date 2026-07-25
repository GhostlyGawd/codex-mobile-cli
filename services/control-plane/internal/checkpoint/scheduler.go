package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

const (
	DefaultInterval      = 15 * time.Minute
	checkpointRunTimeout = 2 * time.Minute
)

type WorkspaceSource func(context.Context) ([]core.Workspace, error)

type RiskUpdater interface {
	UpdateGitRisk(context.Context, string, string, bool, bool, time.Time) error
}

type activityUpdater interface {
	TouchActivity(context.Context, string, string, time.Time) error
}

type Recorder interface {
	RecordCheckpoint(bool)
}

type Scheduler struct {
	service  *Service
	source   WorkspaceSource
	updater  RiskUpdater
	interval time.Duration
	now      func() time.Time
	recorder Recorder
}

func NewScheduler(service *Service, source WorkspaceSource, updater RiskUpdater, interval time.Duration, recorders ...Recorder) (*Scheduler, error) {
	if service == nil || source == nil || updater == nil {
		return nil, errors.New("checkpoint scheduler dependencies are required")
	}
	if len(recorders) > 1 || (len(recorders) == 1 && recorders[0] == nil) {
		return nil, errors.New("checkpoint scheduler accepts at most one non-nil recorder")
	}
	if interval == 0 {
		interval = DefaultInterval
	}
	if interval < time.Minute || interval > 24*time.Hour {
		return nil, errors.New("checkpoint interval must be between one minute and one day")
	}
	scheduler := &Scheduler{
		service: service, source: source, updater: updater, interval: interval,
		now: func() time.Time { return time.Now().UTC() },
	}
	if len(recorders) == 1 {
		scheduler.recorder = recorders[0]
	}
	return scheduler, nil
}

// Run performs an initial scan and then scans on the configured interval.
// Individual workspace failures are reported and retried at the next interval;
// they never make a destructive lifecycle operation proceed without its own
// synchronous checkpoint.
func (s *Scheduler) Run(ctx context.Context, report func(error)) {
	if report == nil {
		report = func(error) {}
	}
	run := func() {
		if err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			report(err)
		}
	}
	run()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (s *Scheduler) RunOnce(ctx context.Context) error {
	if ctx == nil {
		return errors.New("checkpoint scheduler context is required")
	}
	workspaces, err := s.source(ctx)
	if err != nil {
		return fmt.Errorf("list checkpoint candidates: %w", err)
	}
	var result error
	for _, value := range workspaces {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		if !checkpointableState(value.State) || value.ProviderResourceID == "" {
			continue
		}
		operationCtx, cancel := context.WithTimeout(ctx, checkpointRunTimeout)
		_, dirty, unpushed, checkpointErr := s.service.Create(operationCtx, value.ID, value.ProviderResourceID, "periodic")
		cancel()
		if s.recorder != nil {
			s.recorder.RecordCheckpoint(checkpointErr == nil)
		}
		// Persist live risk only after the checkpoint operation succeeds. On a
		// helper/storage error the existing flags remain unchanged (conservative)
		// instead of being incorrectly cleared by zero-value results.
		if checkpointErr == nil {
			observedAt := s.now()
			if updateErr := s.updater.UpdateGitRisk(ctx, value.OwnerID, value.ID, dirty, unpushed, observedAt); updateErr != nil {
				result = errors.Join(result, fmt.Errorf("update checkpoint risk for %s: %w", value.ID, updateErr))
			}
			if updater, ok := s.updater.(activityUpdater); ok {
				if touchErr := updater.TouchActivity(ctx, value.OwnerID, value.ID, observedAt); touchErr != nil && !errors.Is(touchErr, core.ErrConflict) {
					result = errors.Join(result, fmt.Errorf("touch checkpoint activity for %s: %w", value.ID, touchErr))
				}
			}
		}
		if checkpointErr != nil {
			result = errors.Join(result, fmt.Errorf("checkpoint workspace %s: %w", value.ID, checkpointErr))
		}
	}
	return result
}

func checkpointableState(state core.WorkspaceState) bool {
	switch state {
	case core.WorkspaceReady, core.WorkspaceRunning, core.WorkspaceNeedsAttention, core.WorkspaceIdle:
		return true
	default:
		return false
	}
}
