package attachmentjanitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

const DefaultInterval = time.Minute

type Runner interface {
	RunHelper(context.Context, string, []byte) ([]byte, error)
}

type WorkspaceLister func(context.Context) ([]core.Workspace, error)

type Janitor struct {
	runner   Runner
	list     WorkspaceLister
	interval time.Duration
}

func New(runner Runner, list WorkspaceLister, interval time.Duration) (*Janitor, error) {
	if runner == nil || list == nil {
		return nil, errors.New("attachment janitor dependencies are required")
	}
	if interval == 0 {
		interval = DefaultInterval
	}
	if interval < time.Second || interval > time.Hour {
		return nil, errors.New("attachment cleanup interval must be between one second and one hour")
	}
	return &Janitor{runner: runner, list: list, interval: interval}, nil
}

func (j *Janitor) RunOnce(ctx context.Context) error {
	values, err := j.list(ctx)
	if err != nil {
		return err
	}
	var result error
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		if value.ProviderResourceID == "" || !helperAvailable(value.State) {
			continue
		}
		request, marshalErr := json.Marshal(workspacehelper.Request{
			Version: workspacehelper.Version, Operation: workspacehelper.OpAttachmentCleanup,
		})
		if marshalErr != nil {
			return errors.Join(result, marshalErr)
		}
		response, runErr := j.runner.RunHelper(ctx, value.ProviderResourceID, request)
		for index := range request {
			request[index] = 0
		}
		if runErr != nil {
			result = errors.Join(result, fmt.Errorf("cleanup workspace attachment staging: %w", runErr))
			continue
		}
		decoded, decodeErr := workspacehelper.DecodeResponse(response)
		for index := range response {
			response[index] = 0
		}
		if decodeErr != nil || !decoded.OK {
			result = errors.Join(result, errors.New("workspace attachment cleanup returned an invalid response"))
		}
	}
	return result
}

func (j *Janitor) Run(ctx context.Context, report func(error)) {
	if report == nil {
		report = func(error) {}
	}
	run := func() {
		if err := j.RunOnce(ctx); err != nil && ctx.Err() == nil {
			report(err)
		}
	}
	run()
	ticker := time.NewTicker(j.interval)
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

func helperAvailable(state core.WorkspaceState) bool {
	return state == core.WorkspaceRunning || state == core.WorkspaceReady || state == core.WorkspaceIdle || state == core.WorkspaceNeedsAttention
}
