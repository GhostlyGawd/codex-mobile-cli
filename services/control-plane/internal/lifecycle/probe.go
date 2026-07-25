package lifecycle

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

type HelperRunner interface {
	RunHelper(context.Context, string, []byte) ([]byte, error)
}

type HelperProber struct {
	runner HelperRunner
}

func NewHelperProber(runner HelperRunner) (*HelperProber, error) {
	if runner == nil {
		return nil, errors.New("runtime helper runner is required")
	}
	return &HelperProber{runner: runner}, nil
}

func (p *HelperProber) Probe(ctx context.Context, value core.Workspace) (RuntimeActivity, error) {
	if value.ProviderResourceID == "" {
		return RuntimeActivity{}, errors.New("workspace provider is unavailable")
	}
	request, err := json.Marshal(workspacehelper.Request{
		Version: workspacehelper.Version, Operation: workspacehelper.OpRuntimeActivityProbe,
	})
	if err != nil {
		return RuntimeActivity{}, err
	}
	data, err := p.runner.RunHelper(ctx, value.ProviderResourceID, request)
	if err != nil {
		return RuntimeActivity{}, err
	}
	response, err := workspacehelper.DecodeResponse(data)
	if err != nil {
		return RuntimeActivity{}, err
	}
	if response.RuntimeActivity == nil {
		return RuntimeActivity{}, errors.New("runtime helper omitted activity")
	}
	return RuntimeActivity{
		Busy:               response.RuntimeActivity.Busy,
		ActiveProcessCount: response.RuntimeActivity.ActiveProcessCount,
		ListeningPortCount: response.RuntimeActivity.ListeningPortCount,
	}, nil
}
