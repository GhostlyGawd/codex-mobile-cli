package lifecycle

import (
	"context"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type SetupReviewReconciler interface {
	Ensure(context.Context, core.Workspace, time.Time) error
}
