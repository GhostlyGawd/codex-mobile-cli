package postgres

import (
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/maintenance"
)

func TestMaintenanceRunValidationRejectsSensitiveOrInconsistentMetadata(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	base := maintenance.Run{
		ID: "maint_12345678", OwnerID: "owner", State: maintenance.StateScheduled,
		ScheduledFor: now.Add(time.Hour), WarningAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := validMaintenanceRun(base); err != nil {
		t.Fatal(err)
	}
	base.Message = "bad\x00message"
	if err := validMaintenanceRun(base); err == nil {
		t.Fatal("expected NUL rejection")
	}
	base.Message = ""
	base.Urgent = true
	if err := validMaintenanceRun(base); err == nil {
		t.Fatal("urgent maintenance must be best effort")
	}
}
