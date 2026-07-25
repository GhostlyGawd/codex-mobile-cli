package application

import (
	"context"
	"errors"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/maintenance"
)

const serviceVersion = "0.1.0"

func (a *Application) GetMaintenance(ctx context.Context, principal httpapi.Principal) (httpapi.MaintenanceStatus, error) {
	if a.deps.Maintenance == nil {
		return httpapi.MaintenanceStatus{}, fmtPrecondition("maintenance coordination is unavailable")
	}
	run, err := a.deps.Maintenance.Status(ctx, principal.OwnerID)
	if err != nil {
		return httpapi.MaintenanceStatus{}, err
	}
	return maintenanceStatus(run), nil
}

func (a *Application) ScheduleMaintenance(ctx context.Context, principal httpapi.Principal, request httpapi.ScheduleMaintenanceRequest) (httpapi.MaintenanceStatus, error) {
	if a.deps.Maintenance == nil {
		return httpapi.MaintenanceStatus{}, fmtPrecondition("maintenance coordination is unavailable")
	}
	var run maintenance.Run
	var err error
	if request.Urgent {
		run, err = a.deps.Maintenance.ScheduleUrgent(ctx, principal.OwnerID)
	} else {
		run, err = a.deps.Maintenance.ScheduleWeekly(ctx, principal.OwnerID)
	}
	if err != nil {
		return httpapi.MaintenanceStatus{}, err
	}
	a.audit(principal, "", "maintenance.schedule", "success", "maintenance_run", run.ID, map[string]any{"urgent": run.Urgent})
	return maintenanceStatus(run), nil
}

func (a *Application) CancelMaintenance(ctx context.Context, principal httpapi.Principal, runID string) (httpapi.MaintenanceStatus, error) {
	if a.deps.Maintenance == nil {
		return httpapi.MaintenanceStatus{}, fmtPrecondition("maintenance coordination is unavailable")
	}
	if !validMaintenanceID(runID) {
		return httpapi.MaintenanceStatus{}, invalid(errors.New("maintenance run ID is invalid"))
	}
	run, err := a.deps.Maintenance.Cancel(ctx, principal.OwnerID, runID)
	if err != nil {
		return httpapi.MaintenanceStatus{}, err
	}
	a.audit(principal, "", "maintenance.cancel", "success", "maintenance_run", run.ID, nil)
	return maintenanceStatus(run), nil
}

func (a *Application) AdvanceMaintenance(ctx context.Context, principal httpapi.Principal, runID string, request httpapi.MaintenanceActionRequest) (httpapi.MaintenanceStatus, error) {
	if a.deps.Maintenance == nil {
		return httpapi.MaintenanceStatus{}, fmtPrecondition("maintenance coordination is unavailable")
	}
	if !validMaintenanceID(runID) {
		return httpapi.MaintenanceStatus{}, invalid(errors.New("maintenance run ID is invalid"))
	}
	current, err := a.deps.Maintenance.Status(ctx, principal.OwnerID)
	if err != nil {
		return httpapi.MaintenanceStatus{}, err
	}
	if current.ID != runID {
		return httpapi.MaintenanceStatus{}, core.ErrNotFound
	}
	var run maintenance.Run
	switch request.Action {
	case "begin_update":
		if request.RebootRequired != nil {
			return httpapi.MaintenanceStatus{}, invalid(errors.New("reboot_required is not accepted for this action"))
		}
		run, err = a.deps.Maintenance.BeginUpdate(ctx, runID)
	case "updates_applied":
		if request.RebootRequired == nil {
			return httpapi.MaintenanceStatus{}, invalid(errors.New("reboot_required is required for updates_applied"))
		}
		run, err = a.deps.Maintenance.UpdateApplied(ctx, runID, *request.RebootRequired)
	case "begin_verification":
		if request.RebootRequired != nil {
			return httpapi.MaintenanceStatus{}, invalid(errors.New("reboot_required is not accepted for this action"))
		}
		run, err = a.deps.Maintenance.BeginVerification(ctx, runID)
	case "complete":
		if request.RebootRequired != nil {
			return httpapi.MaintenanceStatus{}, invalid(errors.New("reboot_required is not accepted for this action"))
		}
		run, err = a.deps.Maintenance.Complete(ctx, runID)
	default:
		return httpapi.MaintenanceStatus{}, invalid(errors.New("maintenance action is invalid"))
	}
	if err != nil {
		return httpapi.MaintenanceStatus{}, err
	}
	a.audit(principal, "", "maintenance."+request.Action, "success", "maintenance_run", run.ID, map[string]any{"state": run.State})
	return maintenanceStatus(run), nil
}

func (a *Application) GetDiagnostics(ctx context.Context, principal httpapi.Principal) (httpapi.DiagnosticsReport, error) {
	report := httpapi.DiagnosticsReport{
		GeneratedAt: a.deps.Clock.Now().UTC(), ServiceVersion: serviceVersion,
		MetadataOnly: true, IncludesSensitiveData: false,
		GitHubConfigured: a.config.GitHubConfigured, APNSConfigured: a.config.APNSConfigured,
		PreviewsConfigured:       a.config.PreviewsConfigured,
		MaximumRunningWorkspaces: a.config.MaximumRunningWorkspaces,
		MaintenanceState:         "not_scheduled", Health: "healthy",
	}
	if err := a.deps.Health.Ping(ctx); err != nil {
		report.Health = "degraded"
	}
	values, err := a.deps.WorkspaceStore.List(ctx, principal.OwnerID)
	if err != nil {
		return httpapi.DiagnosticsReport{}, err
	}
	report.WorkspaceTotal = len(values)
	for _, value := range values {
		switch value.State {
		case core.WorkspaceRunning, core.WorkspaceReady, core.WorkspaceIdle:
			report.WorkspaceRunning++
		case core.WorkspaceQueued:
			report.WorkspaceQueued++
		case core.WorkspaceSuspended:
			report.WorkspaceSuspended++
		case core.WorkspaceNeedsAttention:
			report.WorkspaceNeedsAttention++
		case core.WorkspaceFailed:
			report.WorkspaceFailed++
		}
	}
	if a.deps.Maintenance != nil {
		if run, statusErr := a.deps.Maintenance.Status(ctx, principal.OwnerID); statusErr == nil {
			report.MaintenanceState = string(run.State)
		} else if !errors.Is(statusErr, core.ErrNotFound) {
			report.MaintenanceState = "unavailable"
		}
	}
	a.audit(principal, "", "diagnostics.view", "success", "diagnostics", "metadata", map[string]any{"metadata_only": true})
	return report, nil
}

func maintenanceStatus(run maintenance.Run) httpapi.MaintenanceStatus {
	return httpapi.MaintenanceStatus{
		ID: run.ID, State: string(run.State), Urgent: run.Urgent, BestEffort: run.BestEffort,
		ScheduledFor: run.ScheduledFor, WarningAt: run.WarningAt, CreatedAt: run.CreatedAt,
		UpdatedAt: run.UpdatedAt, StartedAt: run.StartedAt, CompletedAt: run.CompletedAt,
		CheckpointedWorkspaces: run.CheckpointedWorkspaces, DrainedWorkspaces: run.DrainedWorkspaces,
		FailedWorkspaces: run.FailedWorkspaces, RebootRequired: run.RebootRequired, Message: run.Message,
	}
}

func fmtPrecondition(message string) error {
	return httpapi.NewProblemError(412, "precondition_failed", "Precondition failed", message, core.ErrPrecondition)
}

func validMaintenanceID(value string) bool {
	if len(value) != 30 || value[:6] != "maint_" {
		return false
	}
	for _, character := range value[6:] {
		if (character >= 'a' && character <= 'f') || (character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}
