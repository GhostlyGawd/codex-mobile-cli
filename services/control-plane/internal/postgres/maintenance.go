package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/maintenance"
	"github.com/jackc/pgx/v5/pgxpool"
)

type MaintenanceStore struct{ pool *pgxpool.Pool }

func NewMaintenanceStore(pool *pgxpool.Pool) (*MaintenanceStore, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL pool is required")
	}
	return &MaintenanceStore{pool: pool}, nil
}

func (s *MaintenanceStore) Active(ctx context.Context) (maintenance.Run, error) {
	rows, err := s.pool.Query(ctx, maintenanceSelect+`
		WHERE state NOT IN ('completed','failed','cancelled')
		ORDER BY created_at DESC, id DESC LIMIT 2`)
	if err != nil {
		return maintenance.Run{}, mapError("query active maintenance", err)
	}
	defer rows.Close()
	var values []maintenance.Run
	for rows.Next() {
		value, scanErr := scanMaintenance(rows)
		if scanErr != nil {
			return maintenance.Run{}, scanErr
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return maintenance.Run{}, mapError("iterate active maintenance", err)
	}
	if len(values) == 0 {
		return maintenance.Run{}, core.ErrNotFound
	}
	if len(values) > 1 {
		return maintenance.Run{}, errors.New("multiple owners have active maintenance in a single-owner deployment")
	}
	return values[0], nil
}

func (s *MaintenanceStore) Latest(ctx context.Context, ownerID string) (maintenance.Run, error) {
	if ownerID == "" {
		return maintenance.Run{}, fmt.Errorf("latest maintenance: %w", core.ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, maintenanceSelect+` WHERE owner_id=$1 ORDER BY created_at DESC, id DESC LIMIT 1`, ownerID)
	value, err := scanMaintenance(row)
	if errors.Is(err, core.ErrNotFound) {
		return maintenance.Run{}, core.ErrNotFound
	}
	return value, err
}

func (s *MaintenanceStore) Create(ctx context.Context, value maintenance.Run) error {
	if err := validMaintenanceRun(value); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO maintenance_runs
		    (id, owner_id, state, urgent, best_effort, scheduled_for, warning_at,
		     created_at, updated_at, started_at, completed_at, checkpointed_workspaces,
		     drained_workspaces, failed_workspaces, reboot_required, message)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		value.ID, value.OwnerID, string(value.State), value.Urgent, value.BestEffort,
		value.ScheduledFor, value.WarningAt, value.CreatedAt, value.UpdatedAt,
		value.StartedAt, value.CompletedAt, value.CheckpointedWorkspaces,
		value.DrainedWorkspaces, value.FailedWorkspaces, value.RebootRequired, value.Message)
	return mapError("create maintenance run", err)
}

func (s *MaintenanceStore) Transition(ctx context.Context, value maintenance.Run, expected maintenance.State) error {
	if err := validMaintenanceRun(value); err != nil {
		return err
	}
	if !validMaintenanceState(expected) {
		return fmt.Errorf("maintenance expected state: %w", core.ErrInvalid)
	}
	command, err := s.pool.Exec(ctx, `
		UPDATE maintenance_runs SET
		    state=$3, urgent=$4, best_effort=$5, scheduled_for=$6, warning_at=$7,
		    updated_at=$8, started_at=$9, completed_at=$10, checkpointed_workspaces=$11,
		    drained_workspaces=$12, failed_workspaces=$13, reboot_required=$14, message=$15
		WHERE id=$1 AND owner_id=$2 AND state=$16`,
		value.ID, value.OwnerID, string(value.State), value.Urgent, value.BestEffort,
		value.ScheduledFor, value.WarningAt, value.UpdatedAt, value.StartedAt,
		value.CompletedAt, value.CheckpointedWorkspaces, value.DrainedWorkspaces,
		value.FailedWorkspaces, value.RebootRequired, value.Message, string(expected))
	if err != nil {
		return mapError("transition maintenance run", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("transition maintenance run: %w", core.ErrConflict)
	}
	return nil
}

func (s *ApplicationStore) AddMaintenanceActivity(ctx context.Context, value maintenance.Activity) error {
	if value.ID == "" || value.OwnerID == "" || value.RunID == "" || value.Summary == "" ||
		len(value.Summary) > 512 || value.CreatedAt.IsZero() {
		return fmt.Errorf("maintenance activity: %w", core.ErrInvalid)
	}
	metadata, err := json.Marshal(map[string]string{"event": "server_maintenance", "run_id": value.RunID})
	if err != nil {
		return err
	}
	return s.AddActivity(ctx, value.OwnerID, ActivityRecord{
		ID: value.ID, Kind: "maintenance", Summary: value.Summary,
		Unread: true, Metadata: metadata, CreatedAt: value.CreatedAt,
	})
}

const maintenanceSelect = `
	SELECT id, owner_id, state, urgent, best_effort, scheduled_for, warning_at,
	       created_at, updated_at, started_at, completed_at, checkpointed_workspaces,
	       drained_workspaces, failed_workspaces, reboot_required, message
	FROM maintenance_runs`

type maintenanceScanner interface{ Scan(...any) error }

func scanMaintenance(row maintenanceScanner) (maintenance.Run, error) {
	var value maintenance.Run
	var state string
	err := row.Scan(&value.ID, &value.OwnerID, &state, &value.Urgent, &value.BestEffort,
		&value.ScheduledFor, &value.WarningAt, &value.CreatedAt, &value.UpdatedAt,
		&value.StartedAt, &value.CompletedAt, &value.CheckpointedWorkspaces,
		&value.DrainedWorkspaces, &value.FailedWorkspaces, &value.RebootRequired, &value.Message)
	if err != nil {
		return maintenance.Run{}, mapError("scan maintenance run", err)
	}
	value.State = maintenance.State(state)
	if err := validMaintenanceRun(value); err != nil {
		return maintenance.Run{}, fmt.Errorf("stored maintenance run is invalid: %w", err)
	}
	return value, nil
}

func validMaintenanceRun(value maintenance.Run) error {
	if len(value.ID) < 8 || len(value.ID) > 80 || value.OwnerID == "" || !validMaintenanceState(value.State) ||
		value.ScheduledFor.IsZero() || value.WarningAt.IsZero() || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) ||
		value.WarningAt.After(value.ScheduledFor) || value.CheckpointedWorkspaces < 0 || value.DrainedWorkspaces < 0 ||
		value.FailedWorkspaces < 0 || len(value.Message) > 512 || strings.ContainsRune(value.Message, '\x00') ||
		(value.Urgent && !value.BestEffort) {
		return fmt.Errorf("maintenance run: %w", core.ErrInvalid)
	}
	if value.StartedAt != nil && value.StartedAt.Before(value.CreatedAt) {
		return fmt.Errorf("maintenance start: %w", core.ErrInvalid)
	}
	if value.CompletedAt != nil && value.CompletedAt.Before(value.CreatedAt) {
		return fmt.Errorf("maintenance completion: %w", core.ErrInvalid)
	}
	return nil
}

func validMaintenanceState(value maintenance.State) bool {
	switch value {
	case maintenance.StateScheduled, maintenance.StateWarning, maintenance.StateDraining,
		maintenance.StateReadyForUpdate, maintenance.StateUpdating, maintenance.StateRebootRequired,
		maintenance.StateVerifying, maintenance.StateCompleted, maintenance.StateFailed, maintenance.StateCancelled:
		return true
	default:
		return false
	}
}

var _ maintenance.Store = (*MaintenanceStore)(nil)
var _ maintenance.ActivitySink = (*ApplicationStore)(nil)
