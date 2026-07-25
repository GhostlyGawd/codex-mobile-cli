-- Persist weekly/urgent maintenance coordination across control-plane and host reboots.

CREATE TABLE maintenance_runs (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 8 AND 80),
    owner_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state text NOT NULL CHECK (state IN (
        'scheduled', 'warning', 'draining', 'ready_for_update', 'updating',
        'reboot_required', 'verifying', 'completed', 'failed', 'cancelled'
    )),
    urgent boolean NOT NULL DEFAULT false,
    best_effort boolean NOT NULL DEFAULT false,
    scheduled_for timestamptz NOT NULL,
    warning_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    started_at timestamptz,
    completed_at timestamptz,
    checkpointed_workspaces integer NOT NULL DEFAULT 0 CHECK (checkpointed_workspaces >= 0),
    drained_workspaces integer NOT NULL DEFAULT 0 CHECK (drained_workspaces >= 0),
    failed_workspaces integer NOT NULL DEFAULT 0 CHECK (failed_workspaces >= 0),
    reboot_required boolean NOT NULL DEFAULT false,
    message text NOT NULL DEFAULT '' CHECK (char_length(message) <= 512),
    CHECK (warning_at <= scheduled_for),
    CHECK (updated_at >= created_at),
    CHECK (started_at IS NULL OR started_at >= created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at),
    CHECK (NOT urgent OR best_effort)
);

CREATE UNIQUE INDEX maintenance_runs_one_active_owner_idx
    ON maintenance_runs (owner_id)
    WHERE state NOT IN ('completed', 'failed', 'cancelled');

CREATE INDEX maintenance_runs_owner_timeline_idx
    ON maintenance_runs (owner_id, created_at DESC, id DESC);

CREATE INDEX maintenance_runs_due_idx
    ON maintenance_runs (scheduled_for)
    WHERE state IN ('scheduled', 'warning');
