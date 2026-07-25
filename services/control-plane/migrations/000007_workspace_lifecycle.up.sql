-- True-inactivity lifecycle state. A NULL timeout inherits the owner's
-- current default; suspended_at anchors retention independently of user
-- activity and is cleared on resume.

ALTER TABLE workspaces
    ADD COLUMN idle_timeout_minutes integer
    CHECK (idle_timeout_minutes IS NULL OR idle_timeout_minutes BETWEEN 5 AND 10080),
    ADD COLUMN suspended_at timestamptz;

UPDATE workspaces
SET suspended_at = updated_at
WHERE state = 'suspended' AND suspended_at IS NULL;

ALTER TABLE workspaces
    ADD CONSTRAINT workspaces_suspended_at_state
    CHECK (
        (state = 'suspended' AND suspended_at IS NOT NULL)
        OR (state <> 'suspended' AND suspended_at IS NULL)
    );

CREATE INDEX workspaces_lifecycle_scan_idx
    ON workspaces (state, last_activity_at, created_at);

CREATE INDEX workspaces_suspended_retention_idx
    ON workspaces (suspended_at, retention)
    WHERE state = 'suspended';
