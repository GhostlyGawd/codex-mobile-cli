-- Persist the exact standard Dev Container location detected before the
-- repository's plain bootstrap. Approval and retries must never re-detect a
-- mutable upstream branch or guess which configuration EnvBuilder should run.
ALTER TABLE workspaces
    ADD COLUMN devcontainer_dir text NOT NULL DEFAULT ''
        CHECK (devcontainer_dir IN ('', '.', '.devcontainer')),
    ADD COLUMN devcontainer_supported boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT workspaces_devcontainer_support_requires_config
        CHECK (NOT devcontainer_supported OR devcontainer_dir <> '');

-- A pre-migration approval record has neither a populated plain provider nor
-- an exact configuration location. Fail it closed instead of allowing the new
-- approval path to guess or a later retry to start as a no-devcontainer
-- workspace. The owner can delete and recreate it through the safe bootstrap.
INSERT INTO workspace_state_events
    (owner_id, workspace_id, from_state, to_state, failure_code, occurred_at)
SELECT owner_id, id, 'awaiting_setup_approval', 'failed',
       'devcontainer_secure_recreate_required', now()
FROM workspaces
WHERE state = 'awaiting_setup_approval' AND devcontainer_dir = '';

UPDATE workspaces
SET state = 'failed',
    failure_code = 'devcontainer_secure_recreate_required',
    updated_at = GREATEST(updated_at, now())
WHERE state = 'awaiting_setup_approval' AND devcontainer_dir = '';

ALTER TABLE workspaces
    ADD CONSTRAINT workspaces_setup_approval_requires_config
        CHECK (state <> 'awaiting_setup_approval' OR devcontainer_dir <> '');
