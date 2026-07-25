-- A creation request containing environment variables or an initial prompt
-- is not promotable until every private input has been encrypted and durably
-- stored. The marker survives process loss between those writes and workspace
-- provisioning; recovery fails the row closed for explicit recreation.
ALTER TABLE workspaces
    ADD COLUMN private_inputs_pending boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT workspaces_private_inputs_pending_state
        CHECK (NOT private_inputs_pending OR state IN ('queued', 'provisioning', 'failed', 'deleting'));

-- Older builds used a retryable-looking code for an inherently ambiguous
-- partial persistence outcome. Make those rows visibly nonretryable on upgrade.
UPDATE workspaces
SET failure_code = 'private_inputs_recreate_required',
    updated_at = GREATEST(updated_at, now())
WHERE failure_code = 'environment_persistence_failed';
