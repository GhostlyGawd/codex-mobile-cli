-- Preserve owner-initiated GitHub disconnects independently of provider
-- suspension state so a later installation webhook cannot silently reconnect.

ALTER TABLE github_installations
    ADD COLUMN owner_disconnected_at timestamptz;

ALTER TABLE github_installations
    ADD CONSTRAINT github_installations_owner_disconnect_time_check
    CHECK (owner_disconnected_at IS NULL OR owner_disconnected_at >= created_at);

DROP INDEX github_installations_owner_active_idx;

CREATE INDEX github_installations_owner_active_idx
    ON github_installations (owner_id, updated_at DESC)
    WHERE suspended_at IS NULL AND owner_disconnected_at IS NULL;
