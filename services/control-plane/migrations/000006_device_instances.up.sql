-- Forward-only migration: per-install device identity for synced passkeys.

ALTER TABLE devices
    ADD COLUMN instance_hash bytea;

ALTER TABLE devices
    ADD CONSTRAINT devices_instance_hash_length
    CHECK (instance_hash IS NULL OR octet_length(instance_hash) = 32);

-- Legacy devices remain nullable because the server never possessed their
-- per-install value. All new enrollment/authentication paths populate it.
CREATE UNIQUE INDEX devices_owner_active_instance_idx
    ON devices (owner_id, instance_hash)
    WHERE revoked_at IS NULL AND instance_hash IS NOT NULL;
