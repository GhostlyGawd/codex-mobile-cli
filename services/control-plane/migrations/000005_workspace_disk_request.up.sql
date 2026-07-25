-- Preserve an owner-requested writable-disk ceiling independently from the
-- equal-share quota, so later rebalances cannot silently grant a larger cap.

ALTER TABLE workspaces
    ADD COLUMN requested_disk_gib bigint NOT NULL DEFAULT 12
    CHECK (requested_disk_gib BETWEEN 8 AND 16);
