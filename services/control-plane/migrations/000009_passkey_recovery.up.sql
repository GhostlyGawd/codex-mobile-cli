-- Bind break-glass bootstrap credentials to the existing owner whose
-- passkeys were revoked by the offline administrative recovery transaction.

ALTER TABLE bootstrap_tokens
    ADD COLUMN recovery_owner_id text REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX bootstrap_tokens_active_recovery_idx
    ON bootstrap_tokens (recovery_owner_id, expires_at)
    WHERE recovery_owner_id IS NOT NULL
      AND consumed_at IS NULL
      AND disabled_at IS NULL;
