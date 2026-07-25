-- Forward-only migration: owner-managed encrypted secrets and explicit workspace grants.

ALTER TABLE encrypted_secrets
    ADD COLUMN plaintext_size integer;

ALTER TABLE encrypted_secrets
    ADD CONSTRAINT encrypted_secrets_plaintext_size_check
    CHECK (plaintext_size IS NULL OR plaintext_size BETWEEN 1 AND 8192);

ALTER TABLE encrypted_secrets
    ADD CONSTRAINT encrypted_secrets_owner_id_unique UNIQUE (owner_id, id);

CREATE INDEX encrypted_secrets_user_visible_idx
    ON encrypted_secrets (owner_id, repository_id, name, updated_at DESC)
    WHERE workspace_id IS NULL AND plaintext_size IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE secret_grants (
    owner_id text NOT NULL,
    workspace_id text NOT NULL,
    secret_id text NOT NULL,
    granted_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (owner_id, workspace_id, secret_id),
    FOREIGN KEY (owner_id, workspace_id)
        REFERENCES workspaces(owner_id, id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id, secret_id)
        REFERENCES encrypted_secrets(owner_id, id) ON DELETE CASCADE,
    CHECK (updated_at >= granted_at),
    CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

CREATE INDEX secret_grants_workspace_active_idx
    ON secret_grants (owner_id, workspace_id, secret_id)
    WHERE revoked_at IS NULL;

CREATE INDEX secret_grants_secret_active_idx
    ON secret_grants (owner_id, secret_id, workspace_id)
    WHERE revoked_at IS NULL;
