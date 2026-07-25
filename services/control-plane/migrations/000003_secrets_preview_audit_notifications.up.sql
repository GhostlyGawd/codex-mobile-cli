-- Forward-only migration: token metadata, encrypted secrets, previews, audit, and notifications.

CREATE TABLE github_token_metadata (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    owner_id text NOT NULL,
    installation_id bigint NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    permissions jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(permissions) = 'object'),
    repository_ids jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(repository_ids) = 'array'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    FOREIGN KEY (owner_id, installation_id)
        REFERENCES github_installations(owner_id, installation_id) ON DELETE CASCADE,
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX github_token_expiry_idx
    ON github_token_metadata (owner_id, installation_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE encrypted_secrets (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    owner_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repository_id text,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
    encrypted_envelope bytea NOT NULL CHECK (octet_length(encrypted_envelope) > 0),
    redaction_hash bytea NOT NULL CHECK (octet_length(redaction_hash) = 32),
    aad_version integer NOT NULL DEFAULT 1 CHECK (aad_version > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    rotated_at timestamptz,
    deleted_at timestamptz,
    FOREIGN KEY (owner_id, repository_id) REFERENCES repositories(owner_id, id) ON DELETE CASCADE,
    CHECK (updated_at >= created_at),
    CHECK (rotated_at IS NULL OR rotated_at >= created_at),
    CHECK (deleted_at IS NULL OR deleted_at >= created_at)
);

CREATE UNIQUE INDEX encrypted_secrets_global_name_idx
    ON encrypted_secrets (owner_id, name)
    WHERE repository_id IS NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX encrypted_secrets_repository_name_idx
    ON encrypted_secrets (owner_id, repository_id, name)
    WHERE repository_id IS NOT NULL AND deleted_at IS NULL;

CREATE INDEX encrypted_secrets_owner_scope_idx
    ON encrypted_secrets (owner_id, repository_id, updated_at DESC)
    WHERE deleted_at IS NULL;

CREATE TABLE preview_routes (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    owner_id text NOT NULL,
    workspace_id text NOT NULL,
    port integer NOT NULL CHECK (port BETWEEN 1024 AND 65535),
    process_name text NOT NULL DEFAULT '' CHECK (char_length(process_name) <= 512),
    workspace_host text NOT NULL DEFAULT '' CHECK (char_length(workspace_host) <= 512),
    created_at timestamptz NOT NULL,
    revoked_at timestamptz,
    UNIQUE (owner_id, id, workspace_id),
    UNIQUE (workspace_id, port),
    FOREIGN KEY (owner_id, workspace_id) REFERENCES workspaces(owner_id, id) ON DELETE CASCADE,
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX preview_routes_active_idx
    ON preview_routes (owner_id, workspace_id, port)
    WHERE revoked_at IS NULL;

CREATE TABLE preview_tokens (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    route_id text NOT NULL,
    owner_id text NOT NULL,
    workspace_id text NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (owner_id, route_id, workspace_id)
        REFERENCES preview_routes(owner_id, id, workspace_id) ON DELETE CASCADE,
    CHECK (expires_at > created_at),
    CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX preview_tokens_active_expiry_idx
    ON preview_tokens (owner_id, workspace_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id text REFERENCES users(id) ON DELETE SET NULL,
    device_id text REFERENCES devices(id) ON DELETE SET NULL,
    workspace_id text REFERENCES workspaces(id) ON DELETE SET NULL,
    action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 255),
    result text NOT NULL CHECK (result IN ('success', 'denied', 'failed', 'cancelled')),
    target_type text NOT NULL DEFAULT '' CHECK (char_length(target_type) <= 128),
    target_id text NOT NULL DEFAULT '' CHECK (char_length(target_id) <= 512),
    source_ip_hash bytea CHECK (source_ip_hash IS NULL OR octet_length(source_ip_hash) = 32),
    user_agent_hash bytea CHECK (user_agent_hash IS NULL OR octet_length(user_agent_hash) = 32),
    details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    created_at timestamptz NOT NULL
);

CREATE INDEX audit_events_owner_timeline_idx ON audit_events (owner_id, created_at DESC, id DESC);
CREATE INDEX audit_events_workspace_timeline_idx ON audit_events (workspace_id, created_at DESC, id DESC);
CREATE INDEX audit_events_action_idx ON audit_events (action, created_at DESC);

CREATE TABLE notification_endpoints (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    owner_id text NOT NULL,
    device_id text NOT NULL,
    provider text NOT NULL CHECK (provider = 'apns'),
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    encrypted_token bytea NOT NULL CHECK (octet_length(encrypted_token) > 0),
    topic text NOT NULL CHECK (char_length(topic) BETWEEN 1 AND 255),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    last_success_at timestamptz,
    last_failure_at timestamptz,
    revoked_at timestamptz,
    UNIQUE (owner_id, device_id, provider, environment, token_hash),
    FOREIGN KEY (owner_id, device_id) REFERENCES devices(owner_id, id) ON DELETE CASCADE,
    CHECK (updated_at >= created_at),
    CHECK (last_success_at IS NULL OR last_success_at >= created_at),
    CHECK (last_failure_at IS NULL OR last_failure_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX notification_endpoints_active_idx
    ON notification_endpoints (owner_id, device_id, environment, updated_at DESC)
    WHERE enabled AND revoked_at IS NULL;
