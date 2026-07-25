-- Forward-only migration: owner identity, passkeys, bootstrap credentials, and sessions.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL UNIQUE,
    checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    webauthn_handle bytea NOT NULL UNIQUE CHECK (octet_length(webauthn_handle) = 64),
    username text NOT NULL CHECK (char_length(username) BETWEEN 1 AND 320),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 320),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    disabled_at timestamptz,
    CHECK (updated_at >= created_at),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at)
);

CREATE TABLE devices (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    owner_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 320),
    platform text NOT NULL DEFAULT 'ios' CHECK (char_length(platform) BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    revoked_at timestamptz,
    UNIQUE (owner_id, id),
    CHECK (last_seen_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX devices_owner_active_idx
    ON devices (owner_id, last_seen_at DESC)
    WHERE revoked_at IS NULL;

CREATE TABLE bootstrap_tokens (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    disabled_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at)
);

CREATE INDEX bootstrap_tokens_active_expiry_idx
    ON bootstrap_tokens (expires_at)
    WHERE consumed_at IS NULL AND disabled_at IS NULL;

CREATE TABLE passkeys (
    rp_id text NOT NULL CHECK (char_length(rp_id) BETWEEN 1 AND 253),
    credential_id bytea NOT NULL CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    owner_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id text NOT NULL,
    credential_ciphertext bytea NOT NULL CHECK (octet_length(credential_ciphertext) > 0),
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    PRIMARY KEY (rp_id, credential_id),
    FOREIGN KEY (owner_id, device_id) REFERENCES devices(owner_id, id) ON DELETE CASCADE,
    CHECK (last_used_at IS NULL OR last_used_at >= created_at)
);

CREATE INDEX passkeys_owner_rp_idx ON passkeys (owner_id, rp_id);
CREATE INDEX passkeys_device_idx ON passkeys (owner_id, device_id);

CREATE TABLE session_refresh_families (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    owner_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id text NOT NULL,
    created_at timestamptz NOT NULL,
    last_rotated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    replay_detected_at timestamptz,
    UNIQUE (id, owner_id, device_id),
    FOREIGN KEY (owner_id, device_id) REFERENCES devices(owner_id, id) ON DELETE CASCADE,
    CHECK (last_rotated_at >= created_at),
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK (replay_detected_at IS NULL OR replay_detected_at >= created_at)
);

CREATE INDEX session_families_owner_active_idx
    ON session_refresh_families (owner_id, device_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX session_families_expiry_idx
    ON session_refresh_families (expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE session_tokens (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    family_id text NOT NULL,
    owner_id text NOT NULL,
    device_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('access', 'refresh')),
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    parent_token_id text REFERENCES session_tokens(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (family_id, owner_id, device_id)
        REFERENCES session_refresh_families(id, owner_id, device_id) ON DELETE CASCADE,
    CHECK (expires_at > created_at),
    CHECK (used_at IS NULL OR used_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX session_tokens_owner_active_idx
    ON session_tokens (owner_id, device_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX session_tokens_family_idx ON session_tokens (family_id, created_at DESC);

CREATE INDEX session_tokens_expiry_idx
    ON session_tokens (expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX session_tokens_refresh_replay_idx
    ON session_tokens (family_id, used_at, id)
    WHERE kind = 'refresh';
