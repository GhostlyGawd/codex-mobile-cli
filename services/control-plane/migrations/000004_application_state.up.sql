-- Forward-only migration: owner preferences and persistent terminal metadata.

ALTER TABLE encrypted_secrets
    ADD COLUMN workspace_id text;

ALTER TABLE encrypted_secrets
    ADD CONSTRAINT encrypted_secrets_workspace_fk
    FOREIGN KEY (owner_id, workspace_id)
    REFERENCES workspaces(owner_id, id) ON DELETE CASCADE;

CREATE INDEX encrypted_secrets_workspace_idx
    ON encrypted_secrets (owner_id, workspace_id, updated_at DESC)
    WHERE workspace_id IS NOT NULL AND deleted_at IS NULL;

ALTER TABLE repositories
    ADD COLUMN available boolean NOT NULL DEFAULT true;

CREATE INDEX repositories_available_idx
    ON repositories (owner_id, full_name)
    WHERE available;

CREATE TABLE user_settings (
    owner_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    autonomy_default text NOT NULL DEFAULT 'balanced'
        CHECK (autonomy_default IN ('safe', 'balanced', 'full_access')),
    retention_default text NOT NULL DEFAULT '30_days'
        CHECK (retention_default IN ('7_days', '30_days', '90_days', 'keep_forever')),
    idle_timeout_minutes integer NOT NULL DEFAULT 30
        CHECK (idle_timeout_minutes BETWEEN 5 AND 10080),
    terminal_font_size double precision NOT NULL DEFAULT 14
        CHECK (terminal_font_size BETWEEN 8 AND 48),
    terminal_theme text NOT NULL DEFAULT 'system'
        CHECK (char_length(terminal_theme) BETWEEN 0 AND 100),
    terminal_cursor_style text NOT NULL DEFAULT 'block'
        CHECK (terminal_cursor_style IN ('block', 'beam', 'underline')),
    quiet_hours_enabled boolean NOT NULL DEFAULT false,
    notification_detail_enabled boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL
);

CREATE TABLE repository_preferences (
    owner_id text NOT NULL,
    repository_id text NOT NULL,
    favorite boolean NOT NULL DEFAULT false,
    last_used_at timestamptz,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (owner_id, repository_id),
    FOREIGN KEY (owner_id, repository_id)
        REFERENCES repositories(owner_id, id) ON DELETE CASCADE
);

CREATE INDEX repository_preferences_recent_idx
    ON repository_preferences (owner_id, last_used_at DESC)
    WHERE last_used_at IS NOT NULL;

CREATE TABLE terminal_tabs (
    id text PRIMARY KEY CHECK (char_length(id) = 36),
    owner_id text NOT NULL,
    workspace_id text NOT NULL,
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 120),
    kind text NOT NULL CHECK (kind IN ('codex', 'shell', 'server', 'test', 'log')),
    sort_order integer NOT NULL CHECK (sort_order BETWEEN 0 AND 999),
    coder_reconnect_id text NOT NULL UNIQUE CHECK (char_length(coder_reconnect_id) = 36),
    codex_thread_id text NOT NULL DEFAULT '' CHECK (char_length(codex_thread_id) <= 160),
    created_at timestamptz NOT NULL,
    last_attached_at timestamptz,
    closed_at timestamptz,
    FOREIGN KEY (owner_id, workspace_id)
        REFERENCES workspaces(owner_id, id) ON DELETE CASCADE,
    CHECK (last_attached_at IS NULL OR last_attached_at >= created_at),
    CHECK (closed_at IS NULL OR closed_at >= created_at)
);

CREATE UNIQUE INDEX terminal_tabs_active_order_idx
    ON terminal_tabs (owner_id, workspace_id, sort_order)
    WHERE closed_at IS NULL;

CREATE INDEX terminal_tabs_active_workspace_idx
    ON terminal_tabs (owner_id, workspace_id, created_at)
    WHERE closed_at IS NULL;
