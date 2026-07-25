-- Forward-only migration: GitHub installations, repositories, workspaces, activity, and safety records.

CREATE TABLE github_installations (
    owner_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    installation_id bigint NOT NULL CHECK (installation_id > 0),
    account_id bigint NOT NULL CHECK (account_id > 0),
    account_login text NOT NULL CHECK (char_length(account_login) BETWEEN 1 AND 255),
    account_type text NOT NULL CHECK (account_type IN ('User', 'Organization', 'Enterprise', 'Bot')),
    repository_selection text NOT NULL CHECK (repository_selection IN ('all', 'selected')),
    permissions jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(permissions) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    suspended_at timestamptz,
    PRIMARY KEY (owner_id, installation_id),
    CHECK (updated_at >= created_at),
    CHECK (suspended_at IS NULL OR suspended_at >= created_at)
);

CREATE INDEX github_installations_owner_active_idx
    ON github_installations (owner_id, updated_at DESC)
    WHERE suspended_at IS NULL;

CREATE TABLE repositories (
    owner_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id text NOT NULL CHECK (char_length(id) BETWEEN 1 AND 160),
    installation_id bigint NOT NULL,
    full_name text NOT NULL CHECK (char_length(full_name) BETWEEN 3 AND 512),
    default_branch text NOT NULL CHECK (char_length(default_branch) BETWEEN 1 AND 255),
    private boolean NOT NULL,
    organization boolean NOT NULL,
    permission text NOT NULL CHECK (char_length(permission) BETWEEN 1 AND 64),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (owner_id, id),
    UNIQUE (owner_id, full_name),
    FOREIGN KEY (owner_id, installation_id)
        REFERENCES github_installations(owner_id, installation_id) ON DELETE CASCADE
);

CREATE INDEX repositories_installation_idx ON repositories (owner_id, installation_id);
CREATE INDEX repositories_updated_idx ON repositories (owner_id, updated_at DESC);

CREATE TABLE workspaces (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    owner_id text NOT NULL,
    repository_id text NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    branch text NOT NULL CHECK (char_length(branch) BETWEEN 1 AND 512),
    base_branch text NOT NULL CHECK (char_length(base_branch) BETWEEN 1 AND 512),
    worktree_path text NOT NULL DEFAULT '',
    state text NOT NULL CHECK (state IN (
        'queued', 'provisioning', 'awaiting_setup_approval', 'ready', 'running',
        'needs_attention', 'idle', 'suspending', 'suspended', 'failed',
        'maintenance', 'deleting'
    )),
    safety_mode text NOT NULL CHECK (safety_mode IN ('safe', 'balanced', 'full_access')),
    retention text NOT NULL CHECK (retention IN ('7_days', '30_days', '90_days', 'keep_forever')),
    nested_containers boolean NOT NULL DEFAULT false,
    setup_approved boolean NOT NULL DEFAULT false,
    dirty boolean NOT NULL DEFAULT false,
    unpushed boolean NOT NULL DEFAULT false,
    quota_cpu_milli bigint NOT NULL DEFAULT 0 CHECK (quota_cpu_milli >= 0),
    quota_memory_mib bigint NOT NULL DEFAULT 0 CHECK (quota_memory_mib >= 0),
    quota_disk_gib bigint NOT NULL DEFAULT 0 CHECK (quota_disk_gib >= 0),
    provider_resource_id text NOT NULL DEFAULT '',
    failure_code text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    last_activity_at timestamptz NOT NULL,
    UNIQUE (owner_id, id),
    UNIQUE (owner_id, branch),
    FOREIGN KEY (owner_id, repository_id) REFERENCES repositories(owner_id, id) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at),
    CHECK (last_activity_at >= created_at)
);

CREATE UNIQUE INDEX workspaces_provider_resource_idx
    ON workspaces (provider_resource_id)
    WHERE provider_resource_id <> '';

CREATE UNIQUE INDEX workspaces_worktree_path_idx
    ON workspaces (worktree_path)
    WHERE worktree_path <> '';

CREATE INDEX workspaces_owner_state_idx ON workspaces (owner_id, state, created_at);
CREATE INDEX workspaces_owner_activity_idx ON workspaces (owner_id, last_activity_at DESC);
CREATE INDEX workspaces_repository_idx ON workspaces (owner_id, repository_id, created_at DESC);
CREATE INDEX workspaces_retention_idx ON workspaces (retention, last_activity_at) WHERE state = 'suspended';
CREATE INDEX workspaces_dirty_risk_idx ON workspaces (owner_id, updated_at DESC) WHERE dirty OR unpushed;

CREATE TABLE workspace_activity (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    owner_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id text,
    kind text NOT NULL CHECK (kind IN ('approval', 'question', 'completed', 'failed', 'maintenance')),
    summary text NOT NULL CHECK (char_length(summary) BETWEEN 1 AND 4096),
    unread boolean NOT NULL DEFAULT true,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL,
    read_at timestamptz,
    FOREIGN KEY (owner_id, workspace_id) REFERENCES workspaces(owner_id, id) ON DELETE CASCADE,
    CHECK (read_at IS NULL OR read_at >= created_at)
);

CREATE INDEX workspace_activity_unread_idx
    ON workspace_activity (owner_id, created_at DESC)
    WHERE unread;

CREATE INDEX workspace_activity_workspace_idx
    ON workspace_activity (owner_id, workspace_id, created_at DESC);

CREATE TABLE workspace_state_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id text NOT NULL,
    workspace_id text NOT NULL,
    from_state text CHECK (from_state IS NULL OR from_state IN (
        'queued', 'provisioning', 'awaiting_setup_approval', 'ready', 'running',
        'needs_attention', 'idle', 'suspending', 'suspended', 'failed',
        'maintenance', 'deleting'
    )),
    to_state text NOT NULL CHECK (to_state IN (
        'queued', 'provisioning', 'awaiting_setup_approval', 'ready', 'running',
        'needs_attention', 'idle', 'suspending', 'suspended', 'failed',
        'maintenance', 'deleting'
    )),
    failure_code text NOT NULL DEFAULT '',
    actor_device_id text REFERENCES devices(id) ON DELETE SET NULL,
    occurred_at timestamptz NOT NULL,
    FOREIGN KEY (owner_id, workspace_id) REFERENCES workspaces(owner_id, id) ON DELETE CASCADE
);

CREATE INDEX workspace_state_events_timeline_idx
    ON workspace_state_events (owner_id, workspace_id, occurred_at DESC, id DESC);

CREATE TABLE workspace_safety_events (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 160),
    owner_id text NOT NULL,
    workspace_id text NOT NULL,
    actor_device_id text REFERENCES devices(id) ON DELETE SET NULL,
    safety_mode text NOT NULL CHECK (safety_mode IN ('safe', 'balanced', 'full_access')),
    action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 255),
    decision text NOT NULL CHECK (decision IN ('requested', 'approved', 'denied', 'expired', 'cancelled')),
    reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 4096),
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    resolved_at timestamptz,
    FOREIGN KEY (owner_id, workspace_id) REFERENCES workspaces(owner_id, id) ON DELETE CASCADE,
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (resolved_at IS NULL OR resolved_at >= created_at)
);

CREATE INDEX workspace_safety_pending_idx
    ON workspace_safety_events (owner_id, workspace_id, expires_at)
    WHERE decision = 'requested' AND resolved_at IS NULL;

CREATE INDEX workspace_safety_timeline_idx
    ON workspace_safety_events (owner_id, workspace_id, created_at DESC);
