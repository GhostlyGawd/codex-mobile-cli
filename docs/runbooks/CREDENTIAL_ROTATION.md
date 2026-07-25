# Credential rotation

Rotate one credential class at a time unless incident containment requires a
coordinated reset. Create a database checkpoint first, keep a secure rollback
copy only for the shortest observation window, and never place old/new values
on a command line. Live Compose secret files are root-owned mode `0444` beneath
a root-owned mode-`0700` directory; a replacement may remain `0600` while it is
being written, but must become `0444` immediately before an atomic same-filesystem
replacement so the declared non-root container can read its direct mount.

| Credential | Expected effect | Procedure/gate |
| --- | --- | --- |
| Session pepper | Invalidates persisted token hashes and signs out every device | Maintenance window; replace file atomically, restart control plane, verify old refresh rejection and new passkey login |
| Coder control-plane token | Workspace lifecycle/SSH temporarily unavailable | Create least-privilege replacement in private Coder UI after owner approval, install file, restart/test, revoke old token |
| Coder provisioner key | New builds queue while daemon changes | Create the same exact private provisioner tag/scope, install file, restart/prove one build, then revoke the old key. The provisioner can reach the private root-owned Podman API, so treat its credential and group membership as root-equivalent host authority |
| GitHub App private key/client/webhook secrets | Repository sync/operations or webhook delivery pause | Follow GitHub's manual owner-approved key creation; overlap only long enough to deploy/test, then revoke old key and redeliver a signed event |
| APNs signing key | Notifications pause; sessions/workspaces continue | Create owner-approved replacement, install only in matching environment file, restart/test generic payload, then revoke old key |
| PostgreSQL role passwords | Database restart/reconnect window | Rotate one role using a local `psql` session and same-transaction validation; atomically update its secret/URL, restart dependent service, then discard old value |
| Codex/ChatGPT device credential | Affected workspaces require device login | Use the confirmed per-workspace disconnect to stop only app-owned Codex tmux and remove local tmpfs/encrypted auth while preserving conversation history/non-Codex processes; separately revoke the upstream session when compromise scope requires it, perform genuine device auth, verify TUI/resume |
| TLS/DNS credential | Public auth/preview risk | Follow the reviewed DNS-01 or external-certificate path; validate full chain/API/wildcard before removing old material |

## Routine connection disconnect and recovery

The Settings connection view is owner-authenticated and metadata-only. It
separates server GitHub App configuration from the owner's active local
installations and reports ChatGPT Codex state per workspace. A stopped,
suspended or unreachable workspace reports unavailable rather than exposing or
guessing credential/account state.

GitHub disconnect sets the dedicated local `owner_disconnected_at` boundary,
marks repositories unavailable and blocks workspace initialization/native
remote token minting before any GitHub call. It is idempotent, survives ordinary
webhook installation upserts and does not uninstall/change the external App or
revoke a provider token already issued. Webhooks cannot reconnect it. After
reviewing the intended provider installation, only the explicit owner-run
`github-sync` path clears the local flag. Provider-side App
install/uninstall/repository/permission/key changes remain separate approved
actions under [GITHUB_APP.md](GITHUB_APP.md).

Per-workspace Codex disconnect requires a running/ready/idle/needs-attention
runtime and explicit confirmation. The control plane serializes the mutation
and validates every stored Codex terminal identity. The helper then kills only
their fixed app-owned `cm-<tab-id>` tmux sessions, waits for credential leases,
and deletes materialized tmpfs auth, the tmpfs key and persistent encrypted auth
envelope. That confirmation is the security commit point. Control-plane runtime
unregister follows; a cleanup failure is returned and audited with credentials
already revoked. Conversation session history and non-Codex tmux/shell
processes remain. This does not revoke the upstream ChatGPT account/session.
Resume the workspace if needed, complete `codex login --device-auth` in the real
TUI, and verify retained conversation resume to reconnect.

Live acceptance remains gated. With owner credentials, prove local GitHub
disconnect denies repositories/provider calls, a webhook cannot reconnect it,
explicit sync can reconnect, and provider uninstall remains separate. On Linux,
keep an unrelated shell/history, disconnect Codex, prove only app-owned Codex
sessions stop and all tmpfs/key/encrypted auth paths disappear, inject a runtime
unregister failure and prove auth stays revoked, then complete fresh device
login/resume. Record identifiers/counts/outcomes only, never token/auth content.

## Master encryption key

Do **not** replace `control_plane_master_key` in place. Passkey credential
ciphertexts, every `encrypted_secrets` family, and APNs tokens use it; a blind
replacement makes them undecryptable. Rotation is an offline maintenance
operation:

1. Take and verify a PostgreSQL recovery checkpoint. Stop every
   `control-plane serve` process and keep public traffic disabled. Leave the
   current `MASTER_KEY_FILE` configured.
2. Generate a different 32-byte key into a new root-owned mode-`0400` or
   mode-`0600` file beneath a root-owned mode-`0700` directory. Keep both key
   files outside PostgreSQL, database-only dumps, command arguments, shell
   history, and evidence records. They remain host files, so a scheduled
   whole-server provider backup can capture them; access to such a backup must
   be treated as access to the wrapping keys, not as cryptographically separated
   ciphertext.
3. Run exactly:

   ```shell
   NEW_MASTER_KEY_FILE=/absolute/private/new-key \
     /bin/sh /opt/codex-mobile/current/scripts/infra-admin.sh \
       rewrap-master-key --confirm=REWRAP-ALL-ENVELOPES
   ```

   `NEW_MASTER_KEY_FILE` is a path, never key material. The root-only wrapper
   validates a non-symlink, single-link, bounded key beneath a root-owned
   mode-`0700` directory, stages it as a read-only direct container mount under
   root-only `/run`, and passes only the fixed in-container path to the exact
   manifest-recorded control-plane image. It stops Caddy/control-plane but
   leaves PostgreSQL running, and refuses while any serve process still holds
   its database lease. In a
   serializable transaction it locks and rewraps every passkey, user-vault
   secret, workspace environment value, initial prompt including soft-deleted
   rows, workspace Codex authentication key, and APNs token. It authenticates
   each old envelope and decrypt-verifies every new envelope before the first
   update. An unknown row shape, legacy `aad_version`, tamper, size limit, or
   update failure rolls back the entire transaction; no row is skipped.
4. Check the success log and `vault.master_key.rewrap` audit event. They contain
   counts only. Do not continue if counts differ from the maintenance record.
5. The wrapper deliberately leaves public service stopped. Without starting it
   in between, set the new file to mode `0444`
   and atomically switch the configured `MASTER_KEY_FILE` reference from the
   untouched old file to the untouched new file. Start the service and verify passkey authentication, encrypted
   workspace configuration/grants, Codex resume, and APNs endpoint loading.
6. Keep the old key and matching pre-rotation database checkpoint only for the
   approved observation window. A post-commit rollback restores that exact
   checkpoint and the old key reference together; mixing either key with the
   other database state fails authentication. Securely destroy rollback
   material after verification. Record which key/database generation is present
   in each retained provider recovery point. A provider backup captured during
   rotation may retain an old or new host key for its normal retention period;
   deleting the live rollback copy does not erase that provider copy.

The command never rewrites, renames, deletes, or chmods either key file. Its
transactional rollback covers failures before commit; the operator-controlled
database checkpoint is the rollback boundary after commit.

If the master key, host, or whole-server provider backup is suspected
compromised, contain the service, revoke public
sessions/routes and upstream credentials, preserve metadata-only evidence, and
assume every encrypted value available to the running host may be exposed.
Rewrapping prevents future use of the old wrapping key but does not erase prior
exposure: rotate or re-enter user/runtime values, re-enroll passkeys as needed,
and revoke upstream credentials. Do not treat rewrapping alone as containment.

## Completion checks

Verify the old credential is rejected, the new credential works only at its
intended boundary, integrations remain least-privilege, no secret appears in
process arguments/logs/Git/workspace files, and rollback material is securely
destroyed after the observation window. Record only identifiers, timestamps,
scope, and outcomes.
