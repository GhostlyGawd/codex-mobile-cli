# Active host loss and deferred VPS recovery

The active private beta runs on the owner PC and D-backed Ubuntu WSL under
[ADR 0025](../adr/0025-owner-pc-private-beta-hosting.md). If Windows, WSL, or
its storage is lost, stop or revoke public ingress and active sessions, preserve
available metadata, recover only from owner-controlled validated copies, and
revalidate services, credentials, repository state, and acceptance gates before
readmission. Local checkpoints, terminal replay, active tmux processes,
unpushed Git work, and unbacked changes may be lost. No provider backup,
automatic failover, or replacement purchase is assumed for this beta.

## Deferred future VPS procedure

The remaining procedure applies only if the owner explicitly reopens and
deploys the VPS design. Its expected provider recovery point can be about 24
hours, with no HA or automatic failover or capacity purchase.

1. Declare an incident and determine whether loss is availability-only or a
   compromise. Revoke public sessions/routes, GitHub keys/tokens, Coder tokens,
   APNs keys and ChatGPT/Codex sessions appropriate to scope. Preserve only
   metadata/provider audit evidence.
2. Ask the provider to preserve/investigate existing storage without adding a
   paid service. If the existing VPS can be restored in place, follow
   [PROVIDER_BACKUP_RESTORE.md](PROVIDER_BACKUP_RESTORE.md) after explicit owner
   approval. Do not automatically create a replacement server.
3. If a replacement purchase/rebuild is required, present the full current
   monthly cart and obtain separate owner approval. Ensure the previous bill is
   terminated or otherwise prove only one new recurring VPS remains; never
   overlap paid servers by assumption.
4. Rebuild Ubuntu 24.04 from pinned source using [DEPLOY.md](DEPLOY.md), restore
   the provider backup or validated database/workspace data. A whole-server
   provider restore should already contain the matching root-owned host master
   key; validate the pair without exposing values. Use the offline matching copy
   only if that host file is missing/corrupt or when restoring a database-only
   export. If no matching key exists, encrypted values are unrecoverable. If the
   server/provider/full backup may have been exposed, treat the values as
   compromised and rebuild identity/rotate or re-enter secrets rather than
   assuming envelope encryption protected them.
5. Revalidate DNS/API/wildcard TLS after an IP change only with owner-approved
   DNS mutations. Reinstall GitHub/APNs credentials, reauthenticate Codex via
   device code, and re-enroll passkeys as needed.
6. Reconcile each repository against GitHub: identify commits present remotely,
   mark unpushed changes since backup as lost unless independently recovered,
   and do not claim terminal processes survived. Verify all acceptance gates
   and isolation before admitting normal work.

Record the last-known-good time, provider backup time, restored time, actual
data loss and credentials rotated. Never hide the recovery gap.
