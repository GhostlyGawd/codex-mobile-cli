# Incident response

## Classify and contain

- **SEV-1:** suspected host/container escape, master/GitHub/Coder credential
  compromise, cross-workspace data exposure, unauthorized production change,
  or total outage with data-loss risk.
- **SEV-2:** one-account/device/workspace compromise, repeated auth/preview
  bypass attempt, active-host recovery failure, or sustained capacity
  exhaustion.
- **SEV-3:** degraded non-security feature with bounded impact.

Open a UTC incident record. Preserve available Windows/WSL, ingress, auditd,
Caddy, Coder, and application **metadata-only** logs with hashes and access
controls. Include provider or SSH logs only for an explicitly configured future
remote host. Never copy prompts, terminal streams, full commands, source/file
contents, or secrets into the record.

For SEV-1, restrict the public edge/firewall, stop new admission, revoke preview
routes and sessions, and stop the external provisioner/workspace runtime when
host isolation is in doubt. Do not destroy containers/storage before evidence
and checkpoint decisions. If attacker persistence is possible, do not trust
the host to rotate or store replacement keys.

Treat unauthorized access to any whole-host recovery copy containing encrypted
rows/workspace state and the root-owned host key as master-key compromise. If a
future VPS provider backup is configured, the same boundary applies; the
offline owner copy does not make that provider artifact cryptographically
separate.

## Scope and eradicate

Build a boundary timeline from authentication/device, GitHub installation,
workspace lifecycle, safety mode, secret grant, approval, preview, destructive
Git and admin audit metadata. Determine affected owner/device/repository,
workspaces, data period and credentials. Use `SECURITY.md` threat rows to select
preventive-control and recovery tests.

Revoke at the authoritative upstream, rebuild from pinned clean media, restore
only verified data, and rotate in the order in
[CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md). For a
master-key/host/full-backup compromise, discard/re-enter encrypted runtime
secrets; ciphertext rewrapped
under a new key is not proof the plaintext was safe. For stolen devices, follow
[PASSKEY_RECOVERY.md](PASSKEY_RECOVERY.md). For server loss, follow
[SERVER_LOSS.md](SERVER_LOSS.md).

The Settings disconnects are local containment, not upstream revocation.
GitHub disconnect blocks new local token minting but does not uninstall the App
or invalidate a token already issued by GitHub. Per-workspace Codex disconnect
removes that workspace's app-owned sessions/auth but does not revoke the
upstream ChatGPT account/session. Follow the connection lifecycle in
[CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md), then complete the
corresponding provider-side action when incident scope requires it.

## Recover and review

Before reopening admission, run health, supply-chain, isolation, auth/session
replay, terminal reconnect/backpressure, file traversal/symlink, preview
auth/revocation, GitHub token persistence and generic APNs tests. Owner-gated
tests remain gated. Monitor local metrics/logs through an agreed observation
window; do not add external telemetry.

Write a blameless report: impact, detection, containment, recovery point, data
loss, credentials rotated, root cause, control/test changes and residual risk.
Update threat model, ADRs, runbooks and acceptance evidence. Notify affected
parties only with owner/legal direction and the minimum sensitive detail.
