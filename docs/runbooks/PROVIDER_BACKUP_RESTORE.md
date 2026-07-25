# Provider included-backup restore

The provider's included daily whole-server/volume backup is the only off-host
recovery layer. Local checkpoints are lost with the server. A restore can roll
back roughly 24 hours, destroy newer state, change IP/boot state, and be an
external provider mutation; the repository never invokes it automatically.

The backup is expected to contain the encrypted database/workspace state and
the root-owned host master-key file together. That is useful for consistent
availability recovery but provides no cryptographic separation from provider
administrators or compromise of the full backup. The owner-held offline key is
an independent copy for key loss/corruption, not evidence that the provider copy
is keyless. Treat unauthorized provider/full-backup access as master-key scope.

## Quarterly verification drill

1. In the provider console, read without mutation: backup enabled state,
   successful capture time, protected disk/instance, retention, restore method,
   price/add-on state and estimated interruption. Reject any paid snapshot,
   premium tier, temporary second server or metered transfer.
2. Compare the latest capture time to UTC and record the honest recovery-point
   window. Confirm a server loss could lose all changes since that point.
3. Prefer a provider-supplied non-destructive integrity/test mechanism only if
   it creates no second paid resource. Otherwise schedule a restore-in-place
   drill, warn the owner, drain/checkpoint locally, and obtain explicit approval
   for the exact backup/time and expected downtime.
4. After restore, verify encrypted data mount, SSH/firewall/audit, pinned
   release links and images, the exact XFS project-quota mount, private
   root-owned Podman socket ownership, provisioner/user-namespace identities,
   PostgreSQL/Coder, workspace volume/quota isolation, app health,
   passkey/session behavior, genuine Codex login/TUI, terminal process status,
   Git dirty/unpushed state, previews, APNs/GitHub and checkpoint scheduler.
   Active pre-backup processes must be described as stopped unless actually
   recovered. Re-run the disposable write-past-quota and socket-isolation spike
   before accepting new workspaces. Confirm the restored root-owned master-key
   file authenticates the restored database without printing key or plaintext
   values. If the host key is absent, use only the offline copy proven to match
   that recovery point; never try keys against production by guesswork.
5. Rotate credentials if the restored image contains older or revoked copies.
   Reapply only reviewed forward changes; never mix a newer database with an
   incompatible older encrypted master key. If the restore follows suspected
   provider/full-backup compromise, assume encrypted values were readable and
   rotate/re-enter them; rewrapping alone does not undo exposure.

If the provider requires restoring to a temporary second VPS or bills any
restore/snapshot transfer, stop. That conflicts with the one-fixed-VPS contract
unless the owner makes a new product/cost decision. Do not authorize it from
this runbook.

No provider account or VPS is connected, purchased or mutated in this
worktree. Included-backup enablement and restoration remain `GATED` until the
owner approves the provider and a live drill.
