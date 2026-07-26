# Operations runbooks

The active private-beta target is the owner's Windows PC and D-backed Ubuntu
WSL host under [ADR 0025](../adr/0025-owner-pc-private-beta-hosting.md).
VPS-specific procedures are retained only for a future availability migration
that the owner must explicitly reopen. These procedures never grant permission
to purchase a VPS, change DNS, enable public ingress, create a GitHub App or
Apple key, restore an external backup, push source, or upload a TestFlight
build. The owner must explicitly approve each such external mutation
immediately before it is performed.

## Runbook index

| Operation | Runbook |
| --- | --- |
| Public hosted CI policy | [CI.md](CI.md) |
| Active private-beta hosting decision | [ADR 0025](../adr/0025-owner-pc-private-beta-hosting.md) |
| Deferred future VPS deployment | [DEPLOY.md](DEPLOY.md) |
| Application rollback | [ROLLBACK.md](ROLLBACK.md) |
| Controlled dependency/host update | [UPDATE.md](UPDATE.md) |
| Passkey loss or replacement | [PASSKEY_RECOVERY.md](PASSKEY_RECOVERY.md) |
| Credential and encryption-key rotation | [CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md) |
| GitHub App creation/configuration | [GITHUB_APP.md](GITHUB_APP.md) |
| APNs keys and delivery environments | [APNS.md](APNS.md) |
| Local checkpoint/file/database restore | [CHECKPOINT_RESTORE.md](CHECKPOINT_RESTORE.md) |
| Deferred provider-backup drill/restore | [PROVIDER_BACKUP_RESTORE.md](PROVIDER_BACKUP_RESTORE.md) |
| Host loss and deferred VPS recovery | [SERVER_LOSS.md](SERVER_LOSS.md) |
| Security/availability incident response | [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) |
| Owner-only TestFlight archive/upload | [TESTFLIGHT.md](TESTFLIGHT.md) |
| Release decision | [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) |

## Rules common to every procedure

1. Open an operator record with UTC start time, operator, reason, intended
   release (`sha-<commit>`), recovery point, and explicit owner approvals. Do
   not include prompts, terminal bytes, commands, file contents, or secrets.
2. Check `git status`, immutable image digests, [the supply-chain gate](../security/SUPPLY_CHAIN.md),
   active-host checkpoint/recovery state, and current health. Check provider
   backup state only when executing an explicitly reopened VPS procedure.
3. Never paste secrets into a shell command, ticket, chat, or terminal
   transcript. Install them through root-only files as root-owned mode `0444`
   under the root-owned mode-`0700` secrets directory. Docker mounts only each
   service's declared file. Use SSH only for an approved remote-host procedure,
   from an allowlisted address with a key.
4. Pause before each external mutation. Record only the approval time and type,
   not account identifiers or key material.
5. Keep the prior release and recovery material until post-change checks pass.
6. Record exact commands and redacted results in `docs/verification/ACCEPTANCE.md`.
   `GATED` is the correct result for anything not actually exercised.

For the active beta, local checkpoints remain on owner-controlled PC/WSL
storage and do not survive loss of that storage. Active processes do not
survive a Windows, WSL, or service restart; persistent files can, and stopped
processes must be shown honestly. No provider backup is assumed.

If the owner later reopens the VPS design, its included daily backup may leave
an approximately 24-hour recovery gap. A whole-server backup would contain
encrypted state and the root-owned host master key together, so it is an
availability copy rather than cryptographic separation from provider or
full-backup compromise.
