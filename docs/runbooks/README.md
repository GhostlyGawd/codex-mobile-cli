# Operations runbooks

These procedures operate a single-owner, single-VPS service. They never grant
permission to purchase a VPS, change DNS, create a GitHub App or Apple key,
restore a provider backup, push source, or upload a TestFlight build. The owner
must explicitly approve each such external mutation immediately before it is
performed. Commands in this repository configure only an already-owned host.

## Runbook index

| Operation | Runbook |
| --- | --- |
| Public hosted CI policy | [CI.md](CI.md) |
| First production deployment | [DEPLOY.md](DEPLOY.md) |
| Application rollback | [ROLLBACK.md](ROLLBACK.md) |
| Controlled dependency/host update | [UPDATE.md](UPDATE.md) |
| Passkey loss or replacement | [PASSKEY_RECOVERY.md](PASSKEY_RECOVERY.md) |
| Credential and encryption-key rotation | [CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md) |
| GitHub App creation/configuration | [GITHUB_APP.md](GITHUB_APP.md) |
| APNs keys and delivery environments | [APNS.md](APNS.md) |
| Local checkpoint/file/database restore | [CHECKPOINT_RESTORE.md](CHECKPOINT_RESTORE.md) |
| Provider included-backup drill/restore | [PROVIDER_BACKUP_RESTORE.md](PROVIDER_BACKUP_RESTORE.md) |
| Complete server loss | [SERVER_LOSS.md](SERVER_LOSS.md) |
| Security/availability incident response | [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) |
| Owner-only TestFlight archive/upload | [TESTFLIGHT.md](TESTFLIGHT.md) |
| Release decision | [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) |

## Rules common to every procedure

1. Open an operator record with UTC start time, operator, reason, intended
   release (`sha-<commit>`), recovery point, and explicit owner approvals. Do
   not include prompts, terminal bytes, commands, file contents, or secrets.
2. Check `git status`, immutable image digests, [the supply-chain gate](../security/SUPPLY_CHAIN.md),
   local checkpoint capacity, provider-backup state, and current health.
3. Use an SSH key from an allowlisted address. Never paste secrets into a shell
   command, ticket, chat, or terminal transcript; install them through root-only
   files as root-owned mode `0444` under the root-owned mode-`0700` secrets
   directory. Docker mounts only each service's declared file.
4. Pause before each external mutation. Record only the approval time and type,
   not account identifiers or key material.
5. Keep the prior release and recovery material until post-change checks pass.
6. Record exact commands and redacted results in `docs/verification/ACCEPTANCE.md`.
   `GATED` is the correct result for anything not actually exercised.

Local checkpoints are on the VPS and do not survive total VPS/storage loss.
The provider's included daily backup may leave an approximately 24-hour
recovery gap. Active processes cannot survive a host reboot or whole-server
restore; persistent files can, and stopped processes must be shown honestly.
The whole-server backup is expected to contain encrypted state and the
root-owned host master key together. It is an availability/recovery copy, not
cryptographic separation from provider or full-backup compromise; the offline
matching key copy protects availability only.
