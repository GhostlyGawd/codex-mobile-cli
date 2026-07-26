# ADR 0004: Passkey-only app auth and envelope-encrypted secrets

- Status: accepted
- Date: 2026-07-15

[ADR 0025](0025-owner-pc-private-beta-hosting.md) changes the active host and
backup assumption, not the passkey or encryption design. The active beta
assumes no provider backup; provider-specific recovery below is conditional on
a future explicitly reopened VPS profile.

## Decision

App authentication is WebAuthn/passkey-only after a short-lived single-use console bootstrap. Sessions use opaque random access credentials and rotating refresh families with keyed hashes at rest. Vault values use independently generated data keys and AES-256-GCM; encrypted data keys are wrapped by a root-owned host master key stored outside PostgreSQL and database-only exports. Any whole-host recovery copy must be assessed for whether it captures that key with the encrypted database. A future VPS provider backup would provide availability and key/database consistency, not cryptographic separation from provider or full-backup compromise. An owner-held offline copy is retained independently for key loss/corruption recovery.

Owner-managed values have immutable global or repository scope and
environment-variable names. A value is eligible for a workspace only through
an explicit, owner-scoped grant whose repository scope matches that workspace.
Metadata APIs never return plaintext; the sole plaintext read boundary returns
bounded mutable buffers for active grants so a runtime adapter can wipe them
after use. Grant/revoke operations serialize per workspace and, after the
database mutation commits, replace the authoritative tmpfs grant set for
future process launches. A partial runtime-sync failure is returned and
audited; every terminal launch synchronizes again and fails closed on error.

## Consequences

There is no password/email-code recovery endpoint and no redundant Face ID lock. Recovery uses the audited privileged host admin CLI; SSH applies only to an approved remote host. Losing the RP domain can require passkey re-enrollment. A compromised running host or whole-server backup can access the wrapping key and encrypted rows; field encryption still protects database-only exports but does not prevent either exposure. Revocation changes future launch state; a process already running keeps its inherited environment until it is closed.
