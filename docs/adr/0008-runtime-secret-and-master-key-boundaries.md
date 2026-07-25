# ADR 0008: Runtime secret and master-key boundaries

## Status

Accepted.

## Context

Owner vault values need an explicit workspace runtime boundary without becoming
repository or persistent-volume files. Native Git actions must warn before an
active granted value is staged or pushed, including common encoded forms. The
single database master key also needs a recoverable rotation path: replacing
the key file blindly would strand passkeys, workspace records, user secrets,
and APNs tokens that use different versioned AAD identities.

## Decision

The control plane decrypts only active explicit grants applicable to the
workspace owner and repository. It passes bounded byte buffers only in the
trusted configure request and wipes store results and serialized requests. The
helper validates names/count/bytes, writes the grant map only under its private
tmpfs runtime with mode `0600`, merges it into terminal environments in memory,
and deletes it at checkpoint/suspend sealing. Grant/revoke operations serialize
per workspace, commit the database change, reload the complete authoritative
grant set, and replace that tmpfs file for future process launches. Runtime
sync failures are surfaced as committed-database partial failures. Every new
terminal process performs this sync again before its PTY can open. Resume
reruns configure.

The current authoritative grant values also construct a mandatory streaming
terminal-output redactor before PTY registration. It removes exact, hex,
standard/URL base64, URL-escaped, and wrapped forms across chunk boundaries
before replay or cache. Unsupported value/count/derived-pattern bounds fail
terminal start rather than bypassing redaction.

Every native stage, commit, pull, and push builds a short-lived scanner from the
currently materialized values. Raw, hex, standard/URL base64, and query/path URL
forms are bounded and matched without identifying the matching secret. Values
under eight bytes are injected but intentionally excluded from matching to
avoid destroying ordinary source text. File, blob, pattern, count, and aggregate
limits fail closed; Linux worktree reads use beneath/no-symlink `openat2`.

Each serve process holds a shared session advisory lock. The offline
`rewrap-master-key` command requires the matching exclusive lock and one
serializable transaction. It loads every passkey, every `encrypted_secrets` row
including soft-deleted prompts, and every APNs endpoint; derives only recognized
v1 AAD; authenticates the old envelope; rewraps its data key; decrypt-verifies
under the new master; and prepares every update before applying any. Unknown
row shapes or versions abort. Audit details contain only per-family counts. The
command reads but never mutates either key file; the operator atomically switches
configuration after commit and retains a matching database checkpoint for
post-commit rollback.

The master key is outside PostgreSQL and database-only exports, but remains a
root-owned file on the same VPS. The contracted whole-server provider backup is
expected to capture it together with encrypted state. A separate owner-held
offline copy protects availability after key loss/corruption; neither copy makes
the provider backup cryptographically separate.

## Consequences

Repository code with the workspace's authority can still read an injected
secret and may bypass the native Git UI by invoking Git directly. Four-byte
values are the minimum vault/redaction boundary; native Git deliberately needs
a longer safe matching threshold to avoid making ordinary source unusable.
Runtime revoke and checkpoint sealing change future materialization but cannot
remove values already inherited by a running process, so that process must be
closed and suspension must stop the runtime. The terminal redactor cannot
recognize unrelated sensitive output that is not a derived form of an active
grant. Rewrapping protects future use of the old wrapping key but does not
remediate plaintext previously exposed on a compromised host or full-server
backup. Live tmpfs, full PostgreSQL rotation, and operator
checkpoint/key-switch drills remain target-Linux gates.
