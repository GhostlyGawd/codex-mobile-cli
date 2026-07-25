# ADR 0007: Process-scoped Codex credential materialization

- Status: accepted
- Date: 2026-07-16

## Context

Codex CLI 0.144.5 supports file, keyring, automatic, and ephemeral CLI
credential stores. A Linux keyring cannot be assumed after an approved Dev
Container replaces the workspace root. The ephemeral mode loses device login
across processes and restarts, while an ordinary file store leaves
`auth.json` plaintext in the persistent workspace volume.

The repository and Dev Container execute with the same runtime identity as the
interactive Codex process. No wrapper can make an in-use credential unreadable
to hostile code with that same authority; the goal is to remove plaintext from
the stopped workspace, backups, checkpoints, and normal filesystem browsing.

## Decision

The managed pinned config sets `cli_auth_credentials_store = "file"` and
`forced_login_method = "chatgpt"`. A per-workspace random 32-byte key is stored
as an envelope-encrypted `encrypted_secrets` record in PostgreSQL. On provision
and resume, the control plane sends the unwrapped key only in the bounded
trusted-helper configure request. The helper writes the key and configured
runtime environment only beneath `/tmp/codex-mobile-runtime`, which is a
container tmpfs in both workspace modes.

The immutable helper volume contains the wrapper, the exact pinned Codex binary,
and its code-mode host. Both the Coder terminal and normal `codex` command use
the wrapper; the real binary is invoked by a fixed absolute path. The wrapper
materializes `auth.json` on tmpfs, links the dedicated persistent `CODEX_HOME`
to that process-scoped file, supports concurrent commands with locked lease
records, and AES-256-GCM seals the file to
`/workspaces/.codex-mobile/codex-auth.json.enc` after the last process exits.
Checkpoint, suspend, and delete boundaries request a synchronous seal. Missing
keys, wrong keys, tampered envelopes, unsafe file types/modes, API-key login
arguments, and non-ChatGPT auth records fail closed without reflecting secret
data.

The helper securely removes the legacy persistent `environment.json`; runtime
environment plaintext is restored to tmpfs by the same idempotent initializer
on resume.

## Consequences

- Stopped workspace volumes and their backups contain authenticated ciphertext,
  not Codex or configured-environment plaintext.
- A container stop clears the key and materialized auth. Resume therefore must
  complete trusted configuration before terminals are available.
- Concurrent wrapper processes share one tmpfs auth file and the last exiting
  lease seals it. A checkpoint also seals while a long-running TUI is active.
- A hard-killed wrapper can leave plaintext only on the running container's
  tmpfs until the next launch/checkpoint or container stop.
- Same-authority repository code can read an in-use credential, execute the
  mounted real binary directly, delete ciphertext, or deny service. Preventing
  that requires a stronger process/VM isolation boundary and is not claimed.
- Linux tmpfs, permissions, symlink behavior, helper-volume immutability, and a
  genuine ChatGPT device-login/refresh/resume flow remain deployment acceptance
  gates.
