# Local checkpoint and restore

Local checkpoints live on the same VPS storage. They help with file mistakes,
destructive Git actions, suspension and maintenance; they do **not** protect
against whole-server/storage loss. Verify free space before every checkpoint
and preserve dirty/unpushed work. The current script retains database dumps for
14 days and workspace archives for 30 days; production scheduling and a hard
disk-quota guard must be proven on the VPS before relying on those periods.

The infrastructure script refuses to start unless the filesystem can preserve
the 40 GiB host reserve plus the configured maximum archive size (4 GiB for a
database dump and 16 GiB for a workspace by default). It serializes writers,
captures producer and compressor failures independently, enforces the
compressed-size cap, validates gzip integrity (and workspace tar structure),
syncs the result, and only then atomically publishes the final filename. A
failure leaves no final or partial archive. The byte limits can be lowered for
an approved smaller installation with `CHECKPOINT_RESERVE_BYTES`,
`CHECKPOINT_DATABASE_MAX_BYTES`, and `CHECKPOINT_WORKSPACE_MAX_BYTES`; do not
lower the reserve below the measured control-stack requirement.

## In-app local recovery

The authenticated workspace Git screen lists local checkpoints with their UTC
time, reason, archive version, file/deletion counts, SHA-256, and current hash
verification status. A failed hash disables restore. The app exposes two
owner-confirmed operations:

- **Restore file** accepts one clean workspace-relative path. Version 1 and 2
  checkpoints can be used when that file is present and its digest verifies.
- **Restore workspace** requires an identity-bound version 2 checkpoint. It
  applies only the recorded delta over the current workspace: recorded files
  are atomically replaced, recorded deletions are removed, and unrelated paths
  remain unchanged. Version 1 is rejected with an explicit file-restore-only
  precondition; it is never reinterpreted as a full snapshot.

Both operations verify the persisted archive hash, strict manifest, workspace
identity, version, entry/file/expanded-size caps, paths, modes, duplicate and
case-conflicting names, hierarchy conflicts, and per-file hashes before any
live change. Symlinks, hard-link/special-file representations, `.git`, sensitive
paths, traversal, and unmanifested data fail closed. The control plane creates
a mandatory pre-restore checkpoint first. Full restore stages every replacement
in a private sibling directory, holds `.git/index.lock` so concurrent terminal
Git is surfaced as a conflict, and applies through a private `.git` rollback
journal. A failed apply rolls back in reverse order. If rollback is incomplete,
the helper retains the private journal and reports a conflict instead of
claiming success. Checkpoint storage is outside the workspace and is never a
restore target.

Confirmed native Git discard follows the same boundary: it checkpoints first,
accepts selected tracked paths only, and runs `git restore --source=HEAD
--staged --worktree -- <paths>`. It never invokes reset, force, rebase, or
history rewriting. The response and iOS screen keep the recovery checkpoint ID
and restore action visible. Native pull is fast-forward-only; ahead/behind,
dirty/conflict state, and an actionable terminal fallback are returned when it
cannot fast-forward. Manual conflict resolution remains authoritative in the
real terminal.

## Create and validate

```shell
sudo /bin/sh /opt/codex-mobile/current/scripts/infra-checkpoint.sh --database
sudo /bin/sh /opt/codex-mobile/current/scripts/infra-checkpoint.sh --workspace <WORKSPACE_ID>
```

A workspace must be suspended/stopped; the script refuses running containers
and requires exactly one workspace-labeled data volume. For every returned
absolute path, verify it stays beneath `/srv/codex-mobile/checkpoints`, is
root-only, nonempty, and passes `gzip -t`. Record size, UTC time, workspace ID
and SHA-256 only—never archive contents.

## Operator restore of one file from an infrastructure volume archive

1. Suspend the workspace, record Git/dirty/unpushed status, and create a new
   pre-restore archive. Ask the owner to approve the checkpoint/time and target
   path.
2. Extract the selected archive as root into a new mode-`0700` quarantine
   directory on the encrypted data filesystem. Reject absolute paths, `..`,
   device/FIFO/socket entries, hard links, and any symlink whose resolved target
   leaves the extracted root. Do not preview binary/sensitive content in logs.
3. Compare the quarantined file's type, size and SHA-256. Restore through the
   normal root-confined file API with the current expected ETag, or through a
   reviewed no-follow/atomic operator tool. Never `tar -x` directly over the
   live volume.
4. Resume, verify the file/Git state, then securely remove quarantine. Keep the
   pre-restore checkpoint through the observation window.

This procedure is for the separate infrastructure volume archives produced by
`infra-checkpoint.sh`. Do not feed those tar/gzip archives to the in-app ZIP
checkpoint API. Manual archive extraction remains a drill for a
security-reviewed operator; the shipped safe helper described above operates
only on bounded app-created local checkpoint archives.

## Restore an entire stopped workspace volume

This is destructive and requires explicit approval. Capture `podman volume
inspect` metadata and the exact template release first. Create a scratch volume
through the same private quota runtime with the captured XFS size/inode options,
import the archive into it, attach it only to a disposable no-network
validation container, and verify ownership, confinement, Git fsck/status,
absence of special files, quota enforcement, and expected checkout. Access to
that engine is root-equivalent and belongs only in the owner-approved operator
procedure.

Only after validation: stop the workspace, export the current live volume,
remove/recreate the fixed-name live volume with the captured labels/options,
import the approved archive, and resume. Abort if Coder/Podman has changed the
volume contract; do not improvise a label/name swap. Run the two-workspace
isolation tests afterward. Exact commands must be recorded from a successful
target-Podman drill before this procedure is marked executable.

## Restore PostgreSQL

1. Confirm the dump checksum/time and accepted data loss; create a current dump
   if PostgreSQL is healthy. Ask the owner to approve destructive database
   replacement.
2. Stop control plane and external provisioner while leaving PostgreSQL
   private. Validate the gzip and restore into a disposable database/container
   first. Run migrations and integrity checks there.
3. If validated, use the deployed Compose wrapper to restore `pg_dumpall` as
   the configured admin over stdin—never place a password in argv. Restart in
   dependency order, apply forward migrations, run `infra-health.sh`, then test
   passkey, sessions, repository/workspace ownership and audit continuity.

Database restore and whole-volume restore have not been executed on this
Windows host. Record them as `GATED`, not passing, until a target-VPS drill
captures exact redacted commands and evidence.
