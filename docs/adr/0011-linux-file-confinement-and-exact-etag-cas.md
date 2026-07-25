# ADR 0011: Production Linux file confinement and exact ETag CAS

- Status: accepted; target-filesystem proof required before release
- Date: 2026-07-16

## Context

Repository-controlled paths, directory entries, symlinks, and concurrent
terminal processes are hostile. Resolving a path and checking an ETag before a
normal rename leaves two races: a parent can be replaced by a symlink, and a
writer can change the destination after the last hash but before commit.
Portable APIs can confine normal reads, but do not all expose the namespace
primitive needed to identify the exact content displaced by a rename.

## Decision

The production Linux file service pins the trusted workspace root as a file
descriptor. It resolves parents with fd-relative directory opens and
`O_NOFOLLOW`, opens only regular final files, bounds every read/tree/search,
and never follows repository symlinks. Create installs a staged sibling with
no-replace semantics.

An update writes and fsyncs a randomized sibling, revalidates the expected
ETag, then atomically exchanges the staged and destination names. It hashes the
exact displaced file now at the staged name. If that hash differs from the
expected ETag, it exchanges the names back and reports a precondition failure.
The parent directory is fsynced after a successful namespace operation.

A cleanup, parent-fsync, or final-read error can occur after the destination
was changed. The API therefore treats such an error as commit-uncertain. The
caller must perform a fresh read and reconcile the returned ETag/content before
retrying; a blind retry is forbidden.

Non-Linux development uses `os.Root`, stable regular-file opens, atomic
create-only hard links, and repeated ETag validation. On platforms without
rename-exchange, an uncooperative external writer can still win the final
check-to-rename window. This backend is portable test/development support, not
the authoritative external-writer CAS claim.

## Consequences

- Production and its acceptance race suite require Linux plus filesystem
  support for rename-exchange and directory fsync.
- The service holds a pinned root descriptor for its lifetime and closes it
  deterministically in short-lived helper calls.
- Tree/search skip sensitive and special paths and enforce entry, input,
  output, result, and time/cancellation bounds.
- Live verification must exercise parent/root/path swaps, terminal-vs-native
  contention, commit rollback, and an injected post-commit uncertain error on
  the target workspace filesystem.
