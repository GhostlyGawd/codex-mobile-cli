# ADR 0017: Finalize workspace deletion only after provider and runtime cleanup

- Status: accepted
- Date: 2026-07-16

## Context

Persisting `state = 'deleting'` and merely accepting a Coder delete build is not
proof that a workspace is gone. Removing the database row at that point can
release the unique branch, provider and worktree identities while the provider
still exists. Conversely, never removing the row leaves a permanent terminal
tombstone, prevents same-branch recreation, and retains all child metadata.

The database row also owns the terminal-tab and preview-route metadata needed
to revoke process-local PTYs, reconnect credentials, preview grants and tunnel
processes. Cascading the row before that cleanup makes those authorities
undiscoverable. Automatic retention deletion calls the workspace service
directly, so cleanup cannot exist only in the manual HTTP action.

## Decision

Workspace provider lifecycle operations use a reference-counted in-process gate
keyed by the exact owner/workspace tuple. Resume, retry, setup approval,
suspension and deletion retain the gate across their provider work. Gate entries
are removed after the last holder or waiter, and a waiting operation honors
context cancellation. A delete therefore cannot race a resume that later saves
the workspace as running.

The first authorized delete persists `state = 'deleting'` before calling the
provider. Coder deletion is confirmed only when an owner-scoped workspace read
returns `404`; an accepted delete build is polled, a failed or canceled terminal
build is reported, and an already-absent workspace is idempotent success. A
failure or timeout leaves the durable deleting row. Later manual calls and the
lifecycle coordinator retry that state without repeating confirmation policy or
checkpoint preparation.

Immediately before persistence finalization, the workspace service calls an
injected deletion boundary shared by manual and automatic deletion. The
application implementation acquires the same reference-counted workspace gate
used by terminal and preview creation, snapshots all terminal tabs and preview
routes, drains terminal mutation gates and runtimes, revokes preview grants and
cancels tunnels, then returns a release function. The service retains that
function until the database operation finishes, preventing a new local
authority from appearing between cleanup and cascade. Cleanup failure leaves
the deleting row for retry.

`WorkspaceStore.FinalizeDelete` takes a transaction row lock and removes only
the exact `(owner_id, id)` row whose state is still `deleting`. Reviewed foreign
keys cascade operational children including terminal tabs, preview routes and
tokens, secret grants, workspace-scoped encrypted values, activity, safety and
state events. Existing audit events survive because
`audit_events.workspace_id` uses `ON DELETE SET NULL`; immutable `target_id`
retains the deleted workspace identity. A manual success audit written after
finalization intentionally has a NULL workspace linkage and the workspace ID as
its target.

The manual action snapshots its response before deletion and never refetches the
removed row. It returns HTTP 200 with a bounded deleting tombstone as the
completed action acknowledgement, not HTTP 202: by response time provider
absence, runtime cleanup and database finalization have all succeeded.
Subsequent authoritative reads return not found.

## Consequences

Successful deletion means Coder has confirmed absence, process-local terminal
and preview authority has been drained, and the exact durable row plus reviewed
children has been removed. Branch and provider uniqueness is released only at
that point, allowing safe same-branch recreation.

Provider, cleanup, cancellation and persistence failures remain visible as a
durable deleting state and are retried automatically. A post-finalization retry
is idempotent and does not issue another provider build. Deterministic tests
cover delete/resume ordering, concurrent/repeated deletion, provider and cleanup
failure, timeout, terminal-build retry, no post-delete refetch, terminal/preview
revocation and bounded mutation-gate cleanup. Live PostgreSQL integration covers
owner/state scoping, child cascades, audit retention/null linkage and same-branch
recreation.
