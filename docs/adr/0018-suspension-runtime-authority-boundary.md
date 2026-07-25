# ADR 0018: Drain runtime authority at the durable suspension boundary

- Status: accepted
- Date: 2026-07-16

## Context

The owner HTTP action used to clear process-local terminal runtimes and preview
access only after `WorkspaceService.Suspend` returned. Automatic idle suspension
and maintenance call the workspace service directly, so they bypassed that
application-only cleanup. A stopped Coder workspace could therefore retain
unused terminal tickets and reconnect tokens, active WebSocket subscribers, a
stale running-runtime cache, preview grants, and Coder port-forward processes.
On resume, the stale cache could issue a connection against the old PTY instead
of reopening it.

Moving cleanup after provider stop is also too late. A terminal or preview
request that observed a live workspace before the stop could create new local
authority while cleanup was taking its snapshot. Cleanup must start only after
the durable lifecycle state denies new helper, terminal and preview operations,
and it must serialize with any operation already in flight.

## Decision

Both explicit `Suspend` and automatic `SuspendIfInactive` first persist or
atomically claim `state = 'suspending'`. They then enter one injected
`SuspensionBoundary` before asking Coder to stop. The application implementation
takes the same reference-counted per-workspace mutation gate used by terminal
and preview creation. An authority operation that acquired the gate earlier may
finish, but the boundary then observes and revokes everything it created; a
later operation observes the suspending state and fails.

While holding that gate, the boundary lists every active persisted terminal tab
and preview route. It clears each terminal from the running cache and calls the
terminal manager's synchronous `Unregister`, which invalidates tickets and
reconnect tokens, marks subscriber input and WebSocket-delivery gates revoked,
waits for admitted mutations and writes to drain, disconnects subscribers and
closes the PTY. It revokes preview grants and active request contexts, cancels
the bounded Coder tunnel, and durably marks each preview route revoked.

The boundary returns a once-only release function. The workspace service keeps
it until Coder confirms the workspace stopped and the final suspended state is
saved. The service's own owner/workspace lifecycle gate also remains held, so a
resume cannot interleave with cleanup or the provider stop.

Cleanup, provider confirmation, cancellation, and final-save errors leave the
workspace durably suspending. Manual suspension and lifecycle scans retry that
state without repeating checkpoint creation or the inactivity claim. Runtime
revocation is idempotent. Coder `StopAndWait` preflights provider state: an
already-confirmed stop succeeds without another build, an in-progress stop is
polled, and only a non-stop or terminally failed stop causes a fresh stop build.

The post-return cleanup in the owner HTTP action is removed. Manual, automatic
idle, and maintenance suspension now share the exact same lower-level boundary.

## Consequences

A successful suspension response or coordinator operation means provider stop,
terminal authority drain, preview revocation, and durable lifecycle persistence
have all completed. No ticket, reconnect token, subscriber write, preview grant,
or port-forward process from the prior running generation remains authoritative.
A later terminal connection must open and register a fresh PTY for the persisted
tab and tmux reconnect identity.

Failures remain fail-closed and recover automatically instead of exposing a
stopped workspace with live process-local authority or stranding an ambiguous
provider stop as a generic failed workspace. Deterministic service, lifecycle,
application and terminal tests cover state-before-drain ordering, retained-gate
ordering, cleanup and provider-stop retry, automatic suspension, terminal and
preview revocation, blocked WebSocket-write drain, and fresh PTY registration
after resume. Real Coder/tmux, preview WebSocket and process inspection remain
part of the target Linux acceptance run.
