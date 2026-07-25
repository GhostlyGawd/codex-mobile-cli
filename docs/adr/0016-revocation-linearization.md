# ADR 0016: Linearize credential issuance and revocation

- Status: accepted
- Date: 2026-07-16

## Context

Authentication at HTTP ingress is not a revocation boundary. A terminal request
can authenticate, block while starting a workspace, and otherwise mint a ticket
after its session or device is revoked. Likewise, checking a GitHub installation
before minting leaves a check/use gap in which disconnect can return before a
new provider token is minted or a stale sync rewrites repository availability.

## Decision

Terminal credential operations use a reference-counted in-process gate keyed by
the exact owner/device tuple. Slow workspace setup happens first; while holding
the gate, ticket issuance revalidates the durable owner/device/family principal
immediately before mint. Session revoke, device revoke and refresh rotation use
the same gate. Refresh replay commits family revocation and sweeps tickets,
reconnect tokens and subscribers before releasing it. Gate records are deleted
after the final holder or waiter. Inside the gateway, one manager lock consumes
a ticket and installs its subscriber atomically with the revocation sweep.

GitHub installation-token minting and the complete operation that consumes the
token hold a shared PostgreSQL session advisory lock keyed by a length-prefixed
owner/installation tuple. Git operations and workspace detection/initialization
use that shared form. Ordinary repository synchronization and a signed provider
unsuspend instead take one exclusive lease before fetching fresh installation
metadata and retain it through metadata persistence, the in-lease active check,
token mint/list, and every repository write. Ordinary metadata refresh preserves
both provider suspension and owner disconnect. The unsuspend path may clear only
provider suspension, only when the fresh provider response has no suspension,
and only through its distinct upsert inside that same lease; it never clears an
owner disconnect. There is no standalone resume-then-sync transition.

Disconnect, explicit owner reconnect and provider suspension also take the
exclusive lock. Disconnect/suspension drain prior users and commit authority
plus repository availability before returning. A dedicated PostgreSQL
connection owns each lock and is closed to release it, so a failed unlock cannot
leak a locked session into the ordinary pool.

Dedicated GitHub lock concurrency is bounded separately: shared sessions are
capped at `min(max(1, MaxConns), 8)` and exclusive sessions at
`min(max(1, MaxConns), 2)`. The
callback continues to use the ordinary pool; an integration regression covers
`MaxConns=1` so the lease cannot starve its own operation.

## Consequences

A successful terminal revoke cannot be followed by a ticket from an earlier
authenticated request, and it cannot miss a ticket concurrently becoming a
subscriber. Deterministic application/gateway tests cover both orderings,
refresh replay and reference-count cleanup.

A successful GitHub disconnect is designed as a no-later-mint-or-use boundary
across control-plane processes, while operations already holding the shared lock
finish before disconnect returns. Whichever exclusive sync or authority
transition runs first is drained before the next becomes authoritative; a stale
ordinary sync cannot clear a revocation, and a stale unsuspend whose fresh
provider response remains suspended cannot open even a transient shared-token
window. Local disconnect still cannot invalidate a provider token whose complete
leased use already finished, and it does not uninstall the GitHub App.
Deterministic tests cover sync-first and suspension-first ordering, atomic valid
unsuspend, stale unsuspend and a waiting shared token user. The cross-pool
advisory-lock drain, final-write and `MaxConns=1` cases also passed against a
live disposable PostgreSQL instance, including three race-enabled repetitions.
That local database evidence does not substitute for a real GitHub installation.
