# ADR 0020: Linearize provider starts and reconcile capacity durably

- Status: accepted
- Date: 2026-07-16

[ADR 0025](0025-owner-pc-private-beta-hosting.md) changes the active capacity
target, not the durable provider-state machine. The owner-PC beta must use a
measured conservative local cap; the historical ten-workspace target is
deferred with the VPS profile.

## Context

An equal-share quota changes whenever a workspace begins or stops consuming
runtime capacity. Persisting a provisioning reservation before releasing start
admission prevents simple over-admission after restart, but it is not enough:
another start could pass admission while the first waited for the provider
mutation lock, and a crash after a provider call could leave the database unable
to say whether that runtime was live.

Coder start and quota-build requests are asynchronous. Treating an accepted
request as completion could expose a workspace or admit another consumer before
the requested cgroup limits were active. Quota persistence also needs different
ordering for expansion and shrinkage, and a one-shot rebalance can be lost when
the provider or store is temporarily unavailable.

## Decision

The single control-plane process holds its admission gate continuously from the
capacity snapshot and durable queued/provisioning decision until it has acquired
the global provider-runtime gate. An admitted row first carries
`provider_start_reserved`, which is durable proof that no provider call has
occurred. Before the first provision call it is changed to
`provider_provision_unconfirmed`; after a provider ID exists, a cleanup-pending
start marker is persisted before an explicit start. Only the reserved phase may
be treated as definitely stopped. Every other transitional phase is
capacity-ambiguous and blocks another start or stable-runtime expansion.

Recovery resolves an ambiguous provision through the provider's deterministic
logical-workspace lookup. Confirmed absence restores the reserved phase for a
later retry. A recovered resource ID is persisted and the runtime is confirmed
stopped before its reservation is released as failed. Ambiguous starts follow
the same stop-before-release rule. Starts, stops, deletes, and quota builds all
share the provider-runtime gate.

The Coder adapter treats the exact build as the provider readiness boundary.
Ordinary starts, approved-setup starts, and quota changes capture or recover the
accepted build ID and poll until that same latest `start` build reaches
`running`. A failed, canceled, unknown, timed-out, or superseded build fails
closed. An in-progress start is resolved before another quota build is issued.

For each stable runtime, persisted quota is a conservative component-wise upper
bound across a crash. Before applying an exact target, the service persists
`max(current, target)` independently for CPU, memory, and disk. It then waits
for the exact provider quota build to run and persists the exact target. This is
safe for pure expansions, pure shrinkage, and mixed-direction changes; a crash
can leave a workspace underallocated, but durable capacity never understates a
possibly active provider allocation. Persistent disk remains immutable.

Immediate rebalances after a start, confirmed stop/failure cleanup, or deletion
are best effort and do not turn an otherwise completed lifecycle action into a
failure. The lifecycle coordinator is the level-triggered repair path: every
scan derives owners from durable workspace rows and retries per-owner fair-share
convergence under the provider-runtime gate. No process-memory dirty bit is
required for recovery.

## Consequences

The start boundary is fail-closed across the known persistence/provider crash
windows, and a successful provider start or quota operation means the exact
Coder build is running. Restart recovery may conservatively block starts or
leave surviving workspaces below their eventual fair share until provider
ambiguity is resolved and a scan succeeds.

Provider operations and long-running readiness polls are serialized globally,
so a slow provider can increase start and rebalance latency. This is an accepted
tradeoff for the deferred maximum of ten workspaces on one fixed-price VPS. The gates are
process-local and preserve the single-process deployment invariant from ADR
0005; a multi-replica control plane would require PostgreSQL-backed admission
and provider-mutation locks before it could be supported.
