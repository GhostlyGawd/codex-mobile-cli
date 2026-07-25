# ADR 0019: Reconcile setup reviews durably at the stopped trust boundary

- Status: accepted
- Date: 2026-07-16

## Context

A workspace can reach `awaiting_setup_approval` through a direct create or
retry, or through lifecycle promotion of a queued workspace. Creating the
safety event only in the HTTP application path left lifecycle promotions with
no review the owner could resolve. It also treated event and activity inserts
as separate writes and expired setup decisions after 24 hours even though the
workspace remained stopped indefinitely.

Approval resolution previously marked the event resolved before asking the
workspace service to accept and run setup. A provider or persistence failure
after that first write left a resolved event attached to a workspace that still
required approval, with no safe retry path.

## Decision

A shared `setupreview.Reconciler` is injected into both the application and the
lifecycle coordinator. PostgreSQL reconciliation locks the authoritative
workspace row, verifies that it is still awaiting setup approval, reuses and
renews any unresolved setup event, and atomically creates any missing linked
activity in one transaction. New and renewed setup events have no wall-clock
expiry; legacy requested setup events are also treated as pending and remain
resolvable. Notification delivery occurs only after the transaction commits
and only when a new durable activity was created.

Application create/action paths reconcile every result observed at the setup
boundary. Lifecycle reconciles both existing awaiting rows on every scan and a
queued workspace immediately after promotion reaches the boundary. These calls
are deliberately idempotent, so a crash or transient error after the workspace
transition is repaired without duplicate pending reviews or activities.

For a decision, the application first loads and validates the pending setup
event and serializes decisions for that workspace. Approval then calls the
workspace service; denial first persists the workspace's
`setup_approval_denied` failure. Only after that workspace-side outcome is
durable does the application compare-and-set the safety event to its resolved
decision. A retry recognizes the durable `SetupApproved` or denial marker and
retries only event finalization. Repeating an already-resolved identical
decision is idempotent, while a conflicting decision fails closed.

## Consequences

Every durable stopped setup boundary is eventually paired with one durable,
owner-visible pending review, regardless of whether it was reached by HTTP or
background queue promotion. A store failure cannot leave a half-created event
and activity, and reconciliation after more than 24 hours does not invalidate
the owner's only route forward.

Workspace acceptance can temporarily precede event finalization when the event
write fails, but that intermediate state is explicit and retryable. Repository
setup never runs merely because an event was marked resolved. Unit and race
tests cover queued promotion, existing-boundary repair, non-expiry, idempotent
notification, and an injected event-finalization failure after workspace
acceptance. Live PostgreSQL integration verifies one event/activity pair and a
NULL expiry across repeated reconciliation.
