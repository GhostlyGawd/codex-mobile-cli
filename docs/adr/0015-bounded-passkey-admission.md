# ADR 0015: Bounded and partitioned passkey ceremony admission

- Status: accepted
- Date: 2026-07-16

## Context

Passkey authentication options are intentionally public, but each option creates
short-lived server state. A single global cap prevents unbounded memory use yet
allows anonymous traffic to occupy every slot and lock out owner bootstrap,
authenticated enrollment, and returning devices. Client IP and forwarded-header
identity are unsuitable admission boundaries behind the packaged reverse proxy.

## Decision

All ceremonies expire after five minutes and the process stores at most 4,096.
Login traffic may use 3,840, preserving 256 slots for a validated bootstrap token
or authenticated additional registration. Unknown device instances may hold at
most 512 active logins and share a token bucket with a 32-start burst and one
refill per second.

The native app's this-device-only random 256-bit instance identity is hashed and
used for per-instance fairness. Each instance has one active ceremony; a retry
replaces the prior ceremony only after the new challenge commits. It receives a
four-start burst and one refill per 15 seconds. A bounded lazy cache loads
up to 4,096 historical hashes from persistence, including revoked instances
because device/session revocation does not invalidate a valid passkey. These
recognized instances use an independent 32-start burst and four refills per
second, so anonymous traffic cannot consume their admission credit.

The per-instance rate-state map is capped at 4,608 entries, expired ceremonies
and fully refilled idle entries are pruned, and failed known-device loads retry no
more than once per second. No limiter trusts source headers. Every denial wraps
the same capacity error and maps to the resource-neutral `503
capacity_unavailable` response.

## Consequences

Owner-authorized enrollment and previously known installations retain separate
capacity during an anonymous ceremony flood, retries do not accumulate state,
and both ceremony and rate metadata have explicit memory bounds. Deterministic
tests cover replacement, concurrent unknown-lane exhaustion, known-lane
survival, owner reserve, per-device/global refill, store-load recovery, the
4,608-entry state cap, pruning, and stable public errors.

A distributed attacker rotating unknown 256-bit identifiers can still consume
the unknown lane and delay first login from a new installation. A sufficiently
large network flood can exhaust resources before application admission. Those
are deployment/edge availability risks, not claims solved by this in-process
policy; an owner can use the separately authorized bootstrap recovery path.
