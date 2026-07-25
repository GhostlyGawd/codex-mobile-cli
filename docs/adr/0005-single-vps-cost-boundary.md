# ADR 0005: One fixed-price VPS and no managed dependencies

- Status: accepted; provider selection pending official checkout verification
- Date: 2026-07-15

## Decision

Deploy Caddy, exactly one Go control-plane process, PostgreSQL, Coder Community, workspaces, checkpoints, metrics, and logs to one fixed-price month-to-month VPS. Use direct APNs and local storage. Provisioning scripts configure an existing host only and never call a provider create/resize API.

Workspace start admission is serialized within that single process from the capacity snapshot through persistence of a queued or provisioning state. A provisioning record carries the in-flight disk reservation, so restart recovery remains fail-closed. Running a second control-plane process is unsupported until this boundary is replaced by a PostgreSQL transaction or advisory lock shared by every replica.

## Consequences

There is no HA, separately paid offsite backup, managed database, hosted auth, error-reporting SaaS, or automatic scaling. The included provider daily whole-server backup defines the server-loss recovery point, potentially about 24 hours. It is expected to capture the encrypted database/data and the root-owned host master key together. That consistency supports recovery but provides no cryptographic separation from the provider or compromise of a full backup; the owner-held offline key copy is an additional availability copy only.
