# ADR 0025: Host the first private beta on the owner PC

- Status: accepted
- Date: 2026-07-26

## Context

The original deployment design selected one fixed-price VPS for an always-on
single-owner service. The owner subsequently chose zero-new-cost local hosting
for the first usable private beta. D-backed Ubuntu WSL already provides the
Linux-native repository, Docker, Podman, and verified candidate images.

That newer owner decision was not persisted in the repository. As a result,
later planning incorrectly treated the older VPS design as the next required
step. Chat history is not a sufficient authority boundary for a consequential
deployment decision.

## Decision

Run the first private beta from the owner's Windows PC through the D-backed
Ubuntu WSL distribution. The local host will run the control plane, PostgreSQL,
Coder, the private workspace runtime, and provisioner. Use a reviewed stable
HTTPS ingress for the signed iOS client without exposing internal service,
database, runtime-socket, SSH, or workspace ports.

Use standard public GitHub-hosted Linux and macOS runners for CI and iOS
builds. Do not restore a persistent GitHub Actions runner on the owner PC.

The fixed-price VPS architecture is deferred. It remains a possible future
availability migration only if the owner explicitly reopens that decision; it
is not a private-beta launch dependency and no VPS purchase is authorized.

This ADR supersedes the fixed-VPS host and provider-backup assumptions in ADRs
0004, 0005, 0008, 0010, 0012, 0014, 0020, and 0023 for the active beta, but not
their provider-neutral authentication, isolation, state-machine, provenance,
or audit controls. ADR 0022 remains authoritative for hosted CI.

## Consequences

- The private beta has zero new recurring hosting cost.
- The app is unavailable whenever the PC, WSL distribution, local services, or
  ingress is stopped or disconnected. This limitation must remain visible.
- Existing VPS-only preflight, storage, service-management, and release paths
  need a separate fail-closed local-beta profile rather than weakened
  production checks.
- Host security must account for Windows/WSL boundaries honestly. VPS-specific
  XFS, AppArmor, provider-backup, reboot, and load evidence cannot be claimed
  for the local beta.
- A stable HTTPS origin and Apple associated-domain contract remain necessary
  for the signed app. Selecting or configuring the ingress is a separate
  external-account action and must not introduce a paid or metered dependency.
- ADR 0005 remains historical design for an optional future always-on host. ADR
  0022 remains authoritative for public hosted CI.
