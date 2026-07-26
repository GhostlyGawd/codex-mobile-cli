# ADR 0021: Bound the persistent owner-PC runner to trusted smoke validation

- Status: superseded by
  [ADR 0022](0022-clean-public-history-and-hosted-ci.md); retained as
  private-runner design history
- Date: 2026-07-25

This ADR concerns a historical GitHub Actions runner only. It does not prohibit
hosting the product's private-beta backend on the owner PC; that separate
decision is recorded in [ADR 0025](0025-owner-pc-private-beta-hosting.md).

## Context

Paid GitHub Actions overages are forbidden, and the hosted Linux workflow stays
disabled until the owner proves a hard zero-dollar overage cap. The owner has a
Windows PC but no Mac. A repository-scoped self-hosted runner can provide useful
zero-additional-cost feedback, but workflow code on a persistent runner receives
the signed-in Windows user's local file access.

Retargeting the existing workflow is unsafe and incompatible. It accepts pull
requests, uses Linux commands, and provides race-detector and infrastructure
coverage that a normal Windows process cannot reproduce. A Windows runner also
cannot satisfy Xcode, iOS Simulator, signing, or TestFlight gates.

## Decision

Use one repository-scoped, user-mode Windows x64 runner only while the repository
is private, single-owner, and fully trusted. Route jobs with all four labels:
`self-hosted`, `windows`, `x64`, and `repo-codex-mobile-cli`. Keep the runner
outside the repository with its own work directory and start it through a
per-user sign-in launcher. Do not create a service, account, scheduled task,
inbound listener, broad ACL rule, repository secret, environment secret, or
deployment credential.

The dedicated workflow runs only after manual dispatch of an owner-reviewed
branch or a trusted push to `main`. It has `contents: read`, disables persisted
checkout credentials, pins every Action to a full commit, and executes only the
portable core contract within fixed job and test timeouts. It has no
pull-request, `pull_request_target`, `workflow_run`, schedule, deployment, or
secret-bearing path.

Keep the comprehensive hosted Linux workflow separate and behind
`ZERO_OVERAGE_CI_CONFIRMED == 'true'`. The release validator distinguishes the
exact bounded self-hosted contract from hosted jobs; every other runner job
still requires the zero-overage gate.

## Consequences

The repository gains a real, bounded Actions signal on existing owner hardware
without allocating a GitHub-hosted runner. The signal proves runner routing and
portable core behavior only. Linux race, container, infrastructure, full
verification, Xcode, signing, and device checks remain separate gates.

The runner is unavailable while the PC is asleep, shut down, or the owner is
signed out. A malicious trusted-branch workflow could read or alter anything
available to the signed-in user, including material outside the runner root.
Repository visibility, collaborator trust, triggers, secrets, deployment access,
or execution scope therefore cannot expand silently.

Before making the repository public or allowing untrusted contributors, disable
the workflow route and unregister this persistent runner. Automatic untrusted
validation requires GitHub-hosted or disposable isolated compute, not this PC.
