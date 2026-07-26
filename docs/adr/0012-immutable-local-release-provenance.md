# ADR 0012: Immutable local release provenance

> Extended by [ADR 0023](0023-manifest-bound-image-audit.md), which requires
> the exact built image IDs to pass a manifest-bound audit before promotion.
> [ADR 0025](0025-owner-pc-private-beta-hosting.md) changes the deployment host,
> not the immutable build/manifest/promotion contract. Fixed-VPS, XFS, and
> systemd health details below apply to the deferred VPS profile; the local
> beta requires its own fail-closed health profile.

## Status

Accepted.

## Context

At the time of this decision, the service was designed for one fixed-price VPS
and needed to support an owner-approved
rollback without a registry or another paid service. Previously, activation and
rollback asked Compose to build. Because site configuration held only the newest
image tag, rolling back could rebuild old source under that new tag. Coder
template, workspace images, private-Podman configuration, systemd units and
privileged wrappers also had no single persisted provenance record. Basic HTTP
health could remain green while the workspace runtime or external provisioner
was unusable. Recovery runbooks named a control-plane host binary that is not
installed outside the container image.

## Decision

Build the three local images exactly once before promotion under a validated
`sha-<commit>` release ID. A root-only generator records their content-addressed
local image IDs, the workspace-helper checksum, the complete Coder template
tree, Podman configuration, systemd units, privileged wrappers and critical
release scripts in an immutable per-release manifest. A generated release
environment binds Compose and the external provisioner to the matching image
references. Promotion and rollback verify the manifest and required local image
IDs, install that release's host artifacts, switch the release symlink, restart
the affected units, and activate the matching Coder template. They never build
or retag. Every Coder activation writes a root-only receipt with the template
version ID and the manifest's runtime provenance.

The release verifier deterministically cross-builds the workspace helper for
Linux amd64 and arm64, then hashes the exact artifacts and requires byte-for-byte
SHA-256 equality with the two pins in `EnvBuilder.Dockerfile`. Infrastructure
policy requires those same literal pins in the workspace-image build verifier,
which selects the runtime architecture and hashes the helper inside the built
base image before it can seed the EnvBuilder derivative. A label or filename is
not accepted as helper identity.

The deferred VPS production-health profile verifies installed hashes, unit state, the exact running
control-plane image ID, all Compose services, XFS storage policy, private Podman
socket ownership/API, provisioner metrics and a recent Coder registration with
the required tag. An owner-approved activation also runs one bounded,
networkless, disposable volume/container smoke probe and cleans it up.

Offline passkey recovery and master-key rewrap use a root-only Compose wrapper
around the manifest-recorded control-plane image. It stops public serving but
leaves PostgreSQL running. A new master key is validated from a root-owned file,
copied beneath root-only `/run`, mounted read-only, and referenced only by a
fixed in-container path; key bytes never enter argv or environment variables.

## Consequences

Rollback now depends on retaining the old local image IDs and release directory;
an image prune is therefore an explicit rollback-boundary change and must not be
part of routine maintenance. Forward-only database migrations remain a separate
compatibility decision. Re-activating a release creates another immutable Coder
template version/receipt rather than rewriting history. The health and smoke
checks require the owner-controlled Linux host, Coder credentials and private
runtime, so portable tests validate their parsers/fail-closed structure but do
not report the live drill as passing.
