# ADR 0024: Build the EnvBuilder derivative from pinned source

## Status

Accepted.

## Context

The workspace approval path needs EnvBuilder's real Dev Container behavior, but
the previous derivative inherited a prebuilt `ghcr.io/coder/envbuilder:1.3.0`
image. That made the shipped Go module graph, license inventory, and build
toolchain opaque to this repository. The upstream EnvBuilder source is
Apache-2.0, while the prebuilt binary also linked the much larger Coder server
SDK and its transitive runtime graph even though Codex Mobile only needs the
workspace-agent log HTTP contract.

The release boundary already requires immutable local image IDs and exact
Syft/Trivy evidence. It also treats downloaded archives, build contexts, local
image tags, and image filesystems as hostile input. A source derivative must
therefore prove its origin and patch, preserve EnvBuilder's OCI runtime
contract, and avoid turning a local tag or an unreviewed patch into authority.

## Decision

Build `1.3.0-codex-mobile.1` from the exact upstream EnvBuilder 1.3.0 commit
`da95f80ea89fc615b85441da107c29004061df6a`. The canonical source lock records
the codeload URL, archive SHA-256, upstream license SHA-256, eight patched
paths, patch SHA-256, derivative version, and exact Go builder image digest.
The build verifies all hashes before extraction or application, rejects archive
members outside the one expected root or any non-file/directory member, applies
the patch through Git's index, and rejects an unexpected changed-file set.

The patch:

- replaces the Coder server SDK/dRPC log sender with a local bounded HTTP
  `PATCH /api/v2/workspaceagents/me/logs` client using the exact public wire
  contract;
- bounds credentials, queue, batch, record, request, response, retry cadence,
  request time, and close time; refuses redirects and ambient proxies; and
  sanitizes operational errors;
- removes Coder and Coder/Tailscale runtime modules from the compiled graph;
- upgrades the maintained dependency graph where compatible fixes exist; and
- retains focused, race, malformed-input, retry, cancellation, and
  secret-nondisclosure tests.

Build Linux amd64 and arm64 explicitly with `CGO_ENABLED=0`, `GOOS=linux`, and
the validated target architecture. Two independent clean build caches must
produce byte-identical binaries for each architecture. Build metadata, ELF
architecture, static linkage, derivative version, and absence of Coder runtime
modules are verified. The public Linux workflow is configured to download the
exact archive, safely extract it, apply all eight patch paths, run tidy/module
verification, vet, unit/race tests, compile-only verification for the
registry-dependent `devcontainer` and `integration` packages, and both
reproducible cross-builds. Its first successful hosted execution for this
current tree is still pending and must not be inferred from static or local
checks. Portable verification still validates the lock and patch without
claiming a Linux build.

The final image remains scratch and explicitly preserves upstream's empty
root-user semantics, `/` working directory, fixed `PATH`,
`KANIKO_DIR=/.envbuilder`, empty command/ports/volumes/healthcheck, and
`/.envbuilder/bin/envbuilder` entrypoint. It includes the exact upstream
Apache-2.0 license and source lock. The derivative as a whole is labeled
`LicenseRef-First-Party-No-License`: the upstream source remains Apache-2.0,
but the local patch is not silently relicensed.

The configured release path builds and verifies the workspace image first. Its
mutable tag is resolved to one local immutable image ID before the helper
directory is copied. A non-executing Podman inspection compares a canonical
digest of every expected seed path, type, mode, owner, link target, size, and
file hash between that exact workspace image and the final EnvBuilder image.
Both resulting image IDs remain bound by the release manifest and image audit.
The final documentation-bearing candidate passed that exact Linux build,
runtime, audit, and manifest gate. The proof is release-identity-bound, so
every later commit must repeat it before promotion.

The source SBOM represents the derivative as an application with an upstream
ancestor and an unofficial patch pedigree. It separately inventories the
archive and patch with their exact hashes and distinct licenses. The Syft SBOM
of the exact built image remains authoritative for the shipped binary's
transitive module graph.

## Consequences

EnvBuilder image builds take longer and require access to the exact codeload
archive and Go module proxy unless an already verified cache is present. A
source, patch, dependency, builder, or runtime-contract change requires a new
derivative version, source-lock update, regenerated reports, built-image scan,
and fresh exact dispositions where an upstream vulnerability has no compatible
fix. No module-level or product-wide ignore is permitted.

The local patch is intentionally small enough to audit but is now a maintained
product dependency. Upstream changes must be rebased deliberately; silently
falling back to the prebuilt image or widening the patch path inventory is a
release failure.

## Alternatives rejected

- Continue inheriting the prebuilt image: this leaves build provenance,
  transitive runtime code, and license conclusions opaque.
- Copy EnvBuilder into this repository: this obscures upstream lineage and
  creates a much larger first-party maintenance surface.
- Replace EnvBuilder with an API-key-backed chat or custom pseudo-terminal:
  this breaks the authoritative Codex CLI/TUI and Dev Container product
  boundaries.
