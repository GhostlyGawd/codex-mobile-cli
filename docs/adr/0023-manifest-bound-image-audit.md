# ADR 0023: Manifest-bound release image audit

## Status

Accepted.

[ADR 0025](0025-owner-pc-private-beta-hosting.md) changes the deployment host,
not this manifest-bound audit requirement. Exact beta candidate images still
require audit before promotion.

## Context

ADR 0012 binds a release to the exact local IDs of the three images built from
that release. The deployment path previously created that manifest immediately
after building, however, so a source-tree scan or an earlier scan on another
host did not prove that the promoted image IDs were clean. This matters because
the workspace build installs current Ubuntu packages: a later deployment build
can produce a different image ID even when the source commit is unchanged.

Image scanners also produce security-sensitive reports, use a mutable
vulnerability database, and can discover a new issue in an otherwise unchanged
release. Re-running a scan during rollback would therefore make rollback depend
on current network/database state instead of the evidence accepted when the
release was created.

## Decision

The locked deployment builds all three commit-tagged images, captures their
content-addressed IDs, and scans those captured IDs before manifest creation or
any promotion, checkpoint, host-artifact installation, link change, service
restart, or template activation. The auditor uses checksum-pinned Syft and Trivy
executables installed by host hardening, explicit Docker or private-Podman
sources, one frozen Trivy database snapshot, CycloneDX 1.6 output, and a fixed
vulnerability/secret/license policy. It re-inspects every release tag after the
scans and rejects any ID drift.

The auditor publishes a complete root-only evidence directory atomically. Its
metadata-only receipt binds the release/source identity, exact image subjects,
tool and database hashes, policy hash, report hashes and sizes, and finding
counts. Raw SBOM and Trivy JSON remain mode-restricted inside the immutable
release because they can contain package paths or secret-match context.

Findings are not globally ignored. Scanner profile 3 and evidence/policy schema
2 bind each exact disposition to the image, kind, category, report target,
identifier, package, version, severity, path, result class/type, vulnerability
status, fixed version, and package PURL. Every record has a unique rationale and
expiry. Forbidden licenses require individual exact dispositions. The complete
non-forbidden license inventory is instead reviewed as one expiring,
per-image, duplicate-sensitive canonical multiset baseline, so neither a
changed license nor a missing/extra duplicate can disappear into a broad
allowlist. Profiles 1 and 2 retain their schema-1 interpretation solely as
immutable historical verification contracts.

The audit fails if an exact finding or license baseline is new or changed, a
disposition or baseline is expired or unused, or any finding remains
undispositioned. This keeps upstream issues and the full license inventory
visible without letting a broad ignore conceal a different dependency, file,
result classification, fix transition, or duplicate.

Release-manifest schema 2 binds the receipt and exact report tree to the same
image IDs recorded in the manifest. Every operational verification requires
schema 2 audit evidence. Schema 1 may be inspected for historical diagnosis but
cannot be promoted, activated, or selected for rollback. Rollback verifies the
stored evidence and retained local IDs without rebuilding, retagging, updating
the scanner database, or rescanning.

Scanner/tool policy profiles and deterministic workspace-helper pin profiles
are immutable verification contracts. New releases use the current profile,
while the trusted current verifier retains every profile referenced by a
rollback-eligible release. An unknown or altered profile fails closed; an
incompatible report/parser change requires a new evidence schema and an
explicit version-dispatched verifier rather than reinterpreting old evidence.

## Consequences

A deployment cannot proceed without network access sufficient to refresh the
pinned Trivy database and enough time/disk for all three scans. Scanner,
database, report, subject, disposition, or tag-drift failures leave the staged
release unpromoted.

The host now carries two free operational tools and a root-only scanner cache;
it does not add a service, account, registry, or recurring bill. Evidence is
host-local and is never uploaded automatically.

An old schema-1 release is not an eligible rollback target after this decision.
Because no production release has been recorded, no compatibility exception is
needed. If one is later discovered, rebuild and audit it as a new schema-2
release rather than modifying its immutable directory or weakening the gate.

Portable tests can prove parser, tamper, resource-bound, ordering, and
fail-closed behavior. Only an executed Linux Docker/Podman build and scan proves
the exact candidate images. Owner-PC/WSL service, storage, isolation, and
ingress evidence remains separate local-beta evidence. ADR 0026 defines the
active loop-backed XFS quota profile; AppArmor, provider backup, ten-session
capacity, and other VPS-only controls remain deferred.
