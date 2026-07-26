# Supply-chain verification

The tracked source SBOM is [SBOM.cdx.json](SBOM.cdx.json). The corresponding
[dependency](DEPENDENCIES.md) and [license](LICENSES.md) reports are generated
from every committed dependency lock/pin. Regenerate and verify them with:

```shell
python scripts/generate-supply-chain.py
python scripts/generate-supply-chain.py --check
```

Generator 2.0 also reads the strict EnvBuilder source lock. It models the
source-built derivative as an application with an Apache-2.0 upstream ancestor
and an unofficial first-party patch pedigree, while separately inventorying
the archive and patch hashes/licenses. Reconstruct and compile that derivative
on Linux with:

```shell
python3 -I scripts/verify-envbuilder-source.py
```

The verifier bounds and hashes the download before safe extraction, applies
exactly the eight locked paths, runs tidy/module verification, vet, non-registry
unit and race tests, compiles the registry-dependent `devcontainer` and
`integration` packages
without executing them, and proves two clean static builds for each of amd64 and
arm64 are byte-identical. Portable verification runs `--static-only` and does
not claim a Linux build.

For a release candidate, install the free tools at the exact versions in
`.tool-versions`, verify their official release checksums/signatures, then run
`sh ./scripts/security-audit.sh` or `pwsh ./scripts/security-audit.ps1`. These
wrappers reject a different Syft or Trivy version. Detailed scanner output goes
to ignored `artifacts/supply-chain`; it can contain local paths and is not
uploaded automatically.

## Executed source audit — 2026-07-16

| Check | Result | Scope and caveat |
| --- | --- | --- |
| Deterministic generator 1.0 | PASS | 99 Go, Swift, Terraform, OCI-source, and build-tool records; tracked reports reproduced byte-for-byte |
| Syft 1.46.0 | PASS | Checksum-verified release binary recorded 59 source components after excluding `.git`, `.terraform`, caches, and prior artifacts |
| go-licenses 2.0.1 | PASS | Emitted 76 imported-package rows; the 35 unlicensed first-party-package `Unknown` rows are expected and are not unreviewed third-party licenses |
| Gitleaks 8.30.1 | PASS | No leaks. The general ignored-output rule is path-scoped to local `tmp`, `artifacts`, `coverage`, and Python cache directories; two line-scoped allowlists cover only deliberate invalid PEM fixtures/boundaries |
| Trivy 0.72.0 source scan | PASS | No unsuppressed high/critical misconfiguration, secret, or license finding. The one recorded exception is EnvBuilder's required initial root inside a private user namespace on the dedicated Podman runtime; that container receives no engine socket or host path. Trivy also logged a harmless parser limitation for a `Dockerfile.dockerignore` file. |
| govulncheck 1.6.0 | PASS | The final post-edit run found 0 reachable and 0 imported-package vulnerabilities. Seven vulnerabilities exist only in required modules whose affected symbols are not called. |
| Built-image OS/package scan | PASS (local candidate) | D-backed Ubuntu WSL built and runtime-checked the exact commit-tagged candidates, then profile 3/schema 2 accounted for the complete frozen-database inventory and manifest schema 2 bound the root-only evidence. This is candidate evidence only; repeat the exact gate for every later commit and on the target Linux staging host before deployment. |

The EnvBuilder exception is constrained in `.trivyignore.yaml` to one rule and
one Dockerfile, includes the user-namespace/capability/socket rationale, and
does not suppress normal workspace or control-plane image findings. Review it
on every EnvBuilder or private-runtime update. The root-owned engine exists to
apply XFS project quotas; access to its private provisioner-only API is a
separate root-equivalent host trust boundary, not part of this container
exception.

The upstream EnvBuilder 1.3.0 source and the license copied into the image are
Apache-2.0. That conclusion does not relicense this repository's patch: the
patch is `LicenseRef-First-Party-No-License`, and the combined derivative is
reported as `Apache-2.0 AND LicenseRef-First-Party-No-License`. The final
image's Syft SBOM, not the source report alone, is authoritative for its
transitive compiled modules.

## Release gate

Do not release if the deterministic reports are stale, Gitleaks reports any
unreviewed finding, govulncheck reports a reachable vulnerability without a
documented disposition, a license is `LicenseRef-Needs-Review`, an immutable
image fails Trivy, or an image digest differs from the deployment source.
`LicenseRef-Tooling-Not-Distributed` means a local build tool is inventoried but
not shipped. Syft and Trivy are Apache-2.0 operational tools installed on the
host at no additional cost. Ubuntu and Coder image `LicenseRef` entries require
the full built-image package/license inventory; they are not blanket approvals.

The production deploy builds three commit-tagged local images and runs
`scripts/infra_image_audit.py` before manifest creation or promotion. The
auditor scans captured image IDs through explicit Docker/Podman engines,
rechecks every tag for drift, and atomically publishes root-only CycloneDX 1.6,
Trivy JSON, and a metadata-only receipt. Manifest schema 2 binds that receipt,
the exact report tree, policy/tool/database hashes, and the same image IDs.

Scanner profile 3 uses evidence/policy schema 2. Exact dispositions bind image,
kind, category, report target, finding ID, package/version, severity, path,
result class/type, vulnerability status, fixed version, and package PURL.
Forbidden licenses require those individual exact dispositions. Each image's
complete non-forbidden license inventory is reviewed as an expiring,
duplicate-sensitive canonical multiset baseline. A new/changed finding,
missing/changed/expired/unused baseline, expired or unused disposition,
malformed/oversized report, database/tool drift, or any undispositioned result
fails closed. Raw reports are never uploaded automatically. Rollback verifies
the release-time evidence and retained image IDs without rebuilding or
rescanning; historical scanner profiles remain version-dispatched and are
never reinterpreted as profile 3.
