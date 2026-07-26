# Supply-chain verification

The tracked source SBOM is [SBOM.cdx.json](SBOM.cdx.json). The corresponding
[dependency](DEPENDENCIES.md) and [license](LICENSES.md) reports are generated
from every committed dependency lock/pin. Regenerate and verify them with:

```shell
python scripts/generate-supply-chain.py
python scripts/generate-supply-chain.py --check
```

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
| Built-image OS/package scan | NOT EXECUTED | Docker/Podman is unavailable on this Windows host. Scan each immutable built image on the target Linux staging host before deployment. |

The EnvBuilder exception is constrained in `.trivyignore.yaml` to one rule and
one Dockerfile, includes the user-namespace/capability/socket rationale, and
does not suppress normal workspace or control-plane image findings. Review it
on every EnvBuilder or private-runtime update. The root-owned engine exists to
apply XFS project quotas; access to its private provisioner-only API is a
separate root-equivalent host trust boundary, not part of this container
exception.

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

Tracked dispositions are exact and expiring: image, report target, finding ID,
package/version, severity, and path must all match. A new/changed finding,
expired or unused disposition, malformed/oversized report, database/tool drift,
or any undispositioned result fails closed. Raw reports are never uploaded
automatically. Rollback verifies the release-time evidence and retained image
IDs without rebuilding or rescanning.
