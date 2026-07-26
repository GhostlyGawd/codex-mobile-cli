#!/usr/bin/env python3
"""Generate deterministic source dependency, license, and CycloneDX reports."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote


GENERATOR_VERSION = "1.0"
REPORT_DIRECTORY = Path("docs/security")

GO_LICENSES = {
    "cyphar.com/go-pathrs": "MPL-2.0",
    "dario.cat/mergo": "BSD-3-Clause",
    "github.com/Microsoft/go-winio": "MIT",
    "github.com/ProtonMail/go-crypto": "BSD-3-Clause",
    "github.com/anmitsu/go-shlex": "MIT",
    "github.com/armon/go-socks5": "MIT",
    "github.com/bwesterb/go-ristretto": "MIT",
    "github.com/cloudflare/circl": "BSD-3-Clause",
    "github.com/coder/websocket": "ISC",
    "github.com/cyphar/filepath-securejoin": "BSD-3-Clause AND MPL-2.0",
    "github.com/davecgh/go-spew": "ISC",
    "github.com/elazarl/goproxy": "BSD-3-Clause",
    "github.com/emirpasic/gods": "BSD-2-Clause AND ISC",
    "github.com/fxamacker/cbor/v2": "MIT",
    "github.com/gliderlabs/ssh": "BSD-3-Clause",
    "github.com/go-git/gcfg": "BSD-3-Clause",
    "github.com/go-git/go-billy/v5": "Apache-2.0",
    "github.com/go-git/go-git-fixtures/v4": "Apache-2.0",
    "github.com/go-git/go-git/v5": "Apache-2.0",
    "github.com/go-viper/mapstructure/v2": "MIT",
    "github.com/go-webauthn/webauthn": "BSD-3-Clause",
    "github.com/go-webauthn/x": "BSD-2-Clause AND BSD-3-Clause",
    "github.com/golang-jwt/jwt/v5": "MIT",
    "github.com/golang/groupcache": "Apache-2.0",
    "github.com/golang/protobuf": "BSD-3-Clause",
    "github.com/google/go-tpm": "Apache-2.0",
    "github.com/google/go-tpm-tools": "Apache-2.0",
    "github.com/google/go-cmp": "BSD-3-Clause",
    "github.com/google/uuid": "BSD-3-Clause",
    "github.com/jackc/pgpassfile": "MIT",
    "github.com/jackc/pgservicefile": "MIT",
    "github.com/jackc/pgx/v5": "MIT",
    "github.com/jackc/puddle/v2": "MIT",
    "github.com/jbenet/go-context": "MIT",
    "github.com/kevinburke/ssh_config": "MIT",
    "github.com/klauspost/cpuid/v2": "MIT",
    "github.com/kr/pty": "MIT",
    "github.com/kr/pretty": "MIT",
    "github.com/kr/text": "MIT",
    "github.com/onsi/gomega": "MIT",
    "github.com/philhofer/fwd": "MIT",
    "github.com/pjbgf/sha1cd": "Apache-2.0",
    "github.com/pkg/errors": "BSD-2-Clause",
    "github.com/pmezard/go-difflib": "BSD-3-Clause",
    "github.com/rogpeppe/go-internal": "BSD-3-Clause",
    "github.com/sergi/go-diff": "MIT",
    "github.com/sirupsen/logrus": "MIT",
    "github.com/skeema/knownhosts": "Apache-2.0",
    "github.com/tinylib/msgp": "MIT",
    "github.com/stretchr/objx": "MIT",
    "github.com/stretchr/testify": "MIT",
    "github.com/x448/float16": "MIT",
    "github.com/xanzy/ssh-agent": "Apache-2.0",
    "go.uber.org/mock": "Apache-2.0",
    "golang.org/x/crypto": "BSD-3-Clause",
    "golang.org/x/exp": "BSD-3-Clause",
    "golang.org/x/mod": "BSD-3-Clause",
    "golang.org/x/net": "BSD-3-Clause",
    "golang.org/x/sync": "BSD-3-Clause",
    "golang.org/x/sys": "BSD-3-Clause",
    "golang.org/x/term": "BSD-3-Clause",
    "golang.org/x/text": "BSD-3-Clause",
    "golang.org/x/tools": "BSD-3-Clause",
    "google.golang.org/protobuf": "BSD-3-Clause",
    "gopkg.in/check.v1": "BSD-2-Clause",
    "gopkg.in/warnings.v0": "BSD-2-Clause",
    "gopkg.in/yaml.v2": "Apache-2.0 AND MIT",
    "gopkg.in/yaml.v3": "Apache-2.0 AND MIT",
}

SWIFT_LICENSES = {
    "openapikit": "MIT",
    "runestone": "MIT",
    "swift-algorithms": "Apache-2.0",
    "swift-argument-parser": "Apache-2.0",
    "swift-collections": "Apache-2.0",
    "swift-docc-plugin": "Apache-2.0",
    "swift-docc-symbolkit": "Apache-2.0",
    "swift-http-types": "Apache-2.0",
    "swift-numerics": "Apache-2.0",
    "swift-openapi-generator": "Apache-2.0",
    "swift-openapi-runtime": "Apache-2.0",
    "swiftterm": "MIT",
    "tree-sitter": "MIT",
    "treesitterlanguages": "MIT",
    "yams": "MIT",
}

TERRAFORM_LICENSES = {
    "registry.terraform.io/coder/coder": "MPL-2.0",
    "registry.terraform.io/kreuzwerker/docker": "MPL-2.0",
}

IMAGE_LICENSES = {
    "postgres": "PostgreSQL",
    "ghcr.io/coder/coder": "AGPL-3.0-only AND LicenseRef-Coder-Enterprise-Components",
    "caddy": "Apache-2.0",
    "docker.io/library/golang": "BSD-3-Clause",
    "docker.io/library/ubuntu": "LicenseRef-Ubuntu-Distribution-Mixed",
    "ghcr.io/coder/envbuilder": "AGPL-3.0-only",
}

OPERATIONAL_TOOL_LICENSES = {
    "syft": "Apache-2.0",
    "trivy": "Apache-2.0",
}


@dataclass(frozen=True)
class Component:
    ecosystem: str
    name: str
    version: str
    license_expression: str
    source: str
    checksum_algorithm: str = ""
    checksum: str = ""
    direct: bool = True

    @property
    def key(self) -> tuple[str, str, str]:
        return self.ecosystem, self.name.lower(), self.version


def decode_json_stream(raw: str) -> list[dict[str, object]]:
    decoder = json.JSONDecoder()
    offset = 0
    documents: list[dict[str, object]] = []
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            break
        document, offset = decoder.raw_decode(raw, offset)
        documents.append(document)
    return documents


def go_components(root: Path) -> list[Component]:
    module_file = subprocess.run(
        ["go", "mod", "edit", "-json"],
        cwd=root / "services/control-plane",
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GOTOOLCHAIN": "local"},
    )
    direct_requirements = {
        requirement["Path"]
        for requirement in json.loads(module_file.stdout).get("Require", [])
        if not requirement.get("Indirect", False)
    }
    command = ["go", "list", "-m", "-json", "all"]
    result = subprocess.run(
        command,
        cwd=root / "services/control-plane",
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GOTOOLCHAIN": "local"},
    )
    components: list[Component] = []
    for module in decode_json_stream(result.stdout):
        if module.get("Main"):
            continue
        name = str(module["Path"])
        version = str(module.get("Version", "unknown"))
        checksum = str(module.get("Sum", ""))
        algorithm = ""
        if checksum.startswith("h1:"):
            checksum = base64.b64decode(checksum[3:]).hex()
            algorithm = "SHA-256"
        components.append(
            Component(
                ecosystem="Go module",
                name=name,
                version=version,
                license_expression=GO_LICENSES.get(name, "LicenseRef-Needs-Review"),
                source=f"https://{name}",
                checksum_algorithm=algorithm,
                checksum=checksum,
                direct=name in direct_requirements,
            )
        )
    return components


def swift_components(root: Path) -> list[Component]:
    lock = json.loads((root / "apps/ios/Package.resolved").read_text(encoding="utf-8"))
    components: list[Component] = []
    for pin in lock["pins"]:
        state = pin["state"]
        components.append(
            Component(
                ecosystem="Swift package",
                name=pin["identity"],
                version=state.get("version", state["revision"]),
                license_expression=SWIFT_LICENSES.get(
                    pin["identity"], "LicenseRef-Needs-Review"
                ),
                source=pin["location"],
                checksum_algorithm="SHA-1",
                checksum=state["revision"],
                direct=pin["identity"]
                in {
                    "runestone",
                    "swift-openapi-generator",
                    "swift-openapi-runtime",
                    "swiftterm",
                    "treesitterlanguages",
                },
            )
        )
    return components


def terraform_components(root: Path) -> list[Component]:
    lock = root / "infra/coder/templates/codex-mobile-envbuilder/.terraform.lock.hcl"
    if not lock.exists():
        raise RuntimeError(f"missing required Terraform lockfile: {lock}")
    raw = lock.read_text(encoding="utf-8")
    components: list[Component] = []
    block_pattern = re.compile(r'provider "([^"]+)" \{(.*?)\n\}', re.DOTALL)
    for name, block in block_pattern.findall(raw):
        version_match = re.search(r'^\s*version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        h1_match = re.search(r'"h1:([A-Za-z0-9+/=]+)"', block)
        if not version_match:
            raise RuntimeError(f"provider {name} has no locked version")
        checksum = base64.b64decode(h1_match.group(1)).hex() if h1_match else ""
        components.append(
            Component(
                ecosystem="Terraform provider",
                name=name,
                version=version_match.group(1),
                license_expression=TERRAFORM_LICENSES.get(
                    name, "LicenseRef-Needs-Review"
                ),
                source=f"https://{name}",
                checksum_algorithm="SHA-256" if checksum else "",
                checksum=checksum,
            )
        )
    return components


def image_license(reference: str) -> str:
    normalized = reference.split("@", 1)[0]
    base = normalized.split(":", 1)[0]
    for prefix, license_expression in IMAGE_LICENSES.items():
        if base == prefix or base.startswith(prefix + "/"):
            return license_expression
    if base.startswith("localhost/codex-mobile/"):
        return "LicenseRef-First-Party-No-License"
    return "LicenseRef-Needs-Review"


def image_components(root: Path) -> list[Component]:
    references: set[str] = set()
    compose = (root / "infra/compose.yaml").read_text(encoding="utf-8")
    references.update(re.findall(r"^\s*image:\s*([^\s#]+)", compose, re.MULTILINE))
    for dockerfile in sorted((root / "infra").rglob("*Dockerfile")) + sorted(
        (root / "infra").rglob("Dockerfile")
    ):
        raw = dockerfile.read_text(encoding="utf-8")
        for reference in re.findall(
            r"^FROM\s+([^\s]+)", raw, re.MULTILINE | re.IGNORECASE
        ):
            if "$" not in reference and reference.lower() != "scratch":
                references.add(reference)
    components: list[Component] = []
    for reference in sorted(references):
        reference = re.sub(r"\$\{[A-Z][A-Z0-9_]*:-([^}]+)\}", r"\1", reference)
        without_digest, separator, digest = reference.partition("@sha256:")
        name, tag_separator, tag = without_digest.rpartition(":")
        if not tag_separator or "/" in tag:
            name, tag = without_digest, "unpinned"
        components.append(
            Component(
                ecosystem="OCI image",
                name=name,
                version=tag,
                license_expression=image_license(reference),
                source=reference,
                checksum_algorithm="SHA-256" if separator else "",
                checksum=digest,
                direct=True,
            )
        )
    return components


def tool_components(root: Path) -> list[Component]:
    tools: list[Component] = []
    for raw in (root / ".tool-versions").read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        name, version = raw.split(maxsplit=1)
        operational_license = OPERATIONAL_TOOL_LICENSES.get(name)
        tools.append(
            Component(
                ecosystem="Operational tool" if operational_license else "Build tool",
                name=name,
                version=version,
                license_expression=(
                    operational_license or "LicenseRef-Tooling-Not-Distributed"
                ),
                source=".tool-versions",
            )
        )
    return tools


def purl(component: Component) -> str | None:
    encoded_name = quote(component.name, safe="/@._-")
    encoded_version = quote(component.version, safe="._-")
    if component.ecosystem == "Go module":
        return f"pkg:golang/{encoded_name}@{encoded_version}"
    if component.ecosystem == "Swift package":
        return f"pkg:swift/{encoded_name}@{encoded_version}"
    if component.ecosystem == "Terraform provider":
        return f"pkg:terraform/{encoded_name}@{encoded_version}"
    if component.ecosystem == "OCI image" and component.version != "unpinned":
        return f"pkg:oci/{quote(component.name, safe='/._-')}@{encoded_version}"
    return None


def cyclonedx(components: list[Component]) -> str:
    serial_seed = "\n".join("|".join(component.key) for component in components)
    serial = hashlib.sha256(serial_seed.encode()).hexdigest()
    records: list[dict[str, object]] = []
    for component in components:
        reference = hashlib.sha256("|".join(component.key).encode()).hexdigest()
        record: dict[str, object] = {
            "bom-ref": reference,
            "type": "library" if component.ecosystem != "OCI image" else "container",
            "name": component.name,
            "version": component.version,
            "licenses": [{"expression": component.license_expression}],
            "properties": [
                {"name": "codex-mobile:ecosystem", "value": component.ecosystem},
                {"name": "codex-mobile:direct", "value": str(component.direct).lower()},
                {"name": "codex-mobile:source", "value": component.source},
            ],
        }
        package_url = purl(component)
        if package_url:
            record["purl"] = package_url
        if component.checksum:
            record["hashes"] = [
                {"alg": component.checksum_algorithm, "content": component.checksum}
            ]
        records.append(record)
    document = {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "generate-supply-chain.py",
                        "version": GENERATOR_VERSION,
                    }
                ]
            },
            "component": {
                "bom-ref": "codex-mobile-source",
                "type": "application",
                "name": "codex-mobile",
                "version": "0.1.0-private-mvp",
            },
        },
        "components": records,
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def markdown_table(components: list[Component], include_license: bool) -> str:
    if include_license:
        header = "| Ecosystem | Dependency | Version | Relationship | License conclusion |\n| --- | --- | --- | --- | --- |\n"
    else:
        header = "| Ecosystem | Dependency | Version | Relationship | Integrity/source |\n| --- | --- | --- | --- | --- | --- |\n"
    rows = []
    for component in components:
        relationship = "direct" if component.direct else "transitive"
        if include_license:
            final = component.license_expression
        elif component.checksum:
            final = f"{component.checksum_algorithm} `{component.checksum}`"
        else:
            final = f"`{component.source}`"
        rows.append(
            f"| {component.ecosystem} | `{component.name}` | `{component.version}` | {relationship} | {final} |"
        )
    return header + "\n".join(rows) + "\n"


def report_files(components: list[Component]) -> dict[Path, str]:
    dependency_intro = """# Dependency report

Generated deterministically from `go.mod`/`go.sum`, Swift `Package.resolved`,
Terraform's dependency lockfile, pinned OCI references, and `.tool-versions` by
`python scripts/generate-supply-chain.py`. Run the generator after every
dependency or image change. A checksum listed here is lock/pin evidence, not a
claim that an image was built or executed.

"""
    license_intro = """# Dependency license report

Generated by `python scripts/generate-supply-chain.py`. License conclusions
cover declared source dependencies, providers, and top-level image projects;
they are an engineering inventory, not legal advice. `LicenseRef-*` entries
require the described operator review and are intentionally not presented as
an SPDX conclusion. Transitive OS packages inside images must be re-scanned
from each built release image before deployment.

The publicly visible first-party project grants no open-source or redistribution
license. That deliberate no-license status is distinct from an unknown
third-party license.

"""
    return {
        REPORT_DIRECTORY / "SBOM.cdx.json": cyclonedx(components),
        REPORT_DIRECTORY / "DEPENDENCIES.md": dependency_intro
        + markdown_table(components, False),
        REPORT_DIRECTORY / "LICENSES.md": license_intro
        + markdown_table(components, True),
    }


def build(root: Path) -> dict[Path, str]:
    components = (
        go_components(root)
        + swift_components(root)
        + terraform_components(root)
        + image_components(root)
        + tool_components(root)
    )
    components = sorted(set(components), key=lambda item: item.key)
    needs_review = [
        component
        for component in components
        if component.license_expression == "LicenseRef-Needs-Review"
    ]
    if needs_review:
        names = ", ".join(component.name for component in needs_review)
        raise RuntimeError(
            f"third-party license review mapping is missing for: {names}"
        )
    return report_files(components)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.repo_root.resolve()
    try:
        reports = build(root)
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"supply-chain generation failed: {exc}", file=sys.stderr)
        return 1

    stale: list[Path] = []
    for relative, content in reports.items():
        target = root / relative
        if args.check:
            if not target.exists() or target.read_text(encoding="utf-8") != content:
                stale.append(relative)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        print("tracked supply-chain reports are stale or missing:", file=sys.stderr)
        for path in stale:
            print(f"- {path}", file=sys.stderr)
        print("run: python scripts/generate-supply-chain.py", file=sys.stderr)
        return 1
    action = "verified" if args.check else "generated"
    print(f"supply-chain reports {action}: {len(reports)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
