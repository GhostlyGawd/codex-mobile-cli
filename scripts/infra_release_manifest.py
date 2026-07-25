#!/usr/bin/env python3
"""Create and verify immutable, host-local release provenance.

The manifest binds an immutable source release to the exact local OCI image
IDs and host/runtime artifacts that may be activated.  It deliberately does
not pull, build, tag, promote, or delete anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


SCHEMA_VERSION = 1
RELEASE_ID_PATTERN = re.compile(r"sha-[0-9a-f]{7,64}")
IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

HOST_ARTIFACTS = {
    "containers.conf": (
        "infra/containers.conf",
        "/etc/codex-mobile/containers.conf",
        "0644",
    ),
    "containers-storage.conf": (
        "infra/containers-storage.conf",
        "/etc/codex-mobile/containers-storage.conf",
        "0644",
    ),
    "codex-mobile.service": (
        "infra/systemd/codex-mobile.service",
        "/etc/systemd/system/codex-mobile.service",
        "0644",
    ),
    "codex-mobile-docker-firewall.service": (
        "infra/systemd/codex-mobile-docker-firewall.service",
        "/etc/systemd/system/codex-mobile-docker-firewall.service",
        "0644",
    ),
    "codex-mobile-workspace-runtime.service": (
        "infra/systemd/codex-mobile-workspace-runtime.service",
        "/etc/systemd/system/codex-mobile-workspace-runtime.service",
        "0644",
    ),
    "codex-mobile-provisioner.service": (
        "infra/systemd/codex-mobile-provisioner.service",
        "/etc/systemd/system/codex-mobile-provisioner.service",
        "0644",
    ),
    "apply-docker-firewall": (
        "infra/systemd/apply-docker-firewall.sh",
        "/usr/local/libexec/codex-mobile/apply-docker-firewall",
        "0755",
    ),
    "start-provisioner": (
        "infra/systemd/start-provisioner.sh",
        "/usr/local/libexec/codex-mobile/start-provisioner",
        "0755",
    ),
    "verify-workspace-storage": (
        "infra/systemd/verify-workspace-storage.sh",
        "/usr/local/libexec/codex-mobile/verify-workspace-storage",
        "0755",
    ),
    "ensure-workspace-control-network": (
        "infra/systemd/ensure-workspace-control-network.py",
        "/usr/local/libexec/codex-mobile/ensure-workspace-control-network",
        "0755",
    ),
}

CRITICAL_RELEASE_FILES = (
    "infra/containers.conf",
    "infra/containers-storage.conf",
    "infra/compose.yaml",
    "infra/compose.github.yaml",
    "infra/compose.apns.yaml",
    "infra/docker/control-plane.Dockerfile",
    "infra/workspace/Dockerfile",
    "infra/workspace/EnvBuilder.Dockerfile",
    "infra/systemd/ensure-workspace-control-network.py",
    "scripts/infra-compose.sh",
    "scripts/infra-deploy.sh",
    "scripts/infra-rollback.sh",
    "scripts/infra-build-workspace-image.sh",
    "scripts/infra-checkpoint.sh",
    "scripts/infra-health.sh",
    "scripts/infra-smoke.sh",
    "scripts/infra-admin.sh",
    "scripts/infra_check_provisioner.py",
    "scripts/infra-import-coder-template.sh",
    "scripts/infra-install-release-host-artifacts.sh",
    "scripts/infra_release_manifest.py",
)


class ManifestError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ManifestError(f"release artifact is not a regular non-symlink: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(path: Path) -> str:
    if not path.is_dir() or path.is_symlink():
        raise ManifestError(f"release artifact tree is invalid: {path}")
    if (path / ".terraform").exists():
        raise ManifestError("release Coder template contains a Terraform working directory")
    digest = hashlib.sha256()
    files = sorted(path.rglob("*"))
    for item in files:
        relative = item.relative_to(path).as_posix()
        info = item.lstat()
        if item.is_symlink():
            raise ManifestError(f"release artifact tree contains a symlink: {relative}")
        if item.is_dir():
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ManifestError(f"release artifact tree contains a special file: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{stat.S_IMODE(info.st_mode):04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(item)))
    return digest.hexdigest()


def normalize_image_id(value: str, reference: str) -> str:
    candidate = value.strip()
    if not IMAGE_ID_PATTERN.fullmatch(candidate):
        raise ManifestError(f"{reference} did not resolve to an immutable sha256 image ID")
    return candidate


def inspect_image(engine: str, reference: str, podman_url: str) -> str:
    if engine == "docker":
        argv = ["docker", "image", "inspect", "--format", "{{.Id}}", reference]
    elif engine == "podman":
        argv = [
            "podman",
            "--url",
            podman_url,
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            reference,
        ]
    else:
        raise ManifestError(f"unsupported image engine: {engine}")
    try:
        completed = subprocess.run(
            argv,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ManifestError(f"cannot inspect required image {reference}: {exc}") from exc
    return normalize_image_id(completed.stdout, reference)


def inspect_workspace_helper(reference: str, podman_url: str) -> str:
    argv = [
        "podman",
        "--url",
        podman_url,
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "all",
        "--security-opt",
        "no-new-privileges",
        reference,
        "sha256sum",
        "/opt/codex-mobile-helper/codex-mobile-workspace-helper",
    ]
    try:
        completed = subprocess.run(
            argv,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ManifestError(f"cannot verify workspace helper in {reference}: {exc}") from exc
    checksum = completed.stdout.strip().split(maxsplit=1)[0]
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ManifestError("workspace helper did not produce a valid sha256 checksum")
    return checksum


def image_references(release_id: str) -> dict[str, tuple[str, str]]:
    return {
        "control_plane": (
            "docker",
            f"localhost/codex-mobile/control-plane:{release_id}",
        ),
        "workspace_base": (
            "podman",
            f"localhost/codex-mobile/workspace-base:{release_id}",
        ),
        "envbuilder": (
            "podman",
            f"localhost/codex-mobile/envbuilder:{release_id}",
        ),
    }


def release_environment(release_id: str) -> str:
    references = image_references(release_id)
    return "".join(
        (
            f"RELEASE_ID={release_id}\n",
            f"CONTROL_PLANE_IMAGE_TAG={release_id}\n",
            f"WORKSPACE_BASE_IMAGE={references['workspace_base'][1]}\n",
            f"ENVBUILDER_IMAGE={references['envbuilder'][1]}\n",
        )
    )


def atomic_write(path: Path, content: bytes, mode: int = 0o444) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


ImageResolver = Callable[[str, str], str]


def build_manifest(
    repo_root: Path,
    release_id: str,
    image_resolver: ImageResolver,
    helper_resolver: Callable[[str], str],
) -> dict[str, object]:
    if not RELEASE_ID_PATTERN.fullmatch(release_id):
        raise ManifestError("release ID must be sha-<lowercase commit>")
    repo_root = repo_root.resolve(strict=True)
    release_files: dict[str, str] = {}
    for relative in CRITICAL_RELEASE_FILES:
        release_files[relative] = sha256_file(repo_root / relative)

    host_artifacts: dict[str, dict[str, str]] = {}
    for name, (source, destination, mode) in HOST_ARTIFACTS.items():
        host_artifacts[name] = {
            "source": source,
            "destination": destination,
            "mode": mode,
            "sha256": sha256_file(repo_root / source),
        }

    images: dict[str, dict[str, str]] = {}
    for name, (engine, reference) in image_references(release_id).items():
        images[name] = {
            "engine": engine,
            "reference": reference,
            "id": normalize_image_id(image_resolver(engine, reference), reference),
        }

    helper_checksum = helper_resolver(images["workspace_base"]["reference"])
    if not re.fullmatch(r"[0-9a-f]{64}", helper_checksum):
        raise ManifestError("workspace helper checksum is invalid")
    template_path = "infra/coder/templates/codex-mobile-envbuilder"
    return {
        "schema_version": SCHEMA_VERSION,
        "release_id": release_id,
        "source_commit": release_id.removeprefix("sha-"),
        "images": images,
        "workspace_helper_sha256": helper_checksum,
        "coder": {
            "template_name": "codex-mobile-envbuilder",
            "template_path": template_path,
            "template_sha256": sha256_tree(repo_root / template_path),
            "provisioner_tag": "runtime=private-podman",
            "workspace_base_image": images["workspace_base"]["reference"],
            "envbuilder_image": images["envbuilder"]["reference"],
        },
        "release_environment_sha256": hashlib.sha256(
            release_environment(release_id).encode("ascii")
        ).hexdigest(),
        "release_files": release_files,
        "host_artifacts": host_artifacts,
    }


def write_manifest(repo_root: Path, manifest: dict[str, object]) -> None:
    release_id = str(manifest["release_id"])
    atomic_write(
        repo_root / "infra" / "release.env",
        release_environment(release_id).encode("ascii"),
    )
    serialized = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    atomic_write(repo_root / "infra" / "release-manifest.json", serialized)


def load_manifest(repo_root: Path) -> dict[str, object]:
    path = repo_root / "infra" / "release-manifest.json"
    if path.is_symlink():
        raise ManifestError("release manifest must not be a symlink")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read release manifest: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("release manifest schema is unsupported")
    return document


def verify_manifest(
    repo_root: Path,
    image_resolver: ImageResolver | None = None,
    installed_root: Path | None = None,
) -> dict[str, object]:
    repo_root = repo_root.resolve(strict=True)
    manifest = load_manifest(repo_root)
    release_id = manifest.get("release_id")
    if not isinstance(release_id, str) or not RELEASE_ID_PATTERN.fullmatch(release_id):
        raise ManifestError("release manifest contains an invalid release ID")
    if manifest.get("source_commit") != release_id.removeprefix("sha-"):
        raise ManifestError("release manifest source commit does not match its ID")

    expected_environment = release_environment(release_id).encode("ascii")
    try:
        actual_environment = (repo_root / "infra" / "release.env").read_bytes()
    except OSError as exc:
        raise ManifestError(f"cannot read release environment: {exc}") from exc
    if actual_environment != expected_environment:
        raise ManifestError("release environment does not match immutable manifest")
    if hashlib.sha256(actual_environment).hexdigest() != manifest.get(
        "release_environment_sha256"
    ):
        raise ManifestError("release environment checksum is invalid")

    release_files = manifest.get("release_files")
    if not isinstance(release_files, dict) or set(release_files) != set(
        CRITICAL_RELEASE_FILES
    ):
        raise ManifestError("release manifest critical-file inventory is invalid")
    for relative, expected in release_files.items():
        if sha256_file(repo_root / relative) != expected:
            raise ManifestError(f"release artifact checksum mismatch: {relative}")

    coder = manifest.get("coder")
    if not isinstance(coder, dict):
        raise ManifestError("release manifest Coder provenance is invalid")
    template_path = coder.get("template_path")
    if template_path != "infra/coder/templates/codex-mobile-envbuilder":
        raise ManifestError("release manifest Coder template path is invalid")
    if sha256_tree(repo_root / template_path) != coder.get("template_sha256"):
        raise ManifestError("Coder template checksum does not match manifest")

    host_artifacts = manifest.get("host_artifacts")
    if not isinstance(host_artifacts, dict) or set(host_artifacts) != set(HOST_ARTIFACTS):
        raise ManifestError("release manifest host-artifact inventory is invalid")
    for name, (source, destination, mode) in HOST_ARTIFACTS.items():
        record = host_artifacts.get(name)
        if not isinstance(record, dict):
            raise ManifestError(f"host artifact record is invalid: {name}")
        expected = {
            "source": source,
            "destination": destination,
            "mode": mode,
            "sha256": sha256_file(repo_root / source),
        }
        if record != expected:
            raise ManifestError(f"host artifact does not match release: {name}")
        if installed_root is not None:
            installed = installed_root / destination.lstrip("/")
            if sha256_file(installed) != record["sha256"]:
                raise ManifestError(f"installed host artifact does not match: {destination}")
            installed_info = installed.stat()
            if (installed_info.st_uid, installed_info.st_gid) != (0, 0):
                raise ManifestError(
                    f"installed host artifact is not owned by root:root: {destination}"
                )
            if f"{stat.S_IMODE(installed_info.st_mode):04o}" != mode:
                raise ManifestError(f"installed host artifact mode does not match: {destination}")

    images = manifest.get("images")
    expected_references = image_references(release_id)
    if not isinstance(images, dict) or set(images) != set(expected_references):
        raise ManifestError("release manifest image inventory is invalid")
    for name, (engine, reference) in expected_references.items():
        record = images.get(name)
        if not isinstance(record, dict):
            raise ManifestError(f"image record is invalid: {name}")
        if record.get("engine") != engine or record.get("reference") != reference:
            raise ManifestError(f"image reference does not match release: {name}")
        recorded_id = normalize_image_id(str(record.get("id", "")), reference)
        if image_resolver is not None:
            current_id = normalize_image_id(image_resolver(engine, reference), reference)
            if current_id != recorded_id:
                raise ManifestError(f"local image tag no longer matches manifest: {reference}")
    if coder.get("workspace_base_image") != images["workspace_base"]["reference"]:
        raise ManifestError("Coder workspace image does not match manifest")
    if coder.get("envbuilder_image") != images["envbuilder"]["reference"]:
        raise ManifestError("Coder EnvBuilder image does not match manifest")
    helper_checksum = manifest.get("workspace_helper_sha256")
    if not isinstance(helper_checksum, str) or not re.fullmatch(
        r"[0-9a-f]{64}", helper_checksum
    ):
        raise ManifestError("workspace helper checksum in manifest is invalid")
    return manifest


def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ManifestError("release manifest operations require root")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create", "verify"))
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--release-id")
    parser.add_argument("--require-images", action="store_true")
    parser.add_argument("--verify-installed", action="store_true")
    parser.add_argument(
        "--podman-url",
        default=os.environ.get(
            "PODMAN_URL", "unix:///run/codex-mobile-podman/podman.sock"
        ),
    )
    args = parser.parse_args(argv)
    try:
        require_root()
        if args.action == "create":
            if not args.release_id:
                raise ManifestError("create requires --release-id")
            manifest = build_manifest(
                args.repo_root,
                args.release_id,
                lambda engine, reference: inspect_image(
                    engine, reference, args.podman_url
                ),
                lambda reference: inspect_workspace_helper(reference, args.podman_url),
            )
            write_manifest(args.repo_root, manifest)
            verify_manifest(args.repo_root)
            print(f"release manifest created: {args.release_id}")
        else:
            installed_root = Path("/") if args.verify_installed else None
            resolver = None
            if args.require_images:
                def resolver(engine: str, reference: str) -> str:
                    return inspect_image(engine, reference, args.podman_url)
            manifest = verify_manifest(args.repo_root, resolver, installed_root)
            print(f"release manifest verified: {manifest['release_id']}")
        return 0
    except ManifestError as exc:
        print(f"release manifest verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
