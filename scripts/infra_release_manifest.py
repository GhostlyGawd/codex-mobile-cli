#!/usr/bin/env python3
"""Create and verify immutable, host-local release provenance.

The manifest binds an immutable source release to the exact local OCI image
IDs and host/runtime artifacts that may be activated.  It deliberately does
not pull, build, tag, promote, or delete anything.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import importlib.util
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import BinaryIO, Callable, Mapping, NamedTuple, Sequence
from urllib.parse import unquote, urlsplit


SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = frozenset((1, SCHEMA_VERSION))
RELEASE_ID_PATTERN = re.compile(r"sha-[0-9a-f]{7,64}")
IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
DEFAULT_PODMAN_URL = "unix:///run/codex-mobile-podman/podman.sock"
DOCKER_EXECUTABLE = "/usr/bin/docker"
PODMAN_EXECUTABLE = "/usr/bin/podman"
MINIMAL_SUBPROCESS_PATH = "/usr/bin:/bin"
MAX_COMMAND_STDOUT_BYTES = 16 * 1024
MAX_COMMAND_STDERR_BYTES = 64 * 1024
MAX_HELPER_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RELEASE_ENVIRONMENT_BYTES = 4096
IMAGE_AUDIT_ROOT = Path("infra/image-audit")
IMAGE_AUDIT_RECEIPT = IMAGE_AUDIT_ROOT / "receipt.json"
CURRENT_WORKSPACE_HELPER_PROFILE_VERSION = 2
WORKSPACE_HELPER_PROFILE_REGISTRY = MappingProxyType(
    {
        1: MappingProxyType(
            {
                "amd64": (
                    "f6fc430a2200d13ee0ef04dd576875b4f9a7c95a04287cbdec2deec3b495493c"
                ),
                "arm64": (
                    "c7e4577a465b55721043612f9b6919248806576816388b01898f6c2784dc163e"
                ),
            }
        ),
        2: MappingProxyType(
            {
                "amd64": (
                    "11d1fb9c53549e98bb5a976c2958954ff6eb99fd9485dd09beac50f6157df924"
                ),
                "arm64": (
                    "81a623dae961e640c18ac1df942baf9a797dbeb79b9f90312b62f241d36da1dd"
                ),
            }
        ),
    }
)

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

V1_CRITICAL_RELEASE_FILES = (
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
CRITICAL_RELEASE_FILES = V1_CRITICAL_RELEASE_FILES + (
    ".tool-versions",
    "infra/image-audit-policy.json",
    "scripts/check-billing-policy.py",
    "scripts/infra-preflight.py",
    "scripts/infra_image_audit.py",
)
V1_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "release_id",
        "source_commit",
        "images",
        "workspace_helper_sha256",
        "coder",
        "release_environment_sha256",
        "release_files",
        "host_artifacts",
    }
)
V2_MANIFEST_KEYS = V1_MANIFEST_KEYS | {"image_audit", "workspace_helper"}


def critical_release_files(schema_version: int) -> tuple[str, ...]:
    if schema_version == 1:
        return V1_CRITICAL_RELEASE_FILES
    if schema_version == SCHEMA_VERSION:
        return CRITICAL_RELEASE_FILES
    raise ManifestError("release manifest schema is unsupported")


class ManifestError(RuntimeError):
    pass


def normalize_architecture(value: object) -> str:
    if not isinstance(value, str):
        raise ManifestError("release image architecture is invalid")
    normalized = value.strip().lower()
    if normalized in {"amd64", "x86_64"}:
        return "amd64"
    if normalized in {"arm64", "aarch64"}:
        return "arm64"
    raise ManifestError(f"unsupported release image architecture: {value}")


def workspace_helper_profile(version: object) -> Mapping[str, str]:
    if type(version) is not int or version not in WORKSPACE_HELPER_PROFILE_REGISTRY:
        raise ManifestError("workspace helper profile version is unsupported")
    return WORKSPACE_HELPER_PROFILE_REGISTRY[version]


def read_regular_bytes(path: Path, limit: int, description: str) -> bytes:
    """Read a bounded regular file through a no-follow descriptor."""

    if limit <= 0:
        raise ManifestError(f"{description} size limit is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise ManifestError(f"{description} must be a regular non-symlink")
        if before.st_nlink != 1 or before.st_size > limit:
            raise ManifestError(f"{description} exceeds its trusted file limits")
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > limit
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ManifestError(f"{description} changed or is not a trusted file")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > limit:
                raise ManifestError(f"{description} exceeds its trusted file limits")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) or consumed != opened.st_size:
            raise ManifestError(f"{description} changed while being read")
        return b"".join(chunks)
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError(f"cannot read {description}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def parse_strict_json(content: bytes, description: str) -> object:
    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise ManifestError(
                    f"{description} contains a duplicate object key: {key}"
                )
            document[key] = value
        return document

    def reject_nonfinite(value: str) -> object:
        raise ManifestError(f"{description} contains a non-finite number: {value}")

    try:
        text = content.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except ManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot parse {description}: {exc}") from exc


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
        raise ManifestError(
            "release Coder template contains a Terraform working directory"
        )
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
            raise ManifestError(
                f"release artifact tree contains a special file: {relative}"
            )
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{stat.S_IMODE(info.st_mode):04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(item)))
    return digest.hexdigest()


def normalize_image_id(value: str, reference: str) -> str:
    candidate = value.strip()
    if not IMAGE_ID_PATTERN.fullmatch(candidate):
        raise ManifestError(
            f"{reference} did not resolve to an immutable sha256 image ID"
        )
    return candidate


def normalize_inspected_image_id(engine: str, value: str, reference: str) -> str:
    candidate = value.strip()
    if engine == "podman" and SHA256_PATTERN.fullmatch(candidate):
        candidate = f"sha256:{candidate}"
    return normalize_image_id(candidate, reference)


def validate_podman_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise ManifestError(
            "Podman URL must be an absolute normalized local unix:/// socket URL"
        )
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ManifestError(
            "Podman URL must be an absolute normalized local unix:/// socket URL"
        ) from exc
    decoded_path = unquote(parsed.path)
    if (
        not value.startswith("unix:///")
        or parsed.scheme != "unix"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
        or decoded_path != parsed.path
        or "\\" in decoded_path
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ManifestError(
            "Podman URL must be an absolute normalized local unix:/// socket URL"
        )
    path = PurePosixPath(decoded_path)
    components = decoded_path.split("/")[1:]
    if (
        not path.is_absolute()
        or len(path.parts) < 2
        or not components
        or any(component in {"", ".", ".."} for component in components)
        or path.as_posix() != decoded_path
        or value != f"unix://{decoded_path}"
    ):
        raise ManifestError(
            "Podman URL must be an absolute normalized local unix:/// socket URL"
        )
    return value


def minimal_subprocess_environment() -> dict[str, str]:
    return {
        "PATH": MINIMAL_SUBPROCESS_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


class CommandResult(NamedTuple):
    returncode: int
    stdout: bytes
    stderr: bytes


def _child_file_limit(file_size_limit: int) -> None:
    try:
        import resource

        hard_limit = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
        child_limit = (
            file_size_limit
            if hard_limit == resource.RLIM_INFINITY
            else min(file_size_limit, hard_limit)
        )
        if child_limit <= 0:
            os._exit(126)
        resource.setrlimit(resource.RLIMIT_FSIZE, (child_limit, child_limit))
    except (ImportError, OSError, ValueError):
        os._exit(126)


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def run_bounded_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int,
    stdout_limit: int = MAX_COMMAND_STDOUT_BYTES,
    stderr_limit: int = MAX_COMMAND_STDERR_BYTES,
    file_size_limit: int = MAX_HELPER_BYTES,
) -> CommandResult:
    if (
        not argv
        or timeout_seconds <= 0
        or stdout_limit <= 0
        or stderr_limit <= 0
        or file_size_limit <= 0
        or any(not isinstance(value, str) or "\x00" in value for value in argv)
    ):
        raise ManifestError("image inspection subprocess parameters are invalid")
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
            close_fds=True,
            preexec_fn=(
                functools.partial(_child_file_limit, file_size_limit)
                if os.name == "posix"
                else None
            ),
        )
    except OSError as exc:
        raise ManifestError("cannot start required image inspection tool") from exc
    assert process.stdout is not None and process.stderr is not None
    overflow = threading.Event()
    reader_errors: list[BaseException] = []
    captured = {"stdout": bytearray(), "stderr": bytearray()}

    def drain(name: str, pipe: BinaryIO, limit: int) -> None:
        consumed = 0
        try:
            while True:
                chunk = pipe.read(64 * 1024)
                if not chunk:
                    return
                consumed += len(chunk)
                if consumed > limit:
                    overflow.set()
                    return
                captured[name].extend(chunk)
        except BaseException as exc:  # pragma: no cover - defensive thread boundary
            reader_errors.append(exc)
            overflow.set()
        finally:
            pipe.close()

    stdout_thread = threading.Thread(
        target=drain,
        args=("stdout", process.stdout, stdout_limit),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain,
        args=("stderr", process.stderr, stderr_limit),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    while process.poll() is None:
        if overflow.is_set():
            _terminate_process(process)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _terminate_process(process)
            break
        time.sleep(0.02)
    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        _terminate_process(process)
        raise ManifestError("image inspection tool output did not close")
    if reader_errors:
        raise ManifestError("cannot capture bounded image inspection output")
    if timed_out:
        raise ManifestError("image inspection tool timed out")
    if overflow.is_set():
        raise ManifestError("image inspection tool exceeded its output limit")
    if process.returncode is None:
        raise ManifestError("image inspection tool did not terminate")
    return CommandResult(
        returncode=int(process.returncode),
        stdout=bytes(captured["stdout"]),
        stderr=bytes(captured["stderr"]),
    )


CommandRunner = Callable[..., CommandResult]


def inspect_image(
    engine: str,
    reference: str,
    podman_url: str,
    runner: CommandRunner = run_bounded_command,
) -> str:
    podman_url = validate_podman_url(podman_url)
    if engine == "docker":
        argv = [
            DOCKER_EXECUTABLE,
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            reference,
        ]
    elif engine == "podman":
        argv = [
            PODMAN_EXECUTABLE,
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
    with tempfile.TemporaryDirectory(prefix="codex-mobile-image-inspect.") as raw:
        environment = minimal_subprocess_environment()
        if engine == "docker":
            docker_config = Path(raw) / "docker-config"
            docker_config.mkdir(mode=0o700)
            environment.update(
                {
                    "DOCKER_CONFIG": str(docker_config),
                    "DOCKER_HOST": "unix:///var/run/docker.sock",
                }
            )
        result = runner(
            argv,
            cwd=Path(raw),
            env=environment,
            timeout_seconds=30,
        )
    if result.returncode != 0:
        raise ManifestError(f"cannot inspect required image {reference}")
    try:
        stdout = result.stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"image inspection output is invalid: {reference}") from exc
    return normalize_inspected_image_id(engine, stdout, reference)


def inspect_podman_image_architecture(
    image_id: str,
    podman_url: str,
    runner: CommandRunner = run_bounded_command,
) -> str:
    podman_url = validate_podman_url(podman_url)
    image_id = normalize_image_id(image_id, "Podman image")
    with tempfile.TemporaryDirectory(prefix="codex-mobile-image-architecture.") as raw:
        result = runner(
            [
                PODMAN_EXECUTABLE,
                "--url",
                podman_url,
                "image",
                "inspect",
                "--format",
                "{{.Architecture}}",
                image_id,
            ],
            cwd=Path(raw),
            env=minimal_subprocess_environment(),
            timeout_seconds=30,
        )
    if result.returncode != 0:
        raise ManifestError("cannot inspect workspace image architecture")
    try:
        architecture = result.stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ManifestError("workspace image architecture output is invalid") from exc
    return normalize_architecture(architecture)


def inspect_workspace_helper(
    image_id: str,
    podman_url: str,
    runner: CommandRunner = run_bounded_command,
) -> str:
    """Extract and hash the helper without starting hostile image content."""

    podman_url = validate_podman_url(podman_url)
    image_id = normalize_image_id(image_id, "workspace base image")
    environment = minimal_subprocess_environment()
    container_name = f"cm-helper-inspect-{secrets.token_hex(16)}"
    with tempfile.TemporaryDirectory(prefix="codex-mobile-helper-inspect.") as raw:
        work = Path(raw)
        if os.name == "posix":
            work.chmod(0o700)
        primary_error: BaseException | None = None
        try:
            create = runner(
                [
                    PODMAN_EXECUTABLE,
                    "--url",
                    podman_url,
                    "create",
                    "--name",
                    container_name,
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "all",
                    "--security-opt",
                    "no-new-privileges",
                    image_id,
                ],
                cwd=work,
                env=environment,
                timeout_seconds=30,
            )
            if create.returncode != 0:
                raise ManifestError(
                    "cannot create workspace helper inspection container"
                )
            destination = work / "codex-mobile-workspace-helper"
            copied = runner(
                [
                    PODMAN_EXECUTABLE,
                    "--url",
                    podman_url,
                    "cp",
                    (
                        f"{container_name}:"
                        "/opt/codex-mobile-helper/codex-mobile-workspace-helper"
                    ),
                    str(destination),
                ],
                cwd=work,
                env=environment,
                timeout_seconds=30,
                file_size_limit=MAX_HELPER_BYTES,
            )
            if copied.returncode != 0:
                raise ManifestError("cannot extract workspace helper from image")
            info = destination.lstat()
            if (
                destination.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or not 0 < info.st_size <= MAX_HELPER_BYTES
            ):
                raise ManifestError("workspace helper extraction is invalid")
            return sha256_file(destination)
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            try:
                removed = runner(
                    [
                        PODMAN_EXECUTABLE,
                        "--url",
                        podman_url,
                        "rm",
                        "--force",
                        "--ignore",
                        container_name,
                    ],
                    cwd=work,
                    env=environment,
                    timeout_seconds=30,
                )
                if removed.returncode != 0 and primary_error is None:
                    raise ManifestError(
                        "cannot remove workspace helper inspection container"
                    )
            except BaseException:
                if primary_error is None:
                    raise


def verify_helper_pin(
    reference: str,
    podman_url: str,
    runner: CommandRunner = run_bounded_command,
) -> dict[str, object]:
    """Verify helper bytes from an exact Podman image without starting it."""

    podman_url = validate_podman_url(podman_url)
    before = inspect_image("podman", reference, podman_url, runner)
    architecture = inspect_podman_image_architecture(before, podman_url, runner)
    helper_sha256 = inspect_workspace_helper(before, podman_url, runner)
    expected = workspace_helper_profile(CURRENT_WORKSPACE_HELPER_PROFILE_VERSION)[
        architecture
    ]
    if helper_sha256 != expected:
        raise ManifestError(
            f"workspace helper checksum does not match the {architecture} release pin"
        )
    after = inspect_image("podman", reference, podman_url, runner)
    if after != before:
        raise ManifestError(
            "workspace image tag changed during helper-pin verification"
        )
    return {
        "architecture": architecture,
        "image_id": before,
        "profile_version": CURRENT_WORKSPACE_HELPER_PROFILE_VERSION,
        "workspace_helper_sha256": helper_sha256,
    }


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
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
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
ImageAuditVerifier = Callable[
    [Path, str, dict[str, dict[str, str]], ImageResolver | None, str],
    dict[str, object],
]


def verify_image_audit_evidence(
    repo_root: Path,
    release_id: str,
    expected_images: dict[str, dict[str, str]],
    image_resolver: ImageResolver | None,
    podman_url: str,
) -> dict[str, object]:
    """Load the verifier paired with this manifest implementation.

    Rollback deliberately uses the current release's manifest and audit
    verifiers to validate a target release. It must not delegate schema or
    evidence semantics to code from the target being selected.
    """

    podman_url = validate_podman_url(podman_url)
    script = Path(__file__).resolve().with_name("infra_image_audit.py")
    spec = importlib.util.spec_from_file_location(
        "_codex_mobile_infra_image_audit", script
    )
    if spec is None or spec.loader is None:
        raise ManifestError("cannot load the image-audit verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except (OSError, ImportError, SyntaxError, AttributeError) as exc:
        raise ManifestError(f"cannot load the image-audit verifier: {exc}") from exc
    audit_error = getattr(module, "AuditError", RuntimeError)
    try:
        return module.verify_evidence(
            repo_root,
            release_id,
            expected_images=expected_images,
            image_resolver=image_resolver,
            podman_url=podman_url,
        )
    except (audit_error, OSError, ValueError, KeyError, TypeError) as exc:
        raise ManifestError(f"image-audit evidence is invalid: {exc}") from exc


def image_audit_manifest_record(
    repo_root: Path,
    release_id: str,
    images: dict[str, dict[str, str]],
    evidence_verifier: ImageAuditVerifier,
    image_resolver: ImageResolver | None,
    podman_url: str,
) -> dict[str, object]:
    podman_url = validate_podman_url(podman_url)
    receipt = evidence_verifier(
        repo_root, release_id, images, image_resolver, podman_url
    )
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 1:
        raise ManifestError("image-audit receipt schema is invalid")
    if receipt.get("status") != "pass":
        raise ManifestError("image-audit receipt is not a pass")
    if receipt.get("release_id") != release_id:
        raise ManifestError("image-audit receipt release ID does not match")
    if receipt.get("source_commit") != release_id.removeprefix("sha-"):
        raise ManifestError("image-audit receipt source commit does not match")
    host = receipt.get("host")
    if not isinstance(host, dict):
        raise ManifestError("image-audit host record is invalid")
    architecture = normalize_architecture(host.get("architecture"))
    policy = receipt.get("scanner_policy")
    if not isinstance(policy, dict) or not isinstance(policy.get("version"), int):
        raise ManifestError("image-audit policy version is invalid")
    receipt_images = receipt.get("images")
    if not isinstance(receipt_images, dict) or set(receipt_images) != set(images):
        raise ManifestError("image-audit image inventory is invalid")

    audit_images: dict[str, dict[str, str]] = {}
    for name, expected in images.items():
        record = receipt_images.get(name)
        if not isinstance(record, dict):
            raise ManifestError(f"image-audit image record is invalid: {name}")
        image_id = normalize_image_id(str(record.get("image_id", "")), name)
        before = normalize_image_id(str(record.get("tag_image_id_before", "")), name)
        after = normalize_image_id(str(record.get("tag_image_id_after", "")), name)
        if (
            record.get("engine") != expected["engine"]
            or record.get("reference") != expected["reference"]
            or image_id != expected["id"]
            or before != image_id
            or after != image_id
            or normalize_architecture(record.get("architecture")) != architecture
        ):
            raise ManifestError(f"image-audit identity does not match manifest: {name}")
        reports = record.get("reports")
        if not isinstance(reports, dict) or set(reports) != {"sbom", "trivy"}:
            raise ManifestError(f"image-audit report inventory is invalid: {name}")
        report_hashes: dict[str, str] = {}
        for report_name in ("sbom", "trivy"):
            report = reports.get(report_name)
            if not isinstance(report, dict):
                raise ManifestError(
                    f"image-audit {report_name} report is invalid: {name}"
                )
            digest = report.get("sha256")
            if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
                raise ManifestError(
                    f"image-audit {report_name} checksum is invalid: {name}"
                )
            report_hashes[f"{report_name}_sha256"] = digest
        audit_images[name] = {"image_id": image_id, **report_hashes}

    try:
        receipt_sha256 = sha256_file(repo_root / IMAGE_AUDIT_RECEIPT)
        tree_sha256 = sha256_tree(repo_root / IMAGE_AUDIT_ROOT)
    except OSError as exc:
        raise ManifestError(f"cannot read image-audit evidence: {exc}") from exc
    return {
        "receipt_path": IMAGE_AUDIT_RECEIPT.as_posix(),
        "receipt_sha256": receipt_sha256,
        "tree_sha256": tree_sha256,
        "policy_version": policy["version"],
        "status": "pass",
        "architecture": architecture,
        "images": audit_images,
    }


def build_manifest(
    repo_root: Path,
    release_id: str,
    image_resolver: ImageResolver,
    helper_resolver: Callable[[str], str],
    evidence_verifier: ImageAuditVerifier = verify_image_audit_evidence,
    podman_url: str = DEFAULT_PODMAN_URL,
) -> dict[str, object]:
    podman_url = validate_podman_url(podman_url)
    if not RELEASE_ID_PATTERN.fullmatch(release_id):
        raise ManifestError("release ID must be sha-<lowercase commit>")
    repo_root = repo_root.resolve(strict=True)
    release_files: dict[str, str] = {}
    for relative in critical_release_files(SCHEMA_VERSION):
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

    helper_checksums: dict[str, str] = {}
    for name in ("workspace_base", "envbuilder"):
        image = images[name]
        helper_checksum = helper_resolver(image["id"])
        if not isinstance(helper_checksum, str) or not SHA256_PATTERN.fullmatch(
            helper_checksum
        ):
            raise ManifestError(f"{name} workspace helper checksum is invalid")
        helper_checksums[name] = helper_checksum
    image_audit = image_audit_manifest_record(
        repo_root,
        release_id,
        images,
        evidence_verifier,
        None,
        podman_url,
    )
    architecture = normalize_architecture(image_audit.get("architecture"))
    helper_profile_version = CURRENT_WORKSPACE_HELPER_PROFILE_VERSION
    expected_helper_checksum = workspace_helper_profile(helper_profile_version)[
        architecture
    ]
    if any(
        checksum != expected_helper_checksum for checksum in helper_checksums.values()
    ):
        raise ManifestError(
            f"workspace helper checksum does not match the {architecture} release pin"
        )
    for name, image in images.items():
        image_id_after = normalize_image_id(
            image_resolver(image["engine"], image["reference"]),
            image["reference"],
        )
        if image_id_after != image["id"]:
            raise ManifestError(
                f"{name} image tag changed during exact helper verification"
            )
    template_path = "infra/coder/templates/codex-mobile-envbuilder"
    return {
        "schema_version": SCHEMA_VERSION,
        "release_id": release_id,
        "source_commit": release_id.removeprefix("sha-"),
        "images": images,
        "image_audit": image_audit,
        "workspace_helper_sha256": expected_helper_checksum,
        "workspace_helper": {
            "profile_version": helper_profile_version,
            "architecture": architecture,
            "expected_sha256": expected_helper_checksum,
            "workspace_base_sha256": helper_checksums["workspace_base"],
            "envbuilder_sha256": helper_checksums["envbuilder"],
        },
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
    document = parse_strict_json(
        read_regular_bytes(path, MAX_MANIFEST_BYTES, "release manifest"),
        "release manifest",
    )
    schema_version = (
        document.get("schema_version") if isinstance(document, dict) else None
    )
    if (
        not isinstance(document, dict)
        or type(schema_version) is not int
        or schema_version not in SUPPORTED_SCHEMA_VERSIONS
    ):
        raise ManifestError("release manifest schema is unsupported")
    expected_keys = V1_MANIFEST_KEYS if schema_version == 1 else V2_MANIFEST_KEYS
    if set(document) != expected_keys:
        raise ManifestError("release manifest top-level schema is invalid")
    return document


def verify_manifest(
    repo_root: Path,
    image_resolver: ImageResolver | None = None,
    installed_root: Path | None = None,
    require_image_audit: bool = False,
    evidence_verifier: ImageAuditVerifier = verify_image_audit_evidence,
    podman_url: str = DEFAULT_PODMAN_URL,
    helper_resolver: Callable[[str], str] | None = None,
) -> dict[str, object]:
    podman_url = validate_podman_url(podman_url)
    repo_root = repo_root.resolve(strict=True)
    manifest = load_manifest(repo_root)
    schema_version = manifest["schema_version"]
    if schema_version == 1 and require_image_audit:
        raise ManifestError(
            "legacy schema-v1 release manifest has no image-audit evidence"
        )
    release_id = manifest.get("release_id")
    if not isinstance(release_id, str) or not RELEASE_ID_PATTERN.fullmatch(release_id):
        raise ManifestError("release manifest contains an invalid release ID")
    if manifest.get("source_commit") != release_id.removeprefix("sha-"):
        raise ManifestError("release manifest source commit does not match its ID")

    expected_environment = release_environment(release_id).encode("ascii")
    actual_environment = read_regular_bytes(
        repo_root / "infra" / "release.env",
        MAX_RELEASE_ENVIRONMENT_BYTES,
        "release environment",
    )
    if actual_environment != expected_environment:
        raise ManifestError("release environment does not match immutable manifest")
    if hashlib.sha256(actual_environment).hexdigest() != manifest.get(
        "release_environment_sha256"
    ):
        raise ManifestError("release environment checksum is invalid")

    release_files = manifest.get("release_files")
    if not isinstance(release_files, dict) or set(release_files) != set(
        critical_release_files(schema_version)
    ):
        raise ManifestError("release manifest critical-file inventory is invalid")
    for relative, expected in release_files.items():
        if sha256_file(repo_root / relative) != expected:
            raise ManifestError(f"release artifact checksum mismatch: {relative}")

    coder = manifest.get("coder")
    if not isinstance(coder, dict) or set(coder) != {
        "template_name",
        "template_path",
        "template_sha256",
        "provisioner_tag",
        "workspace_base_image",
        "envbuilder_image",
    }:
        raise ManifestError("release manifest Coder provenance is invalid")
    if (
        coder.get("template_name") != "codex-mobile-envbuilder"
        or coder.get("provisioner_tag") != "runtime=private-podman"
    ):
        raise ManifestError("release manifest Coder identity is invalid")
    template_path = coder.get("template_path")
    if template_path != "infra/coder/templates/codex-mobile-envbuilder":
        raise ManifestError("release manifest Coder template path is invalid")
    if sha256_tree(repo_root / template_path) != coder.get("template_sha256"):
        raise ManifestError("Coder template checksum does not match manifest")

    host_artifacts = manifest.get("host_artifacts")
    if not isinstance(host_artifacts, dict) or set(host_artifacts) != set(
        HOST_ARTIFACTS
    ):
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
                raise ManifestError(
                    f"installed host artifact does not match: {destination}"
                )
            installed_info = installed.stat()
            if (installed_info.st_uid, installed_info.st_gid) != (0, 0):
                raise ManifestError(
                    f"installed host artifact is not owned by root:root: {destination}"
                )
            if f"{stat.S_IMODE(installed_info.st_mode):04o}" != mode:
                raise ManifestError(
                    f"installed host artifact mode does not match: {destination}"
                )

    images = manifest.get("images")
    expected_references = image_references(release_id)
    if not isinstance(images, dict) or set(images) != set(expected_references):
        raise ManifestError("release manifest image inventory is invalid")
    for name, (engine, reference) in expected_references.items():
        record = images.get(name)
        if not isinstance(record, dict) or set(record) != {
            "engine",
            "reference",
            "id",
        }:
            raise ManifestError(f"image record is invalid: {name}")
        if record.get("engine") != engine or record.get("reference") != reference:
            raise ManifestError(f"image reference does not match release: {name}")
        recorded_id = normalize_image_id(str(record.get("id", "")), reference)
        if image_resolver is not None:
            current_id = normalize_image_id(
                image_resolver(engine, reference), reference
            )
            if current_id != recorded_id:
                raise ManifestError(
                    f"local image tag no longer matches manifest: {reference}"
                )
    actual_audit: dict[str, object] | None = None
    if schema_version == SCHEMA_VERSION:
        actual_audit = image_audit_manifest_record(
            repo_root,
            release_id,
            images,
            evidence_verifier,
            image_resolver,
            podman_url,
        )
        if manifest.get("image_audit") != actual_audit:
            raise ManifestError("image-audit evidence does not match release manifest")
    elif "image_audit" in manifest:
        raise ManifestError(
            "legacy schema-v1 manifest cannot claim image-audit evidence"
        )
    if coder.get("workspace_base_image") != images["workspace_base"]["reference"]:
        raise ManifestError("Coder workspace image does not match manifest")
    if coder.get("envbuilder_image") != images["envbuilder"]["reference"]:
        raise ManifestError("Coder EnvBuilder image does not match manifest")
    helper_checksum = manifest.get("workspace_helper_sha256")
    if not isinstance(helper_checksum, str) or not re.fullmatch(
        r"[0-9a-f]{64}", helper_checksum
    ):
        raise ManifestError("workspace helper checksum in manifest is invalid")
    if schema_version == SCHEMA_VERSION:
        assert actual_audit is not None
        architecture = normalize_architecture(actual_audit.get("architecture"))
        helper_record = manifest.get("workspace_helper")
        if not isinstance(helper_record, dict) or set(helper_record) != {
            "profile_version",
            "architecture",
            "expected_sha256",
            "workspace_base_sha256",
            "envbuilder_sha256",
        }:
            raise ManifestError("workspace helper provenance record is invalid")
        helper_profile = workspace_helper_profile(helper_record.get("profile_version"))
        expected_helper = helper_profile[architecture]
        expected_helper_record = {
            "profile_version": helper_record["profile_version"],
            "architecture": architecture,
            "expected_sha256": expected_helper,
            "workspace_base_sha256": expected_helper,
            "envbuilder_sha256": expected_helper,
        }
        if (
            helper_checksum != expected_helper
            or helper_record != expected_helper_record
        ):
            raise ManifestError(
                "workspace helper provenance does not match the architecture pin"
            )
        if image_resolver is not None:
            if helper_resolver is None:

                def resolve_workspace_helper(image_id: str) -> str:
                    return inspect_workspace_helper(image_id, podman_url)

                helper_resolver = resolve_workspace_helper
            for name in ("workspace_base", "envbuilder"):
                record = images[name]
                extracted = helper_resolver(record["id"])
                if extracted != expected_helper:
                    raise ManifestError(
                        f"{name} workspace helper does not match the architecture pin"
                    )
                current_id = normalize_image_id(
                    image_resolver(record["engine"], record["reference"]),
                    record["reference"],
                )
                if current_id != record["id"]:
                    raise ManifestError(
                        f"local image tag changed during helper verification: "
                        f"{record['reference']}"
                    )
    return manifest


def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ManifestError("release manifest operations require root")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=("create", "verify", "validate-podman-url", "verify-helper-pin"),
    )
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--release-id")
    parser.add_argument("--image-reference")
    parser.add_argument("--require-images", action="store_true")
    parser.add_argument("--require-image-audit", action="store_true")
    parser.add_argument("--verify-installed", action="store_true")
    parser.add_argument(
        "--podman-url",
        default=os.environ.get("PODMAN_URL", DEFAULT_PODMAN_URL),
    )
    args = parser.parse_args(argv)
    try:
        args.podman_url = validate_podman_url(args.podman_url)
        if args.action == "validate-podman-url":
            print(f"local Podman URL verified: {args.podman_url}")
            return 0
        require_root()
        if args.action == "verify-helper-pin":
            if not args.image_reference:
                raise ManifestError("verify-helper-pin requires --image-reference")
            result = verify_helper_pin(args.image_reference, args.podman_url)
            print(
                "workspace helper pin verified: "
                f"{result['architecture']} {result['image_id']}"
            )
            return 0
        if args.repo_root is None:
            raise ManifestError(f"{args.action} requires --repo-root")
        if args.action == "create":
            if not args.release_id:
                raise ManifestError("create requires --release-id")
            manifest = build_manifest(
                args.repo_root,
                args.release_id,
                lambda engine, reference: inspect_image(
                    engine, reference, args.podman_url
                ),
                lambda image_id: inspect_workspace_helper(image_id, args.podman_url),
                podman_url=args.podman_url,
            )
            write_manifest(args.repo_root, manifest)

            def resolver(engine: str, reference: str) -> str:
                return inspect_image(engine, reference, args.podman_url)

            verify_manifest(
                args.repo_root,
                resolver,
                require_image_audit=True,
                podman_url=args.podman_url,
                helper_resolver=lambda image_id: inspect_workspace_helper(
                    image_id, args.podman_url
                ),
            )
            print(f"release manifest created: {args.release_id}")
        else:
            installed_root = Path("/") if args.verify_installed else None
            resolver = None
            if args.require_images:

                def resolver(engine: str, reference: str) -> str:
                    return inspect_image(engine, reference, args.podman_url)

                def helper_resolver(image_id: str) -> str:
                    return inspect_workspace_helper(image_id, args.podman_url)
            else:
                helper_resolver = None
            manifest = verify_manifest(
                args.repo_root,
                resolver,
                installed_root,
                args.require_image_audit,
                podman_url=args.podman_url,
                helper_resolver=helper_resolver,
            )
            print(f"release manifest verified: {manifest['release_id']}")
        return 0
    except ManifestError as exc:
        print(f"release manifest verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
