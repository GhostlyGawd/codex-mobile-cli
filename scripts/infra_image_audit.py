#!/usr/bin/env python3
"""Build-time audit gate for the exact local OCI images in a release.

The scanner reports every finding. A finding is accepted only when every
security-relevant field exactly matches one unexpired, tracked disposition.
The completed private evidence directory is published atomically only when
there are zero undispositioned findings and every tracked disposition was used.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import IntEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import BinaryIO, Callable, Mapping, Sequence
from urllib.parse import unquote, urlsplit


SCHEMA_VERSION = 2
POLICY_SCHEMA_VERSION = 2
CURRENT_SCANNER_POLICY_VERSION = 3
SCANNER_POLICY_VERSION = CURRENT_SCANNER_POLICY_VERSION
SUPPORTED_EVIDENCE_SCHEMA_VERSIONS = frozenset({1, 2})
SUPPORTED_POLICY_SCHEMA_VERSIONS = frozenset({1, 2})

DEFAULT_PODMAN_URL = "unix:///run/codex-mobile-podman/podman.sock"
DOCKER_URL = "unix:///var/run/docker.sock"
EVIDENCE_RELATIVE = Path("infra/image-audit")
POLICY_RELATIVE = Path("infra/image-audit-policy.json")

RELEASE_ID_PATTERN = re.compile(r"sha-[0-9a-f]{7,64}")
IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
DISPOSITION_ID_PATTERN = re.compile(r"[A-Z][A-Z0-9-]{5,63}")

MAX_POLICY_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
MAX_COMMAND_LOG_BYTES = 64 * 1024
MAX_COMMAND_VALUE_BYTES = 64 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_TOOL_BYTES = 256 * 1024 * 1024
MAX_DATABASE_BYTES = 2 * 1024 * 1024 * 1024
MAX_IMAGE_BYTES = 8 * 1024 * 1024 * 1024
MAX_EVIDENCE_BYTES = 6 * MAX_REPORT_BYTES + MAX_RECEIPT_BYTES

INSPECT_TIMEOUT_SECONDS = 30
VERSION_TIMEOUT_SECONDS = 15
DATABASE_TIMEOUT_SECONDS = 300
SYFT_TIMEOUT_SECONDS = 300
TRIVY_TIMEOUT_SECONDS = 600
TOTAL_AUDIT_TIMEOUT_SECONDS = 3600

MAX_DISPOSITION_DAYS = 90
MAX_LICENSE_BASELINES = 16
MAX_BASELINE_LICENSES = 4096
LICENSE_BASELINE_ALGORITHM = "sha256-json-sorted-v2-match-key-multiset-v1"
MAX_VULNERABILITY_DB_AGE = timedelta(hours=48)
MAX_DATABASE_DOWNLOAD_AGE = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=15)

TRIVY_PATH = Path("/usr/local/bin/trivy")
SYFT_PATH = Path("/usr/local/bin/syft")
DOCKER_PATH = Path("/usr/bin/docker")
PODMAN_PATH = Path("/usr/bin/podman")
TRIVY_CACHE_PATH = Path("/var/cache/codex-mobile/trivy")
CACHE_LOCK_TIMEOUT_SECONDS = 30

_TOOL_POLICY_RECORD_V1 = {
    "amd64": {
        "trivy": {
            "version": "0.72.0",
            "asset": "trivy_0.72.0_Linux-64bit.tar.gz",
            "asset_sha256": "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea",
            "executable_sha256": "0e69edd134a3c338baa1a6806920773615d682b18cbc6a0cba2a3b658ef9b63e",
        },
        "syft": {
            "version": "1.46.0",
            "asset": "syft_1.46.0_linux_amd64.tar.gz",
            "asset_sha256": "d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca",
            "executable_sha256": "574df1a0862ff88ad933be214e81069e35b17618a13e019f8f1c84fe063222a2",
            "git_commit": "b15c5dbfe2bb21c9d73002c1056a829c8c411c75",
        },
    },
    "arm64": {
        "trivy": {
            "version": "0.72.0",
            "asset": "trivy_0.72.0_Linux-ARM64.tar.gz",
            "asset_sha256": "2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467",
            "executable_sha256": "829aca12d32bc3cee0b01cbb76197e9377790c6b78eb67a703d8033bcf7b3c3d",
        },
        "syft": {
            "version": "1.46.0",
            "asset": "syft_1.46.0_linux_arm64.tar.gz",
            "asset_sha256": "9fafef4db4f032ce81008d3a1529985d41ceb6ccdf2b388c9ce2f1ed7d32082e",
            "executable_sha256": "9640d29da74a63de41d2cc2373ac2092462165ee99709f7d8dc3dea57a748b06",
            "git_commit": "b15c5dbfe2bb21c9d73002c1056a829c8c411c75",
        },
    },
}

_TOOL_POLICY_RECORD_V2 = {
    "amd64": {
        "trivy": {
            "version": "0.72.0",
            "asset": "trivy_0.72.0_Linux-64bit.tar.gz",
            "asset_sha256": "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea",
            "executable_sha256": "0e69edd134a3c338baa1a6806920773615d682b18cbc6a0cba2a3b658ef9b63e",
        },
        "syft": {
            "version": "1.46.0",
            "asset": "syft_1.46.0_linux_amd64.tar.gz",
            "asset_sha256": "d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca",
            "executable_sha256": "574df1a0862ff88ad933be214e81069e35b17618a13e019f8f1c84fe063222a2",
            "git_commit": "b15c5dbfe2bb21c9d73002c1056a829c8c411c75",
        },
    },
    "arm64": {
        "trivy": {
            "version": "0.72.0",
            "asset": "trivy_0.72.0_Linux-ARM64.tar.gz",
            "asset_sha256": "2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467",
            "executable_sha256": "829aca12d32bc3cee0b01cbb76197e9377790c6b78eb67a703d8033bcf7b3c3d",
        },
        "syft": {
            "version": "1.46.0",
            "asset": "syft_1.46.0_linux_arm64.tar.gz",
            "asset_sha256": "9fafef4db4f032ce81008d3a1529985d41ceb6ccdf2b388c9ce2f1ed7d32082e",
            "executable_sha256": "9640d29da74a63de41d2cc2373ac2092462165ee99709f7d8dc3dea57a748b06",
            "git_commit": "b15c5dbfe2bb21c9d73002c1056a829c8c411c75",
        },
    },
}


@dataclass(frozen=True)
class ScannerProfile:
    version: int
    evidence_schema_version: int
    policy_schema_version: int
    scanners: tuple[str, ...]
    image_config_scanners: tuple[str, ...]
    severities: tuple[str, ...]
    pkg_types: tuple[str, ...] | None
    license_full: bool
    include_unfixed: bool
    exit_on_eol: bool
    detection_priority: str
    global_ignores: bool
    max_image_size_bytes: int
    max_report_bytes: int
    max_database_bytes: int
    cyclonedx_spec_version: str
    trivy_report_schema_version: int
    tools: Mapping[str, Mapping[str, Mapping[str, str]]]

    def policy_document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "version": self.version,
            "scanners": list(self.scanners),
            "image_config_scanners": list(self.image_config_scanners),
            "severities": list(self.severities),
            "license_full": self.license_full,
            "include_unfixed": self.include_unfixed,
            "exit_on_eol": self.exit_on_eol,
            "detection_priority": self.detection_priority,
            "global_ignores": self.global_ignores,
            "max_image_size_bytes": self.max_image_size_bytes,
            "max_report_bytes": self.max_report_bytes,
            "max_database_bytes": self.max_database_bytes,
        }
        if self.pkg_types is not None:
            document["pkg_types"] = list(self.pkg_types)
        if self.evidence_schema_version == 2:
            document["finding_match_fields"] = list(MATCH_FIELDS_V2)
            document["license_baseline_algorithm"] = LICENSE_BASELINE_ALGORITHM
        return document


def _freeze_tool_policy(
    record: Mapping[str, Mapping[str, Mapping[str, str]]],
) -> Mapping[str, Mapping[str, Mapping[str, str]]]:
    return MappingProxyType(
        {
            architecture: MappingProxyType(
                {tool: MappingProxyType(dict(pin)) for tool, pin in tools.items()}
            )
            for architecture, tools in record.items()
        }
    )


_PROFILE_1_TOOLS = _freeze_tool_policy(_TOOL_POLICY_RECORD_V1)
_PROFILE_2_TOOLS = _freeze_tool_policy(_TOOL_POLICY_RECORD_V2)
_PROFILE_3_TOOLS = _freeze_tool_policy(_TOOL_POLICY_RECORD_V2)
del _TOOL_POLICY_RECORD_V1
del _TOOL_POLICY_RECORD_V2

# Profiles are immutable verification contracts, not feature flags. Keep every
# profile referenced by a rollback-eligible release. An incompatible report or
# parser change requires a new evidence schema and a version-dispatched verifier
# path; never reinterpret an old profile with a new parser.
SCANNER_PROFILE_REGISTRY: Mapping[int, ScannerProfile] = MappingProxyType(
    {
        1: ScannerProfile(
            version=1,
            evidence_schema_version=1,
            policy_schema_version=1,
            scanners=("vuln", "secret", "license"),
            image_config_scanners=("secret",),
            severities=("UNKNOWN", "HIGH", "CRITICAL"),
            pkg_types=None,
            license_full=True,
            include_unfixed=True,
            exit_on_eol=True,
            detection_priority="precise",
            global_ignores=False,
            max_image_size_bytes=8_589_934_592,
            max_report_bytes=67_108_864,
            max_database_bytes=2_147_483_648,
            cyclonedx_spec_version="1.6",
            trivy_report_schema_version=2,
            tools=_PROFILE_1_TOOLS,
        ),
        2: ScannerProfile(
            version=2,
            evidence_schema_version=1,
            policy_schema_version=1,
            scanners=("vuln", "secret", "license"),
            image_config_scanners=("secret",),
            severities=("UNKNOWN", "HIGH", "CRITICAL"),
            pkg_types=None,
            license_full=True,
            include_unfixed=True,
            exit_on_eol=True,
            detection_priority="precise",
            global_ignores=False,
            max_image_size_bytes=8_589_934_592,
            max_report_bytes=67_108_864,
            max_database_bytes=2_147_483_648,
            cyclonedx_spec_version="1.6",
            trivy_report_schema_version=2,
            tools=_PROFILE_2_TOOLS,
        ),
        3: ScannerProfile(
            version=3,
            evidence_schema_version=2,
            policy_schema_version=2,
            scanners=("vuln", "secret", "license"),
            image_config_scanners=("secret",),
            severities=("UNKNOWN", "HIGH", "CRITICAL"),
            pkg_types=("os", "library"),
            license_full=True,
            include_unfixed=True,
            exit_on_eol=True,
            detection_priority="precise",
            global_ignores=False,
            max_image_size_bytes=8_589_934_592,
            max_report_bytes=67_108_864,
            max_database_bytes=2_147_483_648,
            cyclonedx_spec_version="1.6",
            trivy_report_schema_version=2,
            tools=_PROFILE_3_TOOLS,
        ),
    }
)
del _PROFILE_1_TOOLS
del _PROFILE_2_TOOLS
del _PROFILE_3_TOOLS

# Compatibility alias for callers that inspect the pins used by new scans.
TOOL_POLICY = SCANNER_PROFILE_REGISTRY[CURRENT_SCANNER_POLICY_VERSION].tools


class ExitCode(IntEnum):
    OK = 0
    USAGE = 2
    PREREQUISITE = 3
    IMAGE = 4
    EXECUTION = 5
    POLICY = 6
    EVIDENCE = 7


class AuditError(RuntimeError):
    def __init__(self, message: str, code: ExitCode = ExitCode.EVIDENCE):
        super().__init__(message)
        self.code = code


def scanner_profile(version: object) -> ScannerProfile:
    if not isinstance(version, int) or isinstance(version, bool):
        raise AuditError("image scanner profile version is malformed")
    profile = SCANNER_PROFILE_REGISTRY.get(version)
    if profile is None:
        raise AuditError("image scanner profile version is unknown")
    return profile


@dataclass(frozen=True)
class ImageSpec:
    key: str
    file_stem: str
    engine: str
    repository: str


IMAGE_SPECS = (
    ImageSpec(
        "control_plane",
        "control-plane",
        "docker",
        "localhost/codex-mobile/control-plane",
    ),
    ImageSpec(
        "workspace_base",
        "workspace-base",
        "podman",
        "localhost/codex-mobile/workspace-base",
    ),
    ImageSpec(
        "envbuilder",
        "envbuilder",
        "podman",
        "localhost/codex-mobile/envbuilder",
    ),
)
IMAGE_SPEC_BY_KEY = {item.key: item for item in IMAGE_SPECS}


@dataclass(frozen=True)
class ImageSnapshot:
    image_id: str
    size_bytes: int
    os_name: str
    architecture: str


@dataclass(frozen=True)
class Finding:
    image: str
    kind: str
    category: str
    target: str
    finding_id: str
    package: str
    version: str
    severity: str
    path: str

    @property
    def match_key(self) -> tuple[str, ...]:
        return (
            self.image,
            self.kind,
            self.category,
            self.target,
            self.finding_id,
            self.package,
            self.version,
            self.severity,
            self.path,
        )

    @property
    def safe_id(self) -> str:
        return f"{self.image}:{self.kind}:{self.finding_id}"


@dataclass(frozen=True)
class FindingV2:
    image: str
    kind: str
    category: str
    target: str
    finding_id: str
    package: str
    version: str
    severity: str
    path: str
    result_class: str
    result_type: str
    status: str
    fixed_version: str
    package_purl: str

    @property
    def match_key(self) -> tuple[str, ...]:
        return (
            self.image,
            self.kind,
            self.category,
            self.target,
            self.finding_id,
            self.package,
            self.version,
            self.severity,
            self.path,
            self.result_class,
            self.result_type,
            self.status,
            self.fixed_version,
            self.package_purl,
        )

    @property
    def safe_id(self) -> str:
        return f"{self.image}:{self.kind}:{self.finding_id}"


FindingRecord = Finding | FindingV2


@dataclass(frozen=True)
class Disposition:
    disposition_id: str
    expires_on: date
    statement: str
    match: FindingRecord


@dataclass(frozen=True)
class LicenseBaseline:
    baseline_id: str
    image: str
    expires_on: date
    statement: str
    algorithm: str
    finding_count: int
    canonical_sha256: str
    category_counts: tuple[tuple[str, int], ...]
    severity_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class DispositionPolicy:
    schema_version: int
    policy_id: str
    sha256: str
    dispositions: tuple[Disposition, ...]
    license_baselines: tuple[LicenseBaseline, ...] = ()


@dataclass(frozen=True)
class FindingDecision:
    finding: FindingRecord
    disposition_id: str | None


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_ms: int


CommandRunner = Callable[..., CommandResult]
ImageResolver = Callable[[str, str], str]


def normalize_architecture(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"x86_64", "amd64"}:
        return "amd64"
    if normalized in {"aarch64", "arm64"}:
        return "arm64"
    raise AuditError(
        f"unsupported image-audit architecture: {value}",
        ExitCode.PREREQUISITE,
    )


def normalize_image_id(value: str, reference: str = "image") -> str:
    candidate = value.strip()
    if not IMAGE_ID_PATTERN.fullmatch(candidate):
        raise AuditError(
            f"{reference} did not resolve to a full sha256 image ID",
            ExitCode.IMAGE,
        )
    return candidate


def normalize_inspected_image_id(engine: str, value: str, reference: str) -> str:
    candidate = value.strip()
    if engine == "podman" and SHA256_PATTERN.fullmatch(candidate):
        candidate = f"sha256:{candidate}"
    return normalize_image_id(candidate, reference)


def validate_release_id(release_id: str) -> str:
    if not RELEASE_ID_PATTERN.fullmatch(release_id):
        raise AuditError(
            "release ID must be sha-<7-64 lowercase hexadecimal commit>",
            ExitCode.USAGE,
        )
    return release_id


def image_references(release_id: str) -> dict[str, dict[str, str]]:
    validate_release_id(release_id)
    return {
        spec.key: {
            "engine": spec.engine,
            "reference": f"{spec.repository}:{release_id}",
        }
        for spec in IMAGE_SPECS
    }


def validate_podman_url(value: str) -> tuple[str, str]:
    message = "Podman URL must be an absolute normalized local unix:/// socket URL"
    if not isinstance(value, str) or len(value) > 4096:
        raise AuditError(message, ExitCode.USAGE)
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise AuditError(message, ExitCode.USAGE) from exc
    socket_path = unquote(parsed.path)
    if (
        not value.startswith("unix:///")
        or parsed.scheme != "unix"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
        or socket_path != parsed.path
        or "\\" in socket_path
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AuditError(message, ExitCode.USAGE)
    path = PurePosixPath(socket_path)
    components = socket_path.split("/")[1:]
    if (
        not path.is_absolute()
        or len(path.parts) < 2
        or not components
        or any(component in {"", ".", ".."} for component in components)
        or path.as_posix() != socket_path
        or value != f"unix://{socket_path}"
    ):
        raise AuditError(message, ExitCode.USAGE)
    return value, socket_path


def require_root() -> None:
    if os.name != "posix":
        raise AuditError("image scanning requires Linux", ExitCode.PREREQUISITE)
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise AuditError("image scanning requires root", ExitCode.PREREQUISITE)


def resolve_repo_root(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        absolute_info = absolute.lstat()
        root = path.resolve(strict=True)
        info = root.lstat()
    except OSError as exc:
        raise AuditError(f"cannot resolve release root: {exc}") from exc
    if (
        absolute.is_symlink()
        or not stat.S_ISDIR(absolute_info.st_mode)
        or root != absolute
        or root.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
    ):
        raise AuditError("release root must be a non-symlink directory")
    return root


def require_infra_directory(root: Path) -> Path:
    infra = root / "infra"
    try:
        info = infra.lstat()
    except OSError as exc:
        raise AuditError("release infra directory is invalid") from exc
    if (
        infra.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or infra.resolve(strict=True) != infra
    ):
        raise AuditError("release infra directory is invalid")
    return infra


def _open_regular(path: Path, max_bytes: int) -> tuple[int, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise AuditError(f"cannot inspect required evidence file: {path.name}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise AuditError(f"evidence file is not a regular non-symlink: {path.name}")
    if before.st_size > max_bytes:
        raise AuditError(f"evidence file exceeds its size limit: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise AuditError(f"cannot open required evidence file: {path.name}") from exc
    if (
        not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or after.st_size > max_bytes
    ):
        os.close(descriptor)
        raise AuditError(f"evidence file changed while opening: {path.name}")
    return descriptor, after


def read_regular_bytes(path: Path, max_bytes: int) -> bytes:
    descriptor, _ = _open_regular(path, max_bytes)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            content = handle.read(max_bytes + 1)
    except OSError as exc:
        raise AuditError(f"cannot read evidence file: {path.name}") from exc
    if len(content) > max_bytes:
        raise AuditError(f"evidence file exceeds its size limit: {path.name}")
    return content


def hash_regular_file(path: Path, max_bytes: int) -> tuple[str, int]:
    descriptor, info = _open_regular(path, max_bytes)
    digest = hashlib.sha256()
    consumed = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                consumed += len(chunk)
                if consumed > max_bytes:
                    raise AuditError(f"file exceeds its size limit: {path.name}")
                digest.update(chunk)
    except OSError as exc:
        raise AuditError(f"cannot hash evidence file: {path.name}") from exc
    if consumed != info.st_size:
        raise AuditError(f"file changed while hashing: {path.name}")
    return digest.hexdigest(), consumed


def copy_regular_file(
    source: Path,
    destination: Path,
    max_bytes: int,
) -> tuple[str, int]:
    source_descriptor, source_info = _open_regular(source, max_bytes)
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        destination_descriptor = os.open(destination, destination_flags, 0o600)
    except OSError as exc:
        os.close(source_descriptor)
        raise AuditError(f"cannot create private file: {destination.name}") from exc

    digest = hashlib.sha256()
    consumed = 0
    try:
        with (
            os.fdopen(source_descriptor, "rb", closefd=True) as source_handle,
            os.fdopen(destination_descriptor, "wb", closefd=True) as destination_handle,
        ):
            while True:
                chunk = source_handle.read(1024 * 1024)
                if not chunk:
                    break
                consumed += len(chunk)
                if consumed > max_bytes:
                    raise AuditError(f"file exceeds its size limit: {source.name}")
                destination_handle.write(chunk)
                digest.update(chunk)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
            source_after = os.fstat(source_handle.fileno())
    except OSError as exc:
        raise AuditError(f"cannot copy private file: {source.name}") from exc
    if consumed != source_info.st_size or (
        source_after.st_dev,
        source_after.st_ino,
        source_after.st_size,
        source_after.st_mtime_ns,
        source_after.st_ctime_ns,
    ) != (
        source_info.st_dev,
        source_info.st_ino,
        source_info.st_size,
        source_info.st_mtime_ns,
        source_info.st_ctime_ns,
    ):
        raise AuditError(f"file changed while copying: {source.name}")
    return digest.hexdigest(), consumed


def parse_json_bytes(content: bytes, description: str) -> dict[str, object]:
    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise AuditError(f"{description} contains a duplicate object key")
            document[key] = value
        return document

    def reject_nonfinite(value: str) -> object:
        raise AuditError(f"{description} contains a non-finite number: {value}")

    try:
        document = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"{description} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise AuditError(f"{description} must be a JSON object")
    return document


def parse_rfc3339(value: object, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise AuditError(f"{field} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuditError(f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise AuditError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def format_rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _exact_keys(
    document: Mapping[str, object], expected: set[str], description: str
) -> None:
    if set(document) != expected:
        raise AuditError(f"{description} has an unsupported field inventory")


def _policy_string(
    value: object,
    field: str,
    *,
    allow_empty: bool = False,
    maximum: int = 1024,
    reject_globs: bool = True,
) -> str:
    if not isinstance(value, str) or len(value) > maximum:
        raise AuditError(
            f"disposition {field} must be a bounded string", ExitCode.POLICY
        )
    if not allow_empty and not value:
        raise AuditError(f"disposition {field} must not be empty", ExitCode.POLICY)
    if any(ord(character) < 32 for character in value):
        raise AuditError(
            f"disposition {field} contains a control character",
            ExitCode.POLICY,
        )
    if reject_globs and any(character in value for character in "*?[]"):
        raise AuditError(
            f"disposition {field} must be exact and cannot contain glob syntax",
            ExitCode.POLICY,
        )
    return value


MATCH_FIELDS_V1 = (
    "image",
    "kind",
    "category",
    "target",
    "finding_id",
    "package",
    "version",
    "severity",
    "path",
)
MATCH_FIELDS_V2 = MATCH_FIELDS_V1 + (
    "result_class",
    "result_type",
    "status",
    "fixed_version",
    "package_purl",
)


def finding_match_document(finding: FindingRecord) -> dict[str, str]:
    if type(finding) is FindingV2:
        fields = MATCH_FIELDS_V2
    elif type(finding) is Finding:
        fields = MATCH_FIELDS_V1
    else:
        raise AuditError("image finding type is unsupported")
    return {field: str(getattr(finding, field)) for field in fields}


def _parse_policy_finding(
    match: Mapping[str, object],
    *,
    schema_version: int,
    description: str,
) -> FindingRecord:
    fields = MATCH_FIELDS_V1 if schema_version == 1 else MATCH_FIELDS_V2
    _exact_keys(match, set(fields), description)
    image = _policy_string(match["image"], "image", maximum=64)
    if image not in IMAGE_SPEC_BY_KEY:
        raise AuditError(
            f"{description} names an unknown image",
            ExitCode.POLICY,
        )
    kind = _policy_string(match["kind"], "kind", maximum=32)
    if kind not in {"vulnerability", "secret", "license"}:
        raise AuditError(
            f"{description} names an unsupported finding kind",
            ExitCode.POLICY,
        )
    severity = _policy_string(match["severity"], "severity", maximum=16)
    if severity not in {"UNKNOWN", "HIGH", "CRITICAL"}:
        raise AuditError(
            f"{description} has an unsupported severity",
            ExitCode.POLICY,
        )
    common = {
        "image": image,
        "kind": kind,
        "category": _policy_string(
            match["category"], "category", allow_empty=True, maximum=256
        ),
        "target": _policy_string(match["target"], "target", maximum=4096),
        "finding_id": _policy_string(match["finding_id"], "finding_id", maximum=256),
        "package": _policy_string(
            match["package"], "package", allow_empty=True, maximum=1024
        ),
        "version": _policy_string(
            match["version"], "version", allow_empty=True, maximum=512
        ),
        "severity": severity,
        "path": _policy_string(match["path"], "path", allow_empty=True, maximum=4096),
    }
    if schema_version == 1:
        return Finding(**common)
    return FindingV2(
        **common,
        result_class=_policy_string(
            match["result_class"],
            "result_class",
            allow_empty=True,
            maximum=256,
        ),
        result_type=_policy_string(
            match["result_type"],
            "result_type",
            allow_empty=True,
            maximum=256,
        ),
        status=_policy_string(
            match["status"],
            "status",
            allow_empty=True,
            maximum=256,
        ),
        fixed_version=_policy_string(
            match["fixed_version"],
            "fixed_version",
            allow_empty=True,
            maximum=512,
        ),
        package_purl=_policy_string(
            match["package_purl"],
            "package_purl",
            allow_empty=True,
            maximum=4096,
            reject_globs=False,
        ),
    )


def _policy_count_map(
    value: object,
    field: str,
    *,
    allowed_keys: set[str] | None = None,
) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, dict) or not value or len(value) > 256:
        raise AuditError(
            f"license baseline {field} must be a bounded non-empty object",
            ExitCode.POLICY,
        )
    counts: list[tuple[str, int]] = []
    for raw_key, raw_count in value.items():
        key = _policy_string(
            raw_key,
            field,
            allow_empty=True,
            maximum=256,
            reject_globs=False,
        )
        if allowed_keys is not None and key not in allowed_keys:
            raise AuditError(
                f"license baseline {field} has an unsupported key",
                ExitCode.POLICY,
            )
        if (
            not isinstance(raw_count, int)
            or isinstance(raw_count, bool)
            or raw_count <= 0
            or raw_count > MAX_BASELINE_LICENSES
        ):
            raise AuditError(
                f"license baseline {field} has an invalid count",
                ExitCode.POLICY,
            )
        counts.append((key, raw_count))
    return tuple(sorted(counts))


def load_disposition_policy(
    repo_root: Path,
    as_of: datetime,
    expected_schema_version: int | None = None,
) -> DispositionPolicy:
    path = repo_root / POLICY_RELATIVE
    content = read_regular_bytes(path, MAX_POLICY_BYTES)
    document = parse_json_bytes(content, "image disposition policy")
    schema_version = document.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in SUPPORTED_POLICY_SCHEMA_VERSIONS
    ):
        raise AuditError(
            "image disposition policy schema is unsupported", ExitCode.POLICY
        )
    if (
        expected_schema_version is not None
        and schema_version != expected_schema_version
    ):
        raise AuditError(
            "image disposition policy uses another evidence schema",
            ExitCode.POLICY,
        )
    top_level_fields = {"schema_version", "policy_id", "dispositions"}
    if schema_version == 2:
        top_level_fields.add("license_baselines")
    _exact_keys(
        document,
        top_level_fields,
        "image disposition policy",
    )
    policy_id = _policy_string(
        document["policy_id"],
        "policy_id",
        maximum=128,
        reject_globs=False,
    )
    raw_dispositions = document["dispositions"]
    if not isinstance(raw_dispositions, list) or len(raw_dispositions) > 256:
        raise AuditError(
            "image disposition policy must contain at most 256 records",
            ExitCode.POLICY,
        )

    dispositions: list[Disposition] = []
    seen_ids: set[str] = set()
    seen_matches: set[tuple[str, ...]] = set()
    audit_date = as_of.astimezone(timezone.utc).date()

    def policy_expiry(raw_value: object, record_id: str) -> date:
        expires_raw = _policy_string(
            raw_value,
            "expires_on",
            maximum=10,
            reject_globs=False,
        )
        try:
            expires_on = date.fromisoformat(expires_raw)
        except ValueError as exc:
            raise AuditError(
                f"disposition {record_id} has an invalid expiry date",
                ExitCode.POLICY,
            ) from exc
        if expires_on < audit_date:
            raise AuditError(
                f"disposition {record_id} expired",
                ExitCode.POLICY,
            )
        if expires_on > audit_date + timedelta(days=MAX_DISPOSITION_DAYS):
            raise AuditError(
                f"disposition {record_id} expires more than "
                f"{MAX_DISPOSITION_DAYS} days after the audit",
                ExitCode.POLICY,
            )
        return expires_on

    def policy_statement(raw_value: object, record_id: str) -> str:
        statement = _policy_string(
            raw_value,
            "statement",
            maximum=2000,
            reject_globs=False,
        )
        if len(statement) < 20:
            raise AuditError(
                f"disposition {record_id} needs a meaningful statement",
                ExitCode.POLICY,
            )
        return statement

    def policy_record_id(raw_value: object) -> str:
        record_id = _policy_string(
            raw_value,
            "id",
            maximum=64,
            reject_globs=False,
        )
        if not DISPOSITION_ID_PATTERN.fullmatch(record_id):
            raise AuditError("disposition ID has an invalid shape", ExitCode.POLICY)
        if record_id in seen_ids:
            raise AuditError("disposition IDs must be unique", ExitCode.POLICY)
        seen_ids.add(record_id)
        return record_id

    for index, raw in enumerate(raw_dispositions):
        if not isinstance(raw, dict):
            raise AuditError(
                f"disposition record {index} must be an object",
                ExitCode.POLICY,
            )
        _exact_keys(
            raw,
            {"id", "expires_on", "statement", "match"},
            f"disposition record {index}",
        )
        disposition_id = policy_record_id(raw["id"])
        expires_on = policy_expiry(raw["expires_on"], disposition_id)
        statement = policy_statement(raw["statement"], disposition_id)
        match = raw["match"]
        if not isinstance(match, dict):
            raise AuditError(
                f"disposition {disposition_id} match must be an object",
                ExitCode.POLICY,
            )
        finding = _parse_policy_finding(
            match,
            schema_version=schema_version,
            description=f"disposition {disposition_id} match",
        )
        if finding.match_key in seen_matches:
            raise AuditError(
                "disposition matches must be unique",
                ExitCode.POLICY,
            )
        seen_matches.add(finding.match_key)
        dispositions.append(Disposition(disposition_id, expires_on, statement, finding))

    baselines: list[LicenseBaseline] = []
    seen_baseline_images: set[str] = set()
    if schema_version == 2:
        raw_baselines = document["license_baselines"]
        if (
            not isinstance(raw_baselines, list)
            or len(raw_baselines) > MAX_LICENSE_BASELINES
        ):
            raise AuditError(
                "image disposition policy has too many license baselines",
                ExitCode.POLICY,
            )
        for index, raw in enumerate(raw_baselines):
            if not isinstance(raw, dict):
                raise AuditError(
                    f"license baseline record {index} must be an object",
                    ExitCode.POLICY,
                )
            _exact_keys(
                raw,
                {
                    "id",
                    "image",
                    "expires_on",
                    "statement",
                    "algorithm",
                    "finding_count",
                    "canonical_sha256",
                    "category_counts",
                    "severity_counts",
                },
                f"license baseline record {index}",
            )
            baseline_id = policy_record_id(raw["id"])
            image = _policy_string(raw["image"], "image", maximum=64)
            if image not in IMAGE_SPEC_BY_KEY:
                raise AuditError(
                    f"license baseline {baseline_id} names an unknown image",
                    ExitCode.POLICY,
                )
            if image in seen_baseline_images:
                raise AuditError(
                    "license baselines must name unique images",
                    ExitCode.POLICY,
                )
            seen_baseline_images.add(image)
            expires_on = policy_expiry(raw["expires_on"], baseline_id)
            statement = policy_statement(raw["statement"], baseline_id)
            algorithm = _policy_string(
                raw["algorithm"],
                "algorithm",
                maximum=128,
                reject_globs=False,
            )
            if algorithm != LICENSE_BASELINE_ALGORITHM:
                raise AuditError(
                    f"license baseline {baseline_id} uses an unsupported algorithm",
                    ExitCode.POLICY,
                )
            finding_count = raw["finding_count"]
            if (
                not isinstance(finding_count, int)
                or isinstance(finding_count, bool)
                or not 0 < finding_count <= MAX_BASELINE_LICENSES
            ):
                raise AuditError(
                    f"license baseline {baseline_id} has an invalid finding count",
                    ExitCode.POLICY,
                )
            canonical_sha256 = _policy_string(
                raw["canonical_sha256"],
                "canonical_sha256",
                maximum=64,
                reject_globs=False,
            )
            if not SHA256_PATTERN.fullmatch(canonical_sha256):
                raise AuditError(
                    f"license baseline {baseline_id} has an invalid checksum",
                    ExitCode.POLICY,
                )
            category_counts = _policy_count_map(
                raw["category_counts"],
                "category_counts",
            )
            severity_counts = _policy_count_map(
                raw["severity_counts"],
                "severity_counts",
                allowed_keys={"UNKNOWN", "HIGH", "CRITICAL"},
            )
            if (
                sum(count for _, count in category_counts) != finding_count
                or sum(count for _, count in severity_counts) != finding_count
            ):
                raise AuditError(
                    f"license baseline {baseline_id} count metadata is inconsistent",
                    ExitCode.POLICY,
                )
            if any(is_forbidden_category(category) for category, _ in category_counts):
                raise AuditError(
                    "forbidden licenses require exact individual dispositions",
                    ExitCode.POLICY,
                )
            baselines.append(
                LicenseBaseline(
                    baseline_id=baseline_id,
                    image=image,
                    expires_on=expires_on,
                    statement=statement,
                    algorithm=algorithm,
                    finding_count=finding_count,
                    canonical_sha256=canonical_sha256,
                    category_counts=category_counts,
                    severity_counts=severity_counts,
                )
            )
    return DispositionPolicy(
        schema_version=schema_version,
        policy_id=policy_id,
        sha256=hashlib.sha256(content).hexdigest(),
        dispositions=tuple(dispositions),
        license_baselines=tuple(baselines),
    )


def _finding_string(
    record: Mapping[str, object],
    field: str,
    *,
    fallback: str = "",
) -> str:
    value = record.get(field, fallback)
    if value is None:
        return fallback
    if not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
        raise AuditError(f"Trivy finding field {field} is malformed")
    return value


def _finding_records(
    result: Mapping[str, object],
    field: str,
) -> list[object]:
    value = result.get(field)
    if value is None:
        return []
    if not isinstance(value, list):
        raise AuditError(f"Trivy {field} inventory must be an array")
    return value


def trivy_findings(document: Mapping[str, object], image_key: str) -> list[Finding]:
    raw_results = document.get("Results", [])
    if raw_results is None:
        raw_results = []
    if not isinstance(raw_results, list):
        raise AuditError("Trivy Results must be an array")
    findings: list[Finding] = []
    for result in raw_results:
        if not isinstance(result, dict):
            raise AuditError("Trivy result must be an object")
        target = _finding_string(result, "Target")
        if not target:
            raise AuditError("Trivy result is missing Target")
        for record in _finding_records(result, "Vulnerabilities"):
            if not isinstance(record, dict):
                raise AuditError("Trivy vulnerability record is malformed")
            findings.append(
                Finding(
                    image=image_key,
                    kind="vulnerability",
                    category="",
                    target=target,
                    finding_id=_finding_string(record, "VulnerabilityID"),
                    package=_finding_string(record, "PkgName"),
                    version=_finding_string(record, "InstalledVersion"),
                    severity=_finding_string(record, "Severity").upper(),
                    path=_finding_string(record, "PkgPath"),
                )
            )
        for record in _finding_records(result, "Secrets"):
            if not isinstance(record, dict):
                raise AuditError("Trivy secret record is malformed")
            findings.append(
                Finding(
                    image=image_key,
                    kind="secret",
                    category=_finding_string(record, "Category"),
                    target=target,
                    finding_id=_finding_string(record, "RuleID"),
                    package="",
                    version="",
                    severity=_finding_string(record, "Severity").upper(),
                    path=_finding_string(record, "FilePath"),
                )
            )
        for record in _finding_records(result, "Licenses"):
            if not isinstance(record, dict):
                raise AuditError("Trivy license record is malformed")
            findings.append(
                Finding(
                    image=image_key,
                    kind="license",
                    category=_finding_string(record, "Category"),
                    target=target,
                    finding_id=_finding_string(record, "Name"),
                    package=_finding_string(record, "PkgName"),
                    version=_finding_string(
                        record,
                        "InstalledVersion",
                        fallback=_finding_string(record, "Version"),
                    ),
                    severity=_finding_string(record, "Severity").upper(),
                    path=_finding_string(record, "FilePath"),
                )
            )
        modified = _finding_records(result, "ExperimentalModifiedFindings")
        for index, _ in enumerate(modified):
            findings.append(
                Finding(
                    image=image_key,
                    kind="modified",
                    category="",
                    target=target,
                    finding_id=f"MODIFIED-{index + 1}",
                    package="",
                    version="",
                    severity="UNKNOWN",
                    path="",
                )
            )
    for finding in findings:
        if not finding.finding_id or not finding.severity:
            raise AuditError("Trivy finding lacks a stable ID or severity")
    return findings


def _finding_package_purl(record: Mapping[str, object]) -> str:
    identifier = record.get("PkgIdentifier")
    if identifier is None:
        return ""
    if not isinstance(identifier, dict):
        raise AuditError("Trivy finding package identifier is malformed")
    return _finding_string(identifier, "PURL")


def trivy_findings_v2(
    document: Mapping[str, object],
    image_key: str,
) -> list[FindingV2]:
    raw_results = document.get("Results", [])
    if raw_results is None:
        raw_results = []
    if not isinstance(raw_results, list):
        raise AuditError("Trivy Results must be an array")
    findings: list[FindingV2] = []
    for result in raw_results:
        if not isinstance(result, dict):
            raise AuditError("Trivy result must be an object")
        target = _finding_string(result, "Target")
        if not target:
            raise AuditError("Trivy result is missing Target")
        result_class = _finding_string(result, "Class")
        result_type = _finding_string(result, "Type")
        for record in _finding_records(result, "Vulnerabilities"):
            if not isinstance(record, dict):
                raise AuditError("Trivy vulnerability record is malformed")
            findings.append(
                FindingV2(
                    image=image_key,
                    kind="vulnerability",
                    category="",
                    target=target,
                    finding_id=_finding_string(record, "VulnerabilityID"),
                    package=_finding_string(record, "PkgName"),
                    version=_finding_string(record, "InstalledVersion"),
                    severity=_finding_string(record, "Severity").upper(),
                    path=_finding_string(record, "PkgPath"),
                    result_class=result_class,
                    result_type=result_type,
                    status=_finding_string(record, "Status"),
                    fixed_version=_finding_string(record, "FixedVersion"),
                    package_purl=_finding_package_purl(record),
                )
            )
        for record in _finding_records(result, "Secrets"):
            if not isinstance(record, dict):
                raise AuditError("Trivy secret record is malformed")
            findings.append(
                FindingV2(
                    image=image_key,
                    kind="secret",
                    category=_finding_string(record, "Category"),
                    target=target,
                    finding_id=_finding_string(record, "RuleID"),
                    package="",
                    version="",
                    severity=_finding_string(record, "Severity").upper(),
                    path=_finding_string(record, "FilePath"),
                    result_class=result_class,
                    result_type=result_type,
                    status=_finding_string(record, "Status"),
                    fixed_version="",
                    package_purl="",
                )
            )
        for record in _finding_records(result, "Licenses"):
            if not isinstance(record, dict):
                raise AuditError("Trivy license record is malformed")
            findings.append(
                FindingV2(
                    image=image_key,
                    kind="license",
                    category=_finding_string(record, "Category"),
                    target=target,
                    finding_id=_finding_string(record, "Name"),
                    package=_finding_string(record, "PkgName"),
                    version=_finding_string(
                        record,
                        "InstalledVersion",
                        fallback=_finding_string(record, "Version"),
                    ),
                    severity=_finding_string(record, "Severity").upper(),
                    path=_finding_string(record, "FilePath"),
                    result_class=result_class,
                    result_type=result_type,
                    status=_finding_string(record, "Status"),
                    fixed_version="",
                    package_purl=_finding_package_purl(record),
                )
            )
        modified = _finding_records(result, "ExperimentalModifiedFindings")
        for index, record in enumerate(modified):
            if not isinstance(record, dict):
                raise AuditError("Trivy modified finding record is malformed")
            findings.append(
                FindingV2(
                    image=image_key,
                    kind="modified",
                    category="",
                    target=target,
                    finding_id=f"MODIFIED-{index + 1}",
                    package="",
                    version="",
                    severity="UNKNOWN",
                    path="",
                    result_class=result_class,
                    result_type=result_type,
                    status=_finding_string(record, "Status"),
                    fixed_version="",
                    package_purl="",
                )
            )
    for finding in findings:
        if not finding.finding_id or not finding.severity:
            raise AuditError("Trivy finding lacks a stable ID or severity")
    return findings


def canonical_license_multiset(
    findings: Sequence[FindingV2],
) -> tuple[tuple[str, ...], ...]:
    if any(type(finding) is not FindingV2 for finding in findings):
        raise AuditError("license metadata requires evidence schema 2 findings")
    licenses = [finding for finding in findings if finding.kind == "license"]
    if len(licenses) > MAX_BASELINE_LICENSES:
        raise AuditError("license metadata inventory exceeds its size limit")
    return tuple(sorted(finding.match_key for finding in licenses))


def is_forbidden_category(category: str) -> bool:
    return category.strip().casefold() == "forbidden"


def is_forbidden_license(finding: FindingRecord) -> bool:
    return finding.kind == "license" and is_forbidden_category(finding.category)


def license_baseline_summary(
    findings: Sequence[FindingV2],
) -> dict[str, object]:
    keys = canonical_license_multiset(findings)
    licenses = [finding for finding in findings if finding.kind == "license"]
    if not licenses:
        raise AuditError("license baseline inventory must not be empty")
    images = {finding.image for finding in licenses}
    if len(images) != 1:
        raise AuditError("license baseline inventory must name exactly one image")
    canonical_bytes = json.dumps(
        keys,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "algorithm": LICENSE_BASELINE_ALGORITHM,
        "finding_count": len(keys),
        "canonical_sha256": hashlib.sha256(canonical_bytes).hexdigest(),
        "category_counts": dict(
            sorted(Counter(finding.category for finding in licenses).items())
        ),
        "severity_counts": dict(
            sorted(Counter(finding.severity for finding in licenses).items())
        ),
    }


def license_review_metadata(
    findings: Sequence[FindingV2],
) -> dict[str, object]:
    """Return policy-ready license metadata without secret-match bodies."""

    if any(type(finding) is not FindingV2 for finding in findings):
        raise AuditError("license review requires evidence schema 2 findings")
    by_image: dict[str, list[FindingV2]] = {}
    for finding in findings:
        if finding.kind == "license":
            by_image.setdefault(finding.image, []).append(finding)
    if len(by_image) > MAX_LICENSE_BASELINES or any(
        len(items) > MAX_BASELINE_LICENSES for items in by_image.values()
    ):
        raise AuditError("license review inventory exceeds its size limit")
    metadata: dict[str, object] = {
        "schema_version": 2,
        "algorithm": LICENSE_BASELINE_ALGORITHM,
        "match_fields": list(MATCH_FIELDS_V2),
        "images": [
            {
                "image": image,
                "baseline": (
                    {
                        **license_baseline_summary(
                            [item for item in items if not is_forbidden_license(item)]
                        ),
                        "licenses": [
                            finding_match_document(item)
                            for item in sorted(
                                (
                                    item
                                    for item in items
                                    if not is_forbidden_license(item)
                                ),
                                key=lambda item: item.match_key,
                            )
                        ],
                    }
                    if any(not is_forbidden_license(item) for item in items)
                    else None
                ),
                "exact_disposition_candidates": [
                    finding_match_document(item)
                    for item in sorted(
                        (item for item in items if is_forbidden_license(item)),
                        key=lambda item: item.match_key,
                    )
                ],
            }
            for image, items in sorted(by_image.items())
        ],
    }
    serialized = json.dumps(
        metadata,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(serialized) > MAX_REPORT_BYTES:
        raise AuditError("license review metadata exceeds its size limit")
    return metadata


def evaluate_dispositions(
    findings: Sequence[FindingRecord],
    policy: DispositionPolicy,
) -> tuple[FindingDecision, ...]:
    if policy.schema_version not in SUPPORTED_POLICY_SCHEMA_VERSIONS:
        raise AuditError("image disposition policy schema is unsupported")
    expected_type = Finding if policy.schema_version == 1 else FindingV2
    if any(type(finding) is not expected_type for finding in findings):
        raise AuditError(
            "image findings use another evidence schema",
            ExitCode.POLICY,
        )
    by_match = {item.match.match_key: item for item in policy.dispositions}
    used: set[str] = set()
    decisions: list[FindingDecision] = []
    for finding in findings:
        disposition = by_match.get(finding.match_key)
        if disposition is None or disposition.disposition_id in used:
            decisions.append(FindingDecision(finding, None))
            continue
        used.add(disposition.disposition_id)
        decisions.append(FindingDecision(finding, disposition.disposition_id))
    unused = sorted(
        item.disposition_id
        for item in policy.dispositions
        if item.disposition_id not in used
    )
    if unused:
        raise AuditError(
            "tracked image dispositions were not exercised: " + ", ".join(unused),
            ExitCode.POLICY,
        )
    if policy.schema_version == 2:
        baseline_by_image = {
            baseline.image: baseline for baseline in policy.license_baselines
        }
        remaining_by_image: dict[str, list[int]] = {}
        for index, decision in enumerate(decisions):
            finding = decision.finding
            if (
                decision.disposition_id is None
                and type(finding) is FindingV2
                and finding.kind == "license"
                and not is_forbidden_license(finding)
            ):
                remaining_by_image.setdefault(finding.image, []).append(index)
        missing = sorted(set(remaining_by_image) - set(baseline_by_image))
        if missing:
            raise AuditError(
                "license inventory has no reviewed baseline for: " + ", ".join(missing),
                ExitCode.POLICY,
            )
        for baseline in policy.license_baselines:
            indices = remaining_by_image.get(baseline.image, [])
            actual_findings = [
                decisions[index].finding
                for index in indices
                if type(decisions[index].finding) is FindingV2
            ]
            if not actual_findings:
                raise AuditError(
                    f"reviewed license baseline was not exercised for image "
                    f"{baseline.image}",
                    ExitCode.POLICY,
                )
            actual = license_baseline_summary(
                [finding for finding in actual_findings if type(finding) is FindingV2]
            )
            expected = {
                "algorithm": baseline.algorithm,
                "finding_count": baseline.finding_count,
                "canonical_sha256": baseline.canonical_sha256,
                "category_counts": dict(baseline.category_counts),
                "severity_counts": dict(baseline.severity_counts),
            }
            if actual != expected:
                raise AuditError(
                    f"reviewed license baseline does not match image {baseline.image}",
                    ExitCode.POLICY,
                )
            for index in indices:
                decisions[index] = FindingDecision(
                    decisions[index].finding,
                    baseline.baseline_id,
                )
    return tuple(decisions)


def enforce_dispositions(decisions: Sequence[FindingDecision]) -> None:
    undispositioned = [item for item in decisions if item.disposition_id is None]
    if undispositioned:
        safe_ids = sorted({item.finding.safe_id for item in undispositioned})
        raise AuditError(
            f"{len(undispositioned)} image findings are undispositioned: "
            + ", ".join(safe_ids),
            ExitCode.POLICY,
        )


def finding_summary(decisions: Sequence[FindingDecision]) -> dict[str, object]:
    total = len(decisions)
    disposed = sum(item.disposition_id is not None for item in decisions)
    by_kind = Counter(item.finding.kind for item in decisions)
    return {
        "total": total,
        "disposed": disposed,
        "undispositioned": total - disposed,
        "by_kind": dict(sorted(by_kind.items())),
        "disposition_ids": sorted(
            {
                item.disposition_id
                for item in decisions
                if item.disposition_id is not None
            }
        ),
    }


def validate_cyclonedx_report(
    document: Mapping[str, object],
    image_id: str,
    scanner_policy_version: int = CURRENT_SCANNER_POLICY_VERSION,
    architecture: str = "amd64",
) -> int:
    profile = scanner_profile(scanner_policy_version)
    expected_tools = profile.tools[normalize_architecture(architecture)]
    expected_spec_version = profile.cyclonedx_spec_version
    expected_syft_version = expected_tools["syft"]["version"]
    if (
        document.get("bomFormat") != "CycloneDX"
        or document.get("specVersion") != expected_spec_version
    ):
        raise AuditError(f"Syft report must be CycloneDX {expected_spec_version}")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise AuditError("Syft report metadata is malformed")
    component = metadata.get("component")
    if not isinstance(component, dict):
        raise AuditError("Syft report has no subject component")
    if (
        component.get("type") != "container"
        or component.get("name") != "sha256"
        or component.get("version") != image_id.removeprefix("sha256:")
    ):
        raise AuditError("Syft report subject does not match the captured image ID")
    tools = metadata.get("tools")
    if not isinstance(tools, dict) or not isinstance(tools.get("components"), list):
        raise AuditError("Syft report tool metadata is malformed")
    if not any(
        isinstance(tool, dict)
        and tool.get("name") == "syft"
        and tool.get("version") == expected_syft_version
        for tool in tools["components"]
    ):
        raise AuditError(
            f"Syft report was not produced by Syft {expected_syft_version}"
        )
    components = document.get("components", [])
    if components is None:
        components = []
    if not isinstance(components, list):
        raise AuditError("Syft report components must be an array")
    return len(components)


def validate_trivy_report(
    document: Mapping[str, object],
    image_key: str,
    image_id: str,
    scanner_policy_version: int = CURRENT_SCANNER_POLICY_VERSION,
    architecture: str = "amd64",
) -> list[FindingRecord]:
    profile = scanner_profile(scanner_policy_version)
    expected_tools = profile.tools[normalize_architecture(architecture)]
    expected_trivy_version = expected_tools["trivy"]["version"]
    if document.get("SchemaVersion") != profile.trivy_report_schema_version:
        raise AuditError("Trivy report schema is unsupported")
    trivy = document.get("Trivy")
    if not isinstance(trivy, dict) or trivy.get("Version") != expected_trivy_version:
        raise AuditError(
            f"Trivy report was not produced by Trivy {expected_trivy_version}"
        )
    if document.get("ArtifactType") != "container_image":
        raise AuditError("Trivy report artifact type is not a container image")
    metadata = document.get("Metadata")
    if not isinstance(metadata, dict) or metadata.get("ImageID") != image_id:
        raise AuditError("Trivy report subject does not match the captured image ID")
    os_metadata = metadata.get("OS")
    if isinstance(os_metadata, dict) and os_metadata.get("EOSL") is True:
        raise AuditError(
            "Trivy reports an end-of-life image operating system", ExitCode.POLICY
        )
    if profile.evidence_schema_version == 1:
        return trivy_findings(document, image_key)
    if profile.evidence_schema_version == 2:
        return trivy_findings_v2(document, image_key)
    raise AuditError("image scanner profile evidence schema is unsupported")


def scanner_policy_document(
    version: int = CURRENT_SCANNER_POLICY_VERSION,
) -> dict[str, object]:
    return scanner_profile(version).policy_document()


def minimal_environment(work_directory: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(work_directory / "home"),
        "XDG_CACHE_HOME": str(work_directory / "cache"),
        "TMPDIR": str(work_directory / "tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
    }


def _child_file_limit(file_size_limit: int) -> None:
    try:
        import resource

        file_hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
        child_file_limit = (
            file_size_limit
            if file_hard == resource.RLIM_INFINITY
            else min(file_size_limit, file_hard)
        )
        nofile_hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        child_nofile_limit = (
            256 if nofile_hard == resource.RLIM_INFINITY else min(256, nofile_hard)
        )
        if child_file_limit <= 0 or child_nofile_limit < 32:
            os._exit(126)
        resource.setrlimit(resource.RLIMIT_FSIZE, (child_file_limit, child_file_limit))
        resource.setrlimit(
            resource.RLIMIT_NOFILE, (child_nofile_limit, child_nofile_limit)
        )
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
        except OSError:
            pass


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int,
    stdout_limit: int = MAX_COMMAND_VALUE_BYTES,
    stderr_limit: int = MAX_COMMAND_LOG_BYTES,
    stdout_sink: BinaryIO | None = None,
    file_size_limit: int = MAX_IMAGE_BYTES,
) -> CommandResult:
    if not argv or any(not isinstance(value, str) or "\x00" in value for value in argv):
        raise AuditError("subprocess argv is invalid", ExitCode.EXECUTION)
    if file_size_limit <= 0:
        raise AuditError("subprocess file-size limit is invalid", ExitCode.EXECUTION)
    started = time.monotonic()
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
        raise AuditError(
            "cannot start required image-audit tool", ExitCode.EXECUTION
        ) from exc
    assert process.stdout is not None and process.stderr is not None

    overflow = threading.Event()
    reader_errors: list[BaseException] = []
    captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}

    def drain(
        name: str,
        pipe: BinaryIO,
        limit: int,
        sink: BinaryIO | None,
    ) -> None:
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
                if sink is None:
                    captured[name].extend(chunk)
                else:
                    sink.write(chunk)
        except BaseException as exc:  # pragma: no cover - defensive thread boundary
            reader_errors.append(exc)
            overflow.set()
        finally:
            pipe.close()

    stdout_thread = threading.Thread(
        target=drain,
        args=("stdout", process.stdout, stdout_limit, stdout_sink),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain,
        args=("stderr", process.stderr, stderr_limit, None),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    deadline = started + timeout_seconds
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
        raise AuditError("image-audit tool output did not close", ExitCode.EXECUTION)
    if reader_errors:
        raise AuditError("cannot capture bounded tool output", ExitCode.EXECUTION)
    if timed_out:
        raise AuditError("image-audit tool timed out", ExitCode.EXECUTION)
    if overflow.is_set():
        raise AuditError(
            "image-audit tool exceeded its output limit", ExitCode.EXECUTION
        )
    return CommandResult(
        returncode=process.returncode,
        stdout=bytes(captured["stdout"]),
        stderr=bytes(captured["stderr"]),
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def _checked_result(result: CommandResult, description: str) -> None:
    if result.returncode != 0:
        raise AuditError(f"{description} failed", ExitCode.EXECUTION)


def _validate_executable(path: Path, expected_sha256: str) -> None:
    digest, _ = hash_regular_file(path, MAX_TOOL_BYTES)
    info = path.stat()
    mode = stat.S_IMODE(info.st_mode)
    if digest != expected_sha256:
        raise AuditError(
            f"{path.name} executable checksum is invalid",
            ExitCode.PREREQUISITE,
        )
    if mode & 0o022 or not mode & 0o111:
        raise AuditError(
            f"{path.name} executable permissions are unsafe",
            ExitCode.PREREQUISITE,
        )
    if (
        hasattr(os, "geteuid")
        and os.geteuid() == 0
        and (info.st_uid, info.st_gid) != (0, 0)
    ):
        raise AuditError(
            f"{path.name} executable must be root-owned",
            ExitCode.PREREQUISITE,
        )


def verify_toolchain(
    work_directory: Path,
    syft_config: Path,
    runner: CommandRunner = run_bounded,
) -> tuple[str, dict[str, object]]:
    architecture = normalize_architecture(platform.machine())
    expected = scanner_profile(CURRENT_SCANNER_POLICY_VERSION).tools[architecture]
    environment = minimal_environment(work_directory)
    _validate_executable(TRIVY_PATH, expected["trivy"]["executable_sha256"])
    _validate_executable(SYFT_PATH, expected["syft"]["executable_sha256"])

    trivy_result = runner(
        [str(TRIVY_PATH), "version", "--format", "json"],
        cwd=work_directory,
        env=environment,
        timeout_seconds=VERSION_TIMEOUT_SECONDS,
    )
    _checked_result(trivy_result, "Trivy version check")
    trivy_version = parse_json_bytes(trivy_result.stdout, "Trivy version output")
    if trivy_version.get("Version") != expected["trivy"]["version"]:
        raise AuditError("installed Trivy version is not pinned", ExitCode.PREREQUISITE)

    syft_result = runner(
        [
            str(SYFT_PATH),
            "version",
            "--output",
            "json",
            "--config",
            str(syft_config),
        ],
        cwd=work_directory,
        env=environment,
        timeout_seconds=VERSION_TIMEOUT_SECONDS,
    )
    _checked_result(syft_result, "Syft version check")
    syft_version = parse_json_bytes(syft_result.stdout, "Syft version output")
    if (
        syft_version.get("application") != "syft"
        or syft_version.get("version") != expected["syft"]["version"]
        or syft_version.get("gitCommit") != expected["syft"]["git_commit"]
        or syft_version.get("platform") != f"linux/{architecture}"
    ):
        raise AuditError("installed Syft build is not pinned", ExitCode.PREREQUISITE)

    tools = {
        "trivy": dict(expected["trivy"]),
        "syft": {
            **expected["syft"],
            "platform": syft_version["platform"],
        },
    }
    return architecture, tools


def write_private_bytes(path: Path, content: bytes, mode: int = 0o600) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise AuditError(f"cannot write private evidence file: {path.name}") from exc


def _parse_database_metadata(
    metadata_path: Path,
    database_path: Path,
    audit_start: datetime,
    database_identity: tuple[str, int] | None = None,
) -> dict[str, object]:
    metadata = parse_json_bytes(
        read_regular_bytes(metadata_path, MAX_COMMAND_VALUE_BYTES),
        "Trivy database metadata",
    )
    _exact_keys(
        metadata,
        {"Version", "NextUpdate", "UpdatedAt", "DownloadedAt"},
        "Trivy database metadata",
    )
    if not isinstance(metadata["Version"], int) or metadata["Version"] != 2:
        raise AuditError("Trivy vulnerability database version is unsupported")
    updated_at = parse_rfc3339(metadata["UpdatedAt"], "Trivy DB UpdatedAt")
    next_update = parse_rfc3339(metadata["NextUpdate"], "Trivy DB NextUpdate")
    downloaded_at = parse_rfc3339(metadata["DownloadedAt"], "Trivy DB DownloadedAt")
    if updated_at > audit_start + MAX_CLOCK_SKEW:
        raise AuditError("Trivy vulnerability database timestamp is in the future")
    if audit_start - updated_at > MAX_VULNERABILITY_DB_AGE:
        raise AuditError("Trivy vulnerability database is stale", ExitCode.POLICY)
    if downloaded_at > audit_start + MAX_CLOCK_SKEW:
        raise AuditError("Trivy database download timestamp is in the future")
    if audit_start - downloaded_at > MAX_DATABASE_DOWNLOAD_AGE:
        raise AuditError("Trivy vulnerability database was not freshly downloaded")
    if next_update < audit_start - MAX_CLOCK_SKEW:
        raise AuditError("Trivy vulnerability database is past its next update")
    if database_identity is None:
        digest, size_bytes = hash_regular_file(database_path, MAX_DATABASE_BYTES)
    else:
        digest, size_bytes = database_identity
        if (
            not SHA256_PATTERN.fullmatch(digest)
            or size_bytes <= 0
            or size_bytes > MAX_DATABASE_BYTES
        ):
            raise AuditError("Trivy vulnerability database identity is invalid")
    return {
        "version": 2,
        "updated_at": format_rfc3339(updated_at),
        "next_update": format_rfc3339(next_update),
        "downloaded_at": format_rfc3339(downloaded_at),
        "sha256": digest,
        "size_bytes": size_bytes,
    }


def prepare_trivy_database(
    work_directory: Path,
    audit_start: datetime,
    runner: CommandRunner = run_bounded,
    cache_directory: Path = TRIVY_CACHE_PATH,
) -> tuple[Path, dict[str, object]]:
    if os.name != "posix":
        raise AuditError("Trivy database preparation requires Linux")
    cache = Path(os.path.abspath(cache_directory))
    try:
        resolved_cache = cache.resolve(strict=True)
    except OSError as exc:
        raise AuditError("persistent Trivy cache is unavailable") from exc
    if resolved_cache != cache:
        raise AuditError("persistent Trivy cache path is unsafe")
    _private_mode(cache, 0o700)

    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - Linux prerequisite
        raise AuditError("Trivy cache locking is unavailable") from exc
    lock_path = cache / ".audit.lock"
    lock_flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        lock_descriptor = os.open(lock_path, lock_flags, 0o600)
    except OSError as exc:
        raise AuditError("cannot open the persistent Trivy cache lock") from exc
    try:
        lock_info = os.fstat(lock_descriptor)
        lock_path_info = lock_path.lstat()
        if (
            lock_path.is_symlink()
            or not stat.S_ISREG(lock_info.st_mode)
            or (lock_info.st_dev, lock_info.st_ino)
            != (lock_path_info.st_dev, lock_path_info.st_ino)
            or stat.S_IMODE(lock_info.st_mode) & 0o022
            or (
                hasattr(os, "geteuid")
                and os.geteuid() == 0
                and (lock_info.st_uid, lock_info.st_gid) != (0, 0)
            )
        ):
            raise AuditError("persistent Trivy cache lock is unsafe")
        os.fchmod(lock_descriptor, 0o600)
        lock_deadline = time.monotonic() + CACHE_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(
                    lock_descriptor,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
                break
            except BlockingIOError:
                if time.monotonic() >= lock_deadline:
                    raise AuditError(
                        "timed out waiting for the Trivy cache lock",
                        ExitCode.EXECUTION,
                    )
                time.sleep(0.05)

        # Revalidate after acquiring the lock so a replacement cannot be used.
        current_lock_info = lock_path.lstat()
        if lock_path.is_symlink() or (
            current_lock_info.st_dev,
            current_lock_info.st_ino,
        ) != (lock_info.st_dev, lock_info.st_ino):
            raise AuditError("persistent Trivy cache lock changed")

        config = work_directory / "trivy.yaml"
        write_private_bytes(config, b"{}\n")
        environment = minimal_environment(work_directory)
        result = runner(
            [
                str(TRIVY_PATH),
                "image",
                "--config",
                str(config),
                "--cache-dir",
                str(cache),
                "--download-db-only",
                "--no-progress",
                "--disable-telemetry",
                "--skip-version-check",
                "--timeout",
                "5m",
            ],
            cwd=work_directory,
            env=environment,
            timeout_seconds=DATABASE_TIMEOUT_SECONDS,
            file_size_limit=MAX_DATABASE_BYTES,
        )
        _checked_result(result, "Trivy vulnerability database update")

        persistent_db = cache / "db"
        _validate_ignored_cache_entries(cache, {".audit.lock", "db"})
        _normalize_private_cache_path(persistent_db, 0o700, directory=True)
        if {path.name for path in persistent_db.iterdir()} != {
            "metadata.json",
            "trivy.db",
        }:
            raise AuditError("persistent Trivy database inventory is invalid")
        _normalize_private_cache_path(
            persistent_db / "metadata.json",
            0o600,
            directory=False,
        )
        _normalize_private_cache_path(
            persistent_db / "trivy.db",
            0o600,
            directory=False,
        )

        snapshot_cache = work_directory / "trivy-cache"
        snapshot_cache.mkdir(mode=0o700)
        snapshot_db = snapshot_cache / "db"
        snapshot_db.mkdir(mode=0o700)
        metadata_bytes = read_regular_bytes(
            persistent_db / "metadata.json",
            MAX_COMMAND_VALUE_BYTES,
        )
        database_identity = copy_regular_file(
            persistent_db / "trivy.db",
            snapshot_db / "trivy.db",
            MAX_DATABASE_BYTES,
        )
        if (
            read_regular_bytes(
                persistent_db / "metadata.json",
                MAX_COMMAND_VALUE_BYTES,
            )
            != metadata_bytes
        ):
            raise AuditError("Trivy database metadata changed while snapshotting")
        write_private_bytes(snapshot_db / "metadata.json", metadata_bytes)
        database = _parse_database_metadata(
            snapshot_db / "metadata.json",
            snapshot_db / "trivy.db",
            audit_start,
            database_identity,
        )
        return snapshot_cache, database
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_descriptor)


def syft_argv(
    spec: ImageSpec,
    image_id: str,
    config: Path,
    scanner_policy_version: int = CURRENT_SCANNER_POLICY_VERSION,
) -> list[str]:
    normalize_image_id(image_id)
    if config.suffix not in {".yaml", ".yml"}:
        raise AuditError("Syft config must use a recognized YAML extension")
    profile = scanner_profile(scanner_policy_version)
    return [
        str(SYFT_PATH),
        "scan",
        f"{spec.engine}:{image_id}",
        "--config",
        str(config),
        "--scope",
        "squashed",
        "--parallelism",
        "4",
        "--output",
        f"cyclonedx-json@{profile.cyclonedx_spec_version}",
        "--quiet",
    ]


def trivy_argv(
    spec: ImageSpec,
    image_id: str,
    cache: Path,
    config: Path,
    empty_ignore: Path,
    podman_socket_path: str,
    scanner_policy_version: int = CURRENT_SCANNER_POLICY_VERSION,
) -> list[str]:
    normalize_image_id(image_id)
    profile = scanner_profile(scanner_policy_version)
    if (
        not profile.license_full
        or not profile.include_unfixed
        or not profile.exit_on_eol
        or profile.global_ignores
        or profile.max_image_size_bytes % (1024**3) != 0
    ):
        raise AuditError("image scanner profile cannot be executed safely")
    argv = [
        str(TRIVY_PATH),
        "image",
        "--config",
        str(config),
        "--cache-dir",
        str(cache),
        "--image-src",
        spec.engine,
    ]
    if spec.engine == "docker":
        argv.extend(["--docker-host", DOCKER_URL])
    else:
        argv.extend(["--podman-host", podman_socket_path])
    argv.extend(
        [
            "--scanners",
            ",".join(profile.scanners),
            "--image-config-scanners",
            ",".join(profile.image_config_scanners),
            "--license-full",
            "--severity",
            ",".join(profile.severities),
            "--ignorefile",
            str(empty_ignore),
            "--exit-code",
            "0",
            "--format",
            "json",
            "--list-all-pkgs=false",
            "--detection-priority",
            profile.detection_priority,
            "--max-image-size",
            f"{profile.max_image_size_bytes // (1024**3)}GB",
            "--parallel",
            "4",
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-vex-repo-update",
            "--disable-telemetry",
            "--skip-version-check",
            "--no-progress",
            "--timeout",
            "10m",
            image_id,
        ]
    )
    if profile.pkg_types is not None:
        image_index = len(argv) - 1
        argv[image_index:image_index] = [
            "--pkg-types",
            ",".join(profile.pkg_types),
        ]
    return argv


def _run_report(
    argv: Sequence[str],
    destination: Path,
    work_directory: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    runner: CommandRunner,
) -> tuple[dict[str, object], str, int]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            result = runner(
                argv,
                cwd=work_directory,
                env=environment,
                timeout_seconds=timeout_seconds,
                stdout_limit=MAX_REPORT_BYTES,
                stderr_limit=MAX_COMMAND_LOG_BYTES,
                stdout_sink=handle,
            )
            handle.flush()
            os.fsync(handle.fileno())
        _checked_result(result, "image scanner")
        digest, size_bytes = hash_regular_file(destination, MAX_REPORT_BYTES)
        if size_bytes == 0:
            raise AuditError("image scanner produced an empty report")
        document = parse_json_bytes(
            read_regular_bytes(destination, MAX_REPORT_BYTES),
            "image scanner report",
        )
        return document, digest, size_bytes
    except BaseException:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def inspect_image(
    engine: str,
    reference: str,
    podman_url: str,
    *,
    cwd: Path,
    environment: Mapping[str, str],
    runner: CommandRunner = run_bounded,
) -> ImageSnapshot:
    validated_url, _ = validate_podman_url(podman_url)
    template = "{{.Id}}\t{{.Size}}\t{{.Os}}\t{{.Architecture}}"
    if engine == "docker":
        argv = [
            str(DOCKER_PATH),
            "--host",
            DOCKER_URL,
            "image",
            "inspect",
            "--format",
            template,
            reference,
        ]
    elif engine == "podman":
        argv = [
            str(PODMAN_PATH),
            "--url",
            validated_url,
            "image",
            "inspect",
            "--format",
            template,
            reference,
        ]
    else:
        raise AuditError(f"unsupported image engine: {engine}", ExitCode.IMAGE)
    result = runner(
        argv,
        cwd=cwd,
        env=environment,
        timeout_seconds=INSPECT_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise AuditError(f"cannot inspect required image: {reference}", ExitCode.IMAGE)
    try:
        image_id, size_raw, os_name, architecture_raw = (
            result.stdout.decode("utf-8").strip().split("\t")
        )
        size_bytes = int(size_raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise AuditError(
            "image inspection output is malformed", ExitCode.IMAGE
        ) from exc
    image_id = normalize_inspected_image_id(engine, image_id, reference)
    architecture = normalize_architecture(architecture_raw)
    if size_bytes <= 0 or size_bytes > MAX_IMAGE_BYTES:
        raise AuditError("image exceeds the audit size policy", ExitCode.IMAGE)
    if os_name != "linux":
        raise AuditError("release image must target Linux", ExitCode.IMAGE)
    return ImageSnapshot(image_id, size_bytes, os_name, architecture)


def _require_same_snapshot(
    expected: ImageSnapshot,
    actual: ImageSnapshot,
    reference: str,
) -> None:
    if expected != actual:
        raise AuditError(
            f"local image tag changed during audit: {reference}",
            ExitCode.IMAGE,
        )


def _report_paths(spec: ImageSpec) -> tuple[str, str]:
    return (
        f"reports/{spec.file_stem}.sbom.cdx.json",
        f"reports/{spec.file_stem}.trivy.json",
    )


def _host_document(architecture: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for raw in (
            Path("/etc/os-release")
            .read_text(encoding="utf-8", errors="strict")
            .splitlines()
        ):
            key, separator, value = raw.partition("=")
            if separator and key in {"ID", "VERSION_ID"}:
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return {
        "os_id": values.get("ID", "linux"),
        "os_version_id": values.get("VERSION_ID", "unknown"),
        "architecture": architecture,
        "kernel_release": platform.release(),
    }


def _private_mode(path: Path, expected: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AuditError(f"cannot inspect evidence path: {path.name}") from exc
    if path.is_symlink():
        raise AuditError(f"evidence path is a symlink: {path.name}")
    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise AuditError(f"evidence path has a special type: {path.name}")
    if os.name == "posix" and stat.S_IMODE(info.st_mode) != expected:
        raise AuditError(f"evidence path has unsafe permissions: {path.name}")
    if (
        hasattr(os, "geteuid")
        and os.geteuid() == 0
        and (info.st_uid, info.st_gid) != (0, 0)
    ):
        raise AuditError(f"evidence path is not root-owned: {path.name}")


def _normalize_private_cache_path(
    path: Path,
    expected: int,
    *,
    directory: bool,
) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AuditError(f"cannot inspect Trivy cache path: {path.name}") from exc
    expected_type = (
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    )
    if (
        path.is_symlink()
        or not expected_type
        or stat.S_IMODE(info.st_mode) & 0o022
        or (
            hasattr(os, "geteuid")
            and os.geteuid() == 0
            and (info.st_uid, info.st_gid) != (0, 0)
        )
    ):
        raise AuditError(f"Trivy cache path is unsafe: {path.name}")
    try:
        path.chmod(expected, follow_symlinks=False)
    except OSError as exc:
        raise AuditError(f"cannot restrict Trivy cache path: {path.name}") from exc
    _private_mode(path, expected)


def _validate_ignored_cache_entries(
    cache: Path,
    used_names: set[str],
) -> None:
    cache_info = cache.lstat()
    for path in cache.iterdir():
        if path.name in used_names:
            continue
        info = path.lstat()
        if (
            path.is_symlink()
            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            or (info.st_uid, info.st_gid) != (cache_info.st_uid, cache_info.st_gid)
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise AuditError(f"unrelated Trivy cache entry is unsafe: {path.name}")


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_private_tree(path: Path, expected_parent: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (
        path.parent != expected_parent
        or path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
    ):
        raise AuditError("refusing unsafe image-audit staging cleanup")
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", os.name != "posix"):
        raise AuditError("platform lacks symlink-safe tree cleanup")
    shutil.rmtree(path)


def publish_private_evidence(stage: Path, final: Path) -> None:
    if final.exists() or final.is_symlink():
        raise AuditError("image-audit evidence already exists")
    if stage.parent != final.parent:
        raise AuditError("evidence must be published on one filesystem")
    _fsync_directory(stage / "reports")
    _fsync_directory(stage)
    try:
        os.rename(stage, final)
    except OSError as exc:
        raise AuditError("cannot atomically publish image-audit evidence") from exc
    _fsync_directory(final.parent)


def _verify_then_publish_private_evidence(
    stage: Path,
    final: Path,
    verifier: Callable[[Path], dict[str, object]],
) -> dict[str, object]:
    receipt = verifier(stage)
    publish_private_evidence(stage, final)
    return receipt


def _disposition_policy_receipt(
    policy: DispositionPolicy,
) -> dict[str, object]:
    record: dict[str, object] = {
        "path": POLICY_RELATIVE.as_posix(),
        "schema_version": policy.schema_version,
        "policy_id": policy.policy_id,
        "sha256": policy.sha256,
        "disposition_ids": sorted(item.disposition_id for item in policy.dispositions),
    }
    if policy.schema_version == 2:
        record["license_baselines"] = [
            {
                "id": item.baseline_id,
                "image": item.image,
                "algorithm": item.algorithm,
                "finding_count": item.finding_count,
                "canonical_sha256": item.canonical_sha256,
                "category_counts": dict(item.category_counts),
                "severity_counts": dict(item.severity_counts),
            }
            for item in sorted(
                policy.license_baselines,
                key=lambda candidate: candidate.baseline_id,
            )
        ]
    return record


def _build_receipt(
    *,
    release_id: str,
    started_at: datetime,
    completed_at: datetime,
    architecture: str,
    tools: dict[str, object],
    database: dict[str, object],
    policy: DispositionPolicy,
    images: dict[str, dict[str, object]],
    decisions: Sequence[FindingDecision],
    profile: ScannerProfile | None = None,
) -> dict[str, object]:
    if profile is None:
        profile = scanner_profile(CURRENT_SCANNER_POLICY_VERSION)
    if policy.schema_version != profile.policy_schema_version:
        raise AuditError("image disposition policy uses another evidence schema")
    return {
        "schema_version": profile.evidence_schema_version,
        "status": "pass",
        "release_id": release_id,
        "source_commit": release_id.removeprefix("sha-"),
        "started_at": format_rfc3339(started_at),
        "completed_at": format_rfc3339(completed_at),
        "host": _host_document(architecture),
        "scanner_policy": scanner_policy_document(profile.version),
        "disposition_policy": _disposition_policy_receipt(policy),
        "tools": tools,
        "trivy_database": database,
        "findings": finding_summary(decisions),
        "images": images,
    }


def audit_release_images(
    repo_root: Path,
    release_id: str,
    *,
    podman_url: str = DEFAULT_PODMAN_URL,
    runner: CommandRunner = run_bounded,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    require_root()
    release_id = validate_release_id(release_id)
    validated_podman_url, podman_socket_path = validate_podman_url(podman_url)
    root = resolve_repo_root(repo_root)
    infra = require_infra_directory(root)
    final = root / EVIDENCE_RELATIVE
    if final.exists() or final.is_symlink():
        raise AuditError("image-audit evidence already exists")

    started_at = now().astimezone(timezone.utc)
    deadline = time.monotonic() + TOTAL_AUDIT_TIMEOUT_SECONDS
    profile = scanner_profile(CURRENT_SCANNER_POLICY_VERSION)
    policy = load_disposition_policy(
        root,
        started_at,
        profile.policy_schema_version,
    )
    old_umask = os.umask(0o077)
    stage = Path(tempfile.mkdtemp(prefix=".image-audit.", dir=infra))
    try:
        stage.chmod(0o700)
        reports = stage / "reports"
        reports.mkdir(mode=0o700)
        work = stage / ".work"
        work.mkdir(mode=0o700)
        for directory in ("home", "cache", "tmp"):
            (work / directory).mkdir(mode=0o700)
        empty_ignore = work / "empty.trivyignore"
        write_private_bytes(empty_ignore, b"")
        syft_config = work / "syft.yaml"
        write_private_bytes(syft_config, b"{}\n")

        architecture, tools = verify_toolchain(work, syft_config, runner)
        cache, database = prepare_trivy_database(work, started_at, runner)
        config = work / "trivy.yaml"
        environment = minimal_environment(work)
        references = image_references(release_id)
        snapshots: dict[str, ImageSnapshot] = {}
        for spec in IMAGE_SPECS:
            record = references[spec.key]
            snapshot = inspect_image(
                spec.engine,
                record["reference"],
                validated_podman_url,
                cwd=work,
                environment=environment,
                runner=runner,
            )
            if snapshot.architecture != architecture:
                raise AuditError(
                    "release image architecture does not match the audit host",
                    ExitCode.IMAGE,
                )
            snapshots[spec.key] = snapshot

        images: dict[str, dict[str, object]] = {}
        findings_by_image: dict[str, list[FindingRecord]] = {}
        for spec in IMAGE_SPECS:
            if time.monotonic() >= deadline:
                raise AuditError(
                    "image audit exceeded its total timeout", ExitCode.EXECUTION
                )
            snapshot = snapshots[spec.key]
            reference = references[spec.key]["reference"]
            sbom_relative, trivy_relative = _report_paths(spec)
            sbom_path = stage / sbom_relative
            trivy_path = stage / trivy_relative
            scan_environment = dict(environment)
            if spec.engine == "docker":
                scan_environment["DOCKER_HOST"] = DOCKER_URL
            else:
                scan_environment["CONTAINER_HOST"] = validated_podman_url
            sbom_document, sbom_sha256, sbom_size = _run_report(
                syft_argv(
                    spec,
                    snapshot.image_id,
                    syft_config,
                    profile.version,
                ),
                sbom_path,
                work,
                scan_environment,
                min(SYFT_TIMEOUT_SECONDS, max(1, int(deadline - time.monotonic()))),
                runner,
            )
            component_count = validate_cyclonedx_report(
                sbom_document,
                snapshot.image_id,
                CURRENT_SCANNER_POLICY_VERSION,
                architecture,
            )
            _require_same_snapshot(
                snapshot,
                inspect_image(
                    spec.engine,
                    reference,
                    validated_podman_url,
                    cwd=work,
                    environment=environment,
                    runner=runner,
                ),
                reference,
            )
            trivy_document, trivy_sha256, trivy_size = _run_report(
                trivy_argv(
                    spec,
                    snapshot.image_id,
                    cache,
                    config,
                    empty_ignore,
                    podman_socket_path,
                    profile.version,
                ),
                trivy_path,
                work,
                scan_environment,
                min(TRIVY_TIMEOUT_SECONDS, max(1, int(deadline - time.monotonic()))),
                runner,
            )
            image_findings = validate_trivy_report(
                trivy_document,
                spec.key,
                snapshot.image_id,
                CURRENT_SCANNER_POLICY_VERSION,
                architecture,
            )
            findings_by_image[spec.key] = image_findings
            after = inspect_image(
                spec.engine,
                reference,
                validated_podman_url,
                cwd=work,
                environment=environment,
                runner=runner,
            )
            _require_same_snapshot(snapshot, after, reference)
            images[spec.key] = {
                "engine": spec.engine,
                "reference": reference,
                "image_id": snapshot.image_id,
                "image_size_bytes": snapshot.size_bytes,
                "os": snapshot.os_name,
                "architecture": snapshot.architecture,
                "tag_image_id_before": snapshot.image_id,
                "tag_image_id_after": after.image_id,
                "reports": {
                    "sbom": {
                        "path": sbom_relative,
                        "sha256": sbom_sha256,
                        "size_bytes": sbom_size,
                        "format": "CycloneDX",
                        "spec_version": scanner_profile(
                            CURRENT_SCANNER_POLICY_VERSION
                        ).cyclonedx_spec_version,
                        "component_count": component_count,
                    },
                    "trivy": {
                        "path": trivy_relative,
                        "sha256": trivy_sha256,
                        "size_bytes": trivy_size,
                        "format": "trivy-json",
                        "schema_version": scanner_profile(
                            CURRENT_SCANNER_POLICY_VERSION
                        ).trivy_report_schema_version,
                    },
                },
            }

        all_findings = [
            finding for spec in IMAGE_SPECS for finding in findings_by_image[spec.key]
        ]
        decisions = evaluate_dispositions(all_findings, policy)
        enforce_dispositions(decisions)
        for spec in IMAGE_SPECS:
            image_decisions = [
                item for item in decisions if item.finding.image == spec.key
            ]
            images[spec.key]["findings"] = finding_summary(image_decisions)

        final_db_sha256, final_db_size = hash_regular_file(
            cache / "db" / "trivy.db", MAX_DATABASE_BYTES
        )
        if (
            final_db_sha256 != database["sha256"]
            or final_db_size != database["size_bytes"]
        ):
            raise AuditError("Trivy vulnerability database changed during scanning")
        for spec in IMAGE_SPECS:
            reference = references[spec.key]["reference"]
            _require_same_snapshot(
                snapshots[spec.key],
                inspect_image(
                    spec.engine,
                    reference,
                    validated_podman_url,
                    cwd=work,
                    environment=environment,
                    runner=runner,
                ),
                reference,
            )

        completed_at = now().astimezone(timezone.utc)
        receipt = _build_receipt(
            release_id=release_id,
            started_at=started_at,
            completed_at=completed_at,
            architecture=architecture,
            tools=tools,
            database=database,
            policy=policy,
            images=images,
            decisions=decisions,
            profile=profile,
        )
        serialized = (
            json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        )
        if len(serialized) > MAX_RECEIPT_BYTES:
            raise AuditError("image-audit receipt exceeds its size limit")
        write_private_bytes(stage / "receipt.json", serialized)
        _remove_private_tree(work, stage)
        return _verify_then_publish_private_evidence(
            stage,
            final,
            lambda candidate: _verify_evidence_directory(
                root,
                release_id,
                candidate,
            ),
        )
    finally:
        os.umask(old_umask)
        if stage.exists() and stage != final:
            _remove_private_tree(stage, infra)


def _validate_report_record(
    record: object,
    *,
    expected_path: str,
    expected_format: str,
    profile: ScannerProfile,
) -> dict[str, object]:
    if not isinstance(record, dict):
        raise AuditError("image report receipt record is malformed")
    common = {"path", "sha256", "size_bytes", "format"}
    if expected_format == "CycloneDX":
        expected = common | {"spec_version", "component_count"}
    else:
        expected = common | {"schema_version"}
    _exact_keys(record, expected, "image report receipt record")
    if record.get("path") != expected_path or record.get("format") != expected_format:
        raise AuditError("image report receipt path or format is invalid")
    if not isinstance(record.get("sha256"), str) or not SHA256_PATTERN.fullmatch(
        str(record["sha256"])
    ):
        raise AuditError("image report receipt checksum is invalid")
    if (
        not isinstance(record.get("size_bytes"), int)
        or not 0 < int(record["size_bytes"]) <= profile.max_report_bytes
    ):
        raise AuditError("image report receipt size is invalid")
    if expected_format == "CycloneDX":
        if record.get(
            "spec_version"
        ) != profile.cyclonedx_spec_version or not isinstance(
            record.get("component_count"), int
        ):
            raise AuditError("CycloneDX receipt metadata is invalid")
    elif record.get("schema_version") != profile.trivy_report_schema_version:
        raise AuditError("Trivy receipt schema metadata is invalid")
    return record


def _validate_summary(value: object, expected: dict[str, object]) -> None:
    if value != expected:
        raise AuditError("image finding summary does not match the reports")


def _expected_tool_receipt(
    architecture: str,
    scanner_policy_version: int = CURRENT_SCANNER_POLICY_VERSION,
) -> dict[str, object]:
    expected = scanner_profile(scanner_policy_version).tools[architecture]
    return {
        "trivy": dict(expected["trivy"]),
        "syft": {
            **expected["syft"],
            "platform": f"linux/{architecture}",
        },
    }


def _verify_database_receipt(
    value: object,
    audit_start: datetime,
    profile: ScannerProfile | None = None,
) -> None:
    if profile is None:
        profile = scanner_profile(CURRENT_SCANNER_POLICY_VERSION)
    if not isinstance(value, dict):
        raise AuditError("Trivy database receipt is malformed")
    _exact_keys(
        value,
        {
            "version",
            "updated_at",
            "next_update",
            "downloaded_at",
            "sha256",
            "size_bytes",
        },
        "Trivy database receipt",
    )
    if value["version"] != 2:
        raise AuditError("Trivy database receipt version is invalid")
    if not isinstance(value["sha256"], str) or not SHA256_PATTERN.fullmatch(
        value["sha256"]
    ):
        raise AuditError("Trivy database receipt checksum is invalid")
    if (
        not isinstance(value["size_bytes"], int)
        or not 0 < value["size_bytes"] <= profile.max_database_bytes
    ):
        raise AuditError("Trivy database receipt size is invalid")
    updated_at = parse_rfc3339(value["updated_at"], "receipt DB updated_at")
    next_update = parse_rfc3339(value["next_update"], "receipt DB next_update")
    downloaded_at = parse_rfc3339(value["downloaded_at"], "receipt DB downloaded_at")
    if (
        updated_at > audit_start + MAX_CLOCK_SKEW
        or audit_start - updated_at > MAX_VULNERABILITY_DB_AGE
        or downloaded_at > audit_start + MAX_CLOCK_SKEW
        or audit_start - downloaded_at > MAX_DATABASE_DOWNLOAD_AGE
        or next_update < audit_start - MAX_CLOCK_SKEW
    ):
        raise AuditError("Trivy database receipt freshness is invalid")


def _verify_private_inventory(
    evidence: Path,
    profile: ScannerProfile | None = None,
) -> None:
    if evidence.is_symlink() or not evidence.is_dir():
        raise AuditError("image-audit evidence directory is invalid")
    _private_mode(evidence, 0o700)
    reports = evidence / "reports"
    _private_mode(reports, 0o700)
    expected_root = {"receipt.json", "reports"}
    expected_reports = {
        Path(path).name for spec in IMAGE_SPECS for path in _report_paths(spec)
    }
    if {path.name for path in evidence.iterdir()} != expected_root:
        raise AuditError("image-audit root inventory is invalid")
    if {path.name for path in reports.iterdir()} != expected_reports:
        raise AuditError("image-audit report inventory is invalid")
    _private_mode(evidence / "receipt.json", 0o600)
    total = (evidence / "receipt.json").stat().st_size
    for path in reports.iterdir():
        _private_mode(path, 0o600)
        total += path.stat().st_size
    report_limit = (
        profile.max_report_bytes
        if profile is not None
        else max(item.max_report_bytes for item in SCANNER_PROFILE_REGISTRY.values())
    )
    if total > 6 * report_limit + MAX_RECEIPT_BYTES:
        raise AuditError("image-audit evidence exceeds its aggregate size limit")


def _verify_evidence_directory(
    root: Path,
    release_id: str,
    evidence: Path,
    expected_images: dict[str, dict[str, str]] | None = None,
    image_resolver: ImageResolver | None = None,
) -> dict[str, object]:
    _verify_private_inventory(evidence)
    receipt = parse_json_bytes(
        read_regular_bytes(evidence / "receipt.json", MAX_RECEIPT_BYTES),
        "image-audit receipt",
    )
    _exact_keys(
        receipt,
        {
            "schema_version",
            "status",
            "release_id",
            "source_commit",
            "started_at",
            "completed_at",
            "host",
            "scanner_policy",
            "disposition_policy",
            "tools",
            "trivy_database",
            "findings",
            "images",
        },
        "image-audit receipt",
    )
    receipt_schema_version = receipt["schema_version"]
    if (
        not isinstance(receipt_schema_version, int)
        or isinstance(receipt_schema_version, bool)
        or receipt_schema_version not in SUPPORTED_EVIDENCE_SCHEMA_VERSIONS
    ):
        raise AuditError("image-audit receipt schema is unsupported")
    if (
        receipt["status"] != "pass"
        or receipt["release_id"] != release_id
        or receipt["source_commit"] != release_id.removeprefix("sha-")
    ):
        raise AuditError("image-audit receipt release identity is invalid")
    started_at = parse_rfc3339(receipt["started_at"], "receipt started_at")
    completed_at = parse_rfc3339(receipt["completed_at"], "receipt completed_at")
    if completed_at < started_at or completed_at - started_at > timedelta(
        seconds=TOTAL_AUDIT_TIMEOUT_SECONDS + 300
    ):
        raise AuditError("image-audit receipt duration is invalid")

    scanner_policy_record = receipt["scanner_policy"]
    if not isinstance(scanner_policy_record, dict):
        raise AuditError("image scanner policy receipt is malformed")
    profile = scanner_profile(scanner_policy_record.get("version"))
    if profile.evidence_schema_version != receipt["schema_version"]:
        raise AuditError("image scanner profile uses another evidence schema")
    if scanner_policy_record != scanner_policy_document(profile.version):
        raise AuditError("image scanner policy receipt is invalid")
    _verify_private_inventory(evidence, profile)

    policy = load_disposition_policy(
        root,
        started_at,
        profile.policy_schema_version,
    )
    policy_record = receipt["disposition_policy"]
    if not isinstance(policy_record, dict):
        raise AuditError("image disposition policy receipt is malformed")
    expected_policy_record = _disposition_policy_receipt(policy)
    if policy_record != expected_policy_record:
        raise AuditError("image disposition policy receipt is invalid")

    host = receipt["host"]
    if not isinstance(host, dict):
        raise AuditError("image-audit host receipt is malformed")
    _exact_keys(
        host,
        {"os_id", "os_version_id", "architecture", "kernel_release"},
        "image-audit host receipt",
    )
    architecture = normalize_architecture(str(host["architecture"]))
    if receipt["tools"] != _expected_tool_receipt(
        architecture,
        profile.version,
    ):
        raise AuditError("image-audit tool receipt is invalid")
    _verify_database_receipt(
        receipt["trivy_database"],
        started_at,
        profile,
    )

    images = receipt["images"]
    references = image_references(release_id)
    if not isinstance(images, dict) or set(images) != set(references):
        raise AuditError("image-audit image inventory is invalid")
    all_findings: list[FindingRecord] = []
    findings_by_image: dict[str, list[FindingRecord]] = {}
    for spec in IMAGE_SPECS:
        record = images[spec.key]
        if not isinstance(record, dict):
            raise AuditError("image receipt record is malformed")
        _exact_keys(
            record,
            {
                "engine",
                "reference",
                "image_id",
                "image_size_bytes",
                "os",
                "architecture",
                "tag_image_id_before",
                "tag_image_id_after",
                "reports",
                "findings",
            },
            f"image receipt {spec.key}",
        )
        expected_reference = references[spec.key]
        if (
            record["engine"] != expected_reference["engine"]
            or record["reference"] != expected_reference["reference"]
            or record["os"] != "linux"
            or normalize_architecture(str(record["architecture"])) != architecture
        ):
            raise AuditError(f"image receipt identity is invalid: {spec.key}")
        image_id = normalize_image_id(str(record["image_id"]), spec.key)
        if (
            record["tag_image_id_before"] != image_id
            or record["tag_image_id_after"] != image_id
            or not isinstance(record["image_size_bytes"], int)
            or not 0 < record["image_size_bytes"] <= profile.max_image_size_bytes
        ):
            raise AuditError(f"image receipt drift metadata is invalid: {spec.key}")
        reports = record["reports"]
        if not isinstance(reports, dict) or set(reports) != {"sbom", "trivy"}:
            raise AuditError(f"image report inventory is invalid: {spec.key}")
        sbom_relative, trivy_relative = _report_paths(spec)
        sbom_record = _validate_report_record(
            reports["sbom"],
            expected_path=sbom_relative,
            expected_format="CycloneDX",
            profile=profile,
        )
        trivy_record = _validate_report_record(
            reports["trivy"],
            expected_path=trivy_relative,
            expected_format="trivy-json",
            profile=profile,
        )
        sbom_path = evidence / sbom_relative
        trivy_path = evidence / trivy_relative
        sbom_sha256, sbom_size = hash_regular_file(
            sbom_path,
            profile.max_report_bytes,
        )
        trivy_sha256, trivy_size = hash_regular_file(
            trivy_path,
            profile.max_report_bytes,
        )
        if (sbom_sha256, sbom_size) != (
            sbom_record["sha256"],
            sbom_record["size_bytes"],
        ):
            raise AuditError(f"Syft report hash/size mismatch: {spec.key}")
        if (trivy_sha256, trivy_size) != (
            trivy_record["sha256"],
            trivy_record["size_bytes"],
        ):
            raise AuditError(f"Trivy report hash/size mismatch: {spec.key}")
        sbom_document = parse_json_bytes(
            read_regular_bytes(sbom_path, profile.max_report_bytes),
            "Syft report",
        )
        if (
            validate_cyclonedx_report(
                sbom_document,
                image_id,
                profile.version,
                architecture,
            )
            != sbom_record["component_count"]
        ):
            raise AuditError(f"Syft component count mismatch: {spec.key}")
        trivy_document = parse_json_bytes(
            read_regular_bytes(trivy_path, profile.max_report_bytes),
            "Trivy report",
        )
        image_findings = validate_trivy_report(
            trivy_document,
            spec.key,
            image_id,
            profile.version,
            architecture,
        )
        findings_by_image[spec.key] = image_findings
        all_findings.extend(image_findings)

        if expected_images is not None:
            expected = expected_images.get(spec.key)
            if not isinstance(expected, dict) or (
                expected.get("engine"),
                expected.get("reference"),
                expected.get("id"),
            ) != (spec.engine, expected_reference["reference"], image_id):
                raise AuditError(
                    f"manifest image does not match audit evidence: {spec.key}"
                )
        if image_resolver is not None:
            current = normalize_image_id(
                image_resolver(spec.engine, expected_reference["reference"]),
                expected_reference["reference"],
            )
            if current != image_id:
                raise AuditError(
                    f"local image tag no longer matches audit evidence: {spec.key}",
                    ExitCode.IMAGE,
                )

    if expected_images is not None and set(expected_images) != set(references):
        raise AuditError("manifest image inventory does not match audit evidence")
    decisions = evaluate_dispositions(all_findings, policy)
    enforce_dispositions(decisions)
    _validate_summary(receipt["findings"], finding_summary(decisions))
    for spec in IMAGE_SPECS:
        image_decisions = [item for item in decisions if item.finding.image == spec.key]
        _validate_summary(
            images[spec.key]["findings"],
            finding_summary(image_decisions),
        )
    return receipt


def verify_evidence(
    repo_root: Path,
    release_id: str,
    expected_images: dict[str, dict[str, str]] | None = None,
    image_resolver: ImageResolver | None = None,
    podman_url: str = DEFAULT_PODMAN_URL,
) -> dict[str, object]:
    """Verify private audit evidence and optionally bind it to manifest images.

    This import API performs no privileged mutation and is intentionally
    testable without root. When run as root, root ownership is also enforced.
    """

    validate_podman_url(podman_url)
    root = resolve_repo_root(repo_root)
    release_id = validate_release_id(release_id)
    require_infra_directory(root)
    return _verify_evidence_directory(
        root,
        release_id,
        root / EVIDENCE_RELATIVE,
        expected_images,
        image_resolver,
    )


def _cli_resolver(podman_url: str) -> ImageResolver:
    temporary = tempfile.TemporaryDirectory(prefix="codex-mobile-image-verify.")
    work = Path(temporary.name)
    environment = minimal_environment(work)

    def resolve(engine: str, reference: str) -> str:
        # Keep the temporary directory alive through the closure.
        _ = temporary
        return inspect_image(
            engine,
            reference,
            podman_url,
            cwd=work,
            environment=environment,
        ).image_id

    return resolve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("scan", "verify"))
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--podman-url", default=DEFAULT_PODMAN_URL)
    parser.add_argument("--require-images", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_podman_url(args.podman_url)
        require_root()
        if args.action == "scan":
            if args.require_images:
                raise AuditError(
                    "--require-images is only valid with verify",
                    ExitCode.USAGE,
                )
            receipt = audit_release_images(
                args.repo_root,
                args.release_id,
                podman_url=args.podman_url,
            )
            print(
                "image audit passed and private evidence was published: "
                f"{receipt['release_id']}"
            )
        else:
            resolver = _cli_resolver(args.podman_url) if args.require_images else None
            receipt = verify_evidence(
                args.repo_root,
                args.release_id,
                image_resolver=resolver,
                podman_url=args.podman_url,
            )
            print(f"image audit evidence verified: {receipt['release_id']}")
        return int(ExitCode.OK)
    except AuditError as exc:
        print(f"image audit failed: {exc}", file=sys.stderr)
        return int(exc.code)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"image audit failed safely: {type(exc).__name__}", file=sys.stderr)
        return int(ExitCode.EVIDENCE)


if __name__ == "__main__":
    raise SystemExit(main())
