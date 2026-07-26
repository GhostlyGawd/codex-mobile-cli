#!/usr/bin/env python3
"""Verify the pinned EnvBuilder source derivative without trusting an archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable


LOCK_RELATIVE_PATH = Path("infra/workspace/envbuilder/source-lock.json")
PATCH_RELATIVE_PATH = Path(
    "infra/workspace/envbuilder/envbuilder-v1.3.0-codex-mobile.patch"
)
LOCK_MAX_BYTES = 64 * 1024
PATCH_MAX_BYTES = 1024 * 1024
ARCHIVE_MAX_BYTES = 8 * 1024 * 1024
ARCHIVE_MEMBER_MAX_BYTES = 16 * 1024 * 1024
ARCHIVE_TOTAL_MAX_BYTES = 64 * 1024 * 1024
COMMAND_OUTPUT_MAX_BYTES = 4 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 15 * 60
EXPECTED_COMMIT = "da95f80ea89fc615b85441da107c29004061df6a"
EXPECTED_ARCHIVE_URL = (
    "https://codeload.github.com/coder/envbuilder/tar.gz/" + EXPECTED_COMMIT
)
EXPECTED_ARCHIVE_SHA256 = (
    "f1c6334ee08736dec2585d96ad0afacc1888994bf2a2cdcf86e982b229fb8a85"
)
EXPECTED_LICENSE_SHA256 = (
    "43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1"
)
EXPECTED_PATCH_SHA256 = (
    "aea2941874a27d4deac96a0efe3a006ca6ea56d7cff982caa3a36877fc1756c3"
)
EXPECTED_DERIVATIVE_VERSION = "1.3.0-codex-mobile.1"
EXPECTED_GO_VERSION = "go1.26.5"
EXPECTED_BUILDER_IMAGE = (
    "docker.io/library/golang:1.26.5-bookworm@sha256:"
    "1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651"
)
EXPECTED_PATCH_FILES = (
    "cmd/envbuilder/main.go",
    "cmd/envbuilder/main_internal_test.go",
    "go.mod",
    "go.sum",
    "integration/integration_test.go",
    "log/coder.go",
    "log/coder_internal_test.go",
    "log/log.go",
)
EXPECTED_ROOT = f"envbuilder-{EXPECTED_COMMIT}"
EXPECTED_ARCHIVE_MEMBERS = 122
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
PATCH_HEADER_PATTERN = re.compile(
    rb"^diff --git a/([^\r\n]+) b/([^\r\n]+)$", re.MULTILINE
)


class VerificationError(RuntimeError):
    pass


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise VerificationError("EnvBuilder source download redirected")


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise VerificationError(f"duplicate source-lock key: {key}")
        document[key] = value
    return document


def require_exact_keys(
    value: object, expected: Iterable[str], description: str
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise VerificationError(f"{description} keys are invalid")
    return value


def read_regular_bytes(path: Path, limit: int, description: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > limit
        ):
            raise VerificationError(f"{description} is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != info.st_size or len(content) > limit:
            raise VerificationError(f"{description} changed while being read")
        after = os.fstat(descriptor)
        identity_before = (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_after != identity_before:
            raise VerificationError(f"{description} changed while being read")
        return content
    except OSError as exc:
        raise VerificationError(f"cannot read {description}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def expect_string(
    record: dict[str, object], key: str, expected: str, description: str
) -> None:
    if record.get(key) != expected:
        raise VerificationError(f"{description} is invalid")


def load_and_validate_lock(root: Path) -> tuple[dict[str, object], Path]:
    lock_path = root / LOCK_RELATIVE_PATH
    raw = read_regular_bytes(lock_path, LOCK_MAX_BYTES, "EnvBuilder source lock")
    try:
        lock = json.loads(raw, object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("EnvBuilder source lock is not strict JSON") from exc
    top = require_exact_keys(
        lock,
        ("schema_version", "derivative_version", "upstream", "patch", "builder"),
        "EnvBuilder source lock",
    )
    if type(top.get("schema_version")) is not int or top["schema_version"] != 1:
        raise VerificationError("EnvBuilder source-lock schema is unsupported")
    expect_string(
        top,
        "derivative_version",
        EXPECTED_DERIVATIVE_VERSION,
        "EnvBuilder derivative version",
    )

    upstream = require_exact_keys(
        top["upstream"],
        (
            "repository",
            "version",
            "commit",
            "archive_url",
            "archive_sha256",
            "license",
            "license_sha256",
        ),
        "EnvBuilder upstream record",
    )
    expect_string(
        upstream,
        "repository",
        "https://github.com/coder/envbuilder",
        "EnvBuilder upstream repository",
    )
    expect_string(upstream, "version", "1.3.0", "EnvBuilder upstream version")
    expect_string(upstream, "commit", EXPECTED_COMMIT, "EnvBuilder upstream commit")
    expect_string(
        upstream, "archive_url", EXPECTED_ARCHIVE_URL, "EnvBuilder archive URL"
    )
    expect_string(
        upstream,
        "archive_sha256",
        EXPECTED_ARCHIVE_SHA256,
        "EnvBuilder archive checksum",
    )
    expect_string(upstream, "license", "Apache-2.0", "EnvBuilder upstream license")
    expect_string(
        upstream,
        "license_sha256",
        EXPECTED_LICENSE_SHA256,
        "EnvBuilder license checksum",
    )

    patch = require_exact_keys(
        top["patch"], ("path", "sha256", "license", "files"), "EnvBuilder patch record"
    )
    expect_string(
        patch, "path", PATCH_RELATIVE_PATH.as_posix(), "EnvBuilder patch path"
    )
    expect_string(patch, "sha256", EXPECTED_PATCH_SHA256, "EnvBuilder patch checksum")
    expect_string(
        patch,
        "license",
        "LicenseRef-First-Party-No-License",
        "EnvBuilder patch license",
    )
    if patch.get("files") != list(EXPECTED_PATCH_FILES):
        raise VerificationError("EnvBuilder patched-file inventory is invalid")

    builder = require_exact_keys(
        top["builder"], ("image",), "EnvBuilder builder record"
    )
    expect_string(builder, "image", EXPECTED_BUILDER_IMAGE, "EnvBuilder builder image")

    patch_path = (root / str(patch["path"])).resolve(strict=True)
    try:
        patch_path.relative_to(root)
    except ValueError as exc:
        raise VerificationError("EnvBuilder patch escapes the repository") from exc
    patch_raw = read_regular_bytes(patch_path, PATCH_MAX_BYTES, "EnvBuilder patch")
    if hashlib.sha256(patch_raw).hexdigest() != EXPECTED_PATCH_SHA256:
        raise VerificationError("EnvBuilder patch checksum does not match its lock")
    if b"\r" in patch_raw:
        raise VerificationError("EnvBuilder patch must use canonical LF line endings")
    headers = PATCH_HEADER_PATTERN.findall(patch_raw)
    try:
        patched_paths = tuple(
            left.decode("utf-8", errors="strict")
            for left, right in headers
            if left == right
        )
    except UnicodeDecodeError as exc:
        raise VerificationError("EnvBuilder patch paths are not UTF-8") from exc
    if len(headers) != len(patched_paths) or patched_paths != EXPECTED_PATCH_FILES:
        raise VerificationError("EnvBuilder patch path headers are invalid")
    if (
        b"diff --git a/cmd/envbuilder/main_internal_test.go "
        b"b/cmd/envbuilder/main_internal_test.go\nnew file mode 100644\n"
        not in patch_raw
    ):
        raise VerificationError("EnvBuilder patch omits its new credential test")
    return top, patch_path


def copy_bounded(source: BinaryIO, destination: BinaryIO, size: int) -> None:
    remaining = size
    while remaining:
        chunk = source.read(min(64 * 1024, remaining))
        if not chunk:
            raise VerificationError("EnvBuilder archive member ended early")
        destination.write(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise VerificationError("EnvBuilder archive member exceeded its declared size")


def download_archive(destination: Path) -> None:
    opener = urllib.request.build_opener(RejectRedirects)
    request = urllib.request.Request(
        EXPECTED_ARCHIVE_URL,
        headers={"User-Agent": "codex-mobile-envbuilder-source-verifier/1"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != EXPECTED_ARCHIVE_URL:
                raise VerificationError(
                    "EnvBuilder source download identity is invalid"
                )
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    declared = int(length)
                except ValueError as exc:
                    raise VerificationError(
                        "EnvBuilder source Content-Length is invalid"
                    ) from exc
                if declared <= 0 or declared > ARCHIVE_MAX_BYTES:
                    raise VerificationError(
                        "EnvBuilder source Content-Length is out of bounds"
                    )
            digest = hashlib.sha256()
            total = 0
            with destination.open("xb") as output:
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > ARCHIVE_MAX_BYTES:
                        raise VerificationError(
                            "EnvBuilder source download exceeded its size limit"
                        )
                    digest.update(chunk)
                    output.write(chunk)
            if total <= 0 or digest.hexdigest() != EXPECTED_ARCHIVE_SHA256:
                raise VerificationError("EnvBuilder source archive checksum is invalid")
    except (OSError, urllib.error.URLError) as exc:
        raise VerificationError("cannot download EnvBuilder source archive") from exc


def copy_offline_archive(source: Path, destination: Path) -> None:
    raw = read_regular_bytes(source, ARCHIVE_MAX_BYTES, "offline EnvBuilder archive")
    if hashlib.sha256(raw).hexdigest() != EXPECTED_ARCHIVE_SHA256:
        raise VerificationError("offline EnvBuilder archive checksum is invalid")
    destination.write_bytes(raw)


def safe_extract_archive(archive_path: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    seen: set[str] = set()
    total_size = 0
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) != EXPECTED_ARCHIVE_MEMBERS:
            raise VerificationError("EnvBuilder archive member count is invalid")
        for member in members:
            name = member.name
            if (
                not name
                or "\\" in name
                or "\x00" in name
                or name in seen
                or len(name.encode("utf-8")) > 4096
            ):
                raise VerificationError("EnvBuilder archive member name is invalid")
            seen.add(name)
            path = PurePosixPath(name)
            if (
                path.is_absolute()
                or not path.parts
                or path.parts[0] != EXPECTED_ROOT
                or any(part in {"", ".", ".."} for part in path.parts)
            ):
                raise VerificationError("EnvBuilder archive member escapes its root")
            if not (member.isdir() or member.isreg()):
                raise VerificationError("EnvBuilder archive contains a special member")
            if member.size < 0 or member.size > ARCHIVE_MEMBER_MAX_BYTES:
                raise VerificationError("EnvBuilder archive member size is invalid")
            total_size += member.size
            if total_size > ARCHIVE_TOTAL_MAX_BYTES:
                raise VerificationError("EnvBuilder archive expands beyond its limit")

        for member in members:
            relative_parts = PurePosixPath(member.name).parts[1:]
            if not relative_parts:
                continue
            target = destination.joinpath(*relative_parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=False)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise VerificationError("cannot read EnvBuilder archive member")
            with extracted, target.open("xb") as output:
                copy_bounded(extracted, output, member.size)
            target.chmod(member.mode & 0o777)

    license_bytes = read_regular_bytes(
        destination / "LICENSE", 64 * 1024, "EnvBuilder upstream license"
    )
    if hashlib.sha256(license_bytes).hexdigest() != EXPECTED_LICENSE_SHA256:
        raise VerificationError("EnvBuilder upstream license checksum is invalid")


def command_environment(work: Path) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", str(work)),
        "GOTOOLCHAIN": "local",
        "GOMAXPROCS": "2",
        "GOFLAGS": "-p=2",
        "GOMODCACHE": str(work / "go-mod-cache"),
        "GOTRACEBACK": "none",
        "LC_ALL": "C.UTF-8",
    }
    if os.name == "nt":
        environment["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    return environment


def run_command(
    argv: list[str],
    cwd: Path,
    environment: dict[str, str],
    *,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> str:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError(f"command failed to execute: {argv[0]}") from exc
    output = result.stdout + result.stderr
    if len(output) > COMMAND_OUTPUT_MAX_BYTES:
        raise VerificationError(f"command output exceeded its limit: {argv[0]}")
    stdout_text = result.stdout.decode("utf-8", errors="replace")
    combined_text = output.decode("utf-8", errors="replace")
    if result.returncode != 0:
        detail = combined_text[-8192:].strip()
        raise VerificationError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n{detail}"
        )
    return stdout_text


def elf_architecture(path: Path) -> str:
    with path.open("rb") as binary:
        header = binary.read(64)
        if (
            len(header) != 64
            or header[:4] != b"\x7fELF"
            or header[4] != 2
            or header[5] != 1
        ):
            raise VerificationError("EnvBuilder binary is not 64-bit little-endian ELF")
        machine = struct.unpack_from("<H", header, 18)[0]
        phoff = struct.unpack_from("<Q", header, 32)[0]
        phentsize = struct.unpack_from("<H", header, 54)[0]
        phnum = struct.unpack_from("<H", header, 56)[0]
        if phentsize < 56 or phnum > 256:
            raise VerificationError("EnvBuilder ELF program headers are invalid")
        binary.seek(phoff)
        for _ in range(phnum):
            program = binary.read(phentsize)
            if len(program) != phentsize:
                raise VerificationError("EnvBuilder ELF program header ended early")
            if struct.unpack_from("<I", program, 0)[0] == 3:
                raise VerificationError("EnvBuilder binary has a dynamic interpreter")
    architectures = {62: "amd64", 183: "arm64"}
    if machine not in architectures:
        raise VerificationError("EnvBuilder ELF architecture is unsupported")
    return architectures[machine]


def verify_binary(
    binary: Path,
    architecture: str,
    source: Path,
    environment: dict[str, str],
) -> str:
    if elf_architecture(binary) != architecture:
        raise VerificationError("EnvBuilder binary architecture does not match")
    raw = read_regular_bytes(binary, 128 * 1024 * 1024, "EnvBuilder binary")
    if EXPECTED_DERIVATIVE_VERSION.encode() not in raw:
        raise VerificationError("EnvBuilder binary version tag is missing")
    metadata = run_command(
        ["go", "version", "-m", str(binary)], source, environment, timeout=60
    )
    metadata_lines = metadata.splitlines()
    if not metadata_lines or not metadata_lines[0].endswith(f": {EXPECTED_GO_VERSION}"):
        raise VerificationError("EnvBuilder binary compiler version is invalid")
    for expected in (
        "\tpath\tgithub.com/coder/envbuilder/cmd/envbuilder",
        "\tbuild\tCGO_ENABLED=0",
        f"\tbuild\tGOARCH={architecture}",
        "\tbuild\tGOOS=linux",
    ):
        if expected not in metadata:
            raise VerificationError("EnvBuilder binary build metadata is invalid")
    if re.search(r"github\.com/coder/(?:coder|tailscale)|tailscale\.com", metadata):
        raise VerificationError("EnvBuilder binary retains a Coder runtime dependency")
    return hashlib.sha256(raw).hexdigest()


def apply_and_verify_source(source: Path, patch: Path, work: Path) -> None:
    environment = command_environment(work)
    if (
        run_command(["go", "env", "GOVERSION"], source, environment, timeout=60).strip()
        != EXPECTED_GO_VERSION
    ):
        raise VerificationError(
            f"EnvBuilder source verification requires {EXPECTED_GO_VERSION}"
        )
    run_command(["git", "init", "--quiet"], source, environment, timeout=60)
    run_command(["git", "add", "--all"], source, environment, timeout=60)
    run_command(
        [
            "git",
            "-c",
            "user.name=Codex Mobile source verifier",
            "-c",
            "user.email=source-verifier@invalid.example",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "--message=Exact EnvBuilder 1.3.0 upstream source",
        ],
        source,
        environment,
        timeout=60,
    )
    run_command(["git", "apply", "--check", "--index", str(patch)], source, environment)
    run_command(["git", "apply", "--index", str(patch)], source, environment)
    changed = run_command(
        ["git", "diff", "--cached", "--name-only", "--no-renames"],
        source,
        environment,
        timeout=60,
    ).splitlines()
    if tuple(sorted(changed)) != EXPECTED_PATCH_FILES:
        raise VerificationError("applied EnvBuilder patch changed unexpected files")
    run_command(["git", "diff", "--cached", "--check"], source, environment, timeout=60)
    run_command(["go", "mod", "tidy", "-diff"], source, environment)
    run_command(["go", "mod", "verify"], source, environment)
    package_output = run_command(
        ["go", "list", "-f", "{{.ImportPath}}", "./..."], source, environment
    )
    package_prefix = "github.com/coder/envbuilder"
    all_packages = tuple(line for line in package_output.splitlines() if line)
    if not all_packages or any(
        package != package_prefix and not package.startswith(package_prefix + "/")
        for package in all_packages
    ):
        raise VerificationError("EnvBuilder package inventory is invalid")
    registry_dependent_packages = {
        package_prefix + "/devcontainer",
        package_prefix + "/integration",
    }
    runtime_test_packages = tuple(
        package
        for package in all_packages
        if package not in registry_dependent_packages
    )
    if len(runtime_test_packages) + len(registry_dependent_packages) != len(
        all_packages
    ):
        raise VerificationError(
            "EnvBuilder registry-dependent package inventory is invalid"
        )
    run_command(["go", "vet", *all_packages], source, environment)
    run_command(["go", "test", "-count=1", *runtime_test_packages], source, environment)
    run_command(
        ["go", "test", "-race", "-count=1", "./log", "./cmd/envbuilder"],
        source,
        environment,
    )
    run_command(
        [
            "go",
            "test",
            "-c",
            "-o",
            str(work / "devcontainer.test"),
            "./devcontainer",
        ],
        source,
        environment,
    )
    run_command(
        [
            "go",
            "test",
            "-c",
            "-o",
            str(work / "integration.test"),
            "./integration",
        ],
        source,
        environment,
    )

    for architecture in ("amd64", "arm64"):
        digests: list[str] = []
        for build_number in (1, 2):
            binary = work / f"envbuilder-linux-{architecture}-{build_number}"
            build_environment = {
                **environment,
                "CGO_ENABLED": "0",
                "GOOS": "linux",
                "GOARCH": architecture,
                "GOCACHE": str(work / f"go-build-{architecture}-{build_number}"),
            }
            run_command(
                [
                    "go",
                    "build",
                    "-mod=readonly",
                    "-trimpath",
                    "-buildvcs=false",
                    (
                        "-ldflags=-s -w -X "
                        "github.com/coder/envbuilder/buildinfo.tag="
                        + EXPECTED_DERIVATIVE_VERSION
                    ),
                    "-o",
                    str(binary),
                    "./cmd/envbuilder",
                ],
                source,
                build_environment,
            )
            digests.append(
                verify_binary(binary, architecture, source, build_environment)
            )
        if digests[0] != digests[1]:
            raise VerificationError(
                f"EnvBuilder {architecture} clean builds are not reproducible"
            )
        print(f"EnvBuilder {architecture} binary SHA-256: {digests[0]}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    try:
        root = args.repo_root.resolve(strict=True)
        _, patch = load_and_validate_lock(root)
        if args.static_only:
            print("EnvBuilder source lock and patch verified")
            return 0
        if os.name == "nt":
            raise VerificationError(
                "full EnvBuilder source verification requires a Linux host"
            )
        with tempfile.TemporaryDirectory(
            prefix="codex-mobile-envbuilder-source."
        ) as raw:
            work = Path(raw)
            archive_path = work / "envbuilder.tar.gz"
            if args.archive:
                copy_offline_archive(args.archive.resolve(strict=True), archive_path)
            else:
                download_archive(archive_path)
            source = work / "source"
            safe_extract_archive(archive_path, source)
            apply_and_verify_source(source, patch, work)
        print("EnvBuilder source derivative verified")
        return 0
    except (
        VerificationError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        tarfile.TarError,
    ) as exc:
        print(f"EnvBuilder source verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
