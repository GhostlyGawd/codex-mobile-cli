#!/usr/bin/env python3
"""Serialize the single quota-backed workspace volume on the owner PC.

Podman versions used by the owner-PC beta can assign the same XFS project ID to
more than one named volume. Creating a second quota-backed volume can therefore
change the first volume's quota. This gate records the one permitted workspace
identity before its volume is created and validates every local Podman volume
while holding a stable advisory lock.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import json
import os
import re
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, NamedTuple

try:
    import fcntl
except ImportError:  # pragma: no cover - the production host is Linux.
    fcntl = None  # type: ignore[assignment]

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - the production host is Linux.
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


GATE_DIRECTORY = Path("/srv/codex-mobile/workspaces/.owner-pc-volume-gate")
STATE_DIRECTORY_NAME = "state"
LOCK_FILE_NAME = "gate.lock"
LEASE_FILE_NAME = "lease.json"
LEASE_SCHEMA_VERSION = 1
PROFILE = "owner_pc_beta"
VOLUME_PREFIX = "cm-workspace-v2-"
PODMAN = "/usr/bin/podman"
PODMAN_SOCKET = "unix:///run/codex-mobile-podman/podman.sock"
NETWORK_CONFIG_DIRECTORY = "/srv/codex-mobile/workspaces/.networks"
XFS_QUOTA = "/usr/sbin/xfs_quota"
WORKSPACE_STORAGE_MOUNT = "/srv/codex-mobile"
PHYSICAL_VOLUMES_DIRECTORY = Path("/srv/codex-mobile/workspaces/.containers/volumes")
BACKING_FS_BLOCK_DEVICE_NAME = "backingFsBlockDev"
BACKING_FS_BLOCK_DEVICE_TEMP_NAME = f"{BACKING_FS_BLOCK_DEVICE_NAME}.tmp"
MAX_COMMAND_OUTPUT = 512 * 1024
MAX_XFS_QUOTA_OUTPUT = 64 * 1024
MAX_LEASE_BYTES = 4096
MAX_VOLUMES = 1024
PODMAN_TIMEOUT_SECONDS = 15
XFS_QUOTA_TIMEOUT_SECONDS = 10
LOCK_TIMEOUT_SECONDS = 10

UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)
WORKSPACE_NAME_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?")
VOLUME_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
SIZE_PATTERN = re.compile(r"[1-9][0-9]*(?:[kKmMgGtTpPeE](?:[iI]?[bB])?)?")
INODE_PATTERN = re.compile(r"[1-9][0-9]*")

MANAGED_LABEL = "com.codex-mobile.managed"
PROFILE_LABEL = "com.codex-mobile.profile"
ROLE_LABEL = "com.codex-mobile.volume-role"
WORKSPACE_ID_LABEL = "com.codex-mobile.workspace-id"
WORKSPACE_NAME_LABEL = "com.codex-mobile.workspace-name"
WORKSPACE_DATA_ROLE = "workspace-data"
CPU_LABEL = "com.codex-mobile.cpu-millis"
DISK_BUDGET_LABEL = "com.codex-mobile.disk-budget"
MEMORY_LABEL = "com.codex-mobile.memory-mib"
PIDS_LABEL = "com.codex-mobile.pids-limit"
OWNER_CPU_MILLIS = "2000"
OWNER_MEMORY_MIB = "2048"
OWNER_PIDS_LIMIT = "512"
OWNER_INODE_LIMIT = 1048576
GIBIBYTE = 1024**3
MIN_OWNER_DISK_BYTES = 8 * GIBIBYTE
MAX_OWNER_DISK_BYTES = 16 * GIBIBYTE
FS_XATTR_FORMAT = "=5I8s"
FS_IOC_FSGETXATTR = 0x801C581F


class GateError(RuntimeError):
    """A fail-closed owner-PC volume-gate error."""


def process_effective_uid() -> int:
    getter = getattr(os, "geteuid", None)
    return -1 if getter is None else getter()


class Lease(NamedTuple):
    workspace_id: str
    workspace_name: str
    volume_name: str

    def document(self) -> dict[str, object]:
        return {
            "schema_version": LEASE_SCHEMA_VERSION,
            "workspace_id": self.workspace_id,
            "workspace_name": self.workspace_name,
            "volume_name": self.volume_name,
        }


class CommandResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


class PhysicalVolume(NamedTuple):
    name: str
    project_id: int


class PhysicalQuota(NamedTuple):
    block_soft_kib: int
    block_hard_kib: int
    inode_soft: int
    inode_hard: int


def workspace_lease(workspace_id: str, workspace_name: str) -> Lease:
    """Validate a workspace identity and derive its one canonical volume name."""
    if not isinstance(workspace_id, str) or not UUID_PATTERN.fullmatch(workspace_id):
        raise GateError("workspace ID must be a canonical lowercase UUID")
    try:
        parsed = uuid.UUID(workspace_id)
    except ValueError as exc:
        raise GateError("workspace ID must be a canonical lowercase UUID") from exc
    if str(parsed) != workspace_id or parsed.int == 0:
        raise GateError("workspace ID must be a non-nil canonical lowercase UUID")
    if not isinstance(workspace_name, str) or not WORKSPACE_NAME_PATTERN.fullmatch(
        workspace_name
    ):
        raise GateError("workspace name must be 1-128 safe ASCII label characters")
    workspace_key = workspace_id.replace("-", "")[:24]
    return Lease(
        workspace_id=workspace_id,
        workspace_name=workspace_name,
        volume_name=f"{VOLUME_PREFIX}{workspace_key}",
    )


def read_xfs_project_id(path: Path) -> int:
    """Read a directory's XFS project ID without invoking a shell command."""
    if fcntl is None:
        raise GateError("fcntl ioctl support is required for the physical scan")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise GateError("cannot open a physical Podman volume data directory") from exc
    try:
        metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != path_metadata.st_dev
            or metadata.st_ino != path_metadata.st_ino
        ):
            raise GateError("physical Podman volume data path changed during scan")
        attributes = bytearray(struct.calcsize(FS_XATTR_FORMAT))
        try:
            fcntl.ioctl(descriptor, FS_IOC_FSGETXATTR, attributes, True)
        except OSError as exc:
            raise GateError(
                "cannot read an XFS project ID from a Podman volume"
            ) from exc
    finally:
        os.close(descriptor)
    project_id = struct.unpack(FS_XATTR_FORMAT, attributes)[3]
    if not isinstance(project_id, int) or project_id < 0:
        raise GateError("physical Podman volume has an invalid XFS project ID")
    return project_id


class PhysicalVolumeSource:
    """Scan each immediate Podman volume data directory from the root host."""

    def __init__(
        self,
        *,
        volumes_directory: Path = PHYSICAL_VOLUMES_DIRECTORY,
        project_id_reader: Callable[[Path], int] = read_xfs_project_id,
        root_uid: int = 0,
        root_gid: int = 0,
        backing_device_gid: int | None = None,
    ) -> None:
        self.volumes_directory = volumes_directory
        self.project_id_reader = project_id_reader
        self.root_uid = root_uid
        self.root_gid = root_gid
        self.backing_device_gid = (
            root_gid if backing_device_gid is None else backing_device_gid
        )

    def __call__(self) -> list[PhysicalVolume]:
        try:
            root_metadata = self.volumes_directory.lstat()
        except OSError as exc:
            raise GateError("physical Podman volume root is unavailable") from exc
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != self.root_uid
            or root_metadata.st_gid != self.root_gid
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise GateError("physical Podman volume root ownership or mode drifted")
        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(self.volumes_directory) as scanner:
                for entry in scanner:
                    entries.append(entry)
                    if len(entries) > MAX_VOLUMES + 1:
                        raise GateError(
                            "physical Podman volume root has too many entries"
                        )
        except OSError as exc:
            raise GateError("cannot enumerate physical Podman volumes") from exc

        volumes: list[PhysicalVolume] = []
        backing_device_found = False
        for entry in sorted(entries, key=lambda candidate: candidate.name):
            if entry.name == BACKING_FS_BLOCK_DEVICE_TEMP_NAME:
                raise GateError("temporary Podman quota backing-device residue exists")
            if entry.name == BACKING_FS_BLOCK_DEVICE_NAME:
                try:
                    device_metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise GateError(
                        "cannot inspect the Podman quota backing device"
                    ) from exc
                if (
                    not stat.S_ISBLK(device_metadata.st_mode)
                    or stat.S_IMODE(device_metadata.st_mode) != 0o600
                    or device_metadata.st_uid != self.root_uid
                    or device_metadata.st_gid != self.backing_device_gid
                    or device_metadata.st_dev != root_metadata.st_dev
                    or device_metadata.st_rdev != root_metadata.st_dev
                ):
                    raise GateError(
                        "Podman quota backing-device ownership, mode, or "
                        "device number drifted"
                    )
                backing_device_found = True
                continue
            if not VOLUME_NAME_PATTERN.fullmatch(entry.name):
                raise GateError("physical Podman volume name is invalid")
            if len(volumes) >= MAX_VOLUMES:
                raise GateError("more than 1024 physical Podman volumes exist")
            try:
                volume_metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise GateError(
                    "cannot inspect a physical Podman volume directory"
                ) from exc
            if (
                not stat.S_ISDIR(volume_metadata.st_mode)
                or volume_metadata.st_uid != self.root_uid
                or volume_metadata.st_gid != self.root_gid
                or stat.S_IMODE(volume_metadata.st_mode) != 0o700
                or volume_metadata.st_dev != root_metadata.st_dev
            ):
                raise GateError(
                    "physical Podman volume directory ownership or mode drifted"
                )
            volume_path = Path(entry.path)
            children: list[os.DirEntry[str]] = []
            try:
                with os.scandir(volume_path) as scanner:
                    for child in scanner:
                        children.append(child)
                        if len(children) > 1:
                            raise GateError(
                                "physical Podman volume has unexpected "
                                "immediate children"
                            )
            except OSError as exc:
                raise GateError(
                    "cannot enumerate a physical Podman volume directory"
                ) from exc
            if len(children) != 1 or children[0].name != "_data":
                raise GateError(
                    "physical Podman volume has unexpected immediate children"
                )
            data_entry = children[0]
            try:
                data_metadata = data_entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise GateError(
                    "cannot inspect a physical Podman volume data directory"
                ) from exc
            if (
                not stat.S_ISDIR(data_metadata.st_mode)
                or data_metadata.st_dev != root_metadata.st_dev
            ):
                raise GateError("physical Podman volume data path is unsafe")
            project_id = self.project_id_reader(Path(data_entry.path))
            if type(project_id) is not int or project_id < 0 or project_id > 0xFFFFFFFF:
                raise GateError("physical Podman volume has an invalid XFS project ID")
            volumes.append(PhysicalVolume(entry.name, project_id))
        if (
            any(volume.project_id != 0 for volume in volumes)
            and not backing_device_found
        ):
            raise GateError(
                "a quota-backed physical Podman volume has no backing device"
            )
        return volumes


def _add_quota_option(
    found: dict[str, str], key: str, value: object, source: str
) -> None:
    if not isinstance(value, str) or not value:
        raise GateError(f"{source} quota option {key!r} has an invalid value")
    validator = SIZE_PATTERN if key == "size" else INODE_PATTERN
    if not validator.fullmatch(value):
        raise GateError(f"{source} quota option {key!r} has an invalid value")
    if key in found:
        raise GateError(f"{source} declares quota option {key!r} more than once")
    found[key] = value


def quota_options(options: object, source: str = "volume") -> dict[str, str]:
    """Return validated size/inodes options from direct keys and mount option o."""
    if options is None:
        return {}
    if not isinstance(options, dict):
        raise GateError(f"{source} options must be a JSON object")

    found: dict[str, str] = {}
    direct: dict[str, str] = {}
    engine_mirrors: dict[str, str] = {}
    for raw_key, value in options.items():
        if not isinstance(raw_key, str):
            raise GateError(f"{source} option names must be strings")
        lower_key = raw_key.lower()
        if lower_key in ("size", "inodes"):
            if raw_key in ("SIZE", "INODES"):
                _add_quota_option(engine_mirrors, lower_key, value, source)
            elif raw_key != lower_key:
                raise GateError(f"{source} quota option {raw_key!r} is not canonical")
            else:
                _add_quota_option(found, raw_key, value, source)
                direct[raw_key] = found[raw_key]

    mount_quota: dict[str, str] = {}
    if "o" in options:
        raw_mount_options = options["o"]
        if not isinstance(raw_mount_options, str):
            raise GateError(f"{source} option 'o' must be a string")
        if raw_mount_options:
            for raw_token in raw_mount_options.split(","):
                token = raw_token.strip()
                if not token:
                    raise GateError(f"{source} option 'o' contains an empty token")
                key, separator, value = token.partition("=")
                lower_key = key.lower()
                if lower_key not in ("size", "inodes"):
                    continue
                if key != lower_key or separator != "=" or not value:
                    raise GateError(
                        f"{source} option 'o' contains a malformed quota token"
                    )
                _add_quota_option(found, key, value, source)
                mount_quota[key] = found[key]

    if engine_mirrors:
        if direct:
            raise GateError(
                f"{source} mixes engine quota mirrors with direct quota options"
            )
        if engine_mirrors != mount_quota:
            raise GateError(
                f"{source} engine quota mirrors do not exactly match option 'o'"
            )
    return found


def fixed_podman_environment(*, remote: bool) -> dict[str, str]:
    """Return the complete, non-inherited environment for Podman inspection."""
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    if remote:
        environment["HOME"] = "/srv/codex-mobile/workspaces/.provisioner-home"
    else:
        environment.update(
            {
                "CONTAINERS_CONF": "/etc/codex-mobile/containers.conf",
                "CONTAINERS_STORAGE_CONF": (
                    "/etc/codex-mobile/containers-storage.conf"
                ),
                "HOME": "/srv/codex-mobile/workspaces/.runtime-home",
                "XDG_RUNTIME_DIR": "/run/codex-mobile-podman",
            }
        )
    return environment


def run_bounded_command(
    command: list[str],
    *,
    timeout: float,
    max_output: int,
    env: dict[str, str],
    cwd: str,
) -> CommandResult:
    """Run a fixed command while capping aggregate stdout/stderr in memory."""
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise GateError("cannot start dedicated Podman volume inspection") from exc
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise GateError("cannot capture dedicated Podman volume inspection")

    output = {"stdout": bytearray(), "stderr": bytearray()}
    output_lock = threading.Lock()
    output_changed = threading.Condition(output_lock)
    output_exceeded = [False]

    def read_stream(name: str, stream: BinaryIO) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                with output_changed:
                    consumed = len(output["stdout"]) + len(output["stderr"])
                    remaining = max_output + 1 - consumed
                    if remaining > 0:
                        output[name].extend(chunk[:remaining])
                    if len(output["stdout"]) + len(output["stderr"]) > max_output:
                        output_exceeded[0] = True
                        output_changed.notify_all()
                        return
        except (OSError, ValueError):
            return

    readers = [
        threading.Thread(
            target=read_stream,
            args=("stdout", process.stdout),
            daemon=True,
        ),
        threading.Thread(
            target=read_stream,
            args=("stderr", process.stderr),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout
    timed_out = False
    while process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            process.kill()
            break
        with output_changed:
            if output_exceeded[0]:
                process.kill()
                break
            output_changed.wait(min(0.05, remaining))
    termination_cause: subprocess.TimeoutExpired | None = None
    try:
        returncode = process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            returncode = process.wait(timeout=2)
        except subprocess.TimeoutExpired as exc:
            termination_cause = exc
            returncode = -1
    for reader in readers:
        reader.join(timeout=2)
    readers_alive = any(reader.is_alive() for reader in readers)
    process.stdout.close()
    process.stderr.close()
    if termination_cause is not None:
        raise GateError(
            "dedicated Podman inspection would not terminate"
        ) from termination_cause
    if readers_alive:
        raise GateError("dedicated Podman output reader would not terminate")
    if timed_out:
        raise GateError("dedicated Podman volume inspection timed out")
    if output_exceeded[0]:
        raise GateError("Podman volume inspection output exceeded 512 KiB")
    try:
        stdout = output["stdout"].decode("utf-8")
        stderr = output["stderr"].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateError("Podman volume inspection returned invalid UTF-8") from exc
    return CommandResult(returncode, stdout, stderr)


class XFSQuotaSource:
    """Read exact active XFS project limits through bounded fixed commands."""

    def __init__(
        self,
        run: Callable[..., CommandResult] = run_bounded_command,
    ) -> None:
        self._run = run

    def __call__(self, project_id: int) -> PhysicalQuota:
        if type(project_id) is not int or project_id <= 0 or project_id > 0xFFFFFFFF:
            raise GateError("XFS project ID is invalid for quota inspection")

        limits: dict[str, tuple[int, int]] = {}
        for quota_flag in ("-b", "-i"):
            command = [
                XFS_QUOTA,
                "-x",
                "-c",
                f"quota -p {quota_flag} -n -N -v {project_id}",
                WORKSPACE_STORAGE_MOUNT,
            ]
            try:
                result = self._run(
                    command,
                    timeout=XFS_QUOTA_TIMEOUT_SECONDS,
                    max_output=MAX_XFS_QUOTA_OUTPUT,
                    env={
                        "LANG": "C",
                        "LC_ALL": "C",
                        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    },
                    cwd="/",
                )
            except (GateError, OSError, subprocess.TimeoutExpired) as exc:
                raise GateError("cannot query the active XFS project quota") from exc
            if (
                not isinstance(result, CommandResult)
                or type(result.returncode) is not int
                or not isinstance(result.stdout, str)
                or not isinstance(result.stderr, str)
            ):
                raise GateError("XFS project quota query returned an invalid result")
            if (
                len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8"))
                > MAX_XFS_QUOTA_OUTPUT
            ):
                raise GateError("XFS project quota output exceeded 64 KiB")
            if result.returncode != 0 or result.stderr:
                raise GateError("XFS project quota query failed")

            lines = result.stdout.splitlines()
            fields = lines[0].split() if len(lines) == 1 else []
            numeric_fields = fields[1:4] if len(fields) == 7 else []
            if (
                len(fields) != 7
                or re.fullmatch(r"/dev/[A-Za-z0-9._/+:-]{1,240}", fields[0]) is None
                or fields[-1] != WORKSPACE_STORAGE_MOUNT
                or any(
                    len(value) > 20 or re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None
                    for value in numeric_fields
                )
            ):
                raise GateError("XFS project quota query returned a malformed record")
            limits[quota_flag] = (int(fields[2]), int(fields[3]))

        return PhysicalQuota(
            block_soft_kib=limits["-b"][0],
            block_hard_kib=limits["-b"][1],
            inode_soft=limits["-i"][0],
            inode_hard=limits["-i"][1],
        )


class PodmanVolumeSource:
    """Read every volume from the dedicated Podman engine."""

    def __init__(
        self,
        run: Callable[..., CommandResult] = run_bounded_command,
        effective_uid: Callable[[], int] = process_effective_uid,
    ) -> None:
        self._run = run
        self._effective_uid = effective_uid

    def __call__(self) -> list[object]:
        remote = self._effective_uid() != 0
        if not remote:
            command = [
                PODMAN,
                f"--network-config-dir={NETWORK_CONFIG_DIRECTORY}",
                "volume",
                "inspect",
                "--all",
            ]
        else:
            command = [
                PODMAN,
                "--remote",
                f"--url={PODMAN_SOCKET}",
                "volume",
                "inspect",
                "--all",
            ]
        try:
            result = self._run(
                command,
                timeout=PODMAN_TIMEOUT_SECONDS,
                max_output=MAX_COMMAND_OUTPUT,
                env=fixed_podman_environment(remote=remote),
                cwd="/",
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GateError("cannot enumerate the dedicated Podman volumes") from exc
        if not isinstance(result.stdout, str) or not isinstance(result.stderr, str):
            raise GateError("Podman volume inspection returned non-text output")
        if (
            len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8"))
            > MAX_COMMAND_OUTPUT
        ):
            raise GateError("Podman volume inspection output exceeded 512 KiB")
        if result.returncode != 0:
            raise GateError(
                f"Podman volume inspection failed with exit status {result.returncode}"
            )
        try:
            document = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise GateError("Podman returned malformed volume inspection JSON") from exc
        if not isinstance(document, list):
            raise GateError("Podman volume inspection must return a JSON array")
        if len(document) > MAX_VOLUMES:
            raise GateError("Podman returned more than 1024 local volumes")
        return document


class VolumeGate:
    """Filesystem lease plus whole-engine quota-volume validation."""

    def __init__(
        self,
        *,
        gate_directory: Path = GATE_DIRECTORY,
        volume_source: Callable[[], list[object]] | None = None,
        physical_volume_source: Callable[[], list[PhysicalVolume]] | None = None,
        physical_quota_source: Callable[[int], PhysicalQuota] | None = None,
        root_uid: int = 0,
        workspace_root_gid: int = 0,
        workspace_root_mode: int = 0o711,
        provisioner_uid: int | None = None,
        provisioner_gid: int | None = None,
        effective_uid: Callable[[], int] = process_effective_uid,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        lock_timeout: float = LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self.gate_directory = gate_directory
        self.state_directory = gate_directory / STATE_DIRECTORY_NAME
        self.lock_path = gate_directory / LOCK_FILE_NAME
        self.lease_path = self.state_directory / LEASE_FILE_NAME
        self.root_uid = root_uid
        self.workspace_root_gid = workspace_root_gid
        self.workspace_root_mode = workspace_root_mode
        if provisioner_uid is None:
            if pwd is None:
                raise GateError("POSIX account lookup support is required")
            provisioner_uid = pwd.getpwnam("coder-provisioner").pw_uid
        if provisioner_gid is None:
            if grp is None:
                raise GateError("POSIX group lookup support is required")
            provisioner_gid = grp.getgrnam("coder-provisioner").gr_gid
        self.provisioner_uid = provisioner_uid
        self.provisioner_gid = provisioner_gid
        self.volume_source = volume_source or PodmanVolumeSource(
            effective_uid=effective_uid
        )
        self.physical_volume_source = physical_volume_source or PhysicalVolumeSource(
            root_uid=root_uid,
            root_gid=workspace_root_gid,
            backing_device_gid=provisioner_gid,
        )
        self.physical_quota_source = physical_quota_source or XFSQuotaSource()
        self.effective_uid = effective_uid
        self.monotonic = monotonic
        self.sleep = sleep
        self.lock_timeout = lock_timeout

    def initialize(self) -> dict[str, object]:
        """Create root-owned gate primitives, then validate existing state."""
        if self.effective_uid() != self.root_uid:
            raise GateError("only root may initialize the owner-PC volume gate")
        parent = self.gate_directory.parent
        self._validate_parent(parent)
        self._create_or_validate_directory(self.gate_directory, 0o750, self.root_uid)
        self._create_or_validate_directory(self.state_directory, 0o2770, self.root_uid)
        self._create_or_validate_lock()
        with self._locked():
            return self._inspect_locked(physical=True)

    def claim(self, workspace_id: str, workspace_name: str) -> dict[str, object]:
        """Atomically claim the sole quota-volume identity."""
        expected = workspace_lease(workspace_id, workspace_name)
        self._validate_caller()
        with self._locked():
            existing_lease = self._load_lease()
            state = self._inspect_locked(existing_lease)
            if existing_lease is not None:
                if existing_lease != expected:
                    raise GateError(
                        "the owner-PC quota-volume lease is held by another workspace"
                    )
                return {**state, "action": "unchanged"}
            self._write_lease(expected)
            return {
                **self._inspect_locked(expected),
                "action": "claimed",
            }

    def release(self, workspace_id: str, workspace_name: str) -> dict[str, object]:
        """Release only a matching lease whose quota volume is already absent."""
        expected = workspace_lease(workspace_id, workspace_name)
        self._validate_caller()
        with self._locked():
            existing_lease = self._load_lease()
            state = self._inspect_locked(existing_lease)
            if existing_lease is None:
                raise GateError("the owner-PC quota-volume lease is absent")
            if existing_lease != expected:
                raise GateError(
                    "the owner-PC quota-volume lease belongs to another workspace"
                )
            if state["quota_volume_count"] != 0:
                raise GateError(
                    "the matching quota volume must be absent before release"
                )
            self._remove_lease()
            return {
                **self._inspect_locked(None),
                "action": "released",
            }

    def status(self) -> dict[str, object]:
        """Return validated lease and quota-volume state."""
        self._validate_caller()
        with self._locked():
            return self._inspect_locked()

    def verify(self) -> dict[str, object]:
        """Root-only startup check including physical XFS project IDs."""
        if self.effective_uid() != self.root_uid:
            raise GateError(
                "only root may run the physical owner-PC volume verification"
            )
        with self._locked():
            return self._inspect_locked(physical=True)

    def _validate_caller(self) -> None:
        if self.effective_uid() not in (self.root_uid, self.provisioner_uid):
            raise GateError(
                "only root or coder-provisioner may use the owner-PC volume gate"
            )

    def _validate_parent(self, path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise GateError("workspace storage directory is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise GateError("workspace storage path is not a directory")
        if metadata.st_uid != self.root_uid:
            raise GateError("workspace storage directory has an unexpected owner")
        if metadata.st_gid != self.workspace_root_gid:
            raise GateError("workspace storage directory has an unexpected group")
        if stat.S_IMODE(metadata.st_mode) != self.workspace_root_mode:
            raise GateError("workspace storage directory has an unexpected mode")

    def _create_or_validate_directory(
        self, path: Path, mode: int, owner_uid: int
    ) -> None:
        try:
            os.mkdir(path, mode)
        except FileExistsError:
            pass
        except OSError as exc:
            raise GateError(
                f"cannot create protected gate directory {path.name}"
            ) from exc
        else:
            try:
                os.chown(path, owner_uid, self.provisioner_gid)
                os.chmod(path, mode)
            except OSError as exc:
                raise GateError(
                    f"cannot secure protected gate directory {path.name}"
                ) from exc
        self._validate_directory(path, mode, owner_uid)

    def _validate_directory(self, path: Path, mode: int, owner_uid: int) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise GateError(f"protected gate directory {path.name} is missing") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_gid != self.provisioner_gid
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise GateError(
                f"protected gate directory {path.name} ownership or mode drifted"
            )

    def _create_or_validate_lock(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.lock_path, flags, 0o660)
        except FileExistsError:
            descriptor = -1
        except OSError as exc:
            raise GateError("cannot create the stable volume-gate lock") from exc
        if descriptor >= 0:
            try:
                os.fchown(descriptor, self.root_uid, self.provisioner_gid)
                os.fchmod(descriptor, 0o660)
                os.fsync(descriptor)
            except OSError as exc:
                raise GateError("cannot secure the stable volume-gate lock") from exc
            finally:
                os.close(descriptor)
            self._fsync_directory(self.gate_directory)
        descriptor = self._open_validated_lock()
        os.close(descriptor)

    def _open_validated_lock(self) -> int:
        flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.lock_path, flags)
        except OSError as exc:
            raise GateError("stable volume-gate lock is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            path_metadata = self.lock_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != self.root_uid
                or metadata.st_gid != self.provisioner_gid
                or stat.S_IMODE(metadata.st_mode) != 0o660
                or metadata.st_dev != path_metadata.st_dev
                or metadata.st_ino != path_metadata.st_ino
            ):
                raise GateError("stable volume-gate lock ownership or mode drifted")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        if fcntl is None:
            raise GateError("fcntl flock support is required")
        self._validate_directory(self.gate_directory, 0o750, self.root_uid)
        self._validate_directory(self.state_directory, 0o2770, self.root_uid)
        descriptor = self._open_validated_lock()
        deadline = self.monotonic() + self.lock_timeout
        try:
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN):
                        raise GateError(
                            "cannot acquire the stable volume-gate lock"
                        ) from exc
                    remaining = deadline - self.monotonic()
                    if remaining <= 0:
                        raise GateError(
                            "timed out acquiring the stable volume-gate lock"
                        ) from exc
                    self.sleep(min(0.05, remaining))
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _load_lease(self) -> Lease | None:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.lease_path, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise GateError("cannot open the owner-PC quota-volume lease") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != self.provisioner_uid
                or metadata.st_gid != self.provisioner_gid
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > MAX_LEASE_BYTES
            ):
                raise GateError("owner-PC quota-volume lease ownership or mode drifted")
            with os.fdopen(descriptor, "rb", closefd=False) as lease_file:
                payload = lease_file.read(MAX_LEASE_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(payload) > MAX_LEASE_BYTES:
            raise GateError("owner-PC quota-volume lease exceeds 4 KiB")
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GateError("owner-PC quota-volume lease is malformed JSON") from exc
        expected_keys = (
            "schema_version",
            "workspace_id",
            "workspace_name",
            "volume_name",
        )
        if (
            not isinstance(document, dict)
            or len(document) != len(expected_keys)
            or any(key not in document for key in expected_keys)
        ):
            raise GateError("owner-PC quota-volume lease schema is invalid")
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != LEASE_SCHEMA_VERSION
        ):
            raise GateError("owner-PC quota-volume lease version is unsupported")
        workspace_id = document["workspace_id"]
        workspace_name = document["workspace_name"]
        volume_name = document["volume_name"]
        if not all(
            isinstance(value, str)
            for value in (workspace_id, workspace_name, volume_name)
        ):
            raise GateError("owner-PC quota-volume lease identity is invalid")
        expected = workspace_lease(workspace_id, workspace_name)
        if volume_name != expected.volume_name:
            raise GateError("owner-PC quota-volume lease name is not canonical")
        return expected

    def _write_lease(self, lease: Lease) -> None:
        encoded = (
            json.dumps(
                lease.document(),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        if len(encoded) > MAX_LEASE_BYTES:
            raise GateError("owner-PC quota-volume lease exceeds 4 KiB")
        temporary = self.state_directory / (
            f".lease.{os.getpid()}.{time.time_ns()}.tmp"
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = -1
        try:
            descriptor = os.open(temporary, flags, 0o600)
            if self.effective_uid() == self.root_uid:
                os.fchown(
                    descriptor,
                    self.provisioner_uid,
                    self.provisioner_gid,
                )
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise GateError("cannot write the owner-PC quota-volume lease")
                offset += written
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                metadata.st_uid != self.provisioner_uid
                or metadata.st_gid != self.provisioner_gid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise GateError("new owner-PC quota-volume lease ownership is invalid")
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, self.lease_path)
            self._fsync_directory(self.state_directory)
        except OSError as exc:
            raise GateError("cannot atomically store the quota-volume lease") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _remove_lease(self) -> None:
        try:
            self.lease_path.unlink()
            self._fsync_directory(self.state_directory)
        except OSError as exc:
            raise GateError("cannot remove the owner-PC quota-volume lease") from exc

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | os.O_CLOEXEC
        flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _inspect_locked(
        self,
        lease: Lease | None | object = ...,
        *,
        physical: bool = False,
    ) -> dict[str, object]:
        lease_state = self._load_lease() if lease is ... else lease
        if lease_state is not None and not isinstance(lease_state, Lease):
            raise GateError("internal owner-PC quota-volume lease is invalid")
        records = self.volume_source()
        if not isinstance(records, list):
            raise GateError("Podman volume source did not return a list")

        seen_names: dict[str, None] = {}
        quota_records: list[
            tuple[dict[str, object], dict[str, str], dict[str, object]]
        ] = []
        for index, raw_record in enumerate(records):
            source = f"Podman volume record {index + 1}"
            if not isinstance(raw_record, dict):
                raise GateError(f"{source} is not a JSON object")
            record = raw_record
            name = record["Name"] if "Name" in record else None
            if not isinstance(name, str) or not VOLUME_NAME_PATTERN.fullmatch(name):
                raise GateError(f"{source} has an invalid local volume name")
            if name in seen_names:
                raise GateError("Podman returned a duplicate local volume name")
            seen_names[name] = None
            options = quota_options(
                record["Options"] if "Options" in record else None,
                source,
            )
            raw_labels = record["Labels"] if "Labels" in record else None
            if raw_labels is None:
                labels: dict[str, object] = {}
            elif isinstance(raw_labels, dict):
                labels = raw_labels
            else:
                raise GateError(f"{source} labels must be a JSON object")
            looks_managed = name.startswith(VOLUME_PREFIX) or (
                ROLE_LABEL in labels and labels[ROLE_LABEL] == WORKSPACE_DATA_ROLE
            )
            if looks_managed and not options:
                raise GateError("a workspace-data volume exists without quota options")
            if options:
                quota_records.append((record, options, labels))

        if len(quota_records) > 1:
            raise GateError("more than one local Podman volume has quota options")
        if lease_state is None:
            if quota_records:
                raise GateError("a quota-backed Podman volume exists without a lease")
            return self._finish_state(
                {
                    "lease": None,
                    "quota_volume": None,
                    "quota_volume_count": 0,
                    "state": "idle",
                },
                lease_state,
                quota_records,
                physical=physical,
            )
        if not quota_records:
            return self._finish_state(
                {
                    "lease": lease_state.document(),
                    "quota_volume": None,
                    "quota_volume_count": 0,
                    "state": "claimed",
                },
                lease_state,
                quota_records,
                physical=physical,
            )

        record, options, labels = quota_records[0]
        if "size" not in options:
            raise GateError("the workspace-data volume lacks a byte quota")
        if tuple(options) != ("size",):
            raise GateError("the owner-PC workspace volume must have only a byte quota")
        try:
            disk_bytes = int(options["size"])
        except ValueError as exc:
            raise GateError(
                "the owner-PC workspace byte quota must be canonical bytes"
            ) from exc
        if (
            str(disk_bytes) != options["size"]
            or disk_bytes % GIBIBYTE != 0
            or disk_bytes < MIN_OWNER_DISK_BYTES
            or disk_bytes > MAX_OWNER_DISK_BYTES
        ):
            raise GateError("the owner-PC workspace byte quota must be 8-16 whole GiB")
        expected_labels = {
            MANAGED_LABEL: "true",
            PROFILE_LABEL: PROFILE,
            ROLE_LABEL: WORKSPACE_DATA_ROLE,
            WORKSPACE_ID_LABEL: lease_state.workspace_id,
            WORKSPACE_NAME_LABEL: lease_state.workspace_name,
            CPU_LABEL: OWNER_CPU_MILLIS,
            DISK_BUDGET_LABEL: options["size"],
            MEMORY_LABEL: OWNER_MEMORY_MIB,
            PIDS_LABEL: OWNER_PIDS_LIMIT,
        }
        failures = [
            label
            for label, expected_value in expected_labels.items()
            if label not in labels or labels[label] != expected_value
        ]
        if len(labels) != len(expected_labels) or any(
            label not in expected_labels for label in labels
        ):
            failures.append("label schema")
        if "Name" not in record or record["Name"] != lease_state.volume_name:
            failures.append("volume name")
        if "Driver" not in record or record["Driver"] != "local":
            failures.append("volume driver")
        if "Scope" not in record or record["Scope"] != "local":
            failures.append("volume scope")
        if failures:
            raise GateError(
                "quota-backed Podman volume does not match its lease: "
                + ", ".join(failures)
            )
        return self._finish_state(
            {
                "lease": lease_state.document(),
                "quota_volume": lease_state.volume_name,
                "quota_volume_count": 1,
                "state": "active",
            },
            lease_state,
            quota_records,
            physical=physical,
        )

    def _finish_state(
        self,
        result: dict[str, object],
        lease: Lease | None,
        quota_records: list[
            tuple[dict[str, object], dict[str, str], dict[str, object]]
        ],
        *,
        physical: bool,
    ) -> dict[str, object]:
        if not physical:
            return result
        raw_volumes = self.physical_volume_source()
        if not isinstance(raw_volumes, list):
            raise GateError("physical Podman volume source did not return a list")
        names: dict[str, int] = {}
        nonzero: list[PhysicalVolume] = []
        for raw_volume in raw_volumes:
            if not isinstance(raw_volume, PhysicalVolume):
                raise GateError("physical Podman volume record is invalid")
            if (
                not VOLUME_NAME_PATTERN.fullmatch(raw_volume.name)
                or type(raw_volume.project_id) is not int
                or raw_volume.project_id < 0
                or raw_volume.project_id > 0xFFFFFFFF
                or raw_volume.name in names
            ):
                raise GateError("physical Podman volume record is invalid")
            names[raw_volume.name] = raw_volume.project_id
            if raw_volume.project_id != 0:
                nonzero.append(raw_volume)
        if len(nonzero) > 1:
            raise GateError(
                "more than one physical Podman volume has an XFS project ID"
            )

        quota_name: str | None = None
        if quota_records:
            quota_record = quota_records[0][0]
            candidate = quota_record["Name"] if "Name" in quota_record else None
            if not isinstance(candidate, str):
                raise GateError("quota-backed Podman volume name is invalid")
            quota_name = candidate
            if quota_name not in names:
                raise GateError(
                    "quota-backed Podman volume has no physical data directory"
                )
        if not nonzero:
            if quota_name is not None:
                raise GateError(
                    "quota-backed Podman volume has no physical XFS project ID"
                )
            return result

        physical_volume = nonzero[0]
        if (
            lease is None
            or quota_name is None
            or physical_volume.name != lease.volume_name
            or physical_volume.name != quota_name
        ):
            raise GateError(
                "physical XFS project volume does not match lease and Podman state"
            )
        active_quota = self.physical_quota_source(physical_volume.project_id)
        if not isinstance(active_quota, PhysicalQuota) or any(
            type(value) is not int or value < 0 for value in active_quota
        ):
            raise GateError("active XFS project quota record is invalid")
        expected_block_kib = int(quota_records[0][1]["size"]) // 1024
        expected_quota = PhysicalQuota(
            block_soft_kib=expected_block_kib,
            block_hard_kib=expected_block_kib,
            inode_soft=OWNER_INODE_LIMIT,
            inode_hard=OWNER_INODE_LIMIT,
        )
        if active_quota != expected_quota:
            raise GateError(
                "active XFS project limits do not match the workspace quota"
            )
        return result


def _production_gate() -> VolumeGate:
    if pwd is None or grp is None:
        raise GateError("POSIX account and group lookup support is required")
    try:
        provisioner_uid = pwd.getpwnam("coder-provisioner").pw_uid
        provisioner_gid = grp.getgrnam("coder-provisioner").gr_gid
    except KeyError as exc:
        raise GateError("coder-provisioner account or group is missing") from exc
    return VolumeGate(
        provisioner_uid=provisioner_uid,
        provisioner_gid=provisioner_gid,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="enforce the owner-PC singleton quota-volume lease"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="initialize and verify protected gate state")
    commands.add_parser("status", help="print validated gate state as JSON")
    commands.add_parser("verify", help="fail unless gate and Podman state agree")
    for command in ("claim", "release"):
        identity = commands.add_parser(
            command, help=f"{command} one canonical workspace identity"
        )
        identity.add_argument("--workspace-id", required=True)
        identity.add_argument("--workspace-name", required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        gate = _production_gate()
        if parsed.command == "init":
            result = gate.initialize()
        elif parsed.command == "claim":
            result = gate.claim(parsed.workspace_id, parsed.workspace_name)
        elif parsed.command == "release":
            result = gate.release(parsed.workspace_id, parsed.workspace_name)
        elif parsed.command == "verify":
            result = gate.verify()
        else:
            result = gate.status()
    except GateError as exc:
        print(f"owner-PC workspace volume gate failed: {exc}", file=sys.stderr)
        return 1
    if parsed.command == "verify":
        print("owner-PC workspace volume gate: PASS")
    else:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
