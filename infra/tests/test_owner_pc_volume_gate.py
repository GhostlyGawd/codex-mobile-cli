from __future__ import annotations

import copy
import io
import importlib.util
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "infra" / "systemd" / "owner-pc-workspace-volume-gate.py"
SPEC = importlib.util.spec_from_file_location("owner_pc_volume_gate", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)

WORKSPACE_A = "12345678-1234-4abc-8def-1234567890ab"
WORKSPACE_B = "abcdef01-2345-4abc-8def-1234567890ab"


def volume_record(
    workspace_id: str = WORKSPACE_A,
    workspace_name: str = "alpha",
    *,
    options: object = None,
    labels: object = None,
) -> dict[str, object]:
    lease = GATE.workspace_lease(workspace_id, workspace_name)
    if options is None:
        options = {"SIZE": "8589934592", "o": "size=8589934592"}
    if labels is None:
        labels = {
            GATE.MANAGED_LABEL: "true",
            GATE.PROFILE_LABEL: GATE.PROFILE,
            GATE.ROLE_LABEL: GATE.WORKSPACE_DATA_ROLE,
            GATE.WORKSPACE_ID_LABEL: workspace_id,
            GATE.WORKSPACE_NAME_LABEL: workspace_name,
            GATE.CPU_LABEL: GATE.OWNER_CPU_MILLIS,
            GATE.DISK_BUDGET_LABEL: "8589934592",
            GATE.MEMORY_LABEL: GATE.OWNER_MEMORY_MIB,
            GATE.PIDS_LABEL: GATE.OWNER_PIDS_LIMIT,
        }
    return {
        "Name": lease.volume_name,
        "Driver": "local",
        "Scope": "local",
        "Labels": labels,
        "Options": options,
    }


class MutableVolumeSource:
    def __init__(self, records: list[object] | None = None) -> None:
        self.records = records or []
        self.lock = threading.Lock()

    def __call__(self) -> list[object]:
        with self.lock:
            return copy.deepcopy(self.records)

    def replace_records(self, records: list[object]) -> None:
        with self.lock:
            self.records = records


class MutablePhysicalSource:
    def __init__(self) -> None:
        self.records: list[object] = []
        self.lock = threading.Lock()

    def __call__(self) -> list[object]:
        with self.lock:
            return copy.deepcopy(self.records)

    def replace_records(self, records: list[object]) -> None:
        with self.lock:
            self.records = records


class QuotaOptionTests(unittest.TestCase):
    def test_detects_direct_and_comma_delimited_quota_options(self) -> None:
        self.assertEqual(
            GATE.quota_options({"size": "8589934592", "inodes": "1048576"}),
            {"size": "8589934592", "inodes": "1048576"},
        )
        self.assertEqual(
            GATE.quota_options({"o": "nodev,size=8G,inodes=1048576"}),
            {"size": "8G", "inodes": "1048576"},
        )
        self.assertEqual(
            GATE.quota_options({"SIZE": "8589934592", "o": "size=8589934592"}),
            {"size": "8589934592"},
        )
        self.assertEqual(
            GATE.quota_options(
                {
                    "SIZE": "8589934592",
                    "INODES": "1048576",
                    "o": "nodev,size=8589934592,inodes=1048576",
                }
            ),
            {"size": "8589934592", "inodes": "1048576"},
        )

    def test_rejects_malformed_or_ambiguous_quota_options(self) -> None:
        for options in (
            "size=8G",
            {"o": ["size=8G"]},
            {"o": "size"},
            {"o": "size=0"},
            {"o": "size=8G,size=16G"},
            {"size": "8G", "o": "size=8G"},
            {"Size": "8G"},
            {"Size": "8G", "o": "size=8G"},
            {"SIZE": "8G"},
            {"SIZE": "8G", "o": ""},
            {"SIZE": "8G", "o": "size=16G"},
            {"SIZE": "8G", "INODES": "1048576", "o": "size=8G"},
            {"SIZE": "8G", "o": "size=8G,inodes=1048576"},
            {"SIZE": "8G", "inodes": "1048576", "o": "size=8G"},
            {"SIZE": "8G", "o": "size=8G,size=8G"},
            {"SIZE": "0", "o": "size=0"},
            {"inodes": "-1"},
        ):
            with self.subTest(options=options), self.assertRaises(GATE.GateError):
                GATE.quota_options(options)

    def test_uuid_and_volume_identity_are_strict_and_canonical(self) -> None:
        lease = GATE.workspace_lease(WORKSPACE_A, "alpha")
        self.assertEqual(
            lease.volume_name,
            "cm-workspace-v2-1234567812344abc8def1234",
        )
        for workspace_id in (
            WORKSPACE_A.upper(),
            "1234567812344abc8def1234567890ab",
            "00000000-0000-0000-0000-000000000000",
            "not-a-uuid",
        ):
            with self.subTest(workspace_id=workspace_id):
                with self.assertRaises(GATE.GateError):
                    GATE.workspace_lease(workspace_id, "alpha")


class BoundedCommandTests(unittest.TestCase):
    def test_enforces_aggregate_output_limit_before_process_exit(self) -> None:
        with self.assertRaisesRegex(GATE.GateError, "exceeded"):
            GATE.run_bounded_command(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('x' * 65536)",
                ],
                timeout=5,
                max_output=1024,
                env={"PATH": os.environ.get("PATH", "")},
                cwd=str(ROOT),
            )

    def test_enforces_command_timeout(self) -> None:
        with self.assertRaisesRegex(GATE.GateError, "timed out"):
            GATE.run_bounded_command(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout=0.1,
                max_output=1024,
                env={"PATH": os.environ.get("PATH", "")},
                cwd=str(ROOT),
            )


class XFSQuotaSourceTests(unittest.TestCase):
    def test_uses_fixed_bounded_commands_and_parses_exact_limits(self) -> None:
        runner = mock.Mock(
            side_effect=[
                GATE.CommandResult(
                    0,
                    ("/dev/loop0 0 8388608 8388608 00 [--------] /srv/codex-mobile\n"),
                    "",
                ),
                GATE.CommandResult(
                    0,
                    ("/dev/loop0 1 1048576 1048576 00 [--------] /srv/codex-mobile\n"),
                    "",
                ),
            ]
        )
        source = GATE.XFSQuotaSource(run=runner)

        self.assertEqual(
            source(10490001),
            GATE.PhysicalQuota(8388608, 8388608, 1048576, 1048576),
        )
        common = {
            "timeout": GATE.XFS_QUOTA_TIMEOUT_SECONDS,
            "max_output": GATE.MAX_XFS_QUOTA_OUTPUT,
            "env": {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
            "cwd": "/",
        }
        self.assertEqual(
            runner.call_args_list,
            [
                mock.call(
                    [
                        GATE.XFS_QUOTA,
                        "-x",
                        "-c",
                        "quota -p -b -n -N -v 10490001",
                        GATE.WORKSPACE_STORAGE_MOUNT,
                    ],
                    **common,
                ),
                mock.call(
                    [
                        GATE.XFS_QUOTA,
                        "-x",
                        "-c",
                        "quota -p -i -n -N -v 10490001",
                        GATE.WORKSPACE_STORAGE_MOUNT,
                    ],
                    **common,
                ),
            ],
        )

    def test_rejects_invalid_ids_and_malformed_or_failed_records(self) -> None:
        runner = mock.Mock()
        source = GATE.XFSQuotaSource(run=runner)
        for project_id in (True, 0, -1, 0x100000000, "10490001"):
            with (
                self.subTest(project_id=project_id),
                self.assertRaises(GATE.GateError),
            ):
                source(project_id)
        runner.assert_not_called()

        for result in (
            GATE.CommandResult(1, "", ""),
            GATE.CommandResult(0, "", "warning"),
            GATE.CommandResult(0, "malformed\n", ""),
            GATE.CommandResult(
                0,
                (
                    "/dev/loop0 0 1 1 00 [--------] /srv/codex-mobile\n"
                    "/dev/loop0 0 1 1 00 [--------] /srv/codex-mobile\n"
                ),
                "",
            ),
            GATE.CommandResult(
                0,
                "/dev/loop0 0 -1 1 00 [--------] /srv/codex-mobile\n",
                "",
            ),
            GATE.CommandResult(
                0,
                "/dev/loop0 0 1 1 00 [--------] /unexpected\n",
                "",
            ),
            GATE.CommandResult(
                0,
                (f"/dev/loop0 0 {'9' * 5000} 1 00 [--------] /srv/codex-mobile\n"),
                "",
            ),
        ):
            with (
                self.subTest(result=result),
                self.assertRaises(GATE.GateError),
            ):
                GATE.XFSQuotaSource(run=mock.Mock(return_value=result))(10490001)


class PodmanVolumeSourceTests(unittest.TestCase):
    def test_uses_fixed_remote_command_environment_timeout_and_all(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return GATE.CommandResult(0, "[]", "")

        source = GATE.PodmanVolumeSource(run=run, effective_uid=lambda: 1001)
        self.assertEqual(source(), [])
        command, arguments = calls[0]
        self.assertEqual(command[0], "/usr/bin/podman")
        self.assertEqual(
            command[1:3],
            [
                "--remote",
                "--url=unix:///run/codex-mobile-podman/podman.sock",
            ],
        )
        self.assertEqual(command[-3:], ["volume", "inspect", "--all"])
        self.assertEqual(arguments["timeout"], 15)
        self.assertEqual(
            set(arguments["env"]),
            {
                "HOME",
                "LANG",
                "LC_ALL",
                "PATH",
            },
        )
        self.assertEqual(
            arguments["env"]["HOME"],
            "/srv/codex-mobile/workspaces/.provisioner-home",
        )
        self.assertEqual(arguments["max_output"], GATE.MAX_COMMAND_OUTPUT)
        self.assertEqual(arguments["cwd"], "/")
        self.assertNotIn("DOCKER_HOST", arguments["env"])

        calls.clear()
        self.assertEqual(
            GATE.PodmanVolumeSource(run=run, effective_uid=lambda: 0)(),
            [],
        )
        command, arguments = calls[0]
        self.assertNotIn("--remote", command)
        self.assertEqual(command[-3:], ["volume", "inspect", "--all"])
        self.assertEqual(
            arguments["env"]["CONTAINERS_STORAGE_CONF"],
            "/etc/codex-mobile/containers-storage.conf",
        )
        self.assertEqual(
            arguments["env"]["HOME"],
            "/srv/codex-mobile/workspaces/.runtime-home",
        )

    def test_rejects_malformed_or_unbounded_podman_json(self) -> None:
        def malformed(command, **_kwargs):
            return GATE.CommandResult(0, "{", "")

        with self.assertRaisesRegex(GATE.GateError, "malformed"):
            GATE.PodmanVolumeSource(run=malformed, effective_uid=lambda: 0)()

        def unbounded(command, **_kwargs):
            return GATE.CommandResult(0, " " * (GATE.MAX_COMMAND_OUTPUT + 1), "")

        with self.assertRaisesRegex(GATE.GateError, "512 KiB"):
            GATE.PodmanVolumeSource(run=unbounded, effective_uid=lambda: 0)()


class CommandLineTests(unittest.TestCase):
    def test_verify_reports_pass_and_failure_from_validated_status(self) -> None:
        gate = mock.Mock()
        gate.status.return_value = {
            "lease": None,
            "quota_volume": None,
            "quota_volume_count": 0,
            "state": "idle",
        }
        gate.verify.return_value = gate.status.return_value
        with (
            mock.patch.object(GATE, "_production_gate", return_value=gate),
            mock.patch("sys.stdout", new_callable=io.StringIO) as output,
        ):
            self.assertEqual(GATE.main(["verify"]), 0)
        self.assertEqual(output.getvalue(), "owner-PC workspace volume gate: PASS\n")

        gate.verify.side_effect = GATE.GateError("drift")
        with (
            mock.patch.object(GATE, "_production_gate", return_value=gate),
            mock.patch("sys.stderr", new_callable=io.StringIO) as error,
        ):
            self.assertEqual(GATE.main(["verify"]), 1)
        self.assertIn("drift", error.getvalue())


@unittest.skipUnless(
    GATE.fcntl is not None and os.name == "posix",
    "the production volume gate requires Linux fcntl and ownership semantics",
)
class VolumeGateFilesystemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name) / "workspaces"
        base.mkdir(mode=0o700)
        os.chmod(base, 0o700)
        self.source = MutableVolumeSource()
        self.physical_source = MutablePhysicalSource()
        self.quota_source = mock.Mock(
            return_value=GATE.PhysicalQuota(
                8388608,
                8388608,
                GATE.OWNER_INODE_LIMIT,
                GATE.OWNER_INODE_LIMIT,
            )
        )
        current_uid = os.geteuid()
        current_gid = os.getegid()
        self.gate = GATE.VolumeGate(
            gate_directory=base / ".owner-pc-volume-gate",
            volume_source=self.source,
            physical_volume_source=self.physical_source,
            physical_quota_source=self.quota_source,
            root_uid=current_uid,
            workspace_root_gid=current_gid,
            workspace_root_mode=0o700,
            provisioner_uid=current_uid,
            provisioner_gid=current_gid,
            effective_uid=lambda: current_uid,
        )
        self.gate.initialize()

    def _write_raw_lease(self, payload: bytes) -> None:
        self.gate.lease_path.write_bytes(payload)
        os.chmod(self.gate.lease_path, 0o600)

    def test_initializes_exact_protected_modes(self) -> None:
        gate = self.gate.gate_directory.stat()
        state = self.gate.state_directory.stat()
        lock = self.gate.lock_path.stat()
        self.assertEqual(stat.S_IMODE(gate.st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(state.st_mode), 0o2770)
        self.assertEqual(stat.S_IMODE(lock.st_mode), 0o660)
        self.assertEqual(lock.st_nlink, 1)

    def test_lock_inode_is_stable_and_lock_wait_is_bounded(self) -> None:
        before = self.gate.lock_path.stat()
        self.gate.claim(WORKSPACE_A, "alpha")
        self.gate.release(WORKSPACE_A, "alpha")
        after = self.gate.lock_path.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))

        descriptor = self.gate._open_validated_lock()
        assert GATE.fcntl is not None
        GATE.fcntl.flock(descriptor, GATE.fcntl.LOCK_EX)
        blocked = GATE.VolumeGate(
            gate_directory=self.gate.gate_directory,
            volume_source=self.source,
            root_uid=os.geteuid(),
            workspace_root_gid=os.getegid(),
            workspace_root_mode=0o700,
            provisioner_uid=os.geteuid(),
            provisioner_gid=os.getegid(),
            effective_uid=os.geteuid,
            lock_timeout=0,
        )
        try:
            with self.assertRaisesRegex(GATE.GateError, "timed out"):
                blocked.status()
        finally:
            GATE.fcntl.flock(descriptor, GATE.fcntl.LOCK_UN)
            os.close(descriptor)

    def test_rejects_replaced_or_hardlinked_stable_lock(self) -> None:
        hardlink = self.gate.gate_directory / "unexpected-lock-link"
        os.link(self.gate.lock_path, hardlink)
        with self.assertRaisesRegex(GATE.GateError, "lock ownership or mode"):
            self.gate.status()

    def test_root_verify_correlates_physical_project_id(self) -> None:
        lease = GATE.workspace_lease(WORKSPACE_A, "alpha")
        self.gate.claim(WORKSPACE_A, "alpha")
        self.source.replace_records([volume_record()])

        with self.assertRaisesRegex(GATE.GateError, "no physical data"):
            self.gate.verify()
        self.physical_source.replace_records(
            [GATE.PhysicalVolume(lease.volume_name, 1048577)]
        )
        self.assertEqual(self.gate.verify()["state"], "active")
        self.quota_source.assert_called_once_with(1048577)
        self.quota_source.return_value = GATE.PhysicalQuota(
            8388608,
            8388608,
            1024,
            1024,
        )
        with self.assertRaisesRegex(GATE.GateError, "active XFS project limits"):
            self.gate.verify()
        self.physical_source.replace_records(
            [
                GATE.PhysicalVolume(lease.volume_name, 1048577),
                GATE.PhysicalVolume("untracked", 1048578),
            ]
        )
        with self.assertRaisesRegex(GATE.GateError, "more than one physical"):
            self.gate.verify()

    def test_root_verify_rejects_stale_physical_project_without_lease(self) -> None:
        self.physical_source.replace_records(
            [GATE.PhysicalVolume("stale-volume", 1048577)]
        )
        with self.assertRaisesRegex(GATE.GateError, "does not match"):
            self.gate.verify()

    def test_concurrent_different_claims_are_atomic(self) -> None:
        barrier = threading.Barrier(3)
        outcomes: list[tuple[str, object]] = []
        outcome_lock = threading.Lock()

        def claim(workspace_id: str, name: str) -> None:
            barrier.wait()
            try:
                result: object = self.gate.claim(workspace_id, name)
                kind = "success"
            except GATE.GateError as exc:
                result = exc
                kind = "failure"
            with outcome_lock:
                outcomes.append((kind, result))

        threads = [
            threading.Thread(target=claim, args=(WORKSPACE_A, "alpha")),
            threading.Thread(target=claim, args=(WORKSPACE_B, "bravo")),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

        self.assertEqual(
            sorted(kind for kind, _result in outcomes),
            ["failure", "success"],
        )
        status = self.gate.status()
        self.assertIn(
            status["lease"]["workspace_id"],  # type: ignore[index]
            (WORKSPACE_A, WORKSPACE_B),
        )

    def test_same_claim_is_idempotent_but_different_claim_fails(self) -> None:
        first = self.gate.claim(WORKSPACE_A, "alpha")
        second = self.gate.claim(WORKSPACE_A, "alpha")
        self.assertEqual(first["action"], "claimed")
        self.assertEqual(second["action"], "unchanged")
        self.assertEqual(first["lease"], second["lease"])
        with self.assertRaisesRegex(GATE.GateError, "another workspace"):
            self.gate.claim(WORKSPACE_B, "bravo")

    def test_stopped_quota_volume_blocks_a_different_claim(self) -> None:
        self.gate.claim(WORKSPACE_A, "alpha")
        self.source.replace_records([volume_record()])
        self.assertEqual(self.gate.status()["state"], "active")
        with self.assertRaisesRegex(GATE.GateError, "another workspace"):
            self.gate.claim(WORKSPACE_B, "bravo")

    def test_rejects_unleased_unlabeled_and_second_quota_volumes(self) -> None:
        unlabeled = volume_record(labels={})
        self.source.replace_records([unlabeled])
        with self.assertRaisesRegex(GATE.GateError, "without a lease"):
            self.gate.status()

        self.source.replace_records([])
        self.gate.claim(WORKSPACE_A, "alpha")
        self.source.replace_records(
            [
                volume_record(),
                volume_record(WORKSPACE_B, "bravo"),
            ]
        )
        with self.assertRaisesRegex(GATE.GateError, "more than one"):
            self.gate.status()

    def test_rejects_label_identity_and_unquoted_workspace_drift(self) -> None:
        self.gate.claim(WORKSPACE_A, "alpha")
        for label, value in (
            (GATE.MANAGED_LABEL, "false"),
            (GATE.PROFILE_LABEL, "fixed_price_vps"),
            (GATE.ROLE_LABEL, "other"),
            (GATE.WORKSPACE_ID_LABEL, WORKSPACE_B),
            (GATE.WORKSPACE_NAME_LABEL, "bravo"),
            (GATE.CPU_LABEL, "bogus"),
            (GATE.DISK_BUDGET_LABEL, "1"),
            (GATE.MEMORY_LABEL, "bogus"),
            (GATE.PIDS_LABEL, "bogus"),
        ):
            labels = volume_record()["Labels"]
            assert isinstance(labels, dict)
            labels[label] = value
            self.source.replace_records([volume_record(labels=labels)])
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(GATE.GateError, "does not match"),
            ):
                self.gate.status()
        labels = volume_record()["Labels"]
        assert isinstance(labels, dict)
        labels["com.codex-mobile.unknown"] = "value"
        self.source.replace_records([volume_record(labels=labels)])
        with self.assertRaisesRegex(GATE.GateError, "label schema"):
            self.gate.status()

    def test_rejects_workspace_volume_without_size_or_any_quota(self) -> None:
        self.gate.claim(WORKSPACE_A, "alpha")
        self.source.replace_records([volume_record(options={"inodes": "1048576"})])
        with self.assertRaisesRegex(GATE.GateError, "lacks a byte quota"):
            self.gate.status()
        self.source.replace_records(
            [volume_record(options={"o": "size=8589934592,inodes=1048576"})]
        )
        with self.assertRaisesRegex(GATE.GateError, "only a byte quota"):
            self.gate.status()
        self.source.replace_records([volume_record(options={"o": "size=8G"})])
        with self.assertRaisesRegex(GATE.GateError, "canonical bytes"):
            self.gate.status()
        self.source.replace_records([volume_record(options={})])
        with self.assertRaisesRegex(GATE.GateError, "without quota options"):
            self.gate.status()

    def test_lease_with_zero_volumes_is_valid_during_create_or_delete(self) -> None:
        claimed = self.gate.claim(WORKSPACE_A, "alpha")
        self.assertEqual(claimed["state"], "claimed")
        self.assertEqual(claimed["quota_volume_count"], 0)
        self.source.replace_records([volume_record()])
        self.assertEqual(self.gate.status()["state"], "active")

    def test_release_requires_matching_lease_and_absent_volume(self) -> None:
        self.gate.claim(WORKSPACE_A, "alpha")
        with self.assertRaisesRegex(GATE.GateError, "another workspace"):
            self.gate.release(WORKSPACE_B, "bravo")
        self.source.replace_records([volume_record()])
        with self.assertRaisesRegex(GATE.GateError, "must be absent"):
            self.gate.release(WORKSPACE_A, "alpha")
        self.source.replace_records([])
        released = self.gate.release(WORKSPACE_A, "alpha")
        self.assertEqual(released["action"], "released")
        self.assertEqual(released["state"], "idle")
        with self.assertRaisesRegex(GATE.GateError, "lease is absent"):
            self.gate.release(WORKSPACE_A, "alpha")

    def test_rejects_malformed_lease_json_schema_and_options(self) -> None:
        for payload in (
            b"{",
            json.dumps(
                {
                    **GATE.workspace_lease(WORKSPACE_A, "alpha").document(),
                    "schema_version": True,
                }
            ).encode(),
            json.dumps(
                {
                    **GATE.workspace_lease(WORKSPACE_A, "alpha").document(),
                    "unknown": True,
                }
            ).encode(),
        ):
            self._write_raw_lease(payload)
            with self.subTest(payload=payload), self.assertRaises(GATE.GateError):
                self.gate.status()
        self.gate.lease_path.unlink()
        self.source.replace_records(
            [
                {
                    "Name": "ordinary",
                    "Driver": "local",
                    "Scope": "local",
                    "Labels": {},
                    "Options": "size=8G",
                }
            ]
        )
        with self.assertRaisesRegex(GATE.GateError, "options must"):
            self.gate.status()

    def test_rejects_quota_volume_without_lease(self) -> None:
        self.source.replace_records([volume_record()])
        with self.assertRaisesRegex(GATE.GateError, "without a lease"):
            self.gate.status()


@unittest.skipUnless(
    GATE.fcntl is not None and os.name == "posix",
    "the physical volume scanner requires Linux directory semantics",
)
class PhysicalVolumeSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "volumes"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.project_ids: dict[Path, int] = {}
        self.source = GATE.PhysicalVolumeSource(
            volumes_directory=self.root,
            project_id_reader=lambda path: self.project_ids[path],
            root_uid=os.geteuid(),
            root_gid=os.getegid(),
        )

    def create_volume(self, name: str, project_id: int = 0) -> Path:
        volume = self.root / name
        volume.mkdir(mode=0o700)
        os.chmod(volume, 0o700)
        data = volume / "_data"
        data.mkdir(mode=0o755)
        self.project_ids[data] = project_id
        return volume

    def test_scans_every_immediate_data_directory_project_id(self) -> None:
        first = self.create_volume("first", 0)
        second = self.create_volume("second", 1048577)
        root_metadata = self.root.lstat()
        backing_device = mock.Mock(
            name=GATE.BACKING_FS_BLOCK_DEVICE_NAME,
            path=str(self.root / GATE.BACKING_FS_BLOCK_DEVICE_NAME),
        )
        backing_device.name = GATE.BACKING_FS_BLOCK_DEVICE_NAME
        backing_device.stat.return_value = mock.Mock(
            st_mode=stat.S_IFBLK | 0o600,
            st_uid=os.geteuid(),
            st_gid=self.source.backing_device_gid,
            st_dev=root_metadata.st_dev,
            st_rdev=root_metadata.st_dev,
        )
        real_scandir = os.scandir
        with real_scandir(self.root) as scanner:
            volume_entries = list(scanner)

        class Scanner:
            def __enter__(self):
                return iter([*volume_entries, backing_device])

            def __exit__(self, *_args):
                return False

        def scandir(path):
            if Path(path) == self.root:
                return Scanner()
            return real_scandir(path)

        with mock.patch.object(GATE.os, "scandir", side_effect=scandir):
            self.assertEqual(
                self.source(),
                [
                    GATE.PhysicalVolume(first.name, 0),
                    GATE.PhysicalVolume(second.name, 1048577),
                ],
            )

    def test_requires_and_strictly_validates_the_quota_backing_device(self) -> None:
        self.create_volume("quota-volume", 1048577)
        with self.assertRaisesRegex(GATE.GateError, "has no backing device"):
            self.source()

        backing_device = self.root / GATE.BACKING_FS_BLOCK_DEVICE_NAME
        backing_device.write_text("not a block device", encoding="utf-8")
        with self.assertRaisesRegex(GATE.GateError, "device number drifted"):
            self.source()

    def test_rejects_temporary_quota_backing_device_residue(self) -> None:
        (self.root / GATE.BACKING_FS_BLOCK_DEVICE_TEMP_NAME).write_text(
            "incomplete",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(GATE.GateError, "temporary Podman quota"):
            self.source()

    def test_stops_enumeration_at_the_physical_volume_cap(self) -> None:
        class Entry:
            def __init__(self, index: int) -> None:
                self.name = f"volume-{index}"

        class Scanner:
            def __enter__(self):
                return iter(Entry(index) for index in range(GATE.MAX_VOLUMES + 2))

            def __exit__(self, *_args):
                return False

        with (
            mock.patch.object(GATE.os, "scandir", return_value=Scanner()),
            self.assertRaisesRegex(GATE.GateError, "too many entries"),
        ):
            self.source()

    def test_rejects_non_directory_symlink_and_unexpected_child_drift(self) -> None:
        (self.root / "regular-file").write_text("unsafe", encoding="utf-8")
        with self.assertRaisesRegex(GATE.GateError, "directory ownership"):
            self.source()

        (self.root / "regular-file").unlink()
        volume = self.create_volume("drifted")
        (volume / "unexpected").write_text("unsafe", encoding="utf-8")
        with self.assertRaisesRegex(GATE.GateError, "unexpected immediate"):
            self.source()

        (volume / "unexpected").unlink()
        data = volume / "_data"
        data.rmdir()
        data.symlink_to(self.root)
        with self.assertRaisesRegex(GATE.GateError, "data path is unsafe"):
            self.source()


if __name__ == "__main__":
    unittest.main()
