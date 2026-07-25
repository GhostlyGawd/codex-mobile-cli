from __future__ import annotations

import importlib.util
import ipaddress
import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "infra" / "systemd" / "ensure-workspace-control-network.py"
SPEC = importlib.util.spec_from_file_location("workspace_control_network", SCRIPT)
assert SPEC and SPEC.loader
NETWORK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NETWORK)


class WorkspaceControlNetworkTests(unittest.TestCase):
    def environment(self, subnet: str = "10.87.0.0/24"):
        return mock.patch.dict(
            os.environ,
            {
                "WORKSPACE_CONTROL_SUBNET": subnet,
                "CODER_BIND_ADDRESS": "10.0.0.8",
            },
            clear=True,
        )

    def valid_record(self) -> dict[str, object]:
        return {
            "name": "codex-mobile-control",
            "driver": "bridge",
            "network_interface": "cm-control0",
            "internal": False,
            "ipv6_enabled": False,
            "subnets": [{"subnet": "10.87.0.0/24", "gateway": "10.87.0.1"}],
            "options": {"isolate": "true"},
        }

    def test_accepts_only_collision_free_rfc1918_24_through_28(self) -> None:
        with self.environment():
            self.assertEqual(
                NETWORK.configured_subnet(), ipaddress.ip_network("10.87.0.0/24")
            )
        for invalid in (
            "8.8.8.0/24",
            "10.0.0.0/8",
            "10.0.0.0/24",
            "192.0.2.0/24",
            "10.87.0.1/24",
        ):
            with self.subTest(invalid=invalid), self.environment(invalid):
                with self.assertRaises(RuntimeError):
                    NETWORK.configured_subnet()

        for invalid_address in ("8.8.8.8", "::1", "not-an-ip"):
            with (
                self.subTest(invalid_address=invalid_address),
                mock.patch.dict(
                    os.environ,
                    {
                        "WORKSPACE_CONTROL_SUBNET": "10.87.0.0/24",
                        "CODER_BIND_ADDRESS": invalid_address,
                    },
                    clear=True,
                ),
                self.assertRaises(RuntimeError),
            ):
                NETWORK.configured_subnet()

    def test_rejects_existing_network_policy_drift(self) -> None:
        record = self.valid_record()
        NETWORK.validate_network(record, ipaddress.ip_network("10.87.0.0/24"))
        for key, value in (
            ("driver", "macvlan"),
            ("network_interface", "podman9"),
            ("internal", True),
            ("ipv6_enabled", True),
            ("options", {}),
        ):
            drifted = self.valid_record()
            drifted[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                NETWORK.validate_network(
                    drifted, ipaddress.ip_network("10.87.0.0/24")
                )

    def test_rejects_host_route_overlap_but_allows_managed_bridge_routes(self) -> None:
        class Result:
            returncode = 0
            stderr = ""
            stdout = '[{"dst":"10.87.0.0/24","dev":"cm-control0"}]'

        NETWORK.validate_route_collisions(
            ipaddress.ip_network("10.87.0.0/24"), lambda *_args, **_kwargs: Result()
        )
        Result.stdout = '[{"dst":"10.0.0.0/8","dev":"eth0"}]'
        with self.assertRaisesRegex(RuntimeError, "overlaps host route"):
            NETWORK.validate_route_collisions(
                ipaddress.ip_network("10.87.0.0/24"),
                lambda *_args, **_kwargs: Result(),
            )

    def test_check_mode_does_not_repair_a_missing_network(self) -> None:
        missing = subprocess.CompletedProcess([], 1, "", "")
        with (
            self.environment(),
            mock.patch.object(NETWORK.sys, "argv", [str(SCRIPT), "--check"]),
            mock.patch.object(NETWORK, "run_podman", return_value=missing) as run,
            mock.patch.object(NETWORK, "validate_route_collisions"),
        ):
            self.assertEqual(NETWORK.main(), 1)
        self.assertEqual(run.call_count, 1)

    def test_create_uses_fixed_name_interface_gateway_and_isolation(self) -> None:
        missing = subprocess.CompletedProcess([], 1, "", "")
        created = subprocess.CompletedProcess([], 0, "", "")
        record = self.valid_record()
        calls: list[tuple[str, ...]] = []

        def fake_run(*arguments: str, accepted=(0,)):
            del accepted
            calls.append(arguments)
            if arguments[:2] == ("network", "exists"):
                return missing
            if arguments[:2] == ("network", "create"):
                return created
            return subprocess.CompletedProcess([], 0, f"[{NETWORK.json.dumps(record)}]", "")

        with (
            self.environment(),
            mock.patch.object(NETWORK.sys, "argv", [str(SCRIPT)]),
            mock.patch.object(NETWORK, "run_podman", side_effect=fake_run),
            mock.patch.object(NETWORK, "validate_route_collisions"),
        ):
            self.assertEqual(NETWORK.main(), 0)
        create = next(call for call in calls if call[:2] == ("network", "create"))
        self.assertIn("--subnet=10.87.0.0/24", create)
        self.assertIn("--gateway=10.87.0.1", create)
        self.assertIn("--interface-name=cm-control0", create)
        self.assertIn("--opt=isolate=true", create)
        self.assertEqual(create[-1], "codex-mobile-control")


if __name__ == "__main__":
    unittest.main()
