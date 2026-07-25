#!/usr/bin/env python3
"""Create or fail-closed validate the private Podman relay uplink."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys


NETWORK_NAME = "codex-mobile-control"
NETWORK_INTERFACE = "cm-control0"
NETWORK_CONFIG_DIR = "/srv/codex-mobile/workspaces/.networks"
MAX_OUTPUT = 64 * 1024
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def safe_environment() -> dict[str, str]:
    return {
        name: os.environ[name]
        for name in (
            "HOME",
            "XDG_RUNTIME_DIR",
            "CONTAINERS_STORAGE_CONF",
            "CONTAINERS_CONF",
            "PATH",
        )
        if name in os.environ
    }


def run_podman(*arguments: str, accepted: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
    command = [
        "/usr/bin/podman",
        f"--network-config-dir={NETWORK_CONFIG_DIR}",
        *arguments,
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env=safe_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"cannot execute Podman network validation: {exc}") from exc
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise RuntimeError("Podman network validation output exceeded 64 KiB")
    if result.returncode not in accepted:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(
            f"Podman {' '.join(arguments[:2])} failed"
            + (f": {detail}" if detail else "")
        )
    return result


def configured_subnet() -> ipaddress.IPv4Network:
    raw = os.environ.get("WORKSPACE_CONTROL_SUBNET", "")
    try:
        network = ipaddress.ip_network(raw, strict=True)
    except ValueError as exc:
        raise RuntimeError("WORKSPACE_CONTROL_SUBNET must be a canonical IPv4 CIDR") from exc
    if not isinstance(network, ipaddress.IPv4Network) or not any(
        network.subnet_of(private) for private in RFC1918_NETWORKS
    ):
        raise RuntimeError("WORKSPACE_CONTROL_SUBNET must be an RFC1918 IPv4 network")
    if network.prefixlen < 24 or network.prefixlen > 28:
        raise RuntimeError("WORKSPACE_CONTROL_SUBNET prefix must be between /24 and /28")
    coder_raw = os.environ.get("CODER_BIND_ADDRESS", "")
    try:
        coder_address = ipaddress.ip_address(coder_raw)
    except ValueError as exc:
        raise RuntimeError("CODER_BIND_ADDRESS must be a literal IP address") from exc
    if not isinstance(coder_address, ipaddress.IPv4Address) or not any(
        coder_address in private for private in RFC1918_NETWORKS
    ):
        raise RuntimeError("CODER_BIND_ADDRESS must be a literal RFC1918 IPv4 address")
    if coder_address in network:
        raise RuntimeError("WORKSPACE_CONTROL_SUBNET must not contain CODER_BIND_ADDRESS")
    return network


def inspect_network() -> dict[str, object]:
    result = run_podman("network", "inspect", NETWORK_NAME)
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Podman returned invalid network inspection JSON") from exc
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise RuntimeError("Podman returned an unexpected network inspection record")
    return document[0]


def validate_network(record: dict[str, object], network: ipaddress.IPv4Network) -> None:
    subnets = record.get("subnets")
    options = record.get("options")
    expected_gateway = str(next(network.hosts()))
    expected_subnets = [{"subnet": str(network), "gateway": expected_gateway}]
    failures: list[str] = []
    if record.get("name") != NETWORK_NAME:
        failures.append("name")
    if record.get("driver") != "bridge":
        failures.append("driver")
    if record.get("network_interface") != NETWORK_INTERFACE:
        failures.append("network interface")
    if record.get("internal") is not False:
        failures.append("internal flag")
    if record.get("ipv6_enabled") is not False:
        failures.append("IPv6 flag")
    if subnets != expected_subnets:
        failures.append("subnet/gateway")
    if not isinstance(options, dict) or str(options.get("isolate", "")).lower() != "true":
        failures.append("isolation option")
    if failures:
        raise RuntimeError(
            "existing codex-mobile-control network violates the managed policy: "
            + ", ".join(failures)
        )


def validate_route_collisions(
    network: ipaddress.IPv4Network, run=subprocess.run
) -> None:
    """Reject overlap with host routes other than this managed bridge."""
    try:
        result = run(
            ["/usr/sbin/ip", "-json", "-4", "route", "show", "table", "all"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=safe_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"cannot inspect host routes: {exc}") from exc
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise RuntimeError("host route inspection output exceeded 64 KiB")
    if result.returncode:
        detail = result.stderr.strip()
        raise RuntimeError(
            "cannot inspect host routes" + (f": {detail}" if detail else "")
        )
    try:
        routes = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ip returned invalid route JSON") from exc
    if not isinstance(routes, list):
        raise RuntimeError("ip returned an unexpected route document")
    for route in routes:
        if not isinstance(route, dict):
            raise RuntimeError("ip returned an invalid route record")
        destination = route.get("dst")
        if destination in (None, "default"):
            continue
        try:
            candidate = ipaddress.ip_network(str(destination), strict=False)
        except ValueError as exc:
            raise RuntimeError("ip returned an invalid route destination") from exc
        if not isinstance(candidate, ipaddress.IPv4Network) or not candidate.overlaps(
            network
        ):
            continue
        if route.get("dev") == NETWORK_INTERFACE and candidate.subnet_of(network):
            continue
        raise RuntimeError(
            f"WORKSPACE_CONTROL_SUBNET overlaps host route {candidate}"
        )


def main() -> int:
    if sys.argv[1:] not in ([], ["--check"]):
        print(f"usage: {sys.argv[0]} [--check]", file=sys.stderr)
        return 2
    check_only = sys.argv[1:] == ["--check"]
    try:
        network = configured_subnet()
        existence = run_podman(
            "network", "exists", NETWORK_NAME, accepted=(0, 1)
        ).returncode
        if existence == 1:
            if check_only:
                raise RuntimeError("managed network is missing")
            validate_route_collisions(network)
            gateway = str(next(network.hosts()))
            run_podman(
                "network",
                "create",
                "--driver=bridge",
                f"--subnet={network}",
                f"--gateway={gateway}",
                f"--interface-name={NETWORK_INTERFACE}",
                "--opt=isolate=true",
                NETWORK_NAME,
            )
        validate_network(inspect_network(), network)
        validate_route_collisions(network)
    except RuntimeError as exc:
        print(f"workspace control network validation failed: {exc}", file=sys.stderr)
        return 1
    print("workspace control network: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
