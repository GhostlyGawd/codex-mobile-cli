#!/usr/bin/env python3
"""Fail closed if deployment configuration can introduce another paid service."""

from __future__ import annotations

import argparse
import copy
import itertools
import re
import sys
from pathlib import Path
from typing import Any

import yaml


class PolicyError(RuntimeError):
    pass


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"cannot read {path}: {exc}") from exc


def active_hcl(text: str) -> str:
    """Remove whole-line comments; block declarations remain machine-checkable."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith(("#", "//"))
    )


def check_terraform(root: Path, policy: dict[str, Any], failures: list[str]) -> None:
    allowed_providers = set(policy["allowed_terraform_providers"])
    allowed_prefixes = tuple(policy["allowed_terraform_resource_prefixes"])
    block = re.compile(r'\b(provider|resource)\s+"([A-Za-z0-9_-]+)"')

    for path in sorted((root / "infra").rglob("*.tf")):
        for kind, name in block.findall(active_hcl(path.read_text(encoding="utf-8"))):
            relative = path.relative_to(root)
            if kind == "provider" and name not in allowed_providers:
                failures.append(
                    f"{relative}: Terraform provider {name!r} is not local-policy approved"
                )
            if kind == "resource" and not name.startswith(allowed_prefixes):
                failures.append(
                    f"{relative}: Terraform resource {name!r} can create an unapproved resource"
                )


def merge_compose(base: Any, override: Any) -> Any:
    """Apply the mapping portion of Compose's merge model for policy checks."""
    if not isinstance(base, dict) or not isinstance(override, dict):
        return copy.deepcopy(override)
    merged = copy.deepcopy(base)
    for key, value in override.items():
        merged[key] = (
            merge_compose(merged[key], value) if key in merged else copy.deepcopy(value)
        )
    return merged


def check_compose_document(
    document: Any, label: str, policy: dict[str, Any], failures: list[str]
) -> None:
    if not isinstance(document, dict):
        failures.append(f"{label}: expected a mapping")
        return

    services = document.get("services", {})
    allowed_services = set(policy["allowed_runtime_services"])
    unexpected = set(services) - allowed_services
    missing = allowed_services - set(services)
    if unexpected:
        failures.append(f"{label}: unapproved runtime services: {sorted(unexpected)}")
    if missing:
        failures.append(f"{label}: policy services missing: {sorted(missing)}")

    for section in ("volumes", "networks", "configs", "secrets"):
        values = document.get(section, {}) or {}
        for name, value in values.items():
            if isinstance(value, dict) and value.get("external") is True:
                failures.append(
                    f"{label}: external {section[:-1]} {name!r} is forbidden"
                )

    for name, service in services.items():
        if not isinstance(service, dict):
            failures.append(f"{label}: service {name!r} is malformed")
            continue
        deploy = service.get("deploy") or {}
        if not isinstance(deploy, dict) or deploy.get("replicas", 1) not in (0, 1):
            failures.append(f"{label}: service {name!r} requests scaling")


def check_compose(root: Path, policy: dict[str, Any], failures: list[str]) -> None:
    base_path = root / "infra" / "compose.yaml"
    base = load_yaml(base_path)
    check_compose_document(base, "infra/compose.yaml", policy, failures)
    overrides = sorted((root / "infra").glob("compose.*.yaml"))
    # Validate every supported active overlay combination. Eight overlays is a
    # deliberate bound against a repository change making policy validation
    # exponential or silently skipping a newly introduced deployment surface.
    if len(overrides) > 8:
        failures.append("infra: more than eight Compose overlays require policy review")
        return
    for count in range(1, len(overrides) + 1):
        for selected in itertools.combinations(overrides, count):
            document = copy.deepcopy(base)
            for path in selected:
                document = merge_compose(document, load_yaml(path))
            label = "infra/compose.yaml+" + "+".join(path.name for path in selected)
            check_compose_document(document, label, policy, failures)


def check_manifest_names(
    root: Path, policy: dict[str, Any], failures: list[str]
) -> None:
    forbidden = set(policy["forbidden_deployment_manifests"])
    ignored_parts = {".git", ".terraform", "node_modules", "vendor"}
    for path in root.rglob("*"):
        if not path.is_file() or any(part in ignored_parts for part in path.parts):
            continue
        if path.name in forbidden:
            failures.append(
                f"{path.relative_to(root)}: forbidden billable deployment manifest"
            )


def check_paid_environment(
    root: Path, policy: dict[str, Any], failures: list[str]
) -> None:
    forbidden = set(policy["forbidden_paid_runtime_environment"])
    assignment = re.compile(r"^\s*([A-Z][A-Z0-9_]*)\s*[:=]", re.MULTILINE)
    deployment_suffixes = {".env", ".example", ".yaml", ".yml", ".tf", ".json"}
    for base in (root / "infra", root / ".github" / "workflows"):
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in deployment_suffixes:
                continue
            names = set(
                assignment.findall(path.read_text(encoding="utf-8", errors="replace"))
            )
            disallowed = names & forbidden
            if disallowed:
                failures.append(
                    f"{path.relative_to(root)}: paid/metered runtime variables are forbidden: {sorted(disallowed)}"
                )


def check_provisioning_commands(
    root: Path, policy: dict[str, Any], failures: list[str]
) -> None:
    commands = policy["forbidden_provisioning_commands"]
    script_suffixes = {".sh", ".ps1"}
    for base in (root / "scripts", root / "infra"):
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or (
                path.suffix.lower() not in script_suffixes and path.name != "Makefile"
            ):
                continue
            lines = []
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                lines.append(stripped)
            active = "\n".join(lines)
            for command in commands:
                pattern = rf"(?m)(?:^|[;&|]\s*|\bexec\s+|\bsudo\s+){re.escape(command)}(?:\s|$)"
                if re.search(pattern, active):
                    failures.append(
                        f"{path.relative_to(root)}: automatic billable provisioning command {command!r} is forbidden"
                    )


def validate_policy(root: Path, requested_profile: str | None = None) -> list[str]:
    policy_path = root / "infra" / "policy" / "billing-policy.yml"
    policy = load_yaml(policy_path)
    if (
        not isinstance(policy, dict)
        or type(policy.get("schema_version")) is not int
        or policy.get("schema_version") != 2
    ):
        raise PolicyError("billing policy schema_version must be 2")
    expected_policy_keys = {
        "schema_version",
        "active_deployment",
        "deferred_deployment",
        "allowed_runtime_services",
        "allowed_terraform_providers",
        "allowed_terraform_resource_prefixes",
        "forbidden_deployment_manifests",
        "forbidden_paid_runtime_environment",
        "forbidden_provisioning_commands",
    }
    if set(policy) != expected_policy_keys:
        raise PolicyError("billing policy must contain only the reviewed top-level keys")
    active = policy.get("active_deployment", {})
    if not isinstance(active, dict):
        raise PolicyError("active_deployment must be a mapping")
    if set(active) != {"profile", "new_recurring_bills"}:
        raise PolicyError("active_deployment keys must match the reviewed schema")
    active_recurring = active.get("new_recurring_bills", {})
    if not isinstance(active_recurring, dict):
        raise PolicyError("active_deployment.new_recurring_bills must be a mapping")
    if set(active_recurring) != {"maximum"}:
        raise PolicyError(
            "active_deployment.new_recurring_bills keys must match the reviewed schema"
        )
    if (
        active.get("profile") != "owner_pc_beta"
        or type(active_recurring.get("maximum")) is not int
        or active_recurring.get("maximum") != 0
    ):
        raise PolicyError(
            "active owner_pc_beta policy must permit zero new recurring bills"
        )
    deferred = policy.get("deferred_deployment", {})
    if not isinstance(deferred, dict):
        raise PolicyError("deferred_deployment must be a mapping")
    if set(deferred) != {"profile", "authorized", "new_recurring_bills"}:
        raise PolicyError("deferred_deployment keys must match the reviewed schema")
    deferred_recurring = deferred.get("new_recurring_bills", {})
    if not isinstance(deferred_recurring, dict):
        raise PolicyError("deferred_deployment.new_recurring_bills must be a mapping")
    if set(deferred_recurring) != {
        "maximum",
        "only_allowed_kind",
        "minimum_monthly_price_usd",
        "maximum_monthly_price_usd",
        "required_confirmations",
    }:
        raise PolicyError(
            "deferred_deployment.new_recurring_bills keys must match the reviewed schema"
        )
    if (
        deferred.get("profile") != "fixed_price_vps"
        or deferred.get("authorized") is not False
        or type(deferred_recurring.get("maximum")) is not int
        or deferred_recurring.get("maximum") != 1
        or deferred_recurring.get("only_allowed_kind")
        != "fixed_price_monthly_vps"
        or type(deferred_recurring.get("minimum_monthly_price_usd")) is not int
        or deferred_recurring.get("minimum_monthly_price_usd") != 25
        or type(deferred_recurring.get("maximum_monthly_price_usd")) is not int
        or deferred_recurring.get("maximum_monthly_price_usd") != 75
        or deferred_recurring.get("required_confirmations")
        != [
            "VPS_FIXED_PRICE_CONFIRMED",
            "VPS_INCLUDED_BACKUP_CONFIRMED",
            "VPS_NO_AUTOMATIC_OVERAGE_CONFIRMED",
        ]
    ):
        raise PolicyError(
            "deferred fixed_price_vps policy must remain unauthorized and retain its strict bounds"
        )

    failures: list[str] = []
    if requested_profile is not None:
        if requested_profile == active["profile"]:
            pass
        elif requested_profile == deferred["profile"]:
            failures.append(
                "fixed_price_vps remains deferred and unauthorized; "
                "the owner must explicitly reopen hosting before this policy can change"
            )
        else:
            failures.append(f"unknown deployment profile: {requested_profile}")
    check_terraform(root, policy, failures)
    check_compose(root, policy, failures)
    check_manifest_names(root, policy, failures)
    check_paid_environment(root, policy, failures)
    check_provisioning_commands(root, policy, failures)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--deployment-profile", required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()

    try:
        failures = validate_policy(root, args.deployment_profile)
    except PolicyError as exc:
        print(f"billing policy error: {exc}", file=sys.stderr)
        return 2

    if failures:
        print("billing policy rejected this deployment:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "billing policy: PASS (owner-PC beta; zero new recurring bills; deferred VPS unauthorized)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
