#!/usr/bin/env python3
"""Validate profile-scoped infrastructure configuration and local secret files."""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


PLACEHOLDERS = ("REPLACE_ME", "REPLACE_WITH", "example.com", ".example")
COMMON_REQUIRED = {
    "DEPLOYMENT_PROFILE",
    "APP_ENV",
    "DATA_ROOT",
    "SECRETS_DIR",
    "WORKSPACE_IO_DEVICE",
    "MAX_RUNNING_WORKSPACES",
    "WORKSPACE_CONTROL_SUBNET",
    "PUBLIC_BIND_ADDRESS",
    "PUBLIC_HTTP_PORT",
    "PUBLIC_HTTPS_PORT",
    "API_HOST",
    "API_SITE_ADDRESS",
    "BASE_DOMAIN",
    "PREVIEW_DOMAIN",
    "PREVIEW_SITE_ADDRESS",
    "PASSKEY_RP_ID",
    "PUBLIC_ORIGIN",
    "PASSKEY_ORIGINS",
    "PUBLIC_HEALTH_URL",
    "GITHUB_ENABLED",
    "APNS_ENABLED",
    "CODER_BIND_ADDRESS",
    "CODER_BIND_PORT",
    "CODER_ACCESS_URL",
    "CODER_WORKSPACE_CONNECTIVITY_CONFIRMED",
    "CODER_ORGANIZATION_ID",
    "CODER_TEMPLATE_ID",
    "CODER_OWNER_ID",
    "POSTGRES_ADMIN_USER",
    "APP_DB_USER",
    "APP_DB_NAME",
    "CODER_DB_USER",
    "CODER_DB_NAME",
    "CONTROL_PLANE_IMAGE_TAG",
    "CONTROL_PLANE_PACKAGE",
}
OWNER_PC_STORAGE_IMAGE = "/var/lib/codex-mobile-owner-pc/workspace-storage.xfs"
OWNER_PC_STORAGE_GIB = 64
OWNER_PC_STORAGE_BYTES = OWNER_PC_STORAGE_GIB * 1024 * 1024 * 1024
OWNER_PC_CODER_ADDRESS = "10.86.0.1"
OWNER_PC_MIN_MEMORY_MIB = 5632
OWNER_PC_MIN_CPUS = 6
OWNER_PC_MIN_D_FREE_GIB = 128
VPS_REQUIRED = {
    "VPS_PROVIDER",
    "VPS_PLAN",
    "VPS_REGION",
    "VPS_MONTHLY_PRICE_USD",
    "VPS_FIXED_PRICE_CONFIRMED",
    "VPS_INCLUDED_BACKUP_CONFIRMED",
    "VPS_NO_AUTOMATIC_OVERAGE_CONFIRMED",
}
SECRET_FILES = (
    "postgres_admin_password",
    "app_db_password",
    "coder_db_password",
    "app_database_url",
    "coder_api_token",
    "control_plane_master_key",
    "session_pepper",
    "coder_provisioner_key",
)
GITHUB_SECRET_FILES = (
    "github_client_secret",
    "github_webhook_secret",
    "github_app_private_key",
)
APNS_SECRET_FILES = (
    "apns_sandbox_private_key",
    "apns_production_private_key",
)
INTEGRATION_RUNTIME_SECRET_PATHS = {
    "GITHUB_CLIENT_SECRET_FILE": "/run/secrets/github_client_secret",
    "GITHUB_WEBHOOK_SECRET_FILE": "/run/secrets/github_webhook_secret",
    "GITHUB_APP_PRIVATE_KEY_FILE": "/run/secrets/github_app_private_key",
    "APNS_SANDBOX_PRIVATE_KEY_FILE": "/run/secrets/apns_sandbox_private_key",
    "APNS_PRODUCTION_PRIVATE_KEY_FILE": "/run/secrets/apns_production_private_key",
}
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def _pem_boundary(label: bytes) -> tuple[bytes, bytes]:
    delimiter = b"-" * 5
    return (
        delimiter + b"BEGIN " + label + delimiter,
        delimiter + b"END " + label + delimiter,
    )


PEM_PRIVATE_KEY_BOUNDARIES = dict(
    _pem_boundary(label)
    for label in (b"PRIVATE KEY", b"RSA PRIVATE KEY", b"EC PRIVATE KEY")
)
MAX_SECRET_FILE_BYTES = 64 * 1024


def parse_env(path: Path) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    failures: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {}, [f"cannot read {path}: {exc}"]
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            failures.append(f"line {number}: expected KEY=value")
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            failures.append(f"line {number}: invalid variable name {key!r}")
            continue
        if key in values:
            failures.append(f"line {number}: duplicate variable {key}")
            continue
        values[key] = value.strip()
    return values, failures


def as_port(values: dict[str, str], name: str, failures: list[str]) -> int | None:
    try:
        port = int(values.get(name, ""))
    except ValueError:
        failures.append(f"{name} must be an integer")
        return None
    if not 1 <= port <= 65535:
        failures.append(f"{name} must be between 1 and 65535")
        return None
    return port


def split_url(raw: str, name: str, failures: list[str]):
    try:
        return urlsplit(raw)
    except ValueError:
        failures.append(f"{name} must be a valid URL")
        return urlsplit("")


def url_port(parsed, name: str, failures: list[str]) -> int | None:
    try:
        return parsed.port
    except ValueError:
        failures.append(f"{name} has an invalid port")
        return None


def validate_domains(values: dict[str, str], failures: list[str]) -> None:
    host = values.get("API_HOST", "").rstrip(".").lower()
    base = values.get("BASE_DOMAIN", "").rstrip(".").lower()
    preview = values.get("PREVIEW_DOMAIN", "").rstrip(".").lower()
    rp_id = values.get("PASSKEY_RP_ID", "").rstrip(".").lower()
    domain = re.compile(
        r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
    )
    for name, value in (
        ("API_HOST", host),
        ("BASE_DOMAIN", base),
        ("PASSKEY_RP_ID", rp_id),
    ):
        if not domain.fullmatch(value):
            failures.append(f"{name} must be a fully qualified DNS name")
    if host != base and not host.endswith("." + base):
        failures.append("API_HOST must equal or be a subdomain of BASE_DOMAIN")
    if preview != "preview." + base:
        failures.append(
            "PREVIEW_DOMAIN must be exactly preview.<BASE_DOMAIN> without a wildcard"
        )
    if values.get("PREVIEW_SITE_ADDRESS", "").rstrip(".").lower() != "*." + preview:
        failures.append(
            "production PREVIEW_SITE_ADDRESS must be exactly *.<PREVIEW_DOMAIN> so Caddy routes preview hosts"
        )
    if rp_id != base:
        failures.append("PASSKEY_RP_ID must equal BASE_DOMAIN for stable passkey scope")
    origin = split_url(values.get("PUBLIC_ORIGIN", ""), "PUBLIC_ORIGIN", failures)
    if (
        origin.scheme != "https"
        or origin.hostname != host
        or origin.path not in ("", "/")
    ):
        failures.append("PUBLIC_ORIGIN must be the HTTPS origin for API_HOST")
    origin_port = url_port(origin, "PUBLIC_ORIGIN", failures)
    if (
        origin.username
        or origin.password
        or origin.query
        or origin.fragment
        or origin_port not in (None, 443)
    ):
        failures.append(
            "PUBLIC_ORIGIN cannot contain credentials, a nonstandard port, a query, or a fragment"
        )
    passkey_origins = [
        part.strip()
        for part in values.get("PASSKEY_ORIGINS", "").split(",")
        if part.strip()
    ]
    if passkey_origins != [values.get("PUBLIC_ORIGIN", "")]:
        failures.append(
            "PASSKEY_ORIGINS must contain exactly PUBLIC_ORIGIN for the single public control plane"
        )
    health = split_url(
        values.get("PUBLIC_HEALTH_URL", ""), "PUBLIC_HEALTH_URL", failures
    )
    health_port = url_port(health, "PUBLIC_HEALTH_URL", failures)
    if (
        health.scheme != "https"
        or health.hostname != host
        or health.path != "/healthz"
        or health_port not in (None, 443)
    ):
        failures.append("PUBLIC_HEALTH_URL must be https://<API_HOST>/healthz")
    if health.username or health.password or health.query or health.fragment:
        failures.append(
            "PUBLIC_HEALTH_URL cannot contain credentials, a query, or a fragment"
        )
    if values.get("API_SITE_ADDRESS", "").rstrip(".").lower() != host:
        failures.append(
            "production API_SITE_ADDRESS must equal API_HOST so Caddy manages HTTPS"
        )


def validate_bindings(values: dict[str, str], failures: list[str]) -> None:
    public_address = values.get("PUBLIC_BIND_ADDRESS", "")
    try:
        public_ip = ipaddress.ip_address(public_address)
        if (
            public_ip.version != 4
            or public_ip.is_loopback
            or public_ip.is_link_local
            or public_ip.is_multicast
        ):
            failures.append(
                "PUBLIC_BIND_ADDRESS must be a non-loopback IPv4 address or 0.0.0.0"
            )
    except ValueError:
        failures.append("PUBLIC_BIND_ADDRESS must be an IP address")

    coder_address = values.get("CODER_BIND_ADDRESS", "")
    try:
        coder_ip = ipaddress.ip_address(coder_address)
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if not any(coder_ip in network for network in private_networks):
            failures.append(
                "production CODER_BIND_ADDRESS must be a non-loopback RFC1918 private IP"
            )
        if coder_ip.is_unspecified or coder_ip.is_multicast or coder_ip.is_link_local:
            failures.append(
                "CODER_BIND_ADDRESS cannot be wildcard, link-local, or multicast"
            )
    except ValueError:
        failures.append("CODER_BIND_ADDRESS must be a literal private IP")
        coder_ip = None

    try:
        control_network = ipaddress.ip_network(
            values.get("WORKSPACE_CONTROL_SUBNET", ""), strict=True
        )
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if (
            not isinstance(control_network, ipaddress.IPv4Network)
            or not any(control_network.subnet_of(item) for item in private_networks)
            or not 24 <= control_network.prefixlen <= 28
        ):
            failures.append(
                "WORKSPACE_CONTROL_SUBNET must be an RFC1918 IPv4 /24 through /28"
            )
        elif coder_ip is not None and coder_ip in control_network:
            failures.append(
                "WORKSPACE_CONTROL_SUBNET must not contain CODER_BIND_ADDRESS"
            )
    except ValueError:
        failures.append("WORKSPACE_CONTROL_SUBNET must be a canonical IPv4 CIDR")

    coder_port = as_port(values, "CODER_BIND_PORT", failures)
    public_http_port = as_port(values, "PUBLIC_HTTP_PORT", failures)
    public_https_port = as_port(values, "PUBLIC_HTTPS_PORT", failures)
    if public_http_port != 80 or public_https_port != 443:
        failures.append(
            "production Caddy must publish standard TCP ports 80 and 443 for ACME/TLS"
        )
    if coder_port in {80, 443, 2019, 2112, 2113, 5432, 8080}:
        failures.append(
            "CODER_BIND_PORT conflicts with a reserved proxy, database, API, admin, or metrics port"
        )
    access = split_url(values.get("CODER_ACCESS_URL", ""), "CODER_ACCESS_URL", failures)
    # Coder is intentionally a private, cleartext listener in Compose. TLS
    # terminates only at Caddy for the public control plane, so accepting an
    # HTTPS URL here would create a configuration that cannot work at runtime.
    if access.scheme != "http" or access.hostname is None:
        failures.append(
            "CODER_ACCESS_URL must be an HTTP URL for the private Coder listener"
        )
    else:
        try:
            access_ip = ipaddress.ip_address(access.hostname)
            if coder_ip is not None and access_ip != coder_ip:
                failures.append("CODER_ACCESS_URL host must equal CODER_BIND_ADDRESS")
        except ValueError:
            failures.append("CODER_ACCESS_URL must use the literal private bind IP")
    access_port = url_port(access, "CODER_ACCESS_URL", failures)
    if coder_port is not None and access_port != coder_port:
        failures.append("CODER_ACCESS_URL port must equal CODER_BIND_PORT")
    if (
        access.path not in ("", "/")
        or access.query
        or access.fragment
        or access.username
    ):
        failures.append("CODER_ACCESS_URL must be a bare origin without credentials")


def validate_integrations(values: dict[str, str], failures: list[str]) -> None:
    if values.get("GITHUB_ENABLED", "").lower() == "true":
        required = (
            "GITHUB_APP_ID",
            "GITHUB_CLIENT_ID",
            "GITHUB_CLIENT_SECRET_FILE",
            "GITHUB_WEBHOOK_SECRET_FILE",
            "GITHUB_APP_PRIVATE_KEY_FILE",
        )
        missing = [name for name in required if not values.get(name)]
        if missing:
            failures.append(
                f"GitHub is enabled but variables are missing: {', '.join(missing)}"
            )
        try:
            if int(values.get("GITHUB_APP_ID", "0")) <= 0:
                raise ValueError
        except ValueError:
            failures.append("GITHUB_APP_ID must be a positive integer")
        if not re.fullmatch(
            r"[A-Za-z0-9._-]{8,255}", values.get("GITHUB_CLIENT_ID", "")
        ):
            failures.append("GITHUB_CLIENT_ID has an invalid format")
        for name in required[2:]:
            if values.get(name) != INTEGRATION_RUNTIME_SECRET_PATHS[name]:
                failures.append(
                    f"{name} must equal {INTEGRATION_RUNTIME_SECRET_PATHS[name]}"
                )

    if values.get("APNS_ENABLED", "").lower() == "true":
        required = (
            "APNS_TEAM_ID",
            "APNS_KEY_ID_SANDBOX",
            "APNS_KEY_ID_PRODUCTION",
            "IOS_BUNDLE_ID",
            "APNS_SANDBOX_PRIVATE_KEY_FILE",
            "APNS_PRODUCTION_PRIVATE_KEY_FILE",
        )
        missing = [name for name in required if not values.get(name)]
        if missing:
            failures.append(
                f"APNs is enabled but variables are missing: {', '.join(missing)}"
            )
        for name in required[:3]:
            if not re.fullmatch(r"[A-Z0-9]{10}", values.get(name, "")):
                failures.append(f"{name} must be a 10-character Apple identifier")
        if not re.fullmatch(
            r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", values.get("IOS_BUNDLE_ID", "")
        ):
            failures.append("IOS_BUNDLE_ID must be a reverse-DNS identifier")
        for name in required[4:]:
            if values.get(name) != INTEGRATION_RUNTIME_SECRET_PATHS[name]:
                failures.append(
                    f"{name} must equal {INTEGRATION_RUNTIME_SECRET_PATHS[name]}"
                )


def validate_secret_files(values: dict[str, str], failures: list[str]) -> None:
    secret_dir = Path(values["SECRETS_DIR"])
    contents: dict[str, bytes] = {}
    production = values.get("APP_ENV") == "production"
    try:
        directory_info = secret_dir.lstat()
    except OSError as exc:
        failures.append(f"cannot inspect secret directory {secret_dir}: {exc}")
        return
    if stat.S_ISLNK(directory_info.st_mode):
        failures.append(f"{secret_dir} must not be a symbolic link")
        return
    if not stat.S_ISDIR(directory_info.st_mode):
        failures.append(f"{secret_dir} must be a directory")
        return
    if os.name == "posix":
        if stat.S_IMODE(directory_info.st_mode) != 0o700:
            failures.append(f"{secret_dir} must have exact mode 0700")
        if production and (directory_info.st_uid, directory_info.st_gid) != (0, 0):
            failures.append(f"{secret_dir} must be owned by root:root")
        if production:
            parent = secret_dir.parent
            while True:
                try:
                    parent_info = parent.lstat()
                except OSError as exc:
                    failures.append(f"cannot inspect secret parent {parent}: {exc}")
                    break
                if stat.S_ISLNK(parent_info.st_mode):
                    failures.append(
                        f"secret parent {parent} must not be a symbolic link"
                    )
                elif not stat.S_ISDIR(parent_info.st_mode):
                    failures.append(f"secret parent {parent} must be a directory")
                else:
                    if (parent_info.st_uid, parent_info.st_gid) != (0, 0):
                        failures.append(
                            f"secret parent {parent} must be owned by root:root"
                        )
                    if stat.S_IMODE(parent_info.st_mode) & 0o022:
                        failures.append(
                            f"secret parent {parent} must not be writable by group/other"
                        )
                if parent == parent.parent:
                    break
                parent = parent.parent

    secret_files = list(SECRET_FILES)
    if values.get("GITHUB_ENABLED", "").lower() == "true":
        secret_files.extend(GITHUB_SECRET_FILES)
    if values.get("APNS_ENABLED", "").lower() == "true":
        secret_files.extend(APNS_SECRET_FILES)
    for name in secret_files:
        path = secret_dir / name
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                failures.append(f"{path} must not be a symbolic link")
                continue
            if not stat.S_ISREG(info.st_mode):
                failures.append(f"{path} must be a regular file")
                continue
            if os.name == "posix":
                if stat.S_IMODE(info.st_mode) != 0o444:
                    failures.append(
                        f"{path} must have exact mode 0444 so its read-only Docker secret mount is usable by non-root services"
                    )
                if production and (info.st_uid, info.st_gid) != (0, 0):
                    failures.append(f"{path} must be owned by root:root")
                if info.st_nlink != 1:
                    failures.append(f"{path} must have exactly one hard link")

            flags = os.O_RDONLY
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                opened_info = os.fstat(descriptor)
                if (opened_info.st_dev, opened_info.st_ino) != (
                    info.st_dev,
                    info.st_ino,
                ) or not stat.S_ISREG(opened_info.st_mode):
                    failures.append(f"{path} changed while it was being opened")
                    continue
                if (
                    stat.S_IMODE(opened_info.st_mode) != stat.S_IMODE(info.st_mode)
                    or opened_info.st_nlink != info.st_nlink
                    or (opened_info.st_uid, opened_info.st_gid)
                    != (info.st_uid, info.st_gid)
                ):
                    failures.append(
                        f"{path} metadata changed while it was being opened"
                    )
                    continue
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    data = stream.read(MAX_SECRET_FILE_BYTES + 1)
                finished_info = os.fstat(descriptor)
                if (
                    finished_info.st_size != opened_info.st_size
                    or finished_info.st_mtime_ns != opened_info.st_mtime_ns
                    or finished_info.st_ctime_ns != opened_info.st_ctime_ns
                ):
                    failures.append(f"{path} changed while it was being read")
                    continue
            finally:
                os.close(descriptor)
            if len(data) > MAX_SECRET_FILE_BYTES:
                failures.append(
                    f"{path} exceeds the {MAX_SECRET_FILE_BYTES}-byte secret limit"
                )
                continue
            data = data.rstrip(b"\r\n")
        except OSError as exc:
            failures.append(f"cannot read secret {path}: {exc}")
            continue
        if not data:
            failures.append(f"{path} is empty")
        if any(marker.encode() in data for marker in PLACEHOLDERS):
            failures.append(f"{path} still contains a placeholder")
        contents[name] = data

    for name in ("postgres_admin_password", "app_db_password", "coder_db_password"):
        if len(contents.get(name, b"")) < 24:
            failures.append(
                f"{name} must contain at least 24 bytes of entropy-safe text"
            )
    for name in ("control_plane_master_key", "session_pepper"):
        encoded = contents.get(name, b"")
        decoded = encoded
        if len(encoded) != 32:
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                decoded = b""
        if len(decoded) != 32:
            failures.append(
                f"{name} must contain exactly 32 raw bytes or their standard base64 encoding"
            )
    for name in ("coder_api_token", "coder_provisioner_key"):
        if len(contents.get(name, b"")) < 20:
            failures.append(f"{name} is too short")
    for name in ("github_client_secret", "github_webhook_secret"):
        if name in secret_files and len(contents.get(name, b"")) < 20:
            failures.append(f"{name} is too short")
    for name in (
        "github_app_private_key",
        "apns_sandbox_private_key",
        "apns_production_private_key",
    ):
        if name in secret_files:
            data = contents.get(name, b"")
            normalized = data.replace(b"\r\n", b"\n")
            valid_pem = any(
                normalized.startswith(begin + b"\n")
                and normalized.endswith(b"\n" + end)
                for begin, end in PEM_PRIVATE_KEY_BOUNDARIES.items()
            )
            if not valid_pem:
                failures.append(f"{name} must contain a PEM private key")

    database_url = contents.get("app_database_url", b"").decode(
        "utf-8", errors="replace"
    )
    parsed = split_url(database_url, "app_database_url", failures)
    database_port = url_port(parsed, "app_database_url", failures)
    expected_user = values.get("APP_DB_USER")
    expected_db = values.get("APP_DB_NAME")
    if (
        parsed.scheme not in ("postgres", "postgresql")
        or parsed.hostname != "postgres"
        or database_port != 5432
    ):
        failures.append("app_database_url must target the local postgres:5432 service")
    if unquote(parsed.username or "") != expected_user or parsed.path != "/" + str(
        expected_db
    ):
        failures.append(
            "app_database_url role/database must match APP_DB_USER and APP_DB_NAME"
        )
    if unquote(parsed.password or "").encode() != contents.get("app_db_password", b""):
        failures.append("app_database_url password must match app_db_password")
    if parsed.query != "sslmode=disable" or parsed.fragment:
        failures.append(
            "app_database_url must use only sslmode=disable on the private Compose network"
        )


def validate(
    values: dict[str, str],
    env_path: Path,
    skip_secrets: bool,
    coder_bootstrap: bool = False,
) -> list[str]:
    failures: list[str] = []
    profile = values.get("DEPLOYMENT_PROFILE", "")
    if profile == "fixed_price_vps":
        return [
            "fixed_price_vps remains deferred and unauthorized; "
            "do not supply VPS checkout metadata unless the owner explicitly reopens hosting"
        ]
    required = COMMON_REQUIRED
    missing = sorted(required - values.keys())
    if missing:
        failures.append(f"missing required variables: {', '.join(missing)}")
    if profile not in {"owner_pc_beta", "fixed_price_vps"}:
        failures.append(
            "DEPLOYMENT_PROFILE must be owner_pc_beta or fixed_price_vps; no profile is inferred"
        )
    if profile == "owner_pc_beta":
        unexpected_vps = sorted(VPS_REQUIRED & values.keys())
        if unexpected_vps:
            failures.append(
                "owner_pc_beta must omit deferred VPS checkout variables: "
                + ", ".join(unexpected_vps)
            )
        expected_owner_values = {
            "DATA_ROOT": "/srv/codex-mobile",
            "OWNER_PC_STORAGE_IMAGE": OWNER_PC_STORAGE_IMAGE,
            "OWNER_PC_STORAGE_GIB": str(OWNER_PC_STORAGE_GIB),
            "MAX_RUNNING_WORKSPACES": "1",
            "CODER_BIND_ADDRESS": OWNER_PC_CODER_ADDRESS,
        }
        for name, expected in expected_owner_values.items():
            if values.get(name) != expected:
                failures.append(f"owner_pc_beta requires {name}={expected}")
    for key, value in values.items():
        if not value:
            failures.append(f"{key} cannot be empty")
        bootstrap_placeholder = coder_bootstrap and key in {
            "CODER_ORGANIZATION_ID",
            "CODER_TEMPLATE_ID",
        }
        if not bootstrap_placeholder and any(
            marker.lower() in value.lower() for marker in PLACEHOLDERS
        ):
            failures.append(f"{key} still contains a placeholder/example value")
    if missing or profile not in {"owner_pc_beta", "fixed_price_vps"}:
        return failures

    if values["APP_ENV"] != "production":
        failures.append("APP_ENV must be production")
    for name in ("GITHUB_ENABLED", "APNS_ENABLED"):
        if values[name].lower() not in ("true", "false"):
            failures.append(f"{name} must be true or false")
    connectivity = values["CODER_WORKSPACE_CONNECTIVITY_CONFIRMED"].lower()
    if coder_bootstrap and connectivity not in ("true", "false"):
        failures.append("CODER_WORKSPACE_CONNECTIVITY_CONFIRMED must be true or false")
    elif not coder_bootstrap and connectivity != "true":
        failures.append(
            "CODER_WORKSPACE_CONNECTIVITY_CONFIRMED must be true after the Linux runtime spike"
        )
    for name in ("DATA_ROOT", "SECRETS_DIR"):
        path = PurePosixPath(values[name])
        if not path.is_absolute() or ".." in path.parts:
            failures.append(f"{name} must be an absolute normalized POSIX path")
    if not re.fullmatch(r"/dev/[A-Za-z0-9._/+:-]+", values["WORKSPACE_IO_DEVICE"]):
        failures.append(
            "WORKSPACE_IO_DEVICE must be an explicit normalized /dev path; conventional device names are never guessed"
        )
    if Path(values["SECRETS_DIR"]).resolve() == env_path.resolve().parent:
        failures.append(
            "SECRETS_DIR must be separate from the environment-file directory"
        )

    validate_domains(values, failures)
    validate_bindings(values, failures)
    validate_integrations(values, failures)
    for name in (
        "POSTGRES_ADMIN_USER",
        "APP_DB_USER",
        "APP_DB_NAME",
        "CODER_DB_USER",
        "CODER_DB_NAME",
    ):
        if not IDENTIFIER.fullmatch(values[name]):
            failures.append(f"{name} must be a lowercase PostgreSQL identifier")
    if (
        len(
            {
                values["POSTGRES_ADMIN_USER"],
                values["APP_DB_USER"],
                values["CODER_DB_USER"],
            }
        )
        != 3
    ):
        failures.append("PostgreSQL admin, app, and Coder roles must be distinct")
    if values["APP_DB_NAME"] == values["CODER_DB_NAME"]:
        failures.append("app and Coder databases must be distinct")
    uuid = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    for name in ("CODER_ORGANIZATION_ID", "CODER_TEMPLATE_ID"):
        value = values[name]
        bootstrap_sentinel = coder_bootstrap and value.startswith("REPLACE_ME_")
        if not bootstrap_sentinel and not uuid.fullmatch(value.lower()):
            failures.append(f"{name} must be a canonical UUID")
    if values["CODER_OWNER_ID"] != "me" and not uuid.fullmatch(
        values["CODER_OWNER_ID"].lower()
    ):
        failures.append("CODER_OWNER_ID must be 'me' or a canonical UUID")
    if not re.fullmatch(r"sha-[0-9a-f]{7,64}", values["CONTROL_PLANE_IMAGE_TAG"]):
        failures.append("CONTROL_PLANE_IMAGE_TAG must be an immutable sha-<commit> tag")
    if values["CONTROL_PLANE_PACKAGE"] != "./services/control-plane/cmd/control-plane":
        failures.append(
            "CONTROL_PLANE_PACKAGE is not the reviewed production entrypoint"
        )

    if not skip_secrets:
        validate_secret_files(values, failures)
    return failures


def validate_workspace_storage(
    data_root: str,
    workspace_io_device: str,
    run=subprocess.run,
    stat_path=os.stat,
    *,
    profile: str = "fixed_price_vps",
    owner_storage_image: str = "",
    owner_storage_gib: int = 0,
    lstat_path=os.lstat,
) -> list[str]:
    """Validate the target host mount used by Podman's project quotas."""
    mount_command = (
        ["nsenter", "--target", "1", "--mount", "--"]
        if profile == "owner_pc_beta"
        else []
    )
    try:
        result = run(
            mount_command
            + [
                "findmnt",
                "--noheadings",
                "--output",
                "TARGET,FSTYPE,OPTIONS,SOURCE",
                "--target",
                data_root,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return [f"cannot inspect workspace storage with findmnt: {exc}"]
    if result.returncode:
        detail = result.stderr.strip()
        return [f"cannot inspect DATA_ROOT mount{': ' + detail if detail else ''}"]
    fields = result.stdout.strip().split(maxsplit=3)
    if len(fields) != 4:
        return ["findmnt returned an invalid DATA_ROOT mount record"]
    target, filesystem, raw_options, source = fields
    failures: list[str] = []
    if target != data_root:
        failures.append(
            f"DATA_ROOT must be its own operator-mounted filesystem (found mount {target})"
        )
    if filesystem != "xfs":
        failures.append(
            f"DATA_ROOT must use XFS for Podman project quotas (found {filesystem})"
        )
    options = set(raw_options.split(","))
    if not options.intersection({"pquota", "prjquota"}):
        failures.append("DATA_ROOT XFS mount must enable pquota or prjquota")
    device_info = None
    try:
        device_info = stat_path(workspace_io_device)
    except OSError as exc:
        failures.append(f"cannot inspect WORKSPACE_IO_DEVICE: {exc}")
    else:
        if not stat.S_ISBLK(device_info.st_mode):
            failures.append("WORKSPACE_IO_DEVICE must be an existing block device")
    if profile != "owner_pc_beta":
        if source != workspace_io_device:
            failures.append(
                "WORKSPACE_IO_DEVICE must exactly match the DATA_ROOT findmnt source; refusing to guess a throttle device"
            )
        return failures

    if owner_storage_image != OWNER_PC_STORAGE_IMAGE:
        failures.append(
            f"owner_pc_beta storage image must be {OWNER_PC_STORAGE_IMAGE}"
        )
    if owner_storage_gib != OWNER_PC_STORAGE_GIB:
        failures.append(
            f"owner_pc_beta storage image must be exactly {OWNER_PC_STORAGE_GIB} GiB"
        )
    try:
        inode_default = run(
            mount_command
            + [
                "xfs_quota",
                "-x",
                "-c",
                "quota -p -i -n -N -v 0",
                data_root,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        failures.append(f"cannot inspect XFS default project inode ceiling: {exc}")
    else:
        valid_default = any(
            len(fields) >= 4 and fields[2:4] == ["1048576", "1048576"]
            for fields in (
                line.split() for line in inode_default.stdout.splitlines()
            )
        )
        if inode_default.returncode or not valid_default:
            failures.append(
                "owner_pc_beta requires the 1048576-inode default XFS project ceiling"
            )
    image = PurePosixPath(owner_storage_image)
    if not image.is_absolute() or str(image).startswith("/mnt/") or ".." in image.parts:
        failures.append(
            "owner-PC storage image must use the exact Linux-native absolute path"
        )
    try:
        image_info = lstat_path(image)
    except OSError as exc:
        failures.append(f"cannot inspect owner-PC storage image: {exc}")
        image_info = None
    if image_info is not None:
        if stat.S_ISLNK(image_info.st_mode) or not stat.S_ISREG(image_info.st_mode):
            failures.append("owner-PC storage image must be a non-symlink regular file")
        if stat.S_IMODE(image_info.st_mode) != 0o600:
            failures.append("owner-PC storage image must have exact mode 0600")
        if os.name == "posix" and (image_info.st_uid, image_info.st_gid) != (0, 0):
            failures.append("owner-PC storage image must be owned by root:root")
        if image_info.st_nlink != 1:
            failures.append("owner-PC storage image must have exactly one hard link")
        if image_info.st_size != OWNER_PC_STORAGE_BYTES:
            failures.append(
                f"owner-PC storage image must be exactly {OWNER_PC_STORAGE_GIB} GiB"
            )
        if image_info.st_blocks * 512 < image_info.st_size:
            failures.append("owner-PC storage image must be fully allocated, not sparse")
    try:
        source_info = stat_path(source)
    except OSError as exc:
        failures.append(f"cannot inspect owner-PC loop source: {exc}")
        source_info = None
    if source_info is not None and not stat.S_ISBLK(source_info.st_mode):
        failures.append("owner-PC XFS mount source must be a loop block device")
    if not re.fullmatch(r"/dev/loop[0-9]+", source):
        failures.append("owner-PC XFS mount source must be an explicit loop device")
    try:
        loop = run(
            ["losetup", "--noheadings", "--output", "BACK-FILE", source],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        failures.append(f"cannot inspect owner-PC loop backing file: {exc}")
    else:
        if loop.returncode or os.path.realpath(loop.stdout.strip()) != os.path.realpath(
            owner_storage_image
        ):
            failures.append(
                "owner-PC XFS loop device must use the exact configured backing file"
            )
    try:
        image_mount = run(
            [
                "findmnt",
                "--noheadings",
                "--output",
                "SOURCE",
                "--target",
                owner_storage_image,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        failures.append(f"cannot inspect owner-PC image filesystem: {exc}")
    else:
        parent_source = image_mount.stdout.strip()
        if image_mount.returncode or not parent_source.startswith("/dev/"):
            failures.append(
                "owner-PC storage image must reside on a Linux-native block filesystem"
            )
        else:
            try:
                parent_info = stat_path(parent_source)
            except OSError as exc:
                failures.append(f"cannot inspect owner-PC image device: {exc}")
            else:
                if (
                    not stat.S_ISBLK(parent_info.st_mode)
                    or device_info is None
                    or not stat.S_ISBLK(device_info.st_mode)
                    or parent_info.st_rdev != device_info.st_rdev
                ):
                    failures.append(
                        "WORKSPACE_IO_DEVICE must identify the block device backing the owner-PC storage image"
                    )
    return failures


def validate_owner_pc_host(
    values: dict[str, str],
    *,
    read_text=lambda path: Path(path).read_text(encoding="utf-8"),
    cpu_count=os.cpu_count,
    statvfs=None,
) -> list[str]:
    """Validate the measured WSL/cgroup envelope for the one-workspace beta."""
    # owner_pc_beta is approved; do not substitute fixed_price_vps when
    # reconciling stale deployment prose.
    failures: list[str] = []
    try:
        release = read_text("/proc/sys/kernel/osrelease").strip().lower()
    except OSError as exc:
        failures.append(f"cannot inspect WSL kernel release: {exc}")
    else:
        if "microsoft" not in release:
            failures.append("owner_pc_beta requires WSL2")
    try:
        os_release = read_text("/etc/os-release")
    except OSError as exc:
        failures.append(f"cannot inspect Ubuntu release: {exc}")
    else:
        if 'ID=ubuntu' not in os_release or 'VERSION_ID="24.04"' not in os_release:
            failures.append("owner_pc_beta requires Ubuntu 24.04")
    for database in ("/etc/subuid", "/etc/subgid"):
        try:
            records = [
                line
                for line in read_text(database).splitlines()
                if line.startswith("containers:")
            ]
        except OSError as exc:
            failures.append(f"cannot inspect {database}: {exc}")
        else:
            if records != ["containers:1000000:1048576"]:
                failures.append(
                    f"{database} must contain exactly containers:1000000:1048576"
                )
    cpus = cpu_count()
    if cpus is None or cpus < OWNER_PC_MIN_CPUS:
        failures.append(
            f"owner_pc_beta requires at least {OWNER_PC_MIN_CPUS} WSL CPUs"
        )
    try:
        meminfo = read_text("/proc/meminfo")
        match = re.search(r"(?m)^MemTotal:\s+([0-9]+)\s+kB$", meminfo)
        memory_mib = int(match.group(1)) // 1024 if match else 0
    except (OSError, ValueError) as exc:
        failures.append(f"cannot inspect WSL memory: {exc}")
    else:
        if memory_mib < OWNER_PC_MIN_MEMORY_MIB:
            failures.append(
                f"owner_pc_beta requires at least {OWNER_PC_MIN_MEMORY_MIB} MiB WSL memory"
            )
    try:
        mountinfo = read_text("/proc/self/mountinfo")
        controllers = read_text("/sys/fs/cgroup/cgroup.controllers").split()
    except OSError as exc:
        failures.append(f"cannot inspect cgroup v2 controllers: {exc}")
    else:
        if " - cgroup2 cgroup2 " not in mountinfo:
            failures.append("owner_pc_beta requires the unified cgroup v2 hierarchy")
        missing = sorted({"cpu", "io", "memory", "pids"} - set(controllers))
        if missing:
            failures.append(
                "owner_pc_beta is missing cgroup v2 controllers: "
                + ", ".join(missing)
            )
    statvfs_fn = statvfs or getattr(os, "statvfs", None)
    if statvfs_fn is None:
        failures.append("cannot inspect D: free space outside a POSIX host")
    else:
        try:
            d_drive = statvfs_fn("/mnt/d")
            d_free_gib = (d_drive.f_bavail * d_drive.f_frsize) // (1024**3)
        except OSError as exc:
            failures.append(f"cannot inspect D: free space from WSL: {exc}")
        else:
            if d_free_gib < OWNER_PC_MIN_D_FREE_GIB:
                failures.append(
                    f"owner_pc_beta requires at least {OWNER_PC_MIN_D_FREE_GIB} GiB free on D:"
                )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--skip-secret-files", action="store_true", help="static validation only"
    )
    parser.add_argument(
        "--coder-bootstrap",
        action="store_true",
        help="allow only the organization/template placeholders and unconfirmed connectivity needed before initial Coder setup",
    )
    args = parser.parse_args()

    values, failures = parse_env(args.env_file)
    failures.extend(
        validate(values, args.env_file, args.skip_secret_files, args.coder_bootstrap)
    )
    if not failures:
        failures.extend(
            validate_workspace_storage(
                values["DATA_ROOT"],
                values["WORKSPACE_IO_DEVICE"],
                profile=values["DEPLOYMENT_PROFILE"],
                owner_storage_image=values.get("OWNER_PC_STORAGE_IMAGE", ""),
                owner_storage_gib=int(values.get("OWNER_PC_STORAGE_GIB", "0")),
            )
        )
    if not failures and values["DEPLOYMENT_PROFILE"] == "owner_pc_beta":
        failures.extend(validate_owner_pc_host(values))
    if not failures:
        policy = subprocess.run(
            [
                sys.executable,
                str(args.repo_root / "scripts" / "check-billing-policy.py"),
                "--repo-root",
                str(args.repo_root),
                "--deployment-profile",
                values["DEPLOYMENT_PROFILE"],
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if policy.returncode:
            failures.append(policy.stderr.strip() or "billing policy check failed")

    if failures:
        print("infrastructure preflight failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("infrastructure preflight: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
