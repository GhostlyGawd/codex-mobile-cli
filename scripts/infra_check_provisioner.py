#!/usr/bin/env python3
"""Fail closed unless Coder reports a recent private-Podman provisioner."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def load_environment(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("environment file contains an invalid line")
        key, value = line.split("=", 1)
        values[key] = value
    return values


def read_token(path: Path) -> str:
    parent = path.parent
    parent_info = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != 0
        or stat.S_IMODE(parent_info.st_mode) != 0o700
    ):
        raise ValueError("Coder API token parent must be root-owned mode 0700")
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("Coder API token is not a regular non-symlink")
    if (
        info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o444
        or info.st_nlink != 1
        or not 1 <= info.st_size <= 4096
    ):
        raise ValueError("Coder API token ownership/mode/link/size is invalid")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("Coder API token changed while being opened")
        content = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    token = content.decode("utf-8").strip()
    if not token or len(token) > 4096 or any(character.isspace() for character in token):
        raise ValueError("Coder API token content is invalid")
    return token


def tags_of(daemon: dict[str, object]) -> dict[str, str]:
    raw = daemon.get("tags", {})
    if isinstance(raw, dict):
        return {str(key): str(value) for key, value in raw.items()}
    if isinstance(raw, list):
        tags: dict[str, str] = {}
        for item in raw:
            if isinstance(item, dict) and "key" in item and "value" in item:
                tags[str(item["key"])] = str(item["value"])
        return tags
    return {}


def recent(value: object, now: dt.datetime) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        return False
    age = now - parsed.astimezone(dt.timezone.utc)
    return dt.timedelta(seconds=-30) <= age <= dt.timedelta(minutes=3)


def eligible_daemon(daemon: object, now: dt.datetime) -> bool:
    if not isinstance(daemon, dict):
        return False
    provisioners = daemon.get("provisioners")
    return (
        isinstance(provisioners, list)
        and tags_of(daemon).get("runtime") == "private-podman"
        and recent(daemon.get("last_seen_at"), now)
        and daemon.get("status") in ("idle", "busy")
        and "terraform" in [str(item) for item in provisioners]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", required=True, type=Path)
    args = parser.parse_args()
    try:
        values = load_environment(args.env_file)
        base = values["CODER_ACCESS_URL"]
        parsed = urllib.parse.urlsplit(base)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("CODER_ACCESS_URL is invalid")
        organization = str(uuid.UUID(values["CODER_ORGANIZATION_ID"]))
        secrets_dir = Path(values["SECRETS_DIR"])
        token = read_token(secrets_dir / "coder_api_token")
        endpoint = (
            f"{base.rstrip('/')}/api/v2/organizations/{organization}/provisionerdaemons"
        )
        request = urllib.request.Request(
            endpoint,
            headers={"Coder-Session-Token": token, "Accept": "application/json"},
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise ValueError("Coder provisioner API returned a non-success status")
            body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError("Coder provisioner response exceeds the size limit")
        document = json.loads(body)
        if isinstance(document, list):
            daemons = document
        elif isinstance(document, dict) and isinstance(document.get("daemons"), list):
            daemons = document["daemons"]
        else:
            raise ValueError("Coder provisioner response shape is invalid")
        now = dt.datetime.now(dt.timezone.utc)
        eligible = [daemon for daemon in daemons if eligible_daemon(daemon, now)]
        if not eligible:
            raise ValueError(
                "Coder has no recently seen Terraform provisioner tagged runtime=private-podman"
            )
        print("Coder private-Podman provisioner registration: PASS")
        return 0
    except (
        KeyError,
        OSError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
        urllib.error.URLError,
    ) as exc:
        print(f"Coder provisioner registration failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
