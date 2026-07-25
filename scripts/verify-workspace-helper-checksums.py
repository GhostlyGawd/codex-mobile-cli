#!/usr/bin/env python3
"""Verify cross-built workspace helpers match the pinned image checksums."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "infra" / "workspace" / "EnvBuilder.Dockerfile"
CHECKSUM_PATTERN = re.compile(
    r"^ARG WORKSPACE_HELPER_(AMD64|ARM64)_SHA256=([0-9a-f]{64})$", re.MULTILINE
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    pins = {
        architecture.lower(): checksum
        for architecture, checksum in CHECKSUM_PATTERN.findall(
            DOCKERFILE.read_text(encoding="utf-8")
        )
    }
    if set(pins) != {"amd64", "arm64"}:
        raise SystemExit("workspace-helper image checksum pins are incomplete")

    for architecture in ("amd64", "arm64"):
        artifact = ROOT / "coverage" / f"workspace-helper-linux-{architecture}"
        if not artifact.is_file():
            raise SystemExit(f"workspace-helper artifact is missing: {artifact}")
        actual = sha256(artifact)
        if actual != pins[architecture]:
            raise SystemExit(
                f"workspace-helper {architecture} checksum mismatch: "
                f"expected {pins[architecture]}, got {actual}"
            )
    print("workspace-helper checksums: PASS (amd64, arm64)")


if __name__ == "__main__":
    main()
