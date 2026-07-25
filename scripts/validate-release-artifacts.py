#!/usr/bin/env python3
"""Portable structural checks for release, supply-chain, and runbook artifacts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_RUNBOOKS = {
    "README.md",
    "CI.md",
    "DEPLOY.md",
    "ROLLBACK.md",
    "UPDATE.md",
    "PASSKEY_RECOVERY.md",
    "CREDENTIAL_ROTATION.md",
    "GITHUB_APP.md",
    "APNS.md",
    "CHECKPOINT_RESTORE.md",
    "PROVIDER_BACKUP_RESTORE.md",
    "SERVER_LOSS.md",
    "INCIDENT_RESPONSE.md",
    "TESTFLIGHT.md",
    "RELEASE_CHECKLIST.md",
}
PUBLIC_CI_GATE = (
    "github.event.repository.private == false"
    " && vars.PUBLIC_CI_ENABLED == 'true'"
)
STANDARD_HOSTED_RUNNERS = {"ubuntu-24.04", "macos-26"}
EXPECTED_XCODEGEN_SHA256 = (
    "090ec29491aad50aec10631bf6e62253fed733c50f3aab0f5ffc86bc170bdbef"
)


def check_links(path: Path, failures: list[str]) -> None:
    raw = path.read_text(encoding="utf-8")
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", raw):
        target = target.strip().strip("<>")
        if not target or target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        local = target.split("#", 1)[0]
        if local and not (path.parent / local).resolve().exists():
            failures.append(f"{path.relative_to(ROOT)}: broken local link {target!r}")


def check_ci(failures: list[str], root: Path = ROOT) -> None:
    workflow_root = root / ".github" / "workflows"
    paths = sorted(workflow_root.glob("*.yml")) + sorted(workflow_root.glob("*.yaml"))
    if not paths:
        failures.append(".github/workflows: public-safe CI workflows are required")
        return

    required_workflows = {
        "ci.yml": (
            "name: CI",
            PUBLIC_CI_GATE,
            "runs-on: ubuntu-24.04",
            "timeout-minutes: 25",
            "permissions:\n  contents: read",
            "persist-credentials: false",
            "cache: false",
            "cancel-in-progress: true",
        ),
        "ios.yml": (
            "name: iOS",
            PUBLIC_CI_GATE,
            "runs-on: macos-26",
            "timeout-minutes: 45",
            "permissions:\n  contents: read",
            "persist-credentials: false",
            "cancel-in-progress: true",
            "DEVELOPER_DIR: /Applications/Xcode_26.6.app/Contents/Developer",
            "XCODEGEN_VERSION: 2.45.4",
            f"XCODEGEN_SHA256: {EXPECTED_XCODEGEN_SHA256}",
            (
                "https://github.com/yonaskolb/XcodeGen/releases/download/"
                "${XCODEGEN_VERSION}/xcodegen.zip"
            ),
            "shasum -a 256 --check",
            "./scripts/generate-ios-project.sh",
            "-destination 'platform=iOS Simulator,name=iPhone 17 Pro'",
            "-onlyUsePackageVersionsFromResolvedFile",
            "-skipPackagePluginValidation",
            "CODE_SIGNING_ALLOWED=NO",
        ),
    }
    for name, required in required_workflows.items():
        path = workflow_root / name
        if path not in paths:
            failures.append(f".github/workflows/{name}: required workflow is missing")
            continue
        raw = path.read_text(encoding="utf-8")
        for value in required:
            if value not in raw:
                failures.append(f".github/workflows/{name}: missing {value!r}")

    for workflow in paths:
        workflow_raw = workflow.read_text(encoding="utf-8")
        relative = workflow.relative_to(root)

        trigger_match = re.search(
            r"(?ms)^on:\s*\n(?P<body>.*?)(?=^[A-Za-z_][A-Za-z0-9_-]*:\s*$)",
            workflow_raw,
        )
        trigger_block = trigger_match.group("body") if trigger_match else ""
        triggers = set(
            re.findall(r"(?m)^ {2}([A-Za-z_][A-Za-z0-9_-]*):", trigger_block)
        )
        expected_triggers = {"pull_request", "push", "workflow_dispatch"}
        if triggers != expected_triggers:
            failures.append(
                f"{relative}: triggers must be exactly pull_request, push, "
                "and workflow_dispatch"
            )
        if "push:\n    branches:\n      - main" not in trigger_block:
            failures.append(f"{relative}: push must target only main")
        branch_entries = re.findall(r"(?m)^ {6}-\s+(.+?)\s*$", trigger_block)
        if branch_entries != ["main"]:
            failures.append(f"{relative}: push branches must be exactly ['main']")

        job_match = re.search(r"(?ms)^jobs:\s*\n(?P<body>.*)", workflow_raw)
        job_body = job_match.group("body") if job_match else ""
        job_starts = list(
            re.finditer(
                r"(?m)^ {2}([A-Za-z_][A-Za-z0-9_-]*):\s*(?:#.*)?$",
                job_body,
            )
        )
        for index, start in enumerate(job_starts):
            end = (
                job_starts[index + 1].start()
                if index + 1 < len(job_starts)
                else len(job_body)
            )
            job_name = start.group(1)
            job = job_body[start.start() : end]
            has_runner = re.search(r"(?m)^    runs-on:", job) is not None
            delegates_runner = re.search(r"(?m)^    uses:", job) is not None
            has_job_gate = (
                re.search(
                    r"(?m)^    if:\s*\$\{\{\s*"
                    + re.escape(PUBLIC_CI_GATE)
                    + r"\s*\}\}\s*$",
                    job,
                )
                is not None
            )
            if (has_runner or delegates_runner) and not has_job_gate:
                failures.append(
                    f"{relative}: runner job {job_name!r} lacks the mandatory "
                    "public-visibility and PUBLIC_CI_ENABLED gate"
                )
            if delegates_runner:
                failures.append(
                    f"{relative}: reusable-workflow runner delegation is not allowed"
                )

        runners = re.findall(r"(?m)^\s+runs-on:\s*([^\s#]+)", workflow_raw)
        for runner in runners:
            if runner not in STANDARD_HOSTED_RUNNERS:
                failures.append(
                    f"{relative}: runner {runner!r} is not an approved standard "
                    "GitHub-hosted runner"
                )

        if "runs-on:" in workflow_raw and "permissions:\n  contents: read" not in workflow_raw:
            failures.append(f"{relative}: workflow permissions must be contents: read")

        for forbidden in (
            "self-hosted",
            "upload-artifact",
            "actions/cache",
            "pull_request_target",
            "workflow_run",
            "repository_dispatch",
            "schedule:",
            "secrets.",
            "${{ secrets",
            "environment:",
            "write-all",
        ):
            if forbidden in workflow_raw:
                failures.append(
                    f"{relative}: forbidden runner, trigger, secret, or token "
                    f"pattern {forbidden!r}"
                )
        for permission in re.findall(
            r"(?m)^\s+(?:actions|checks|contents|deployments|discussions|id-token|"
            r"issues|packages|pages|pull-requests|repository-projects|"
            r"security-events|statuses):\s*([A-Za-z-]+)\s*$",
            workflow_raw,
        ):
            if permission != "read":
                failures.append(
                    f"{relative}: workflow permissions must remain read-only"
                )
        for action in re.findall(r"uses:\s*([^\s#]+)", workflow_raw):
            if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action):
                failures.append(f"{relative}: action is not commit-pinned: {action}")


def check_sbom(failures: list[str]) -> None:
    path = ROOT / "docs/security/SBOM.cdx.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"docs/security/SBOM.cdx.json: {exc}")
        return
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        failures.append("docs/security/SBOM.cdx.json: expected CycloneDX 1.6")
    components = document.get("components", [])
    if len(components) < 40:
        failures.append(
            "docs/security/SBOM.cdx.json: implausibly small component inventory"
        )
    references = [component.get("bom-ref") for component in components]
    if len(references) != len(set(references)):
        failures.append("docs/security/SBOM.cdx.json: duplicate component references")
    serialized = json.dumps(document)
    if "LicenseRef-Needs-Review" in serialized:
        failures.append("docs/security/SBOM.cdx.json: unresolved third-party license")
    if re.search(r"[A-Za-z]:\\|/Users/|/home/", serialized):
        failures.append("docs/security/SBOM.cdx.json: local absolute path leaked")


def main() -> int:
    failures: list[str] = []
    runbooks = ROOT / "docs/runbooks"
    actual = {path.name for path in runbooks.glob("*.md")}
    missing = EXPECTED_RUNBOOKS - actual
    unexpected = actual - EXPECTED_RUNBOOKS
    if missing:
        failures.append(f"docs/runbooks: missing {sorted(missing)}")
    if unexpected:
        failures.append(f"docs/runbooks: unindexed files {sorted(unexpected)}")

    for path in sorted(runbooks.glob("*.md")) + sorted(
        (ROOT / "docs/security").glob("*.md")
    ):
        check_links(path, failures)

    check_ci(failures)
    check_sbom(failures)

    passkey = (runbooks / "PASSKEY_RECOVERY.md").read_text(encoding="utf-8")
    if (
        "release-blocking operational limitation" not in passkey
        or "no password fallback" not in passkey.lower()
    ):
        failures.append(
            "PASSKEY_RECOVERY.md must preserve and disclose the total-loss limitation"
        )
    rotation = (runbooks / "CREDENTIAL_ROTATION.md").read_text(encoding="utf-8")
    if "Do **not** replace `control_plane_master_key` in place" not in rotation:
        failures.append(
            "CREDENTIAL_ROTATION.md must block unsafe master-key replacement"
        )
    testflight = (runbooks / "TESTFLIGHT.md").read_text(encoding="utf-8")
    if (
        "GATED" not in testflight
        or "testflight` environment" not in testflight
        or "environment-scoped" not in testflight
    ):
        failures.append(
            "TESTFLIGHT.md must retain the signing and protected-environment gate"
        )
    acceptance = (ROOT / "docs/verification/ACCEPTANCE.md").read_text(encoding="utf-8")
    for gate in ("Docker", "Xcode", "provider", "NOT EXECUTED", "GATED"):
        if gate.upper() not in acceptance.upper():
            failures.append(f"ACCEPTANCE.md must distinguish unavailable gate: {gate}")

    if failures:
        print("release artifact validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(
        "release artifacts: PASS (portable structure, links, SBOM, CI and safety gates)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
