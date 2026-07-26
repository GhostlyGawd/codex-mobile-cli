from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MANIFEST = load_script("infra_release_manifest.py")
PROVISIONER = load_script("infra_check_provisioner.py")


def image_id(engine: str, reference: str) -> str:
    return "sha256:" + hashlib.sha256(f"{engine}:{reference}".encode()).hexdigest()


def load_test_evidence(
    repo_root: Path,
    _release_id: str,
    _expected_images: dict[str, dict[str, str]],
    _image_resolver,
    _podman_url: str,
) -> dict[str, object]:
    return json.loads(
        (repo_root / MANIFEST.IMAGE_AUDIT_RECEIPT).read_text(encoding="utf-8")
    )


class ReleaseManifestTests(unittest.TestCase):
    helper_sha256 = MANIFEST.workspace_helper_profile(
        MANIFEST.CURRENT_WORKSPACE_HELPER_PROFILE_VERSION
    )["amd64"]

    def make_release(self, root: Path) -> None:
        paths = set(MANIFEST.CRITICAL_RELEASE_FILES)
        paths.update(source for source, _, _ in MANIFEST.HOST_ARTIFACTS.values())
        for relative in paths:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"reviewed:{relative}\n", encoding="utf-8")
        template = root / "infra/coder/templates/codex-mobile-envbuilder"
        template.mkdir(parents=True, exist_ok=True)
        (template / "main.tf").write_text("terraform {}\n", encoding="utf-8")
        (template / ".terraform.lock.hcl").write_text("# locked\n", encoding="utf-8")

    def make_image_audit(
        self, root: Path, release_id: str = "sha-0123456789abcdef"
    ) -> dict[str, object]:
        reports_root = root / MANIFEST.IMAGE_AUDIT_ROOT / "reports"
        reports_root.mkdir(parents=True, exist_ok=True)
        receipt_images: dict[str, dict[str, object]] = {}
        for name, (engine, reference) in MANIFEST.image_references(release_id).items():
            reports: dict[str, dict[str, object]] = {}
            for report_name in ("sbom", "trivy"):
                suffix = "sbom.cdx.json" if report_name == "sbom" else "trivy.json"
                path = reports_root / f"{name.replace('_', '-')}.{suffix}"
                content = json.dumps(
                    {"image": name, "report": report_name},
                    sort_keys=True,
                ).encode("utf-8")
                path.write_bytes(content)
                reports[report_name] = {
                    "path": path.relative_to(
                        root / MANIFEST.IMAGE_AUDIT_ROOT
                    ).as_posix(),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                }
            resolved_id = image_id(engine, reference)
            receipt_images[name] = {
                "engine": engine,
                "reference": reference,
                "image_id": resolved_id,
                "architecture": "amd64",
                "tag_image_id_before": resolved_id,
                "tag_image_id_after": resolved_id,
                "reports": reports,
            }
        receipt: dict[str, object] = {
            "schema_version": 1,
            "status": "pass",
            "release_id": release_id,
            "source_commit": release_id.removeprefix("sha-"),
            "host": {"architecture": "amd64"},
            "scanner_policy": {"version": 1},
            "images": receipt_images,
        }
        (root / MANIFEST.IMAGE_AUDIT_RECEIPT).write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return receipt

    def make_manifest(self, root: Path, release_id: str = "sha-0123456789abcdef"):
        self.make_image_audit(root, release_id)
        manifest = MANIFEST.build_manifest(
            root,
            release_id,
            image_id,
            lambda _: self.helper_sha256,
            load_test_evidence,
        )
        MANIFEST.write_manifest(root, manifest)
        return manifest

    def verify_manifest(
        self,
        root: Path,
        resolver=image_id,
        installed_root: Path | None = None,
        require_image_audit: bool = True,
    ):
        return MANIFEST.verify_manifest(
            root,
            resolver,
            installed_root,
            require_image_audit,
            load_test_evidence,
            helper_resolver=lambda _: self.helper_sha256,
        )

    def make_writable(self, root: Path) -> None:
        for path in root.rglob("*"):
            if path.is_file():
                try:
                    path.chmod(0o600)
                except OSError:
                    pass

    def test_manifest_binds_source_images_template_and_release_environment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                expected = self.make_manifest(root)
                actual = self.verify_manifest(root)
                self.assertEqual(actual["release_id"], "sha-0123456789abcdef")
                self.assertEqual(actual["images"], expected["images"])
                self.assertEqual(actual["schema_version"], 2)
                self.assertEqual(actual["image_audit"]["status"], "pass")
                self.assertEqual(
                    (root / "infra/release.env").read_text(encoding="ascii"),
                    MANIFEST.release_environment("sha-0123456789abcdef"),
                )
            finally:
                self.make_writable(root)

    def test_changed_source_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                self.make_manifest(root)
                path = root / "scripts/infra-health.sh"
                path.chmod(0o600)
                path.write_text("tampered\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "checksum mismatch"
                ):
                    self.verify_manifest(root)
            finally:
                self.make_writable(root)

    def test_envbuilder_source_inputs_are_manifest_bound(self) -> None:
        protected = (
            "infra/workspace/Dockerfile.dockerignore",
            "infra/workspace/EnvBuilder.Dockerfile.dockerignore",
            "infra/workspace/envbuilder/source-lock.json",
            ("infra/workspace/envbuilder/envbuilder-v1.3.0-codex-mobile.patch"),
            "scripts/verify-envbuilder-source.py",
        )
        for relative in protected:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                try:
                    self.make_release(root)
                    self.make_manifest(root)
                    path = root / relative
                    path.chmod(0o600)
                    path.write_text("tampered\n", encoding="utf-8")
                    with self.assertRaisesRegex(
                        MANIFEST.ManifestError, "checksum mismatch"
                    ):
                        self.verify_manifest(root)
                finally:
                    self.make_writable(root)

    def test_retagged_or_missing_image_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                self.make_manifest(root)

                def changed_image(engine: str, reference: str) -> str:
                    if engine == "docker":
                        return "sha256:" + "f" * 64
                    return image_id(engine, reference)

                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "no longer matches"
                ):
                    self.verify_manifest(root, changed_image)
            finally:
                self.make_writable(root)

    def test_tampered_receipt_or_report_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                self.make_manifest(root)
                receipt = root / MANIFEST.IMAGE_AUDIT_RECEIPT
                original_receipt = receipt.read_bytes()
                receipt.write_text(
                    receipt.read_text(encoding="utf-8") + " ",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "does not match release manifest"
                ):
                    self.verify_manifest(root)

                receipt.write_bytes(original_receipt)
                report = (
                    root
                    / MANIFEST.IMAGE_AUDIT_ROOT
                    / "reports/control-plane.sbom.cdx.json"
                )
                report.write_text("tampered\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "does not match release manifest"
                ):
                    self.verify_manifest(root)
            finally:
                self.make_writable(root)

    def test_missing_or_extra_audit_report_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                self.make_manifest(root)
                report = (
                    root
                    / MANIFEST.IMAGE_AUDIT_ROOT
                    / "reports/workspace-base.trivy.json"
                )
                original_report = report.read_bytes()
                report.unlink()
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "does not match release manifest"
                ):
                    self.verify_manifest(root)

                report.write_bytes(original_report)
                extra = root / MANIFEST.IMAGE_AUDIT_ROOT / "reports/unreviewed.json"
                extra.write_text("{}\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "does not match release manifest"
                ):
                    self.verify_manifest(root)
            finally:
                self.make_writable(root)

    def test_audit_image_identity_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                self.make_manifest(root)
                receipt_path = root / MANIFEST.IMAGE_AUDIT_RECEIPT
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                wrong = "sha256:" + "f" * 64
                for key in (
                    "image_id",
                    "tag_image_id_before",
                    "tag_image_id_after",
                ):
                    receipt["images"]["control_plane"][key] = wrong
                receipt_path.write_text(
                    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "identity does not match manifest"
                ):
                    self.verify_manifest(root)
            finally:
                self.make_writable(root)

    def test_helper_uses_captured_id_and_tag_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                self.make_image_audit(root)
                workspace_reference = MANIFEST.image_references("sha-0123456789abcdef")[
                    "workspace_base"
                ][1]
                workspace_id = image_id("podman", workspace_reference)
                workspace_calls = 0
                helper_subjects: list[str] = []

                def drifting_resolver(engine: str, reference: str) -> str:
                    nonlocal workspace_calls
                    if reference == workspace_reference:
                        workspace_calls += 1
                        if workspace_calls == 2:
                            return "sha256:" + "f" * 64
                    return image_id(engine, reference)

                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "changed during exact helper verification"
                ):
                    MANIFEST.build_manifest(
                        root,
                        "sha-0123456789abcdef",
                        drifting_resolver,
                        lambda subject: (
                            helper_subjects.append(subject) or self.helper_sha256
                        ),
                        load_test_evidence,
                    )
                envbuilder_reference = MANIFEST.image_references(
                    "sha-0123456789abcdef"
                )["envbuilder"][1]
                self.assertEqual(
                    helper_subjects,
                    [workspace_id, image_id("podman", envbuilder_reference)],
                )
            finally:
                self.make_writable(root)

    def test_wrong_helper_bytes_and_envbuilder_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                self.make_image_audit(root)
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "does not match the amd64 release pin"
                ):
                    MANIFEST.build_manifest(
                        root,
                        "sha-0123456789abcdef",
                        image_id,
                        lambda _subject: "f" * 64,
                        load_test_evidence,
                    )

                envbuilder_reference = MANIFEST.image_references(
                    "sha-0123456789abcdef"
                )["envbuilder"][1]
                envbuilder_calls = 0

                def drifting_resolver(engine: str, reference: str) -> str:
                    nonlocal envbuilder_calls
                    if reference == envbuilder_reference:
                        envbuilder_calls += 1
                        if envbuilder_calls == 2:
                            return "sha256:" + "e" * 64
                    return image_id(engine, reference)

                with self.assertRaisesRegex(
                    MANIFEST.ManifestError,
                    "envbuilder image tag changed during exact helper verification",
                ):
                    MANIFEST.build_manifest(
                        root,
                        "sha-0123456789abcdef",
                        drifting_resolver,
                        lambda _subject: self.helper_sha256,
                        load_test_evidence,
                    )
            finally:
                self.make_writable(root)

    def test_helper_profile_is_versioned_for_historical_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                manifest = self.make_manifest(root)
                future_profile = {
                    1: dict(MANIFEST.workspace_helper_profile(1)),
                    2: dict(MANIFEST.workspace_helper_profile(2)),
                    3: {"amd64": "d" * 64, "arm64": "e" * 64},
                }
                with (
                    mock.patch.object(
                        MANIFEST, "CURRENT_WORKSPACE_HELPER_PROFILE_VERSION", 3
                    ),
                    mock.patch.object(
                        MANIFEST, "WORKSPACE_HELPER_PROFILE_REGISTRY", future_profile
                    ),
                ):
                    verified = self.verify_manifest(root)
                self.assertEqual(
                    verified["workspace_helper"]["profile_version"],
                    manifest["workspace_helper"]["profile_version"],
                )

                manifest["workspace_helper"]["profile_version"] = 999
                (root / "infra/release-manifest.json").chmod(0o600)
                (root / "infra/release.env").chmod(0o600)
                MANIFEST.write_manifest(root, manifest)
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "profile version is unsupported"
                ):
                    self.verify_manifest(root)
            finally:
                self.make_writable(root)

    def test_manifest_parser_rejects_duplicates_oversize_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                self.make_manifest(root)
                path = root / "infra/release-manifest.json"
                path.chmod(0o600)
                text = path.read_text(encoding="utf-8")
                needle = '"template_name": "codex-mobile-envbuilder",'
                path.write_text(
                    text.replace(needle, f"{needle}\n    {needle}", 1),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "duplicate object key: template_name"
                ):
                    MANIFEST.load_manifest(root)

                path.write_bytes(b" " * (MANIFEST.MAX_MANIFEST_BYTES + 1))
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "exceeds its trusted file limits"
                ):
                    MANIFEST.load_manifest(root)

                path.unlink()
                target = root / "infra/elsewhere.json"
                target.write_text("{}\n", encoding="utf-8")
                try:
                    path.symlink_to(target)
                except OSError as exc:
                    self.skipTest(f"symlinks unavailable: {exc}")
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "regular non-symlink"
                ):
                    MANIFEST.load_manifest(root)
            finally:
                self.make_writable(root)

    def test_release_environment_read_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                self.make_manifest(root)
                path = root / "infra/release.env"
                path.chmod(0o600)
                path.write_bytes(b"A" * (MANIFEST.MAX_RELEASE_ENVIRONMENT_BYTES + 1))
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "exceeds its trusted file limits"
                ):
                    self.verify_manifest(root)
            finally:
                self.make_writable(root)

    def test_nested_manifest_schema_and_coder_identity_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                manifest = self.make_manifest(root)
                for field, value in (
                    ("template_name", "attacker-template"),
                    ("provisioner_tag", "runtime=attacker"),
                ):
                    with self.subTest(field=field):
                        changed = json.loads(json.dumps(manifest))
                        changed["coder"][field] = value
                        (root / "infra/release-manifest.json").chmod(0o600)
                        (root / "infra/release.env").chmod(0o600)
                        MANIFEST.write_manifest(root, changed)
                        with self.assertRaisesRegex(
                            MANIFEST.ManifestError, "Coder identity is invalid"
                        ):
                            self.verify_manifest(root)

                changed = json.loads(json.dumps(manifest))
                changed["images"]["control_plane"]["unknown"] = True
                (root / "infra/release-manifest.json").chmod(0o600)
                (root / "infra/release.env").chmod(0o600)
                MANIFEST.write_manifest(root, changed)
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "image record is invalid"
                ):
                    self.verify_manifest(root)
            finally:
                self.make_writable(root)

    def test_schema_v1_is_archival_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                manifest = self.make_manifest(root)
                manifest["schema_version"] = 1
                manifest.pop("image_audit")
                manifest.pop("workspace_helper")
                manifest["release_files"] = {
                    relative: manifest["release_files"][relative]
                    for relative in MANIFEST.V1_CRITICAL_RELEASE_FILES
                }
                (root / "infra/release.env").chmod(0o600)
                (root / "infra/release-manifest.json").chmod(0o600)
                MANIFEST.write_manifest(root, manifest)
                archived = MANIFEST.verify_manifest(
                    root,
                    image_id,
                    evidence_verifier=load_test_evidence,
                )
                self.assertEqual(archived["schema_version"], 1)
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "has no image-audit evidence"
                ):
                    self.verify_manifest(root)
            finally:
                self.make_writable(root)

    @unittest.skipUnless(
        os.name == "posix" and os.geteuid() == 0,
        "root POSIX ownership/mode semantics",
    )
    def test_installed_host_artifact_fault_is_detected(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw,
            tempfile.TemporaryDirectory() as installed_raw,
        ):
            root = Path(raw)
            installed = Path(installed_raw)
            try:
                self.make_release(root)
                self.make_manifest(root)
                for source, destination, mode in MANIFEST.HOST_ARTIFACTS.values():
                    target = installed / destination.lstrip("/")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((root / source).read_bytes())
                    target.chmod(int(mode, 8))
                self.verify_manifest(root, image_id, installed)
                victim = installed / "etc/systemd/system/codex-mobile.service"
                victim.chmod(0o600)
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "mode does not match"
                ):
                    self.verify_manifest(root, image_id, installed)
            finally:
                self.make_writable(root)


class ReleaseSubprocessBoundaryTests(unittest.TestCase):
    def test_remote_or_malformed_podman_url_fails_before_api_callbacks(self) -> None:
        invalid = (
            "tcp://127.0.0.1:8080",
            "ssh://host/run/podman.sock",
            "unix://remote/run/podman.sock",
            "unix://[malformed/run/podman.sock",
            "unix:/run/podman.sock",
            "unix:////run/podman.sock",
            "unix:///run/../podman.sock",
            "unix:///run//podman.sock",
            "unix:///run/%2e%2e/podman.sock",
            "unix:///run/%ZZ/podman.sock",
            "unix:///run/podman.sock?remote=true",
        )
        for value in invalid:
            with self.subTest(url=value):
                callbacks: list[str] = []

                def resolver(_engine: str, _reference: str) -> str:
                    callbacks.append("resolver")
                    raise AssertionError("resolver must not run")

                def helper(_subject: str) -> str:
                    callbacks.append("helper")
                    raise AssertionError("helper must not run")

                def evidence(*_args):
                    callbacks.append("evidence")
                    raise AssertionError("evidence verifier must not run")

                with self.assertRaisesRegex(MANIFEST.ManifestError, "Podman URL"):
                    MANIFEST.build_manifest(
                        Path("does-not-exist"),
                        "sha-0123456789abcdef",
                        resolver,
                        helper,
                        evidence,
                        value,
                    )
                with self.assertRaisesRegex(MANIFEST.ManifestError, "Podman URL"):
                    MANIFEST.verify_manifest(
                        Path("does-not-exist"),
                        resolver,
                        evidence_verifier=evidence,
                        podman_url=value,
                    )
                self.assertEqual(callbacks, [])

    def test_cli_rejects_remote_podman_before_root_or_subprocess(self) -> None:
        with (
            mock.patch.object(
                MANIFEST,
                "require_root",
                side_effect=AssertionError("root check must not run"),
            ),
            mock.patch.object(
                MANIFEST.subprocess,
                "Popen",
                side_effect=AssertionError("subprocess must not run"),
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            result = MANIFEST.main(
                [
                    "verify",
                    "--repo-root",
                    "does-not-exist",
                    "--podman-url",
                    "tcp://remote.example:8080",
                ]
            )
        self.assertEqual(result, 1)

    def test_validation_only_action_never_checks_root_or_starts_a_process(self) -> None:
        with (
            mock.patch.object(
                MANIFEST,
                "require_root",
                side_effect=AssertionError("root check must not run"),
            ),
            mock.patch.object(
                MANIFEST.subprocess,
                "Popen",
                side_effect=AssertionError("subprocess must not run"),
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = MANIFEST.main(
                [
                    "validate-podman-url",
                    "--podman-url",
                    MANIFEST.DEFAULT_PODMAN_URL,
                ]
            )
        self.assertEqual(result, 0)

    def test_validation_action_blocks_remote_encoded_and_traversal_urls(self) -> None:
        invalid = (
            "tcp://remote.example:8080",
            "ssh://remote.example/run/podman.sock",
            "unix:///run/%2e%2e/attacker.sock",
            "unix:///run/../attacker.sock",
        )
        for value in invalid:
            with (
                self.subTest(url=value),
                mock.patch.object(
                    MANIFEST,
                    "require_root",
                    side_effect=AssertionError("root check must not run"),
                ),
                mock.patch.object(
                    MANIFEST.subprocess,
                    "Popen",
                    side_effect=AssertionError("subprocess must not run"),
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    MANIFEST.main(["validate-podman-url", "--podman-url", value]),
                    1,
                )

    def test_helper_pin_uses_exact_id_and_rejects_hostile_helper_bytes(self) -> None:
        captured_id = "sha256:" + "5" * 64
        expected = MANIFEST.workspace_helper_profile(
            MANIFEST.CURRENT_WORKSPACE_HELPER_PROFILE_VERSION
        )["amd64"]
        with (
            mock.patch.object(
                MANIFEST,
                "inspect_image",
                side_effect=(captured_id, captured_id),
            ) as inspect,
            mock.patch.object(
                MANIFEST,
                "inspect_podman_image_architecture",
                return_value="amd64",
            ) as architecture,
            mock.patch.object(
                MANIFEST,
                "inspect_workspace_helper",
                return_value=expected,
            ) as helper,
        ):
            result = MANIFEST.verify_helper_pin(
                "localhost/codex-mobile/workspace-base:sha-0123456",
                MANIFEST.DEFAULT_PODMAN_URL,
            )
        self.assertEqual(result["image_id"], captured_id)
        self.assertEqual(inspect.call_count, 2)
        architecture.assert_called_once_with(
            captured_id, MANIFEST.DEFAULT_PODMAN_URL, MANIFEST.run_bounded_command
        )
        helper.assert_called_once_with(
            captured_id, MANIFEST.DEFAULT_PODMAN_URL, MANIFEST.run_bounded_command
        )

        with (
            mock.patch.object(
                MANIFEST,
                "inspect_image",
                return_value=captured_id,
            ),
            mock.patch.object(
                MANIFEST,
                "inspect_podman_image_architecture",
                return_value="amd64",
            ),
            mock.patch.object(
                MANIFEST,
                "inspect_workspace_helper",
                return_value="0" * 64,
            ),
        ):
            with self.assertRaisesRegex(
                MANIFEST.ManifestError, "does not match the amd64 release pin"
            ):
                MANIFEST.verify_helper_pin(
                    "localhost/codex-mobile/workspace-base:sha-0123456",
                    MANIFEST.DEFAULT_PODMAN_URL,
                )

    def test_helper_seed_compares_exact_stable_image_ids(self) -> None:
        source_id = "sha256:" + "6" * 64
        comparison_id = "sha256:" + "7" * 64
        seed_sha256 = "8" * 64
        with (
            mock.patch.object(
                MANIFEST,
                "inspect_image",
                side_effect=(
                    source_id,
                    comparison_id,
                    source_id,
                    comparison_id,
                ),
            ) as inspect,
            mock.patch.object(
                MANIFEST,
                "inspect_podman_image_architecture",
                side_effect=("amd64", "amd64"),
            ) as architecture,
            mock.patch.object(
                MANIFEST,
                "inspect_workspace_helper_seed",
                side_effect=(seed_sha256, seed_sha256),
            ) as seed,
        ):
            result = MANIFEST.verify_helper_seed(
                "localhost/codex-mobile/workspace-base:sha-0123456",
                "localhost/codex-mobile/envbuilder:sha-0123456",
                MANIFEST.DEFAULT_PODMAN_URL,
            )
        self.assertEqual(result["seed_sha256"], seed_sha256)
        self.assertEqual(inspect.call_count, 4)
        self.assertEqual(architecture.call_count, 2)
        self.assertEqual(
            [call.args[0] for call in seed.call_args_list],
            [source_id, comparison_id],
        )

        with (
            mock.patch.object(
                MANIFEST,
                "inspect_image",
                side_effect=(source_id, comparison_id),
            ),
            mock.patch.object(
                MANIFEST,
                "inspect_podman_image_architecture",
                side_effect=("amd64", "amd64"),
            ),
            mock.patch.object(
                MANIFEST,
                "inspect_workspace_helper_seed",
                side_effect=("8" * 64, "9" * 64),
            ),
        ):
            with self.assertRaisesRegex(
                MANIFEST.ManifestError, "helper seeds do not match"
            ):
                MANIFEST.verify_helper_seed(
                    "localhost/codex-mobile/workspace-base:sha-0123456",
                    "localhost/codex-mobile/envbuilder:sha-0123456",
                    MANIFEST.DEFAULT_PODMAN_URL,
                )

    def test_inspectors_use_fixed_executables_and_literal_path(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []
        resolved = "sha256:" + "1" * 64

        def runner(argv, **kwargs):
            calls.append((list(argv), kwargs))
            return MANIFEST.CommandResult(0, (resolved + "\n").encode(), b"")

        with mock.patch.dict(
            os.environ, {"PATH": "C:\\attacker-controlled"}, clear=False
        ):
            self.assertEqual(
                MANIFEST.inspect_image(
                    "docker",
                    "localhost/example:tag",
                    MANIFEST.DEFAULT_PODMAN_URL,
                    runner,
                ),
                resolved,
            )
            self.assertEqual(
                MANIFEST.inspect_image(
                    "podman",
                    "localhost/example:tag",
                    MANIFEST.DEFAULT_PODMAN_URL,
                    runner,
                ),
                resolved,
            )
        self.assertEqual(calls[0][0][0], "/usr/bin/docker")
        self.assertEqual(calls[1][0][0], "/usr/bin/podman")
        self.assertEqual(
            calls[0][1]["env"]["DOCKER_HOST"],
            "unix:///var/run/docker.sock",
        )
        self.assertTrue(calls[0][1]["env"]["DOCKER_CONFIG"].endswith("docker-config"))
        self.assertNotIn("DOCKER_HOST", calls[1][1]["env"])
        for _, kwargs in calls:
            self.assertEqual(kwargs["env"]["PATH"], "/usr/bin:/bin")
            self.assertNotIn("C:\\attacker-controlled", kwargs["env"].values())

    def test_only_podman_bare_image_ids_are_canonicalized(self) -> None:
        bare = "2" * 64

        def runner(_argv, **_kwargs):
            return MANIFEST.CommandResult(0, (bare + "\n").encode(), b"")

        self.assertEqual(
            MANIFEST.inspect_image(
                "podman",
                "localhost/example:tag",
                MANIFEST.DEFAULT_PODMAN_URL,
                runner,
            ),
            f"sha256:{bare}",
        )
        with self.assertRaisesRegex(MANIFEST.ManifestError, "immutable sha256"):
            MANIFEST.inspect_image(
                "docker",
                "localhost/example:tag",
                MANIFEST.DEFAULT_PODMAN_URL,
                runner,
            )
        for invalid in ("a" * 63, "A" * 64, "a" * 65, "sha512:" + "a" * 64):
            with self.subTest(invalid=invalid):

                def invalid_runner(_argv, **_kwargs):
                    return MANIFEST.CommandResult(0, (invalid + "\n").encode(), b"")

                with self.assertRaisesRegex(MANIFEST.ManifestError, "immutable sha256"):
                    MANIFEST.inspect_image(
                        "podman",
                        "localhost/example:tag",
                        MANIFEST.DEFAULT_PODMAN_URL,
                        invalid_runner,
                    )

    def test_helper_is_extracted_from_exact_id_without_starting_image(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []
        image_id_value = "sha256:" + "2" * 64
        helper = b"reviewed helper bytes"

        def runner(argv, **kwargs):
            command = list(argv)
            calls.append((command, kwargs))
            action = command[3]
            if action == "create":
                return MANIFEST.CommandResult(0, b"malformed-output-is-ignored\n", b"")
            if action == "cp":
                Path(command[-1]).write_bytes(helper)
                return MANIFEST.CommandResult(0, b"", b"")
            if action == "rm":
                return MANIFEST.CommandResult(0, b"", b"")
            raise AssertionError(f"unexpected Podman action: {action}")

        with mock.patch.dict(os.environ, {"PATH": "/attacker/bin"}, clear=False):
            checksum = MANIFEST.inspect_workspace_helper(
                image_id_value,
                MANIFEST.DEFAULT_PODMAN_URL,
                runner,
            )
        self.assertEqual(checksum, hashlib.sha256(helper).hexdigest())
        self.assertEqual([command[3] for command, _ in calls], ["create", "cp", "rm"])
        self.assertIn(image_id_value, calls[0][0])
        self.assertNotIn("run", [value for command, _ in calls for value in command])
        container_name = calls[0][0][calls[0][0].index("--name") + 1]
        self.assertRegex(container_name, r"^cm-helper-inspect-[0-9a-f]{32}$")
        self.assertTrue(calls[1][0][4].startswith(f"{container_name}:"))
        self.assertEqual(calls[2][0][-1], container_name)
        for command, kwargs in calls:
            self.assertEqual(command[0], "/usr/bin/podman")
            self.assertEqual(kwargs["env"]["PATH"], "/usr/bin:/bin")

    def test_helper_create_failure_still_attempts_named_cleanup(self) -> None:
        calls: list[list[str]] = []
        image_id_value = "sha256:" + "4" * 64

        def runner(argv, **_kwargs):
            command = list(argv)
            calls.append(command)
            if command[3] == "create":
                raise MANIFEST.ManifestError("bounded create output was invalid")
            if command[3] == "rm":
                return MANIFEST.CommandResult(0, b"", b"")
            raise AssertionError("copy must not run after create failure")

        with self.assertRaisesRegex(
            MANIFEST.ManifestError, "bounded create output was invalid"
        ):
            MANIFEST.inspect_workspace_helper(
                image_id_value,
                MANIFEST.DEFAULT_PODMAN_URL,
                runner,
            )
        self.assertEqual([command[3] for command in calls], ["create", "rm"])
        container_name = calls[0][calls[0].index("--name") + 1]
        self.assertEqual(calls[1][-1], container_name)

    def test_bounded_runner_rejects_excessive_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(
                MANIFEST.ManifestError, "exceeded its output limit"
            ):
                MANIFEST.run_bounded_command(
                    [sys.executable, "-c", "print('x' * 65536)"],
                    cwd=Path(raw),
                    env={"PATH": MANIFEST.MINIMAL_SUBPROCESS_PATH},
                    timeout_seconds=10,
                    stdout_limit=128,
                )


class ReleaseScriptStaticTests(unittest.TestCase):
    def test_activation_builds_once_and_rollback_never_builds(self) -> None:
        deploy = (ROOT / "scripts/infra-deploy.sh").read_text(encoding="utf-8")
        rollback = (ROOT / "scripts/infra-rollback.sh").read_text(encoding="utf-8")
        unit = (ROOT / "infra/systemd/codex-mobile.service").read_text(encoding="utf-8")
        self.assertIn('infra_release_manifest.py" create', deploy)
        self.assertIn('infra_image_audit.py" scan', deploy)
        self.assertLess(
            deploy.index('infra-compose.sh" build'),
            deploy.index('infra_image_audit.py" scan'),
        )
        self.assertLess(
            deploy.index("infra-build-workspace-image.sh"),
            deploy.index('infra_image_audit.py" scan'),
        )
        self.assertLess(
            deploy.index('infra_image_audit.py" scan'),
            deploy.index('infra_release_manifest.py" create'),
        )
        self.assertLess(
            deploy.index('infra_release_manifest.py" create'),
            deploy.index('mv "$release" "$target"'),
        )
        self.assertIn("--require-image-audit --verify-installed", deploy)
        self.assertIn("infra-import-coder-template.sh", deploy)
        self.assertIn('infra-health.sh" --smoke', deploy)
        self.assertNotIn("infra-build-workspace-image", rollback)
        self.assertNotIn("infra_image_audit.py", rollback)
        self.assertNotIn(' compose.sh" build', rollback)
        self.assertIn(
            'manifest_verifier="$old/scripts/infra_release_manifest.py"', rollback
        )
        self.assertNotIn(
            'python3 "$target/scripts/infra_release_manifest.py"', rollback
        )
        self.assertIn("--require-images --require-image-audit", rollback)
        self.assertLess(
            rollback.index('--repo-root "$target" --require-images'),
            rollback.index(
                '/usr/bin/python3 -I "$target/scripts/check-billing-policy.py"'
            ),
        )
        self.assertIn("--no-build", unit)
        self.assertNotIn("--build", unit)

    def test_activation_receipt_binds_manifest_and_image_audit(self) -> None:
        template_import = (ROOT / "scripts/infra-import-coder-template.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('"schema_version": 2', template_import)
        self.assertIn('"release_manifest_sha256"', template_import)
        self.assertIn('"image_audit": manifest["image_audit"]', template_import)

    def test_engine_endpoints_are_pinned_before_any_build_context_transfer(
        self,
    ) -> None:
        deploy = (ROOT / "scripts/infra-deploy.sh").read_text(encoding="utf-8")
        builder = (ROOT / "scripts/infra-build-workspace-image.sh").read_text(
            encoding="utf-8"
        )
        compose = (ROOT / "scripts/infra-compose.sh").read_text(encoding="utf-8")
        health = (ROOT / "scripts/infra-health.sh").read_text(encoding="utf-8")

        self.assertLess(
            deploy.index("validate-podman-url"),
            deploy.index('infra-compose.sh" build'),
        )
        self.assertLess(
            builder.index("validate-podman-url"),
            builder.index("/usr/bin/podman --url"),
        )
        self.assertIn(
            '/usr/bin/docker --host "$docker_host" compose',
            compose,
        )
        self.assertIn("docker_host=unix:///var/run/docker.sock", compose)
        self.assertIn("unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG", compose)
        self.assertIn("DOCKER_CONFIG=$docker_config", compose)
        self.assertNotIn("exec docker compose", compose)
        self.assertNotIn("\ndocker ", health)
        self.assertIn("/usr/bin/docker --host unix:///var/run/docker.sock", health)

    def test_builder_pin_check_does_not_trust_image_entrypoint_or_sha256sum(
        self,
    ) -> None:
        builder = (ROOT / "scripts/infra-build-workspace-image.sh").read_text(
            encoding="utf-8"
        )
        first_run = builder.index("/usr/bin/podman --url", builder.index(" run "))
        self.assertLess(builder.index("verify-helper-pin"), first_run)
        self.assertIn("--entrypoint /bin/sh", builder)
        self.assertNotIn(
            "sha256sum /opt/codex-mobile-helper/codex-mobile-workspace-helper",
            builder,
        )
        self.assertEqual(builder.count("verify-helper-pin"), 2)
        self.assertIn("XDG_CONFIG_HOME XDG_RUNTIME_DIR", builder)
        self.assertIn(
            "v1.3.0-codex-mobile.1 - Build development environments "
            "from repositories in a container",
            builder,
        )

    def test_root_engine_scripts_sanitize_client_selector_environment(self) -> None:
        scripts = (
            "scripts/infra-deploy.sh",
            "scripts/infra-rollback.sh",
            "scripts/infra-build-workspace-image.sh",
            "scripts/infra-compose.sh",
            "scripts/infra-health.sh",
            "scripts/infra-smoke.sh",
            "scripts/infra-admin.sh",
            "scripts/infra-install-release-host-artifacts.sh",
            "scripts/infra-import-coder-template.sh",
        )
        for relative in scripts:
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", text)
                self.assertIn("PYTHONHOME PYTHONPATH", text)
                self.assertIn("DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG", text)
                for selector in (
                    "CONTAINER_HOST",
                    "CONTAINER_CONNECTION",
                    "CONTAINERS_CONF",
                    "CONTAINERS_STORAGE_CONF",
                ):
                    self.assertIn(selector, text)
                first_engine = min(
                    (
                        index
                        for marker in (
                            "/usr/bin/docker",
                            "/usr/bin/podman",
                            "/usr/bin/python3",
                        )
                        if (index := text.find(marker)) >= 0
                    ),
                    default=len(text),
                )
                self.assertLess(
                    text.index("PATH=/usr/sbin:/usr/bin:/sbin:/bin"), first_engine
                )

    def test_every_operational_manifest_gate_requires_image_audit(self) -> None:
        expected_counts = {
            "scripts/infra-deploy.sh": 3,
            "scripts/infra-rollback.sh": 3,
            "scripts/infra-health.sh": 1,
            "scripts/infra-install-release-host-artifacts.sh": 2,
            "scripts/infra-import-coder-template.sh": 1,
            "scripts/infra-smoke.sh": 1,
            "scripts/infra-admin.sh": 1,
        }
        for relative, expected in expected_counts.items():
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(text.count("--require-image-audit"), expected)

    def test_health_covers_units_socket_storage_runtime_and_registration(self) -> None:
        health = (ROOT / "scripts/infra-health.sh").read_text(encoding="utf-8")
        for control in (
            "codex-mobile-workspace-runtime.service",
            "codex-mobile-provisioner.service",
            "verify-workspace-storage",
            "ensure-workspace-control-network --check",
            "root:coder-provisioner:660",
            "podman --url",
            "infra_check_provisioner.py",
            "running control-plane image does not match",
            "infra-smoke.sh",
        ):
            self.assertIn(control, health)

    def test_admin_wrapper_stages_key_and_uses_fixed_container_path(self) -> None:
        admin = (ROOT / "scripts/infra-admin.sh").read_text(encoding="utf-8")
        self.assertIn("NEW_MASTER_KEY_FILE", admin)
        self.assertIn("O_NOFOLLOW", admin)
        self.assertIn("root-owned mode-0700", admin)
        self.assertIn("0:0:444:1", admin)
        self.assertIn("/run/codex-mobile-admin/new-master-key", admin)
        self.assertNotIn("$new_key --confirm", admin)
        self.assertIn("compose stop --timeout 60 caddy control-plane", admin)


class ProvisionerResponseTests(unittest.TestCase):
    def test_tag_shapes_and_recent_registration(self) -> None:
        self.assertEqual(
            PROVISIONER.tags_of({"tags": {"runtime": "private-podman"}}),
            {"runtime": "private-podman"},
        )
        self.assertEqual(
            PROVISIONER.tags_of(
                {"tags": [{"key": "runtime", "value": "private-podman"}]}
            ),
            {"runtime": "private-podman"},
        )
        now = dt.datetime.now(dt.timezone.utc)
        self.assertTrue(PROVISIONER.recent(now.isoformat(), now))
        self.assertFalse(
            PROVISIONER.recent((now - dt.timedelta(minutes=4)).isoformat(), now)
        )
        self.assertTrue(
            PROVISIONER.eligible_daemon(
                {
                    "tags": {"runtime": "private-podman"},
                    "last_seen_at": now.isoformat(),
                    "status": "idle",
                    "provisioners": ["terraform"],
                },
                now,
            )
        )
        self.assertFalse(
            PROVISIONER.eligible_daemon(
                {
                    "tags": {"runtime": "private-podman"},
                    "last_seen_at": now.isoformat(),
                    "status": "offline",
                    "provisioners": ["terraform"],
                },
                now,
            )
        )


if __name__ == "__main__":
    unittest.main()
