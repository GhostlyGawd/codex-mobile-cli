from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


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


class ReleaseManifestTests(unittest.TestCase):
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
        (template / ".terraform.lock.hcl").write_text(
            "# locked\n", encoding="utf-8"
        )

    def make_manifest(self, root: Path, release_id: str = "sha-0123456789abcdef"):
        manifest = MANIFEST.build_manifest(
            root,
            release_id,
            image_id,
            lambda _: "a" * 64,
        )
        MANIFEST.write_manifest(root, manifest)
        return manifest

    def make_writable(self, root: Path) -> None:
        for path in root.rglob("*"):
            if path.is_file():
                try:
                    path.chmod(0o600)
                except OSError:
                    pass

    def test_manifest_binds_source_images_template_and_release_environment(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            try:
                self.make_release(root)
                expected = self.make_manifest(root)
                actual = MANIFEST.verify_manifest(root, image_id)
                self.assertEqual(actual["release_id"], "sha-0123456789abcdef")
                self.assertEqual(actual["images"], expected["images"])
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
                    MANIFEST.verify_manifest(root, image_id)
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
                    MANIFEST.verify_manifest(root, changed_image)
            finally:
                self.make_writable(root)

    @unittest.skipUnless(
        os.name == "posix" and os.geteuid() == 0,
        "root POSIX ownership/mode semantics",
    )
    def test_installed_host_artifact_fault_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as installed_raw:
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
                MANIFEST.verify_manifest(root, image_id, installed)
                victim = installed / "etc/systemd/system/codex-mobile.service"
                victim.chmod(0o600)
                with self.assertRaisesRegex(
                    MANIFEST.ManifestError, "mode does not match"
                ):
                    MANIFEST.verify_manifest(root, image_id, installed)
            finally:
                self.make_writable(root)


class ReleaseScriptStaticTests(unittest.TestCase):
    def test_activation_builds_once_and_rollback_never_builds(self) -> None:
        deploy = (ROOT / "scripts/infra-deploy.sh").read_text(encoding="utf-8")
        rollback = (ROOT / "scripts/infra-rollback.sh").read_text(encoding="utf-8")
        unit = (ROOT / "infra/systemd/codex-mobile.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("infra_release_manifest.py\" create", deploy)
        self.assertIn("--require-images --verify-installed", deploy)
        self.assertIn("infra-import-coder-template.sh", deploy)
        self.assertIn("infra-health.sh\" --smoke", deploy)
        self.assertNotIn("infra-build-workspace-image", rollback)
        self.assertNotIn(" compose.sh\" build", rollback)
        self.assertIn("--require-images", rollback)
        self.assertIn("--no-build", unit)
        self.assertNotIn("--build", unit)

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
