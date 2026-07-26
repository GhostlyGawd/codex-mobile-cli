from __future__ import annotations

import base64
import importlib.util
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "infra" / "compose.yaml"
COMPOSE_GITHUB = ROOT / "infra" / "compose.github.yaml"
COMPOSE_APNS = ROOT / "infra" / "compose.apns.yaml"
TEMPLATE = (
    ROOT / "infra" / "coder" / "templates" / "codex-mobile-envbuilder" / "main.tf"
)


def load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BILLING = load_script("check-billing-policy.py")
PREFLIGHT = load_script("infra-preflight.py")
RELEASE_VALIDATOR = load_script("validate-release-artifacts.py")


def production_values() -> dict[str, str]:
    return {
        "APP_ENV": "production",
        "DATA_ROOT": "/srv/codex-mobile",
        "SECRETS_DIR": "/etc/codex-mobile/secrets",
        "WORKSPACE_IO_DEVICE": "/dev/mapper/codex-mobile-data",
        "WORKSPACE_CONTROL_SUBNET": "10.87.0.0/24",
        "PUBLIC_BIND_ADDRESS": "0.0.0.0",
        "PUBLIC_HTTP_PORT": "80",
        "PUBLIC_HTTPS_PORT": "443",
        "API_HOST": "api.codex.owner.test",
        "API_SITE_ADDRESS": "api.codex.owner.test",
        "BASE_DOMAIN": "codex.owner.test",
        "PREVIEW_DOMAIN": "preview.codex.owner.test",
        "PREVIEW_SITE_ADDRESS": "*.preview.codex.owner.test",
        "PASSKEY_RP_ID": "codex.owner.test",
        "PUBLIC_ORIGIN": "https://api.codex.owner.test",
        "PASSKEY_ORIGINS": "https://api.codex.owner.test",
        "PUBLIC_HEALTH_URL": "https://api.codex.owner.test/healthz",
        "GITHUB_ENABLED": "false",
        "APNS_ENABLED": "false",
        "CODER_BIND_ADDRESS": "10.0.0.8",
        "CODER_BIND_PORT": "7080",
        "CODER_ACCESS_URL": "http://10.0.0.8:7080",
        "CODER_WORKSPACE_CONNECTIVITY_CONFIRMED": "true",
        "CODER_ORGANIZATION_ID": "123e4567-e89b-42d3-a456-426614174000",
        "CODER_TEMPLATE_ID": "123e4567-e89b-42d3-a456-426614174001",
        "CODER_OWNER_ID": "me",
        "POSTGRES_ADMIN_USER": "codex_bootstrap_admin",
        "APP_DB_USER": "codex_app",
        "APP_DB_NAME": "codex_app",
        "CODER_DB_USER": "coder",
        "CODER_DB_NAME": "coder",
        "CONTROL_PLANE_IMAGE_TAG": "sha-0123456789abcdef",
        "CONTROL_PLANE_PACKAGE": "./services/control-plane/cmd/control-plane",
        "VPS_PROVIDER": "fixed-price-provider",
        "VPS_PLAN": "fixed-32gb",
        "VPS_REGION": "owner-approved-region",
        "VPS_MONTHLY_PRICE_USD": "50.00",
        "VPS_FIXED_PRICE_CONFIRMED": "true",
        "VPS_INCLUDED_BACKUP_CONFIRMED": "true",
        "VPS_NO_AUTOMATIC_OVERAGE_CONFIRMED": "true",
    }


class ComposeSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        cls.services = cls.document["services"]

    def test_only_approved_local_services_exist(self) -> None:
        self.assertEqual(
            set(self.services), {"caddy", "postgres", "coder", "control-plane"}
        )

    def test_every_image_is_exact_and_control_plane_is_local(self) -> None:
        expected = {
            "caddy": "caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648",
            "postgres": "postgres:18.4-bookworm@sha256:1961f96e6029a02c3812d7cb329a3b03a3ac2bb067058dec17b0f5596aca9296",
            "coder": "ghcr.io/coder/coder:v2.34.6@sha256:0ac9c07e9ff18ea9fecb07c08da838a032352e2b95c5fcd3bf279297cff1808a",
        }
        for service, image in expected.items():
            self.assertEqual(self.services[service]["image"], image)
        control = self.services["control-plane"]
        self.assertIn("build", control)
        self.assertTrue(
            control["image"].startswith("localhost/codex-mobile/control-plane:")
        )

    def test_only_caddy_may_publish_public_ports(self) -> None:
        self.assertNotIn("ports", self.services["postgres"])
        self.assertNotIn("ports", self.services["control-plane"])
        coder_ports = self.services["coder"]["ports"]
        self.assertEqual(len(coder_ports), 1)
        self.assertIn("CODER_BIND_ADDRESS:-127.0.0.1", coder_ports[0])
        for port in self.services["caddy"]["ports"]:
            self.assertIn("PUBLIC_BIND_ADDRESS", port)

    def test_control_services_are_read_only_and_drop_capabilities(self) -> None:
        allowed_add = {
            "postgres": {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
            "caddy": {"NET_BIND_SERVICE"},
            "coder": set(),
            "control-plane": set(),
        }
        for name, service in self.services.items():
            with self.subTest(service=name):
                self.assertIs(service.get("read_only"), True)
                self.assertEqual(service.get("cap_drop"), ["ALL"])
                self.assertEqual(set(service.get("cap_add", [])), allowed_add[name])
                self.assertIn("no-new-privileges:true", service.get("security_opt", []))
                self.assertIsNot(service.get("privileged"), True)
                self.assertNotIn("pid", service)
                self.assertNotIn("ipc", service)
                self.assertNotIn("devices", service)

    def test_no_container_engine_socket_or_cross_workspace_mount(self) -> None:
        text = COMPOSE.read_text(encoding="utf-8").lower()
        for forbidden in (
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/run/podman/podman.sock",
            "privileged: true",
        ):
            self.assertNotIn(forbidden, text)
        for service in self.services.values():
            for volume in service.get("volumes", []):
                target = (
                    volume["target"]
                    if isinstance(volume, dict)
                    else str(volume).split(":")[-1]
                )
                self.assertNotEqual(target, "/workspaces")

    def test_data_network_is_internal(self) -> None:
        self.assertIs(self.document["networks"]["data"]["internal"], True)
        self.assertEqual(
            self.document["networks"]["data"]["driver_opts"][
                "com.docker.network.bridge.name"
            ],
            "cm-data0",
        )
        self.assertEqual(self.services["postgres"]["networks"], ["data"])

    def test_database_credentials_are_separate_secret_files(self) -> None:
        env = self.services["postgres"]["environment"]
        self.assertNotEqual(env["APP_DB_USER"], env["CODER_DB_USER"])
        self.assertNotEqual(env["APP_DB_NAME"], env["CODER_DB_NAME"])
        self.assertTrue(env["APP_DB_PASSWORD_FILE"].startswith("/run/secrets/"))
        self.assertTrue(env["CODER_DB_PASSWORD_FILE"].startswith("/run/secrets/"))
        for definition in self.document["secrets"].values():
            self.assertIn("file", definition)
            self.assertNotIn("environment", definition)

    def test_file_secrets_are_container_readable_but_host_confined(self) -> None:
        generator = (ROOT / "scripts" / "infra-generate-secrets.sh").read_text(
            encoding="utf-8"
        )
        preflight = (ROOT / "scripts" / "infra-preflight.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('chmod 0444 "$secrets_dir"/*', generator)
        for control in (
            ".lstat()",
            "stat.S_IMODE(directory_info.st_mode) != 0o700",
            "directory_info.st_uid, directory_info.st_gid) != (0, 0)",
            "stat.S_IMODE(parent_info.st_mode) & 0o022",
            "stat.S_IMODE(info.st_mode) != 0o444",
            "info.st_nlink != 1",
            'getattr(os, "O_NOFOLLOW", 0)',
            "os.fstat(descriptor)",
        ):
            self.assertIn(control, preflight)

    def test_control_plane_environment_matches_backend_contract(self) -> None:
        environment = self.services["control-plane"]["environment"]
        for name in (
            "HTTP_ADDR",
            "PUBLIC_ORIGIN",
            "PASSKEY_RP_ID",
            "PASSKEY_ORIGINS",
            "SESSION_PEPPER_FILE",
            "GITHUB_ENABLED",
            "GITHUB_APP_ID",
            "GITHUB_CLIENT_ID",
            "APNS_ENABLED",
            "APNS_TEAM_ID",
            "APNS_KEY_ID_SANDBOX",
            "APNS_KEY_ID_PRODUCTION",
            "IOS_BUNDLE_ID",
            "WORKSPACE_DISK_PROBE_PATH",
            "MAX_RUNNING_WORKSPACES",
        ):
            self.assertIn(name, environment)
        for name in (
            "GITHUB_CLIENT_SECRET_FILE",
            "GITHUB_WEBHOOK_SECRET_FILE",
            "GITHUB_APP_PRIVATE_KEY_FILE",
            "APNS_SANDBOX_PRIVATE_KEY_FILE",
            "APNS_PRODUCTION_PRIVATE_KEY_FILE",
        ):
            self.assertNotIn(name, environment)
        self.assertNotIn("HTTP_LISTEN_ADDRESS", environment)
        self.assertNotIn("PASSKEY_ORIGIN", environment)
        self.assertEqual(
            environment["WORKSPACE_DISK_PROBE_PATH"], "/workspace-disk-probe"
        )
        self.assertEqual(environment["MAX_RUNNING_WORKSPACES"], "10")
        probe = next(
            volume
            for volume in self.services["control-plane"]["volumes"]
            if volume["target"] == "/workspace-disk-probe"
        )
        self.assertIn("DATA_ROOT", probe["source"])
        self.assertIs(probe["read_only"], True)

    def test_api_and_preview_sites_are_separate(self) -> None:
        caddy_environment = self.services["caddy"]["environment"]
        self.assertIn("API_SITE_ADDRESS", caddy_environment)
        self.assertIn("PREVIEW_SITE_ADDRESS", caddy_environment)
        self.assertIn("PREVIEW_DOMAIN", caddy_environment)
        caddyfile = (ROOT / "infra" / "caddy" / "Caddyfile").read_text(encoding="utf-8")
        self.assertIn("{$API_SITE_ADDRESS:http://localhost}", caddyfile)
        self.assertIn("{$PREVIEW_SITE_ADDRESS:http://*.preview.localhost}", caddyfile)
        self.assertIn("header_up Host {http.request.host}", caddyfile)


class OptionalIntegrationComposeTests(unittest.TestCase):
    def test_github_override_uses_only_file_backed_secrets(self) -> None:
        document = yaml.safe_load(COMPOSE_GITHUB.read_text(encoding="utf-8"))
        self.assertEqual(set(document["services"]), {"control-plane"})
        service = document["services"]["control-plane"]
        expected = {
            "github_client_secret": "/run/secrets/github_client_secret",
            "github_webhook_secret": "/run/secrets/github_webhook_secret",
            "github_app_private_key": "/run/secrets/github_app_private_key",
        }
        self.assertEqual(set(service["secrets"]), set(expected))
        for secret, runtime_path in expected.items():
            self.assertEqual(
                document["secrets"][secret]["file"],
                f"${{SECRETS_DIR:?set SECRETS_DIR}}/{secret}",
            )
            env_name = secret.upper() + "_FILE"
            self.assertIn(runtime_path, service["environment"][env_name])

    def test_apns_override_uses_only_file_backed_secrets(self) -> None:
        document = yaml.safe_load(COMPOSE_APNS.read_text(encoding="utf-8"))
        self.assertEqual(set(document["services"]), {"control-plane"})
        service = document["services"]["control-plane"]
        expected = {
            "apns_sandbox_private_key": "/run/secrets/apns_sandbox_private_key",
            "apns_production_private_key": "/run/secrets/apns_production_private_key",
        }
        self.assertEqual(set(service["secrets"]), set(expected))
        for secret, runtime_path in expected.items():
            self.assertEqual(
                document["secrets"][secret]["file"],
                f"${{SECRETS_DIR:?set SECRETS_DIR}}/{secret}",
            )
            env_name = secret.upper() + "_FILE"
            self.assertIn(runtime_path, service["environment"][env_name])

    def test_wrapper_selects_overrides_only_for_exact_true_flags(self) -> None:
        wrapper = (ROOT / "scripts" / "infra-compose.sh").read_text(encoding="utf-8")
        self.assertIn("false:false)", wrapper)
        self.assertIn("true:false)", wrapper)
        self.assertIn("false:true)", wrapper)
        self.assertIn("true:true)", wrapper)
        self.assertIn("infra/compose.github.yaml", wrapper)
        self.assertIn("infra/compose.apns.yaml", wrapper)
        self.assertIn("must each be exactly true or false", wrapper)


class WorkspaceTemplateSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = TEMPLATE.read_text(encoding="utf-8")

    def test_versions_and_images_are_exact(self) -> None:
        for pin in (
            'required_version = "= 1.14.5"',
            'version = "= 2.18.0"',
            'version = "= 4.5.0"',
            "localhost/codex-mobile/envbuilder:1.3.0-helper-2026-07-15",
        ):
            self.assertIn(pin, self.text)

    def test_safe_plain_container_and_approved_envbuilder(self) -> None:
        for control in (
            'drop = ["ALL"]',
            '"no-new-privileges:true"',
            'userns_mode  = "private"',
            "read_only    = true",
            "memory_swap  = data.coder_parameter.memory_mb.value",
            '"com.codex-mobile.pids-limit"',
            "device_read_bps",
            "device_write_bps",
            "device_read_iops",
            "device_write_iops",
            "approval_receipt_ok",
            'regex = "^\\\\.$|^\\\\.devcontainer$"',
            'api_key_scope = "no_user_data"',
        ):
            self.assertIn(control, self.text)
        self.assertNotIn("privileged = true", self.text)
        self.assertNotIn('host_path = "/"', self.text)
        self.assertNotIn("docker.sock:/", self.text)
        self.assertEqual(self.text.count("device_read_bps {"), 2)
        self.assertEqual(self.text.count("device_write_bps {"), 2)
        self.assertEqual(self.text.count("device_read_iops {"), 2)
        self.assertEqual(self.text.count("device_write_iops {"), 2)
        self.assertIn('size   = "4G"', self.text)
        self.assertIn('inodes = "262144"', self.text)
        self.assertIn('variable "workspace_io_device"', self.text)

    def test_workspace_volume_network_and_identity_are_per_workspace(self) -> None:
        self.assertIn('name = "cm-workspace-v2-${local.workspace_key}"', self.text)
        self.assertIn(
            'name = "cm-helper-${local.workspace_key}-'
            "${substr(local.workspace_helper_sha256, 0, 16)}-"
            '${substr(local.workspace_codex_package_sha256, 0, 8)}"',
            self.text,
        )
        self.assertIn('name     = "cm-net-${local.workspace_key}"', self.text)
        self.assertIn("internal = true", self.text)
        self.assertIn('name   = "cm-egress-${local.workspace_key}"', self.text)
        self.assertIn("data.coder_parameter.allow_egress.value ? 1 : 0", self.text)
        self.assertIn('name = "codex-mobile-control"', self.text)
        self.assertIn('name         = "cm-relay-${local.workspace_key}"', self.text)
        self.assertIn('aliases = ["cm-coder-control"]', self.text)
        self.assertIn('"CODER_AGENT_TOKEN=${coder_agent.main.token}"', self.text)
        self.assertIn('"CODER_AGENT_URL=${local.coder_relay_url}"', self.text)
        self.assertNotIn("network_mode =", self.text)
        self.assertIn('user         = "1000:1000"', self.text)
        self.assertEqual(
            self.text.count('container_path = "/opt/codex-mobile-helper"'), 2
        )
        self.assertEqual(
            self.text.count(
                '"/codex-mobile-attachments" = "rw,nosuid,nodev,noexec,size=67108864,uid=1000,gid=1000,mode=0700"'
            ),
            2,
        )
        self.assertGreaterEqual(self.text.count("read_only      = true"), 2)
        self.assertIn(
            "ENVBUILDER_IGNORE_PATHS=/var/run,/product_uuid,/product_name,/opt/codex-mobile-helper",
            self.text,
        )

    def test_workspace_volume_has_immutable_xfs_project_quota(self) -> None:
        for control in (
            'name         = "disk_gib"',
            "default      = 12",
            "mutable      = false",
            "min   = 8",
            "max   = 16",
            'o = "size=${data.coder_parameter.disk_gib.value}G,inodes=${local.workspace_inode_limit}"',
            "workspace_inode_limit = data.coder_parameter.disk_gib.value * 65536",
            '"com.codex-mobile.disk-budget"',
            "tostring(local.workspace_disk_bytes)",
            "ignore_changes = all",
        ):
            self.assertIn(control, self.text)
        self.assertEqual(self.text.count('"com.codex-mobile.disk-budget"'), 1)
        self.assertIn("max   = 18432", self.text)

    def test_workspace_and_helper_volumes_have_distinct_lifecycle_roles(self) -> None:
        self.assertIn('"com.codex-mobile.volume-role" = "workspace-data"', self.text)
        self.assertIn(
            '"com.codex-mobile.volume-role"             = "trusted-helper"', self.text
        )
        workspace_lifecycle = self.text.index("ignore_changes = all")
        helper_lifecycle = self.text.index("create_before_destroy = true")
        self.assertLess(workspace_lifecycle, helper_lifecycle)
        checkpoint = (ROOT / "scripts" / "infra-checkpoint.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("label=com.codex-mobile.volume-role=workspace-data", checkpoint)
        for control in (
            "CHECKPOINT_RESERVE_BYTES:-42949672960",
            "CHECKPOINT_DATABASE_MAX_BYTES:-4294967296",
            "CHECKPOINT_WORKSPACE_MAX_BYTES:-17179869184",
            "flock -x 9",
            "ulimit -f",
            'gzip -t "$temporary"',
            'tar -tzf "$temporary"',
            'mv -- "$temporary" "$checkpoint_output"',
            'sync -f "$checkpoint_directory"',
            "-name '*.partial.*'",
            "producer_status",
            "compressor_status",
        ):
            self.assertIn(control, checkpoint)


class ImageSupplyChainTests(unittest.TestCase):
    def test_security_audit_requires_exact_image_scanner_versions(self) -> None:
        shell = (ROOT / "scripts" / "security-audit.sh").read_text(encoding="utf-8")
        powershell = (ROOT / "scripts" / "security-audit.ps1").read_text(
            encoding="utf-8"
        )
        for text in (shell, powershell):
            self.assertIn("0.72.0", text)
            self.assertIn("1.46.0", text)
            self.assertIn("--format json", text)
        self.assertIn('get("Version", "")', shell)
        self.assertIn('get("version", "")', shell)
        self.assertIn("ConvertFrom-Json", powershell)

    def test_workspace_image_installs_checksum_verified_codex_cli(self) -> None:
        dockerfile = (ROOT / "infra" / "workspace" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        for pin in (
            "ARG CODEX_CLI_VERSION=0.144.5",
            "23a7022a493c5404c50c62a4ad5655836adbee019d93c73114954d8daff20053",
            "7703bbb6cbd4ba3df60c32d200bca2987691047353d3a6c825af2b8bc99f1808",
            "sha256sum --check --strict",
            "codex-package_SHA256SUMS",
            "ubuntu-package-versions.txt",
            "USER 1000:1000",
        ):
            self.assertIn(pin, dockerfile)
        self.assertNotIn("npm install", dockerfile)
        self.assertNotIn("curl |", dockerfile)

    def test_workspace_image_builds_fixed_root_owned_helper(self) -> None:
        dockerfile = (ROOT / "infra" / "workspace" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        envbuilder_dockerfile = (
            ROOT / "infra" / "workspace" / "EnvBuilder.Dockerfile"
        ).read_text(encoding="utf-8")
        build = (ROOT / "scripts" / "infra-build-workspace-image.sh").read_text(
            encoding="utf-8"
        )
        verify_sh = (ROOT / "scripts" / "verify.sh").read_text(encoding="utf-8")
        verify_ps1 = (ROOT / "scripts" / "verify.ps1").read_text(encoding="utf-8")
        checksum_verifier = (
            ROOT / "scripts" / "verify-workspace-helper-checksums.py"
        ).read_text(encoding="utf-8")
        self.assertIn("docker.io/library/golang:1.26.5-bookworm@sha256:", dockerfile)
        self.assertIn("docker.io/library/ubuntu:24.04@sha256:", dockerfile)
        self.assertIn("./cmd/workspace-helper", dockerfile)
        self.assertIn("-ldflags='-s -w'", dockerfile)
        self.assertIn("--chown=0:0 --chmod=0755", dockerfile)
        self.assertIn("/usr/local/bin/codex-mobile-workspace-helper", dockerfile)
        self.assertIn(
            "/opt/codex-mobile-helper/codex-mobile-workspace-helper", dockerfile
        )
        self.assertIn("/opt/codex-mobile-helper/codex-real", dockerfile)
        self.assertIn("/opt/codex-mobile-helper/codex-code-mode-host", dockerfile)
        self.assertNotIn("ARG WORKSPACE_HELPER_COMMAND", dockerfile)
        self.assertIn("Dockerfile.dockerignore", build)
        for checksum in (
            "11d1fb9c53549e98bb5a976c2958954ff6eb99fd9485dd09beac50f6157df924",
            "81a623dae961e640c18ac1df942baf9a797dbeb79b9f90312b62f241d36da1dd",
        ):
            self.assertIn(checksum, envbuilder_dockerfile)
            self.assertIn(checksum, build)
        self.assertIn(
            "ghcr.io/coder/envbuilder:1.3.0@sha256:b34ade2fb90a8536df76e7a15c6dd8c6352d0ae835a187b13467fa0c8a71e280",
            envbuilder_dockerfile,
        )
        self.assertIn("--entrypoint /opt/codex-mobile-helper/codex-real", build)
        self.assertIn("-ldflags='-s -w'", verify_sh)
        self.assertIn("-ldflags=-s -w", verify_ps1)
        self.assertIn("verify-workspace-helper-checksums.py", verify_sh)
        self.assertIn("verify-workspace-helper-checksums.py", verify_ps1)
        self.assertIn("EnvBuilder.Dockerfile", checksum_verifier)
        self.assertIn("workspace-helper-linux-", checksum_verifier)

    def test_control_plane_builder_and_runtime_are_immutable(self) -> None:
        dockerfile = (ROOT / "infra" / "docker" / "control-plane.Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "docker.io/library/golang:${GO_VERSION}-bookworm@${GO_IMAGE_DIGEST}",
            dockerfile,
        )
        self.assertIn(
            "sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651",
            dockerfile,
        )
        self.assertIn("FROM scratch", dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertIn("ARG CODER_CLI_VERSION=2.34.6", dockerfile)
        self.assertIn(
            "091acfd4356ab2f02bcaf561928841e9aecc630a28bc9678658d4ae47632df09",
            dockerfile,
        )
        self.assertIn(
            "d16b0f9393404e1d85669ec620aa90d2a0c10b1977c11c95e11b2d6b9bb0917d",
            dockerfile,
        )
        self.assertIn("/usr/share/licenses/coder/LICENSE.enterprise", dockerfile)
        ignore = (
            ROOT / "infra" / "docker" / "control-plane.Dockerfile.dockerignore"
        ).read_text(encoding="utf-8")
        self.assertTrue(ignore.startswith("**\n"))


class PolicyCheckerTests(unittest.TestCase):
    def test_current_repository_passes(self) -> None:
        self.assertEqual(BILLING.validate_policy(ROOT), [])

    def copy_policy_tree(self, destination: Path) -> None:
        shutil.copytree(ROOT / "infra", destination / "infra")
        (destination / "scripts").mkdir()

    def test_cloud_terraform_resource_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.copy_policy_tree(root)
            (root / "infra" / "bad.tf").write_text(
                'provider "aws" {}\nresource "aws_instance" "metered" {}\n',
                encoding="utf-8",
            )
            failures = BILLING.validate_policy(root)
            self.assertTrue(any("provider 'aws'" in item for item in failures))
            self.assertTrue(any("resource 'aws_instance'" in item for item in failures))

    def test_paid_runtime_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.copy_policy_tree(root)
            (root / "infra" / "bad.env").write_text(
                "OPENAI_API_KEY=forbidden\n", encoding="utf-8"
            )
            failures = BILLING.validate_policy(root)
            self.assertTrue(any("OPENAI_API_KEY" in item for item in failures))

    def test_external_compose_resource_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.copy_policy_tree(root)
            path = root / "infra" / "compose.yaml"
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            document["networks"]["paid-cloud"] = {"external": True}
            path.write_text(yaml.safe_dump(document), encoding="utf-8")
            failures = BILLING.validate_policy(root)
            self.assertTrue(any("external network" in item for item in failures))

    def test_unapproved_service_in_compose_overlay_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.copy_policy_tree(root)
            (root / "infra" / "compose.metered.yaml").write_text(
                "services:\n  paid-worker:\n    image: example.invalid/paid:latest\n",
                encoding="utf-8",
            )
            failures = BILLING.validate_policy(root)
            self.assertTrue(any("paid-worker" in item for item in failures))

    def test_excess_compose_overlays_require_explicit_policy_review(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.copy_policy_tree(root)
            for index in range(9):
                (root / "infra" / f"compose.extra-{index}.yaml").write_text(
                    "services: {}\n", encoding="utf-8"
                )
            failures = BILLING.validate_policy(root)
            self.assertTrue(any("more than eight" in item for item in failures))

    def test_provider_cli_provisioning_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.copy_policy_tree(root)
            (root / "scripts" / "buy-vps.sh").write_text(
                "#!/bin/sh\nhcloud server create --name forbidden\n", encoding="utf-8"
            )
            failures = BILLING.validate_policy(root)
            self.assertTrue(
                any("provisioning command 'hcloud'" in item for item in failures)
            )

    def test_public_hosted_workflows_pass_ci_policy(self) -> None:
        failures: list[str] = []
        RELEASE_VALIDATOR.check_ci(failures)
        self.assertEqual(failures, [])
        self.assertFalse(
            (ROOT / ".github" / "workflows" / "self-hosted-windows.yml").exists()
        )

    def test_unsafe_hosted_workflow_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            for name in ("ci.yml", "ios.yml"):
                shutil.copy(ROOT / ".github" / "workflows" / name, workflows / name)
            (workflows / "unsafe.yml").write_text(
                """name: Unsafe
on:
  pull_request_target:
  push:
    branches:
      - main
  workflow_dispatch:
permissions:
  contents: write
jobs:
  unsafe:
    runs-on: macos-26-large
    steps:
      - uses: actions/checkout@v4
      - uses: actions/upload-artifact@v4
      - run: echo "${{ secrets.RELEASE_TOKEN }}"
""",
                encoding="utf-8",
            )
            failures: list[str] = []
            RELEASE_VALIDATOR.check_ci(failures, root)
            self.assertTrue(any("lacks the mandatory" in item for item in failures))
            self.assertTrue(any("macos-26-large" in item for item in failures))
            self.assertTrue(any("pull_request_target" in item for item in failures))
            self.assertTrue(any("upload-artifact" in item for item in failures))
            self.assertTrue(any("secrets." in item for item in failures))
            self.assertTrue(any("read-only" in item for item in failures))
            self.assertTrue(any("not commit-pinned" in item for item in failures))

    def test_self_hosted_runner_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            for name in ("ci.yml", "ios.yml"):
                shutil.copy(ROOT / ".github" / "workflows" / name, workflows / name)
            (workflows / "unsafe-self-hosted.yml").write_text(
                """name: Unsafe self-hosted
on:
  pull_request:
  push:
    branches:
      - main
  workflow_dispatch:
permissions:
  contents: read
jobs:
  unsafe:
    if: ${{ github.event.repository.private == false && vars.PUBLIC_CI_ENABLED == 'true' }}
    runs-on: [self-hosted, windows, x64]
    steps:
      - run: echo unsafe
""",
                encoding="utf-8",
            )
            failures: list[str] = []
            RELEASE_VALIDATOR.check_ci(failures, root)
            self.assertTrue(any("self-hosted" in item for item in failures))
            self.assertTrue(
                any("not an approved standard" in item for item in failures)
            )

    def test_public_visibility_gate_is_required_on_every_runner_job(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            for name in ("ci.yml", "ios.yml"):
                source = ROOT / ".github" / "workflows" / name
                text = source.read_text(encoding="utf-8")
                if name == "ci.yml":
                    text = text.replace(
                        (
                            "github.event.repository.private == false && "
                            "vars.PUBLIC_CI_ENABLED == 'true'"
                        ),
                        "vars.PUBLIC_CI_ENABLED == 'true'",
                    )
                (workflows / name).write_text(text, encoding="utf-8")
            failures: list[str] = []
            RELEASE_VALIDATOR.check_ci(failures, root)
            self.assertTrue(
                any(
                    "public-visibility and PUBLIC_CI_ENABLED" in item
                    for item in failures
                )
            )

    def test_ios_toolchain_and_checksum_pins_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            shutil.copy(ROOT / ".github" / "workflows" / "ci.yml", workflows / "ci.yml")
            ios = (ROOT / ".github" / "workflows" / "ios.yml").read_text(
                encoding="utf-8"
            )
            ios = (
                ios.replace("Xcode_26.6.app", "Xcode_26.5.app")
                .replace(
                    RELEASE_VALIDATOR.EXPECTED_XCODEGEN_SHA256,
                    "0" * 64,
                )
                .replace("-skipPackagePluginValidation", "-packagePluginValidation")
            )
            (workflows / "ios.yml").write_text(ios, encoding="utf-8")
            failures: list[str] = []
            RELEASE_VALIDATOR.check_ci(failures, root)
            self.assertTrue(any("Xcode_26.6.app" in item for item in failures))
            self.assertTrue(
                any(
                    RELEASE_VALIDATOR.EXPECTED_XCODEGEN_SHA256 in item
                    for item in failures
                )
            )
            self.assertTrue(
                any("-skipPackagePluginValidation" in item for item in failures)
            )


class ProductionPreflightTests(unittest.TestCase):
    def test_valid_static_production_configuration_passes(self) -> None:
        values = production_values()
        self.assertEqual(
            PREFLIGHT.validate(values, Path("/etc/codex-mobile/production.env"), True),
            [],
        )

    def test_workspace_storage_requires_exact_xfs_project_quota_mount(self) -> None:
        class Result:
            returncode = 0
            stdout = "/srv/codex-mobile xfs rw,relatime,prjquota /dev/mapper/codex-mobile-data\n"
            stderr = ""

        class Device:
            st_mode = stat.S_IFBLK

        def run(*_args, **_kwargs):
            return Result()

        self.assertEqual(
            PREFLIGHT.validate_workspace_storage(
                "/srv/codex-mobile",
                "/dev/mapper/codex-mobile-data",
                run,
                lambda _path: Device(),
            ),
            [],
        )

        Result.stdout = "/ ext4 rw,relatime /dev/sda1\n"
        failures = PREFLIGHT.validate_workspace_storage(
            "/srv/codex-mobile",
            "/dev/mapper/codex-mobile-data",
            run,
            lambda _path: Device(),
        )
        self.assertTrue(any("own operator-mounted" in failure for failure in failures))
        self.assertTrue(any("must use XFS" in failure for failure in failures))
        self.assertTrue(any("pquota or prjquota" in failure for failure in failures))
        self.assertTrue(any("exactly match" in failure for failure in failures))

    def test_workspace_io_device_must_be_explicit(self) -> None:
        values = production_values()
        values["WORKSPACE_IO_DEVICE"] = "auto"
        failures = PREFLIGHT.validate(
            values, Path("/etc/codex-mobile/production.env"), True
        )
        self.assertTrue(any("WORKSPACE_IO_DEVICE" in item for item in failures))

    def test_workspace_control_subnet_must_be_narrow_rfc1918_and_disjoint(self) -> None:
        for subnet in ("8.8.8.0/24", "10.0.0.0/8", "10.0.0.0/24"):
            values = production_values()
            values["WORKSPACE_CONTROL_SUBNET"] = subnet
            failures = PREFLIGHT.validate(
                values, Path("/etc/codex-mobile/production.env"), True
            )
            with self.subTest(subnet=subnet):
                self.assertTrue(
                    any("WORKSPACE_CONTROL_SUBNET" in item for item in failures)
                )

    def test_coder_bootstrap_allows_only_expected_prebootstrap_state(self) -> None:
        values = production_values()
        values["CODER_ORGANIZATION_ID"] = "REPLACE_ME_CODER_ORGANIZATION_UUID"
        values["CODER_TEMPLATE_ID"] = "REPLACE_ME_IMPORTED_TEMPLATE_UUID"
        values["CODER_WORKSPACE_CONNECTIVITY_CONFIRMED"] = "false"
        env_path = Path("/etc/codex-mobile/production.env")
        self.assertEqual(PREFLIGHT.validate(values, env_path, True, True), [])
        failures = PREFLIGHT.validate(values, env_path, True)
        self.assertTrue(any("placeholder" in item for item in failures))
        self.assertTrue(
            any("after the Linux runtime spike" in item for item in failures)
        )

    def test_public_coder_binding_is_rejected(self) -> None:
        values = production_values()
        values["CODER_BIND_ADDRESS"] = "8.8.8.8"
        values["CODER_ACCESS_URL"] = "http://8.8.8.8:7080"
        failures = PREFLIGHT.validate(
            values, Path("/etc/codex-mobile/production.env"), True
        )
        self.assertTrue(any("non-loopback RFC1918" in item for item in failures))

    def test_https_coder_origin_is_rejected_for_cleartext_private_listener(
        self,
    ) -> None:
        values = production_values()
        values["CODER_ACCESS_URL"] = "https://10.0.0.8:7080"
        failures = PREFLIGHT.validate(
            values, Path("/etc/codex-mobile/production.env"), True
        )
        self.assertTrue(any("must be an HTTP URL" in item for item in failures))

    def test_reserved_coder_port_and_nonstandard_public_ports_are_rejected(
        self,
    ) -> None:
        values = production_values()
        values["CODER_BIND_PORT"] = "443"
        values["CODER_ACCESS_URL"] = "http://10.0.0.8:443"
        values["PUBLIC_HTTPS_PORT"] = "8443"
        failures = PREFLIGHT.validate(
            values, Path("/etc/codex-mobile/production.env"), True
        )
        self.assertTrue(any("conflicts with a reserved" in item for item in failures))
        self.assertTrue(any("standard TCP ports" in item for item in failures))

    def test_malformed_url_is_reported_instead_of_crashing(self) -> None:
        values = production_values()
        values["PUBLIC_ORIGIN"] = "https://["
        values["PASSKEY_ORIGINS"] = "https://["
        failures = PREFLIGHT.validate(
            values, Path("/etc/codex-mobile/production.env"), True
        )
        self.assertTrue(
            any("PUBLIC_ORIGIN must be a valid URL" in item for item in failures)
        )

    def test_unconfirmed_or_out_of_range_vps_is_rejected(self) -> None:
        values = production_values()
        values["VPS_MONTHLY_PRICE_USD"] = "100"
        values["VPS_NO_AUTOMATIC_OVERAGE_CONFIRMED"] = "false"
        failures = PREFLIGHT.validate(
            values, Path("/etc/codex-mobile/production.env"), True
        )
        self.assertTrue(any("between 25 and 75" in item for item in failures))
        self.assertTrue(any("NO_AUTOMATIC_OVERAGE" in item for item in failures))

    def test_placeholder_is_rejected(self) -> None:
        values = production_values()
        values["VPS_PLAN"] = "REPLACE_ME"
        failures = PREFLIGHT.validate(
            values, Path("/etc/codex-mobile/production.env"), True
        )
        self.assertTrue(any("placeholder" in item for item in failures))

    def test_enabled_integration_without_identifiers_is_rejected(self) -> None:
        values = production_values()
        values["GITHUB_ENABLED"] = "true"
        values["APNS_ENABLED"] = "true"
        failures = PREFLIGHT.validate(
            values, Path("/etc/codex-mobile/production.env"), True
        )
        self.assertTrue(
            any(
                "GitHub is enabled but variables are missing" in item
                for item in failures
            )
        )
        self.assertTrue(
            any(
                "APNs is enabled but variables are missing" in item for item in failures
            )
        )

    def test_secret_bundle_and_database_url_are_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            secret_dir = Path(raw)
            values = production_values()
            # This content-contract test runs under an unprivileged CI account.
            # Separate static/target-host controls enforce production root
            # ownership and protected ancestors.
            values["APP_ENV"] = "development"
            values["SECRETS_DIR"] = str(secret_dir)
            values.update(
                {
                    "GITHUB_ENABLED": "true",
                    "GITHUB_APP_ID": "123456",
                    "GITHUB_CLIENT_ID": "Iv1.owner123456",
                    "GITHUB_CLIENT_SECRET_FILE": "/run/secrets/github_client_secret",
                    "GITHUB_WEBHOOK_SECRET_FILE": "/run/secrets/github_webhook_secret",
                    "GITHUB_APP_PRIVATE_KEY_FILE": "/run/secrets/github_app_private_key",
                    "APNS_ENABLED": "true",
                    "APNS_TEAM_ID": "ABCDEFGHIJ",
                    "APNS_KEY_ID_SANDBOX": "ABCDEFGHIJ",
                    "APNS_KEY_ID_PRODUCTION": "KLMNOPQRST",
                    "IOS_BUNDLE_ID": "com.owner.codexmobile",
                    "APNS_SANDBOX_PRIVATE_KEY_FILE": "/run/secrets/apns_sandbox_private_key",
                    "APNS_PRODUCTION_PRIVATE_KEY_FILE": "/run/secrets/apns_production_private_key",
                }
            )
            app_password = "a" * 64
            contents = {
                "postgres_admin_password": "b" * 64,
                "app_db_password": app_password,
                "coder_db_password": "c" * 64,
                "app_database_url": f"postgresql://codex_app:{app_password}@postgres:5432/codex_app?sslmode=disable",
                "coder_api_token": "d" * 48,
                "control_plane_master_key": base64.b64encode(b"e" * 32).decode(),
                "session_pepper": base64.b64encode(b"p" * 32).decode(),
                "coder_provisioner_key": "f" * 48,
                "github_client_secret": "g" * 48,
                "github_webhook_secret": "h" * 48,
                "github_app_private_key": "-----BEGIN PRIVATE KEY-----\ngithub\n-----END PRIVATE KEY-----",
                "apns_sandbox_private_key": "-----BEGIN PRIVATE KEY-----\nsandbox\n-----END PRIVATE KEY-----",
                "apns_production_private_key": "-----BEGIN PRIVATE KEY-----\nproduction\n-----END PRIVATE KEY-----",
            }
            for name, value in contents.items():
                path = secret_dir / name
                path.write_text(value + "\n", encoding="utf-8")
                path.chmod(0o444)
            secret_dir.chmod(0o700)
            failures: list[str] = []
            PREFLIGHT.validate_integrations(values, failures)
            PREFLIGHT.validate_secret_files(values, failures)
            self.assertEqual(failures, [])

            if os.name == "posix":
                victim = secret_dir / "app_db_password"
                victim.chmod(0o600)
                failures = []
                PREFLIGHT.validate_secret_files(values, failures)
                self.assertTrue(any("exact mode 0444" in item for item in failures))
                victim.chmod(0o444)

                hardlink = secret_dir / "app_db_password.extra-link"
                os.link(victim, hardlink)
                failures = []
                PREFLIGHT.validate_secret_files(values, failures)
                self.assertTrue(
                    any("exactly one hard link" in item for item in failures)
                )
                hardlink.unlink()

                real = secret_dir / "app_db_password.real"
                victim.rename(real)
                victim.symlink_to(real.name)
                failures = []
                PREFLIGHT.validate_secret_files(values, failures)
                self.assertTrue(
                    any("must not be a symbolic link" in item for item in failures)
                )
                victim.unlink()
                real.rename(victim)

                values["APP_ENV"] = "production"
                failures = []
                PREFLIGHT.validate_secret_files(values, failures)
                self.assertTrue(
                    any(
                        "secret parent" in item and "writable by group/other" in item
                        for item in failures
                    ),
                    failures,
                )
                if os.geteuid() != 0:
                    self.assertTrue(
                        any(
                            str(secret_dir) in item and "owned by root:root" in item
                            for item in failures
                        ),
                        failures,
                    )


class HostHardeningStaticTests(unittest.TestCase):
    def test_ansible_requires_explicit_existing_host_confirmation(self) -> None:
        text = (ROOT / "infra" / "ansible" / "playbook.yml").read_text(encoding="utf-8")
        for control in (
            "CONFIGURE_EXISTING_UBUNTU_24_04",
            "codex_require_encrypted_data_mount",
            "PasswordAuthentication no",
            "coder-provisioner",
            "ufw --force reset",
            "unattended-upgrades",
            "auditd",
            "chrony",
            "fail2ban",
            "xfsprogs",
            "pquota",
            "prjquota",
            "verify-workspace-storage.sh",
            "codex_workspace_io_device",
            "containers.conf",
        ):
            if control == "PasswordAuthentication no":
                security = (
                    ROOT / "infra" / "security" / "sshd-hardening.conf"
                ).read_text(encoding="utf-8")
                self.assertIn(control, security)
            else:
                self.assertIn(control, text)

    def test_ansible_installs_checksum_pinned_security_tools(self) -> None:
        path = ROOT / "infra" / "ansible" / "playbook.yml"
        text = path.read_text(encoding="utf-8")
        play = yaml.safe_load(text)[0]
        variables = play["vars"]
        tasks = {task["name"]: task for task in play["tasks"]}

        self.assertEqual(
            variables["security_tool_architecture"],
            {"x86_64": "amd64", "aarch64": "arm64"},
        )
        self.assertEqual(variables["trivy_version"], "0.72.0")
        self.assertEqual(
            variables["trivy_archive_architecture"],
            {"amd64": "64bit", "arm64": "ARM64"},
        )
        self.assertEqual(
            variables["trivy_sha256"],
            {
                "amd64": "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea",
                "arm64": "2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467",
            },
        )
        self.assertEqual(variables["syft_version"], "1.46.0")
        self.assertEqual(
            variables["syft_sha256"],
            {
                "amd64": "d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca",
                "arm64": "9fafef4db4f032ce81008d3a1529985d41ceb6ccdf2b388c9ce2f1ed7d32082e",
            },
        )

        cache = tasks["Create root-only security tool cache directories"]
        self.assertEqual(cache["ansible.builtin.file"]["owner"], "root")
        self.assertEqual(cache["ansible.builtin.file"]["group"], "root")
        self.assertEqual(cache["ansible.builtin.file"]["mode"], "0700")
        self.assertEqual(
            cache["loop"],
            [
                "/var/cache/codex-mobile",
                "/var/cache/codex-mobile/downloads",
                "/var/cache/codex-mobile/trivy",
            ],
        )

        downloads = {
            "Download exact Trivy archive": (
                "https://github.com/aquasecurity/trivy/releases/download/"
                "v{{ trivy_version }}/trivy_{{ trivy_version }}_Linux-"
                "{{ trivy_archive_architecture[security_tool_architecture"
                "[ansible_facts.architecture]] }}.tar.gz",
                "trivy_sha256",
            ),
            "Download exact Syft archive": (
                "https://github.com/anchore/syft/releases/download/"
                "v{{ syft_version }}/syft_{{ syft_version }}_linux_"
                "{{ security_tool_architecture[ansible_facts.architecture] }}"
                ".tar.gz",
                "syft_sha256",
            ),
        }
        for name, (expected_url, checksum_variable) in downloads.items():
            task = tasks[name]
            get_url = task["ansible.builtin.get_url"]
            self.assertEqual(get_url["url"], expected_url)
            self.assertTrue(
                get_url["dest"].startswith("/var/cache/codex-mobile/downloads/")
            )
            self.assertEqual(get_url["owner"], "root")
            self.assertEqual(get_url["group"], "root")
            self.assertEqual(get_url["mode"], "0600")
            self.assertEqual(
                get_url["checksum"],
                f"sha256:{{{{ {checksum_variable}"
                "[security_tool_architecture[ansible_facts.architecture]] }}",
            )
            self.assertEqual(task["when"], "not ansible_check_mode")

        for name, binary in (
            ("Unpack exact Trivy binary", "trivy"),
            ("Unpack exact Syft binary", "syft"),
        ):
            task = tasks[name]
            unarchive = task["ansible.builtin.unarchive"]
            self.assertEqual(unarchive["dest"], "/usr/local/bin")
            self.assertEqual(unarchive["include"], [binary])
            self.assertEqual(unarchive["owner"], "root")
            self.assertEqual(unarchive["group"], "root")
            self.assertEqual(unarchive["mode"], "0755")
            self.assertEqual(task["when"], "not ansible_check_mode")

        trivy_version = tasks["Read installed Trivy version as JSON"]
        self.assertEqual(
            trivy_version["ansible.builtin.command"]["argv"],
            ["/usr/local/bin/trivy", "--version", "--format", "json"],
        )
        syft_version = tasks["Read installed Syft version as JSON"]
        self.assertEqual(
            syft_version["ansible.builtin.command"]["argv"],
            ["/usr/local/bin/syft", "version", "--output", "json"],
        )
        for task in (trivy_version, syft_version):
            self.assertIs(task["changed_when"], False)
            self.assertEqual(task["when"], "not ansible_check_mode")
            self.assertNotIn("failed_when", task)

        exact_version_gate = tasks["Require exact installed security tool versions"]
        checks = exact_version_gate["ansible.builtin.assert"]["that"]
        self.assertIn(
            "(codex_trivy_version_output.stdout | from_json).Version == trivy_version",
            checks,
        )
        self.assertIn(
            "(codex_syft_version_output.stdout | from_json).version == syft_version",
            checks,
        )
        self.assertEqual(exact_version_gate["when"], "not ansible_check_mode")
        self.assertNotIn("trivy_version not in", text)
        self.assertNotIn("syft_version not in", text)
        self.assertNotRegex(text, r"(?m)^\s*(?:curl|wget)\b[^\n]*\|")

    def test_systemd_units_do_not_grant_engine_access_to_control_stack(self) -> None:
        control = (ROOT / "infra" / "systemd" / "codex-mobile.service").read_text(
            encoding="utf-8"
        )
        runtime = (
            ROOT / "infra" / "systemd" / "codex-mobile-workspace-runtime.service"
        ).read_text(encoding="utf-8")
        provisioner = (
            ROOT / "infra" / "systemd" / "codex-mobile-provisioner.service"
        ).read_text(encoding="utf-8")
        self.assertNotIn("coder.service.wants", control)
        self.assertIn("User=root", runtime)
        self.assertIn("Group=coder-provisioner", runtime)
        self.assertIn("verify-workspace-storage", runtime)
        self.assertIn("ensure-workspace-control-network", runtime)
        self.assertIn("CONTAINERS_CONF=/etc/codex-mobile/containers.conf", runtime)
        self.assertIn("EnvironmentFile=/etc/codex-mobile/production.env", runtime)
        self.assertIn("PrivateDevices=no", runtime)
        self.assertIn("DevicePolicy=closed", runtime)
        self.assertIn("chmod 0660", runtime)
        self.assertIn(
            "--network-config-dir=/srv/codex-mobile/workspaces/.networks", runtime
        )
        self.assertIn("User=coder-provisioner", provisioner)
        self.assertIn("LoadCredential=coder_provisioner_key", provisioner)
        self.assertNotIn("0.0.0.0:2113", provisioner)
        firewall = (ROOT / "infra" / "systemd" / "apply-docker-firewall.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("DOCKER-USER", firewall)
        self.assertIn("-i cm-data0", firewall)
        self.assertIn("-i cm-control0", firewall)
        self.assertIn("WORKSPACE_CONTROL_SUBNET", firewall)
        self.assertIn("CODEX-MOBILE-INPUT", firewall)
        self.assertNotIn("--dport 443", firewall)

    def test_workspace_runtime_fails_closed_without_xfs_project_quotas(self) -> None:
        verifier = (
            ROOT / "infra" / "systemd" / "verify-workspace-storage.sh"
        ).read_text(encoding="utf-8")
        for control in (
            "/srv/codex-mobile/workspaces",
            "/srv/codex-mobile",
            "findmnt",
            "FSTYPE",
            "OPTIONS",
            "pquota",
            "prjquota",
            "WORKSPACE_IO_DEVICE",
            "-b",
            "pids_limit",
            "0:0:600",
            "262144",
            "com.codex-mobile.managed=true",
            "violates the current runtime admission policy",
        ):
            self.assertIn(control, verifier)
        for destructive in ("mkfs", "mount -o", "losetup", "parted"):
            self.assertNotIn(destructive, verifier)

        spike = (ROOT / "scripts" / "infra-linux-runtime-spike.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("--opt o=size=8M,inodes=1024", spike)
        self.assertIn("--storage-opt size=8M", spike)
        self.assertIn("--storage-opt inodes=1024", spike)
        self.assertIn("disk quota exceeded|quota exceeded", spike)
        self.assertIn("--userns private", spike)
        self.assertIn("com.codex-mobile.managed=true", spike)
        self.assertIn("/pids.max", spike)
        self.assertIn("/io.max", spike)
        self.assertNotIn('name "$prefix-limits"', spike)

        defaults = (ROOT / "infra" / "containers.conf").read_text(encoding="utf-8")
        self.assertIn("pids_limit = 512", defaults)
        storage = (ROOT / "infra" / "containers-storage.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn('size = "4G"', storage)
        self.assertIn('inodes = "262144"', storage)

    def test_proxy_never_routes_to_coder(self) -> None:
        caddy = (
            (ROOT / "infra" / "caddy" / "Caddyfile").read_text(encoding="utf-8").lower()
        )
        self.assertIn("reverse_proxy control-plane:8080", caddy)
        self.assertNotIn("reverse_proxy coder", caddy)

    def test_wildcard_certificate_gate_is_explicit(self) -> None:
        runbook = (ROOT / "infra" / "README.md").read_text(encoding="utf-8")
        self.assertIn("Wildcard issuance requires DNS-01", runbook)
        self.assertIn("Do not enable unrestricted on-demand TLS", runbook)
        self.assertIn("*.PREVIEW_DOMAIN", runbook)

    def test_template_import_targets_only_private_podman_provisioner(self) -> None:
        script = (ROOT / "scripts" / "infra-import-coder-template.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("--provisioner-tag runtime=private-podman", script)
        self.assertIn('--variable "workspace_io_device=$workspace_io_device"', script)
        self.assertIn(
            '--variable "coder_control_address=$coder_control_address"', script
        )
        self.assertIn('--variable "coder_control_port=$coder_control_port"', script)
        self.assertIn("CODER_SESSION_TOKEN", script)
        self.assertNotIn("--token", script)


if __name__ == "__main__":
    unittest.main()
