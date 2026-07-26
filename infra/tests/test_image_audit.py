from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_script():
    path = ROOT / "scripts" / "infra_image_audit.py"
    spec = importlib.util.spec_from_file_location("infra_image_audit", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


AUDIT = load_script()
AS_OF = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
RELEASE_ID = "sha-0123456789abcdef"


def canonical(document: dict[str, object]) -> bytes:
    return json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def disposition(
    *,
    disposition_id: str = "IMG-2026-900",
    expires_on: str = "2026-08-26",
    finding: object | None = None,
) -> dict[str, object]:
    finding = finding or AUDIT.Finding(
        image="control_plane",
        kind="vulnerability",
        category="",
        target="usr/local/bin/control-plane",
        finding_id="CVE-2026-0001",
        package="example/module",
        version="v1.2.3",
        severity="HIGH",
        path="",
    )
    return {
        "id": disposition_id,
        "expires_on": expires_on,
        "statement": "Exact temporary disposition with a bounded review date.",
        "match": {
            "image": finding.image,
            "kind": finding.kind,
            "category": finding.category,
            "target": finding.target,
            "finding_id": finding.finding_id,
            "package": finding.package,
            "version": finding.version,
            "severity": finding.severity,
            "path": finding.path,
        },
    }


def policy_document(dispositions: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "test-image-dispositions",
        "dispositions": dispositions,
    }


class IdentityAndCommandTests(unittest.TestCase):
    def test_release_references_are_fixed_and_commit_derived(self) -> None:
        references = AUDIT.image_references(RELEASE_ID)
        self.assertEqual(
            references,
            {
                "control_plane": {
                    "engine": "docker",
                    "reference": f"localhost/codex-mobile/control-plane:{RELEASE_ID}",
                },
                "workspace_base": {
                    "engine": "podman",
                    "reference": f"localhost/codex-mobile/workspace-base:{RELEASE_ID}",
                },
                "envbuilder": {
                    "engine": "podman",
                    "reference": f"localhost/codex-mobile/envbuilder:{RELEASE_ID}",
                },
            },
        )
        for invalid in ("latest", "sha-ABCDEF0", "sha-123", "sha-abc/def"):
            with self.subTest(invalid=invalid), self.assertRaises(AUDIT.AuditError):
                AUDIT.image_references(invalid)

    def test_only_absolute_local_podman_socket_urls_are_accepted(self) -> None:
        self.assertEqual(
            AUDIT.validate_podman_url("unix:///run/codex-mobile-podman/podman.sock")[1],
            "/run/codex-mobile-podman/podman.sock",
        )
        for invalid in (
            "tcp://127.0.0.1:8080",
            "unix://host/run/podman.sock",
            "unix:///run/../tmp/podman.sock",
            "unix:////run/podman.sock",
            "unix:///run//podman.sock",
            "unix:///run/%2Fpodman.sock",
            "unix:///run/%ZZ-podman.sock",
            "unix:///run\\podman.sock",
            "unix:///run/\npodman.sock",
            "unix:///run/\x7fpodman.sock",
            "unix://[::1",
            "unix:///",
            "unix:relative.sock",
            "https://example.test/socket",
            None,
        ):
            with self.subTest(invalid=invalid), self.assertRaises(AUDIT.AuditError):
                AUDIT.validate_podman_url(invalid)

    def test_verify_require_images_rejects_remote_podman_url_before_execution(
        self,
    ) -> None:
        with redirect_stderr(io.StringIO()):
            result = AUDIT.main(
                [
                    "verify",
                    "--repo-root",
                    str(ROOT),
                    "--release-id",
                    RELEASE_ID,
                    "--require-images",
                    "--podman-url",
                    "tcp://127.0.0.1:8080",
                ]
            )
        self.assertEqual(result, int(AUDIT.ExitCode.USAGE))

    def test_non_normalized_podman_url_fails_before_cli_prerequisites(self) -> None:
        with redirect_stderr(io.StringIO()):
            result = AUDIT.main(
                [
                    "scan",
                    "--repo-root",
                    str(ROOT),
                    "--release-id",
                    RELEASE_ID,
                    "--podman-url",
                    "unix:///run//podman.sock",
                ]
            )
        self.assertEqual(result, int(AUDIT.ExitCode.USAGE))

    def test_non_finite_json_numbers_fail_closed_at_any_depth(self) -> None:
        with self.assertRaisesRegex(AUDIT.AuditError, "non-finite number"):
            AUDIT.parse_json_bytes(
                b'{"nested":{"value":NaN}}',
                "hostile report",
            )

    def test_scanner_commands_use_captured_ids_and_no_global_ignore(self) -> None:
        image_id = "sha256:" + "a" * 64
        docker_spec = AUDIT.IMAGE_SPEC_BY_KEY["control_plane"]
        podman_spec = AUDIT.IMAGE_SPEC_BY_KEY["workspace_base"]
        syft_config = Path("/private/syft.yaml")
        syft = AUDIT.syft_argv(docker_spec, image_id, syft_config)
        self.assertIn(f"docker:{image_id}", syft)
        self.assertIn("cyclonedx-json@1.6", syft)
        self.assertEqual(syft[syft.index("--config") + 1], str(syft_config))
        self.assertNotIn("/dev/null", syft)
        self.assertNotIn("latest", " ".join(syft))
        with self.assertRaisesRegex(AUDIT.AuditError, "YAML extension"):
            AUDIT.syft_argv(docker_spec, image_id, Path("/dev/null"))

        trivy = AUDIT.trivy_argv(
            podman_spec,
            image_id,
            Path("/private/cache"),
            Path("/private/trivy.yaml"),
            Path("/private/empty.ignore"),
            "/run/podman/podman.sock",
        )
        self.assertIn(image_id, trivy)
        self.assertEqual(trivy[trivy.index("--exit-code") + 1], "0")
        self.assertEqual(trivy[trivy.index("--image-src") + 1], "podman")
        self.assertEqual(
            trivy[trivy.index("--podman-host") + 1],
            "/run/podman/podman.sock",
        )
        self.assertNotIn(".trivyignore.yaml", trivy)
        self.assertIn("--skip-db-update", trivy)
        self.assertIn("--offline-scan", trivy)

    def test_only_podman_bare_image_ids_are_canonicalized(self) -> None:
        bare = "b" * 64

        def runner(_argv, **_kwargs):
            return AUDIT.CommandResult(
                0,
                f"{bare}\t1024\tlinux\tamd64\n".encode(),
                b"",
                0,
            )

        snapshot = AUDIT.inspect_image(
            "podman",
            "localhost/example:tag",
            "unix:///run/podman/podman.sock",
            cwd=ROOT,
            environment=AUDIT.minimal_environment(ROOT),
            runner=runner,
        )
        self.assertEqual(snapshot.image_id, f"sha256:{bare}")
        with self.assertRaisesRegex(AUDIT.AuditError, "full sha256"):
            AUDIT.inspect_image(
                "docker",
                "localhost/example:tag",
                "unix:///run/podman/podman.sock",
                cwd=ROOT,
                environment=AUDIT.minimal_environment(ROOT),
                runner=runner,
            )
        for invalid in ("c" * 63, "C" * 64, "c" * 65, "sha512:" + "c" * 64):
            with self.subTest(invalid=invalid):

                def invalid_runner(_argv, **_kwargs):
                    return AUDIT.CommandResult(
                        0,
                        f"{invalid}\t1024\tlinux\tamd64\n".encode(),
                        b"",
                        0,
                    )

                with self.assertRaisesRegex(AUDIT.AuditError, "full sha256"):
                    AUDIT.inspect_image(
                        "podman",
                        "localhost/example:tag",
                        "unix:///run/podman/podman.sock",
                        cwd=ROOT,
                        environment=AUDIT.minimal_environment(ROOT),
                        runner=invalid_runner,
                    )

    def test_minimal_environment_does_not_inherit_credentials_or_proxies(self) -> None:
        environment = AUDIT.minimal_environment(Path("/private/audit"))
        for forbidden in (
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "DOCKER_AUTH_CONFIG",
            "TRIVY_USERNAME",
            "TRIVY_PASSWORD",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "AWS_SECRET_ACCESS_KEY",
        ):
            self.assertNotIn(forbidden, environment)
        self.assertEqual(
            environment["PATH"], "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )

    def test_tool_and_database_size_pins_cover_supported_architectures(self) -> None:
        self.assertEqual(set(AUDIT.TOOL_POLICY), {"amd64", "arm64"})
        for architecture, tools in AUDIT.TOOL_POLICY.items():
            with self.subTest(architecture=architecture):
                for name in ("trivy", "syft"):
                    self.assertRegex(tools[name]["asset_sha256"], r"^[0-9a-f]{64}$")
                    self.assertRegex(
                        tools[name]["executable_sha256"], r"^[0-9a-f]{64}$"
                    )
        self.assertEqual(AUDIT.MAX_DATABASE_BYTES, 2 * 1024 * 1024 * 1024)

    def test_scanner_profile_registry_retains_immutable_history(self) -> None:
        self.assertEqual(AUDIT.CURRENT_SCANNER_POLICY_VERSION, 2)
        self.assertEqual(set(AUDIT.SCANNER_PROFILE_REGISTRY), {1, 2})
        historical = AUDIT.SCANNER_PROFILE_REGISTRY[1]
        current = AUDIT.SCANNER_PROFILE_REGISTRY[2]
        self.assertEqual(AUDIT.scanner_policy_document(1)["version"], 1)
        self.assertEqual(historical.tools, current.tools)
        self.assertIsNot(historical.tools, current.tools)
        self.assertIsNot(
            historical.tools["amd64"],
            current.tools["amd64"],
        )
        self.assertIsNot(
            historical.tools["amd64"]["trivy"],
            current.tools["amd64"]["trivy"],
        )
        self.assertEqual(historical.max_report_bytes, 67_108_864)
        self.assertEqual(
            historical.tools["amd64"]["trivy"]["version"],
            "0.72.0",
        )
        self.assertEqual(current.evidence_schema_version, AUDIT.SCHEMA_VERSION)
        self.assertEqual(current.max_image_size_bytes, AUDIT.MAX_IMAGE_BYTES)
        self.assertEqual(current.max_report_bytes, AUDIT.MAX_REPORT_BYTES)
        self.assertEqual(current.max_database_bytes, AUDIT.MAX_DATABASE_BYTES)
        with self.assertRaises(TypeError):
            AUDIT.SCANNER_PROFILE_REGISTRY[3] = AUDIT.SCANNER_PROFILE_REGISTRY[2]
        with self.assertRaises(TypeError):
            current.tools["amd64"]["trivy"]["version"] = "changed"
        self.assertEqual(
            historical.tools["amd64"]["trivy"]["version"],
            "0.72.0",
        )


class DispositionPolicyTests(unittest.TestCase):
    def make_repo(self, document: dict[str, object]) -> Path:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "infra").mkdir()
        (root / AUDIT.POLICY_RELATIVE).write_bytes(canonical(document))
        return root

    def test_tracked_starter_policy_is_exact_and_loads(self) -> None:
        policy = AUDIT.load_disposition_policy(ROOT, AS_OF)
        self.assertEqual(policy.policy_id, "codex-mobile-release-image-dispositions")
        self.assertEqual(len(policy.dispositions), 8)
        self.assertEqual(
            {item.disposition_id for item in policy.dispositions},
            {f"IMG-2026-{index:03d}" for index in range(1, 9)},
        )
        license_disposition = next(
            item for item in policy.dispositions if item.match.kind == "license"
        )
        self.assertEqual(license_disposition.match.category, "forbidden")
        self.assertEqual(
            license_disposition.match.path,
            "usr/share/licenses/coder/LICENSE",
        )

    def test_duplicate_policy_keys_fail_closed(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "infra").mkdir()
        (root / AUDIT.POLICY_RELATIVE).write_text(
            '{"schema_version":1,"policy_id":"reviewed",'
            '"policy_id":"shadowed","dispositions":[]}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "duplicate object key"):
            AUDIT.load_disposition_policy(root, AS_OF)

    def test_exact_finding_is_disposed_and_summary_contains_only_metadata(self) -> None:
        finding = AUDIT.Finding(
            image="control_plane",
            kind="vulnerability",
            category="",
            target="usr/local/bin/control-plane",
            finding_id="CVE-2026-0001",
            package="example/module",
            version="v1.2.3",
            severity="HIGH",
            path="",
        )
        root = self.make_repo(policy_document([disposition(finding=finding)]))
        policy = AUDIT.load_disposition_policy(root, AS_OF)
        decisions = AUDIT.evaluate_dispositions([finding], policy)
        AUDIT.enforce_dispositions(decisions)
        summary = AUDIT.finding_summary(decisions)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["disposed"], 1)
        self.assertEqual(summary["undispositioned"], 0)
        self.assertEqual(summary["disposition_ids"], ["IMG-2026-900"])
        serialized = json.dumps(summary)
        self.assertNotIn("example/module", serialized)
        self.assertNotIn("usr/local/bin/control-plane", serialized)

    def test_every_match_field_is_exact(self) -> None:
        finding = AUDIT.Finding(
            image="control_plane",
            kind="vulnerability",
            category="",
            target="usr/local/bin/control-plane",
            finding_id="CVE-2026-0001",
            package="example/module",
            version="v1.2.3",
            severity="HIGH",
            path="",
        )
        root = self.make_repo(policy_document([disposition(finding=finding)]))
        policy = AUDIT.load_disposition_policy(root, AS_OF)
        replacements = {
            "image": "workspace_base",
            "kind": "license",
            "category": "forbidden",
            "target": "different",
            "finding_id": "CVE-2026-9999",
            "package": "other/module",
            "version": "v9.9.9",
            "severity": "CRITICAL",
            "path": "different/path",
        }
        for field, value in replacements.items():
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(AUDIT.AuditError, "not exercised"),
            ):
                changed = dataclasses.replace(finding, **{field: value})
                AUDIT.evaluate_dispositions([changed], policy)

    def test_unused_disposition_fails_closed(self) -> None:
        root = self.make_repo(policy_document([disposition()]))
        policy = AUDIT.load_disposition_policy(root, AS_OF)
        with self.assertRaisesRegex(AUDIT.AuditError, "not exercised"):
            AUDIT.evaluate_dispositions([], policy)

    def test_duplicate_ids_matches_wildcards_and_extra_fields_are_rejected(
        self,
    ) -> None:
        duplicate_id = policy_document(
            [
                disposition(),
                disposition(
                    finding=dataclasses.replace(
                        AUDIT.Finding(
                            image="control_plane",
                            kind="vulnerability",
                            category="",
                            target="one",
                            finding_id="CVE-1",
                            package="p",
                            version="v",
                            severity="HIGH",
                            path="",
                        ),
                        target="two",
                    )
                ),
            ]
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "IDs must be unique"):
            AUDIT.load_disposition_policy(self.make_repo(duplicate_id), AS_OF)

        wildcard = disposition()
        wildcard["match"]["package"] = "example/*"
        with self.assertRaisesRegex(AUDIT.AuditError, "glob"):
            AUDIT.load_disposition_policy(
                self.make_repo(policy_document([wildcard])), AS_OF
            )

        extra = disposition()
        extra["match"]["cvss"] = 9.8
        with self.assertRaisesRegex(AUDIT.AuditError, "field inventory"):
            AUDIT.load_disposition_policy(
                self.make_repo(policy_document([extra])), AS_OF
            )

    def test_expired_and_effectively_permanent_dispositions_are_rejected(self) -> None:
        for expiry, message in (
            ("2026-07-25", "expired"),
            ("2027-07-26", "more than"),
        ):
            with (
                self.subTest(expiry=expiry),
                self.assertRaisesRegex(AUDIT.AuditError, message),
            ):
                AUDIT.load_disposition_policy(
                    self.make_repo(policy_document([disposition(expires_on=expiry)])),
                    AS_OF,
                )

    def test_modified_findings_cannot_be_silently_disposed(self) -> None:
        modified = AUDIT.Finding(
            image="control_plane",
            kind="modified",
            category="",
            target="binary",
            finding_id="MODIFIED-1",
            package="",
            version="",
            severity="UNKNOWN",
            path="",
        )
        root = self.make_repo(policy_document([]))
        decisions = AUDIT.evaluate_dispositions(
            [modified], AUDIT.load_disposition_policy(root, AS_OF)
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "undispositioned"):
            AUDIT.enforce_dispositions(decisions)


class ReportValidationTests(unittest.TestCase):
    image_id = "sha256:" + "a" * 64

    def cyclonedx(self) -> dict[str, object]:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "syft",
                            "version": "1.46.0",
                        }
                    ]
                },
                "component": {
                    "type": "container",
                    "name": "sha256",
                    "version": self.image_id.removeprefix("sha256:"),
                },
            },
            "components": [{"type": "library", "name": "one", "version": "1"}],
        }

    def trivy(self) -> dict[str, object]:
        return {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.72.0"},
            "ArtifactID": "not-the-image-id",
            "ArtifactName": self.image_id,
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": self.image_id,
                "OS": {"Family": "ubuntu", "Name": "24.04"},
            },
            "Results": [
                {
                    "Target": "usr/local/bin/control-plane",
                    "Class": "lang-pkgs",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "PkgName": "example/module",
                            "InstalledVersion": "v1.2.3",
                            "Severity": "HIGH",
                            "PkgPath": "",
                        }
                    ],
                },
                {
                    "Target": "Loose File License(s)",
                    "Class": "license-file",
                    "Licenses": [
                        {
                            "Name": "AGPL-3.0",
                            "Category": "forbidden",
                            "Severity": "CRITICAL",
                            "PkgName": "",
                            "FilePath": "usr/share/licenses/coder/LICENSE",
                        }
                    ],
                },
            ],
        }

    def test_syft_version_subject_and_component_count_are_bound(self) -> None:
        self.assertEqual(
            AUDIT.validate_cyclonedx_report(self.cyclonedx(), self.image_id),
            1,
        )
        for mutation in ("version", "spec", "tool"):
            report = self.cyclonedx()
            if mutation == "version":
                report["metadata"]["component"]["version"] = "b" * 64
            elif mutation == "spec":
                report["specVersion"] = "1.7"
            else:
                report["metadata"]["tools"]["components"][0]["version"] = "1.45.0"
            with self.subTest(mutation=mutation), self.assertRaises(AUDIT.AuditError):
                AUDIT.validate_cyclonedx_report(report, self.image_id)

    def test_trivy_metadata_image_id_not_artifact_id_binds_subject(self) -> None:
        findings = AUDIT.validate_trivy_report(
            self.trivy(), "control_plane", self.image_id
        )
        self.assertEqual(len(findings), 2)
        vulnerability, license_finding = findings
        self.assertEqual(vulnerability.package, "example/module")
        self.assertEqual(vulnerability.version, "v1.2.3")
        self.assertEqual(license_finding.category, "forbidden")
        self.assertEqual(license_finding.path, "usr/share/licenses/coder/LICENSE")

        wrong = self.trivy()
        wrong["Metadata"]["ImageID"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(AUDIT.AuditError, "subject"):
            AUDIT.validate_trivy_report(wrong, "control_plane", self.image_id)

    def test_end_of_life_and_modified_findings_fail_closed(self) -> None:
        eol = self.trivy()
        eol["Metadata"]["OS"]["EOSL"] = True
        with self.assertRaisesRegex(AUDIT.AuditError, "end-of-life"):
            AUDIT.validate_trivy_report(eol, "control_plane", self.image_id)

        modified = self.trivy()
        modified["Results"][0]["ExperimentalModifiedFindings"] = [{"Status": "ignored"}]
        findings = AUDIT.validate_trivy_report(modified, "control_plane", self.image_id)
        self.assertTrue(any(item.kind == "modified" for item in findings))

    def test_falsey_non_array_finding_inventories_fail_closed(self) -> None:
        for field in (
            "Vulnerabilities",
            "Secrets",
            "Licenses",
            "ExperimentalModifiedFindings",
        ):
            for malformed in ({}, 0, ""):
                with self.subTest(field=field, malformed=malformed):
                    report = self.trivy()
                    report["Results"][0][field] = malformed
                    with self.assertRaisesRegex(
                        AUDIT.AuditError,
                        "must be an array",
                    ):
                        AUDIT.validate_trivy_report(
                            report,
                            "control_plane",
                            self.image_id,
                        )

    def test_secret_finding_records_rule_category_severity_and_path_only(self) -> None:
        report = self.trivy()
        report["Results"] = [
            {
                "Target": "image-config",
                "Secrets": [
                    {
                        "RuleID": "github-pat",
                        "Category": "GitHub",
                        "Severity": "CRITICAL",
                        "FilePath": "config.Env",
                        "Match": "do-not-copy-secret-body",
                    }
                ],
            }
        ]
        finding = AUDIT.validate_trivy_report(report, "control_plane", self.image_id)[0]
        self.assertEqual(finding.finding_id, "github-pat")
        self.assertEqual(finding.category, "GitHub")
        self.assertEqual(finding.path, "config.Env")
        self.assertNotIn("do-not-copy", repr(finding))


class BoundedSubprocessAndFileTests(unittest.TestCase):
    def test_bounded_command_captures_small_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = AUDIT.run_bounded(
                [sys.executable, "-c", "print('ok')"],
                cwd=Path(raw),
                env=os.environ.copy(),
                timeout_seconds=5,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), b"ok")

    def test_output_limit_and_timeout_kill_the_command(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(AUDIT.AuditError, "output limit"):
                AUDIT.run_bounded(
                    [sys.executable, "-c", "print('x' * 10000)"],
                    cwd=Path(raw),
                    env=os.environ.copy(),
                    timeout_seconds=5,
                    stdout_limit=64,
                )
            started = time.monotonic()
            with self.assertRaisesRegex(AUDIT.AuditError, "timed out"):
                AUDIT.run_bounded(
                    [sys.executable, "-c", "import time; time.sleep(10)"],
                    cwd=Path(raw),
                    env=os.environ.copy(),
                    timeout_seconds=1,
                )
            self.assertLess(time.monotonic() - started, 5)

    def test_report_stdout_can_stream_to_a_bounded_private_sink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "report"
            with destination.open("wb") as sink:
                result = AUDIT.run_bounded(
                    [sys.executable, "-c", "print('{\"ok\": true}')"],
                    cwd=Path(raw),
                    env=os.environ.copy(),
                    timeout_seconds=5,
                    stdout_limit=1024,
                    stdout_sink=sink,
                )
            self.assertEqual(result.stdout, b"")
            self.assertEqual(destination.read_text().strip(), '{"ok": true}')

    def test_regular_file_reader_rejects_oversize_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            file = root / "file"
            file.write_bytes(b"12345")
            with self.assertRaisesRegex(AUDIT.AuditError, "size limit"):
                AUDIT.read_regular_bytes(file, 4)
            link = root / "link"
            try:
                link.symlink_to(file.name)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(AUDIT.AuditError, "non-symlink"):
                AUDIT.read_regular_bytes(link, 100)

    @unittest.skipUnless(os.name == "posix", "POSIX cache-lock semantics")
    def test_persistent_trivy_cache_is_locked_and_copied_to_a_frozen_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            work = root / "work"
            work.mkdir(mode=0o700)
            for name in ("home", "cache", "tmp"):
                (work / name).mkdir(mode=0o700)
            persistent = root / "persistent"
            persistent.mkdir(mode=0o700)
            fanal = persistent / "fanal"
            fanal.mkdir(mode=0o755)
            sentinel = fanal / "keep"
            sentinel.write_bytes(b"unrelated cache")
            calls: list[dict[str, object]] = []

            def runner(argv, **kwargs):
                calls.append({"argv": list(argv), **kwargs})
                cache = Path(argv[argv.index("--cache-dir") + 1])
                database = cache / "db"
                database.mkdir(mode=0o700)
                metadata = {
                    "Version": 2,
                    "NextUpdate": "2026-07-27T07:38:45Z",
                    "UpdatedAt": "2026-07-26T07:38:45Z",
                    "DownloadedAt": "2026-07-26T08:44:37Z",
                }
                metadata_path = database / "metadata.json"
                data_path = database / "trivy.db"
                metadata_path.write_bytes(canonical(metadata))
                data_path.write_bytes(b"frozen database")
                database.chmod(0o700)
                metadata_path.chmod(0o600)
                data_path.chmod(0o600)
                return AUDIT.CommandResult(0, b"", b"", 1)

            snapshot, receipt = AUDIT.prepare_trivy_database(
                work,
                AS_OF,
                runner,
                persistent,
            )
            self.assertNotEqual(snapshot, persistent)
            self.assertEqual(
                calls[0]["file_size_limit"],
                AUDIT.MAX_DATABASE_BYTES,
            )
            self.assertEqual(
                receipt["sha256"],
                hashlib.sha256(b"frozen database").hexdigest(),
            )
            (persistent / "db" / "trivy.db").write_bytes(b"changed later")
            self.assertEqual(
                (snapshot / "db" / "trivy.db").read_bytes(),
                b"frozen database",
            )
            self.assertEqual(sentinel.read_bytes(), b"unrelated cache")

    def test_snapshot_drift_checks_every_captured_property(self) -> None:
        expected = AUDIT.ImageSnapshot(
            "sha256:" + "a" * 64,
            1024,
            "linux",
            "amd64",
        )
        changes = (
            {"image_id": "sha256:" + "b" * 64},
            {"size_bytes": 2048},
            {"os_name": "windows"},
            {"architecture": "arm64"},
        )
        for change in changes:
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(
                    AUDIT.AuditError,
                    "changed during audit",
                ),
            ):
                AUDIT._require_same_snapshot(
                    expected,
                    dataclasses.replace(expected, **change),
                    "localhost/example",
                )

    def test_failed_stage_verification_cannot_publish_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            stage = parent / ".image-audit.test"
            final = parent / "image-audit"
            stage.mkdir()

            def reject(_stage: Path) -> dict[str, object]:
                raise AUDIT.AuditError("invalid staged evidence")

            with self.assertRaisesRegex(AUDIT.AuditError, "invalid staged"):
                AUDIT._verify_then_publish_private_evidence(
                    stage,
                    final,
                    reject,
                )
            self.assertTrue(stage.is_dir())
            self.assertFalse(final.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX private-tree semantics")
    def test_private_cleanup_does_not_follow_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            stage = parent / ".image-audit.test"
            stage.mkdir(mode=0o700)
            outside = parent / "outside"
            outside.mkdir()
            sentinel = outside / "keep"
            sentinel.write_text("keep", encoding="utf-8")
            (stage / "escape").symlink_to(outside, target_is_directory=True)
            AUDIT._remove_private_tree(stage, parent)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")


class EvidenceVerificationTests(unittest.TestCase):
    image_ids = {
        "control_plane": "sha256:" + "1" * 64,
        "workspace_base": "sha256:" + "2" * 64,
        "envbuilder": "sha256:" + "3" * 64,
    }

    def make_fixture(self) -> tuple[Path, dict[str, dict[str, str]]]:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        infra = root / "infra"
        infra.mkdir()
        policy_bytes = canonical(policy_document([]))
        (root / AUDIT.POLICY_RELATIVE).write_bytes(policy_bytes)
        policy = AUDIT.load_disposition_policy(root, AS_OF)
        evidence = root / AUDIT.EVIDENCE_RELATIVE
        evidence.mkdir(mode=0o700)
        reports_directory = evidence / "reports"
        reports_directory.mkdir(mode=0o700)
        references = AUDIT.image_references(RELEASE_ID)
        image_records: dict[str, dict[str, object]] = {}
        expected_images: dict[str, dict[str, str]] = {}
        for spec in AUDIT.IMAGE_SPECS:
            image_id = self.image_ids[spec.key]
            sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {
                    "tools": {
                        "components": [
                            {
                                "type": "application",
                                "name": "syft",
                                "version": "1.46.0",
                            }
                        ]
                    },
                    "component": {
                        "type": "container",
                        "name": "sha256",
                        "version": image_id.removeprefix("sha256:"),
                    },
                },
                "components": [],
            }
            trivy = {
                "SchemaVersion": 2,
                "Trivy": {"Version": "0.72.0"},
                "ArtifactType": "container_image",
                "Metadata": {"ImageID": image_id},
                "Results": [],
            }
            sbom_relative, trivy_relative = AUDIT._report_paths(spec)
            sbom_bytes = canonical(sbom)
            trivy_bytes = canonical(trivy)
            sbom_path = evidence / sbom_relative
            trivy_path = evidence / trivy_relative
            sbom_path.write_bytes(sbom_bytes)
            trivy_path.write_bytes(trivy_bytes)
            if os.name == "posix":
                sbom_path.chmod(0o600)
                trivy_path.chmod(0o600)
            reference = references[spec.key]["reference"]
            image_records[spec.key] = {
                "engine": spec.engine,
                "reference": reference,
                "image_id": image_id,
                "image_size_bytes": 1024,
                "os": "linux",
                "architecture": "amd64",
                "tag_image_id_before": image_id,
                "tag_image_id_after": image_id,
                "reports": {
                    "sbom": {
                        "path": sbom_relative,
                        "sha256": hashlib.sha256(sbom_bytes).hexdigest(),
                        "size_bytes": len(sbom_bytes),
                        "format": "CycloneDX",
                        "spec_version": "1.6",
                        "component_count": 0,
                    },
                    "trivy": {
                        "path": trivy_relative,
                        "sha256": hashlib.sha256(trivy_bytes).hexdigest(),
                        "size_bytes": len(trivy_bytes),
                        "format": "trivy-json",
                        "schema_version": 2,
                    },
                },
                "findings": {
                    "total": 0,
                    "disposed": 0,
                    "undispositioned": 0,
                    "by_kind": {},
                    "disposition_ids": [],
                },
            }
            expected_images[spec.key] = {
                "engine": spec.engine,
                "reference": reference,
                "id": image_id,
            }
        database = {
            "version": 2,
            "updated_at": "2026-07-26T07:38:45Z",
            "next_update": "2026-07-27T07:38:45Z",
            "downloaded_at": "2026-07-26T08:44:37Z",
            "sha256": "a" * 64,
            "size_bytes": 1_205_448_704,
        }
        receipt = AUDIT._build_receipt(
            release_id=RELEASE_ID,
            started_at=AS_OF,
            completed_at=AS_OF,
            architecture="amd64",
            tools=AUDIT._expected_tool_receipt("amd64"),
            database=database,
            policy=policy,
            images=image_records,
            decisions=[],
        )
        receipt_path = evidence / "receipt.json"
        receipt_path.write_bytes(canonical(receipt))
        if os.name == "posix":
            evidence.chmod(0o700)
            reports_directory.chmod(0o700)
            receipt_path.chmod(0o600)
        return root, expected_images

    def test_verify_evidence_cross_binds_manifest_and_current_images(self) -> None:
        root, expected = self.make_fixture()

        def resolver(engine: str, reference: str) -> str:
            for key, record in expected.items():
                if (engine, reference) == (record["engine"], record["reference"]):
                    return record["id"]
            raise AssertionError("unexpected image")

        receipt = AUDIT.verify_evidence(
            root,
            RELEASE_ID,
            expected_images=expected,
            image_resolver=resolver,
        )
        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["findings"]["undispositioned"], 0)

    def test_report_tampering_and_extra_files_fail_closed(self) -> None:
        root, _ = self.make_fixture()
        report = root / AUDIT.EVIDENCE_RELATIVE / "reports/control-plane.trivy.json"
        report.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(AUDIT.AuditError, "hash/size"):
            AUDIT.verify_evidence(root, RELEASE_ID)

        root, _ = self.make_fixture()
        extra = root / AUDIT.EVIDENCE_RELATIVE / "reports/extra.json"
        extra.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(AUDIT.AuditError, "inventory"):
            AUDIT.verify_evidence(root, RELEASE_ID)

    def test_duplicate_receipt_and_report_keys_fail_closed(self) -> None:
        root, _ = self.make_fixture()
        receipt_path = root / AUDIT.EVIDENCE_RELATIVE / "receipt.json"
        receipt_text = receipt_path.read_text(encoding="utf-8")
        receipt_path.write_text(
            receipt_text.replace(
                '  "status": "pass",',
                '  "status": "fail",\n  "status": "pass",',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AUDIT.AuditError, "duplicate object key"):
            AUDIT.verify_evidence(root, RELEASE_ID)

        root, _ = self.make_fixture()
        report_path = (
            root / AUDIT.EVIDENCE_RELATIVE / "reports/control-plane.trivy.json"
        )
        report_text = report_path.read_text(encoding="utf-8")
        ambiguous_report = report_text.replace(
            '  "SchemaVersion": 2,',
            '  "SchemaVersion": 999,\n  "SchemaVersion": 2,',
            1,
        ).encode("utf-8")
        report_path.write_bytes(ambiguous_report)
        receipt_path = root / AUDIT.EVIDENCE_RELATIVE / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        report_record = receipt["images"]["control_plane"]["reports"]["trivy"]
        report_record["sha256"] = hashlib.sha256(ambiguous_report).hexdigest()
        report_record["size_bytes"] = len(ambiguous_report)
        receipt_path.write_bytes(canonical(receipt))
        with self.assertRaisesRegex(AUDIT.AuditError, "duplicate object key"):
            AUDIT.verify_evidence(root, RELEASE_ID)

    def test_manifest_and_current_image_mismatches_fail_closed(self) -> None:
        root, expected = self.make_fixture()
        changed = {key: dict(value) for key, value in expected.items()}
        changed["control_plane"]["id"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(AUDIT.AuditError, "manifest image"):
            AUDIT.verify_evidence(root, RELEASE_ID, expected_images=changed)

        with self.assertRaisesRegex(AUDIT.AuditError, "no longer matches"):
            AUDIT.verify_evidence(
                root,
                RELEASE_ID,
                image_resolver=lambda _engine, _reference: "sha256:" + "e" * 64,
            )

    def test_policy_and_receipt_tampering_fail_closed(self) -> None:
        root, _ = self.make_fixture()
        policy_path = root / AUDIT.POLICY_RELATIVE
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["policy_id"] = "changed-policy"
        policy_path.write_bytes(canonical(policy))
        with self.assertRaisesRegex(AUDIT.AuditError, "policy receipt"):
            AUDIT.verify_evidence(root, RELEASE_ID)

        root, _ = self.make_fixture()
        receipt_path = root / AUDIT.EVIDENCE_RELATIVE / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["findings"]["undispositioned"] = 1
        receipt_path.write_bytes(canonical(receipt))
        with self.assertRaisesRegex(AUDIT.AuditError, "summary"):
            AUDIT.verify_evidence(root, RELEASE_ID)

    def test_public_verifier_rejects_remote_podman_urls(self) -> None:
        root, _ = self.make_fixture()
        with self.assertRaisesRegex(AUDIT.AuditError, "local unix"):
            AUDIT.verify_evidence(
                root,
                RELEASE_ID,
                podman_url="tcp://127.0.0.1:8080",
            )

    def test_database_receipt_staleness_and_oversize_fail_closed(self) -> None:
        value = {
            "version": 2,
            "updated_at": "2026-07-26T07:38:45Z",
            "next_update": "2026-07-27T07:38:45Z",
            "downloaded_at": "2026-07-26T08:44:37Z",
            "sha256": "a" * 64,
            "size_bytes": 1024,
        }
        stale = dict(value, updated_at="2026-07-20T07:38:45Z")
        with self.assertRaisesRegex(AUDIT.AuditError, "freshness"):
            AUDIT._verify_database_receipt(stale, AS_OF)
        oversize = dict(value, size_bytes=AUDIT.MAX_DATABASE_BYTES + 1)
        with self.assertRaisesRegex(AUDIT.AuditError, "size"):
            AUDIT._verify_database_receipt(oversize, AS_OF)

    def test_known_historical_scanner_profile_remains_verifiable(self) -> None:
        root, _ = self.make_fixture()
        receipt_path = root / AUDIT.EVIDENCE_RELATIVE / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["scanner_policy"] = AUDIT.scanner_policy_document(1)
        receipt["tools"] = AUDIT._expected_tool_receipt("amd64", 1)
        receipt_path.write_bytes(canonical(receipt))

        verified = AUDIT.verify_evidence(root, RELEASE_ID)
        self.assertEqual(verified["scanner_policy"]["version"], 1)

    def test_unknown_or_tampered_scanner_profiles_fail_closed(self) -> None:
        root, _ = self.make_fixture()
        receipt_path = root / AUDIT.EVIDENCE_RELATIVE / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["scanner_policy"]["version"] = 999
        receipt_path.write_bytes(canonical(receipt))
        with self.assertRaisesRegex(AUDIT.AuditError, "unknown"):
            AUDIT.verify_evidence(root, RELEASE_ID)

        root, _ = self.make_fixture()
        receipt_path = root / AUDIT.EVIDENCE_RELATIVE / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["scanner_policy"]["global_ignores"] = True
        receipt_path.write_bytes(canonical(receipt))
        with self.assertRaisesRegex(AUDIT.AuditError, "policy receipt"):
            AUDIT.verify_evidence(root, RELEASE_ID)


if __name__ == "__main__":
    unittest.main()
