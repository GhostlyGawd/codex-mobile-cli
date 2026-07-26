from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = load_script("generate-supply-chain.py")
VALIDATOR = load_script("validate-release-artifacts.py")


def ecosystem(component: dict[str, object]) -> str:
    for property_record in component.get("properties", []):
        if (
            isinstance(property_record, dict)
            and property_record.get("name") == "codex-mobile:ecosystem"
        ):
            return str(property_record.get("value"))
    return ""


class CodexCLISupplyChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(
            (ROOT / "docs/security/SBOM.cdx.json").read_text(encoding="utf-8")
        )

    @staticmethod
    def failures(document: dict[str, object]) -> list[str]:
        failures: list[str] = []
        VALIDATOR.check_sbom(failures, document=document)
        return failures

    def test_generator_binds_both_official_release_assets(self) -> None:
        components = GENERATOR.codex_cli_components(ROOT)
        application = [
            component
            for component in components
            if component.ecosystem == "Codex CLI application"
        ]
        assets = {
            component.name: component
            for component in components
            if component.ecosystem == "Codex CLI release asset"
        }

        self.assertEqual(len(application), 1)
        self.assertEqual(application[0].version, "0.145.0")
        self.assertEqual(application[0].license_expression, "Apache-2.0")
        self.assertEqual(
            {name: component.checksum for name, component in assets.items()},
            {
                "codex-package-x86_64-unknown-linux-musl.tar.gz": (
                    "71a28d362c96ac9829bf8203a2c71be451aeb726adb843167fdaf0eae8fe7dd9"
                ),
                "codex-package-aarch64-unknown-linux-musl.tar.gz": (
                    "54f79a05aba6f9abf8ef988abcae8bf2fcefba20beb549b4ff2b3acdb2cb6f54"
                ),
            },
        )
        for name, component in assets.items():
            self.assertEqual(component.component_type, "file")
            self.assertEqual(component.license_expression, "Apache-2.0")
            self.assertEqual(component.checksum_algorithm, "SHA-256")
            self.assertEqual(
                component.source,
                (
                    "https://github.com/openai/codex/releases/download/"
                    f"rust-v0.145.0/{name}"
                ),
            )

    def test_generated_sbom_passes_codex_semantic_validation(self) -> None:
        self.assertEqual(self.failures(copy.deepcopy(self.document)), [])

    def test_missing_application_or_asset_fails_closed(self) -> None:
        for omitted_ecosystem, expected_failure in (
            ("Codex CLI application", "exact Codex CLI application is missing"),
            ("Codex CLI release asset", "exact Codex CLI release assets are missing"),
        ):
            with self.subTest(omitted_ecosystem=omitted_ecosystem):
                document = copy.deepcopy(self.document)
                document["components"] = [
                    component
                    for component in document["components"]
                    if ecosystem(component) != omitted_ecosystem
                ]
                self.assertTrue(
                    any(
                        expected_failure in failure
                        for failure in self.failures(document)
                    )
                )

    def test_release_asset_hash_drift_fails_closed(self) -> None:
        document = copy.deepcopy(self.document)
        target = next(
            component
            for component in document["components"]
            if ecosystem(component) == "Codex CLI release asset"
        )
        target["hashes"][0]["content"] = "0" * 64

        self.assertTrue(
            any(
                "Codex CLI release asset" in failure and "is invalid" in failure
                for failure in self.failures(document)
            )
        )


if __name__ == "__main__":
    unittest.main()
