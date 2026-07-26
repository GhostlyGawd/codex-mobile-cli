from __future__ import annotations

import hashlib
import importlib.util
import io
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "verify-envbuilder-source.py"
SPEC = importlib.util.spec_from_file_location("verify_envbuilder_source", SCRIPT_PATH)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class EnvBuilderSourceTests(unittest.TestCase):
    def make_minimal_repo(self, root: Path) -> tuple[Path, Path]:
        lock = root / VERIFIER.LOCK_RELATIVE_PATH
        patch = root / VERIFIER.PATCH_RELATIVE_PATH
        lock.parent.mkdir(parents=True)
        lock.write_bytes((ROOT / VERIFIER.LOCK_RELATIVE_PATH).read_bytes())
        shutil.copyfile(ROOT / VERIFIER.PATCH_RELATIVE_PATH, patch)
        return lock, patch

    def test_tracked_source_lock_and_patch_are_exact(self) -> None:
        lock, patch = VERIFIER.load_and_validate_lock(ROOT)
        self.assertEqual(lock["derivative_version"], "1.3.0-codex-mobile.1")
        self.assertEqual(patch, (ROOT / VERIFIER.PATCH_RELATIVE_PATH).resolve())

    def test_duplicate_lock_key_and_patch_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            lock, _ = self.make_minimal_repo(root)
            content = lock.read_text(encoding="utf-8")
            lock.write_text(
                content.replace(
                    '"schema_version": 1,',
                    '"schema_version": 1, "schema_version": 1,',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                VERIFIER.VerificationError, "duplicate source-lock key"
            ):
                VERIFIER.load_and_validate_lock(root)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, patch = self.make_minimal_repo(root)
            patch.write_bytes(patch.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                VERIFIER.VerificationError, "checksum does not match"
            ):
                VERIFIER.load_and_validate_lock(root)

    def write_archive(self, path: Path, members: list[tarfile.TarInfo]) -> None:
        with tarfile.open(path, mode="w:gz") as archive:
            for member in members:
                if member.isfile():
                    archive.addfile(member, io.BytesIO(b"license\n"))
                else:
                    archive.addfile(member)

    def test_archive_rejects_traversal_and_special_members(self) -> None:
        root_name = VERIFIER.EXPECTED_ROOT
        for malicious in (
            tarfile.TarInfo(f"{root_name}/../escape"),
            tarfile.TarInfo(f"{root_name}/link"),
        ):
            malicious.size = len(b"license\n")
            if malicious.name.endswith("/link"):
                malicious.type = tarfile.SYMTYPE
                malicious.linkname = "../../escape"
                malicious.size = 0
            root = tarfile.TarInfo(root_name)
            root.type = tarfile.DIRTYPE
            with tempfile.TemporaryDirectory() as raw:
                work = Path(raw)
                archive = work / "source.tar.gz"
                self.write_archive(archive, [root, malicious])
                with (
                    mock.patch.object(VERIFIER, "EXPECTED_ARCHIVE_MEMBERS", 2),
                    self.assertRaises(VERIFIER.VerificationError),
                ):
                    VERIFIER.safe_extract_archive(archive, work / "source")
                self.assertFalse((work / "escape").exists())

    def test_archive_extracts_only_bounded_regular_content(self) -> None:
        root_name = VERIFIER.EXPECTED_ROOT
        root = tarfile.TarInfo(root_name)
        root.type = tarfile.DIRTYPE
        license_member = tarfile.TarInfo(f"{root_name}/LICENSE")
        license_member.size = len(b"license\n")
        license_member.mode = 0o644
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            archive = work / "source.tar.gz"
            self.write_archive(archive, [root, license_member])
            with (
                mock.patch.object(VERIFIER, "EXPECTED_ARCHIVE_MEMBERS", 2),
                mock.patch.object(
                    VERIFIER,
                    "EXPECTED_LICENSE_SHA256",
                    hashlib.sha256(b"license\n").hexdigest(),
                ),
            ):
                VERIFIER.safe_extract_archive(archive, work / "source")
            self.assertEqual((work / "source/LICENSE").read_bytes(), b"license\n")


if __name__ == "__main__":
    unittest.main()
