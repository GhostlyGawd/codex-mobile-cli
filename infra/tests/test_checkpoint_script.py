from __future__ import annotations

import gzip
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "infra-checkpoint.sh"


@unittest.skipUnless(
    os.name == "posix" and Path("/bin/sh").is_file(),
    "checkpoint execution tests require a POSIX host",
)
class CheckpointScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        for executable in (
            "awk",
            "dd",
            "df",
            "flock",
            "gzip",
            "mkfifo",
            "sync",
            "tar",
        ):
            if shutil.which(executable) is None:
                self.skipTest(f"{executable} is required")

    def fixture(self, compose_body: str) -> tuple[Path, Path, dict[str, str]]:
        raw = Path(self.enterContext(tempfile.TemporaryDirectory()))
        repo = raw / "repo"
        scripts = repo / "scripts"
        scripts.mkdir(parents=True)
        compose = scripts / "infra-compose.sh"
        compose.write_text("#!/bin/sh\nset -eu\n" + compose_body, encoding="utf-8")
        compose.chmod(0o700)
        env_file = raw / "production.env"
        env_file.write_text("POSTGRES_ADMIN_USER=checkpoint_admin\n", encoding="utf-8")
        checkpoint_root = raw / "checkpoints"
        environment = os.environ.copy()
        environment.update(
            {
                "REPO_ROOT": str(repo),
                "ENV_FILE": str(env_file),
                "CHECKPOINT_ROOT": str(checkpoint_root),
                "CHECKPOINT_RESERVE_BYTES": "0",
                "CHECKPOINT_DATABASE_MAX_BYTES": str(1024 * 1024),
                "CHECKPOINT_WORKSPACE_MAX_BYTES": str(1024 * 1024),
            }
        )
        return raw, checkpoint_root, environment

    def run_script(
        self, arguments: list[str], environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", str(SCRIPT), *arguments],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=20,
        )

    def assert_no_staging_files(self, checkpoint_root: Path) -> None:
        leftovers = [
            path
            for path in checkpoint_root.rglob("*")
            if ".partial." in path.name or ".fifo." in path.name
        ]
        self.assertEqual(leftovers, [])

    def test_database_dump_is_verified_then_atomically_published(self) -> None:
        _, checkpoint_root, environment = self.fixture(
            "printf '%s\\n' '-- PostgreSQL database cluster dump'\n"
        )
        result = self.run_script(["--database"], environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        archives = list((checkpoint_root / "database").glob("postgres-*.sql.gz"))
        self.assertEqual(len(archives), 1)
        self.assertIn(
            b"PostgreSQL database cluster dump",
            gzip.decompress(archives[0].read_bytes()),
        )
        self.assertEqual(archives[0].stat().st_mode & 0o777, 0o600)
        self.assert_no_staging_files(checkpoint_root)

    def test_failed_dump_never_publishes_a_partial_archive(self) -> None:
        _, checkpoint_root, environment = self.fixture(
            "printf '%s\\n' 'truncated output'\nexit 7\n"
        )
        result = self.run_script(["--database"], environment)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            list((checkpoint_root / "database").glob("postgres-*.sql.gz")), []
        )
        self.assert_no_staging_files(checkpoint_root)

    def test_compressed_size_cap_never_publishes_an_oversized_archive(self) -> None:
        _, checkpoint_root, environment = self.fixture(
            "dd if=/dev/urandom bs=4096 count=4 status=none\n"
        )
        environment["CHECKPOINT_DATABASE_MAX_BYTES"] = "512"
        result = self.run_script(["--database"], environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            list((checkpoint_root / "database").glob("postgres-*.sql.gz")), []
        )
        self.assert_no_staging_files(checkpoint_root)

    def test_invalid_workspace_tar_is_rejected_before_publish(self) -> None:
        raw, checkpoint_root, environment = self.fixture("exit 99\n")
        fake_bin = raw / "bin"
        fake_bin.mkdir()
        podman = fake_bin / "podman"
        podman.write_text(
            """#!/bin/sh
case " $* " in
  *" ps "*) exit 0 ;;
  *" volume ls "*) printf '%s\\n' workspace-volume ;;
  *" volume export "*) printf '%s\\n' not-a-tar-archive ;;
  *) exit 64 ;;
esac
""",
            encoding="utf-8",
        )
        podman.chmod(0o700)
        environment["PATH"] = str(fake_bin) + os.pathsep + environment["PATH"]
        result = self.run_script(["--workspace", "ws-123"], environment)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("not a valid tar archive", result.stderr)
        self.assertEqual(list((checkpoint_root / "workspaces").glob("*.tar.gz")), [])
        self.assert_no_staging_files(checkpoint_root)

    def test_capacity_reserve_refuses_before_starting_producer(self) -> None:
        raw, checkpoint_root, environment = self.fixture(
            'printf started > "$PRODUCER_MARKER"\nprintf data\n'
        )
        marker = raw / "producer-started"
        environment["PRODUCER_MARKER"] = str(marker)
        environment["CHECKPOINT_RESERVE_BYTES"] = "900000000000000000"
        result = self.run_script(["--database"], environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checkpoint refused", result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(
            list((checkpoint_root / "database").glob("postgres-*.sql.gz")), []
        )
        self.assert_no_staging_files(checkpoint_root)


if __name__ == "__main__":
    unittest.main()
