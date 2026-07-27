from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "infra" / "systemd" / "prepare-workspace-overlay-quota.sh"


class OverlayQuotaMountIdempotencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")
        cls.loop = cls.source.split(
            'for quota_root in "$overlay_root" "$volume_root"; do', 1
        )[1]

    def test_existing_top_mount_is_inspected_before_any_mount_mutation(self) -> None:
        inspect_index = self.loop.index("quota_records=$(findmnt")
        bind_index = self.loop.index('mount --bind "$quota_root" "$quota_root"')
        remount_index = self.loop.index(
            'mount -o remount,bind,rw,dev,nosuid "$quota_root"'
        )

        self.assertLess(inspect_index, bind_index)
        self.assertLess(bind_index, remount_index)
        self.assertGreaterEqual(self.loop.count('--mountpoint "$quota_root"'), 2)
        self.assertIn(
            "--output ID,PARENT,TARGET,FSTYPE,OPTIONS,FSROOT,MAJ:MIN", self.loop
        )
        self.assertIn('-v expected_parent="$mount_id"', self.loop)
        self.assertIn("$2 == expected_parent", self.loop)
        self.assertIn("older exact bind can remain listed but be hidden", self.loop)
        self.assertNotIn("INVOCATION_ID", self.loop)

    def test_valid_existing_bind_is_reused_without_stacking_or_remounting(self) -> None:
        self.assertEqual(self.loop.count('mount --bind "$quota_root" "$quota_root"'), 1)
        self.assertIn(
            """  else
    mount --bind "$quota_root" "$quota_root"
    created=true
    remount_required=true
  fi""",
            self.loop,
        )
        self.assertIn(
            """  if [ "$remount_required" = true ] &&
    ! mount -o remount,bind,rw,dev,nosuid "$quota_root"; then""",
            self.loop,
        )
        self.assertIn("*,rw,*) ;;\n      *,ro,*) remount_required=true ;;", self.loop)

    def test_existing_identity_or_security_drift_fails_before_bind(self) -> None:
        bind_index = self.loop.index('mount --bind "$quota_root" "$quota_root"')
        pre_bind = self.loop[:bind_index]

        for invariant in (
            '[ "$quota_target" = "$quota_root" ]',
            '[ "$quota_filesystem" = xfs ]',
            '[ "$quota_fsroot" = "$expected_fsroot" ]',
            '[ "$quota_device" = "$parent_device" ]',
            '[ "$active_parent" = "$mount_id" ]',
            '[ "$active_target" = "$quota_root" ]',
            "*,nodev,*)",
            "*,nosuid,*)",
        ):
            with self.subTest(invariant=invariant):
                self.assertIn(invariant, pre_bind)
        self.assertIn(
            "workspace quota exception is not the exact reviewed self-bind",
            pre_bind,
        )
        self.assertIn("workspace quota path has multiple active exact binds", pre_bind)
        self.assertIn("must permit its private backing device", pre_bind)
        self.assertIn("must remain nosuid", pre_bind)

    def test_missing_bind_is_restored_and_postconditions_are_rechecked(self) -> None:
        self.assertIn(
            "containers/storage removes its temporary backing-device mount",
            self.loop,
        )
        self.assertGreaterEqual(
            self.loop.count('[ "$quota_fsroot" = "$expected_fsroot" ]'), 2
        )
        self.assertGreaterEqual(
            self.loop.count('[ "$quota_device" = "$parent_device" ]'), 2
        )
        self.assertIn("*,rw,*) ;; *) echo", self.loop)
        self.assertGreaterEqual(self.loop.count("*,nodev,*)"), 2)
        self.assertGreaterEqual(self.loop.count("*,nosuid,*)"), 2)

    def test_script_remains_valid_posix_shell(self) -> None:
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("a POSIX shell is unavailable on this platform")
        result = subprocess.run(
            [shell, "-n", str(SCRIPT)],
            cwd=ROOT,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
