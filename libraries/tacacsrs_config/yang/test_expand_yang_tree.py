from __future__ import annotations

import subprocess
import stat
import os
import tempfile
import unittest
from pathlib import Path

from expand_yang_tree import _remove_readonly, _verify_repo_revision


class VerifyRepoRevisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary_directory.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "config", "user.name", "P2 Test"], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "config", "user.email", "p2-test@example.invalid"],
            cwd=self.repo,
            check=True,
        )
        (self.repo / "input.yang").write_text("module input {}", encoding="utf-8")
        subprocess.run(["git", "add", "input.yang"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "input"], cwd=self.repo, check=True)
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_accepts_expected_detached_commit(self) -> None:
        subprocess.run(["git", "checkout", "-q", "--detach", self.commit], cwd=self.repo, check=True)

        _verify_repo_revision(self.repo, self.commit)

    def test_rejects_wrong_commit(self) -> None:
        subprocess.run(["git", "checkout", "-q", "--detach", self.commit], cwd=self.repo, check=True)

        with self.assertRaisesRegex(RuntimeError, "expected 000000"):
            _verify_repo_revision(self.repo, "0" * 40)

    def test_rejects_attached_head(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "expected detached HEAD"):
            _verify_repo_revision(self.repo, self.commit)

    def test_remove_readonly_retries_after_making_file_writable(self) -> None:
        readonly_file = self.repo / "readonly"
        readonly_file.write_text("content", encoding="utf-8")
        readonly_file.chmod(stat.S_IREAD)

        _remove_readonly(os.unlink, str(readonly_file), None)

        self.assertFalse(readonly_file.exists())


if __name__ == "__main__":
    unittest.main()