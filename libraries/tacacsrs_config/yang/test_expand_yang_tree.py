from __future__ import annotations

import configparser
import os
import subprocess
import stat
import tempfile
import unittest
from pathlib import Path

from expand_yang_tree import _remove_readonly, _verify_repo_revision
from verify_generated import load_manifest, verify_manifest


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

        with self.assertRaisesRegex(RuntimeError, "The expected commit is 000000"):
            _verify_repo_revision(self.repo, "0" * 40)

    def test_rejects_attached_head(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "The repository must have a detached HEAD"):
            _verify_repo_revision(self.repo, self.commit)

    def test_remove_readonly_retries_after_making_file_writable(self) -> None:
        readonly_file = self.repo / "readonly"
        readonly_file.write_text("content", encoding="utf-8")
        readonly_file.chmod(stat.S_IREAD)

        _remove_readonly(os.unlink, str(readonly_file), None)

        self.assertFalse(readonly_file.exists())


class FeatureFlagScopeTests(unittest.TestCase):
    def test_only_reviewed_optional_features_are_enabled(self) -> None:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(Path(__file__).with_name("feature-flags.ini"), encoding="utf-8")
        actual = {
            section: {name: parser.getboolean(section, name) for name in parser[section]}
            for section in parser.sections()
        }

        self.assertEqual(
            actual,
            {
                "ietf-system-tacacs-plus": {"credential-reference": True},
                "ietf-crypto-types": {
                    "certificate-expiration-notification": False,
                    "cleartext-private-keys": True,
                    "cleartext-symmetric-keys": True,
                    "csr-generation": False,
                    "encrypted-private-keys": False,
                    "encrypted-symmetric-keys": False,
                    "hidden-private-keys": False,
                    "hidden-symmetric-keys": False,
                },
                "ietf-keystore": {
                    "asymmetric-keys": True,
                    "central-keystore-supported": True,
                    "inline-definitions-supported": True,
                    "symmetric-keys": True,
                },
                "ietf-tls-client": {
                    "client-ident-raw-public-key": False,
                    "client-ident-tls13-epsk": True,
                    "server-auth-raw-public-key": False,
                    "server-auth-tls13-epsk": True,
                },
                "ietf-tls-common": {"hello-params": False, "tls13": True},
                "ietf-truststore": {
                    "central-truststore-supported": True,
                    "certificates": True,
                    "inline-definitions-supported": True,
                    "public-keys": True,
                },
                "tacacsrs": {"psk-dhe-ke-hello-params": True},
            },
        )

    def test_generation_manifest_matches_reviewed_inputs_and_outputs(self) -> None:
        verify_manifest(load_manifest())


if __name__ == "__main__":
    unittest.main()