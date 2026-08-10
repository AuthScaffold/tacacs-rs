from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from plugins.yang2rust import SecretFieldManifest


class SecretFieldManifestTests(unittest.TestCase):
    def write_manifest(self, content: str) -> Path:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        path = Path(temporary_directory.name) / "secret-fields.toml"
        path.write_text(content, encoding="utf-8")
        return path

    def test_loads_and_matches_reviewed_secret_fields(self) -> None:
        manifest = SecretFieldManifest.load(
            self.write_manifest(
                """
[[secret]]
module = "ietf-system-tacacs-plus"
leaf = "shared-secret"
kind = "string"
expected_matches = 1

[[secret]]
module = "ietf-crypto-types"
leaf = "cleartext-symmetric-key"
kind = "binary"
expected_matches = 1
"""
            )
        )

        self.assertEqual(
            manifest.match("ietf-system-tacacs-plus", "shared-secret", "String"),
            "string",
        )
        self.assertEqual(
            manifest.match("ietf-crypto-types", "cleartext-symmetric-key", "Vec<u8>"),
            "binary",
        )
        self.assertIsNone(manifest.match("ietf-keystore", "cert-data", "Vec<u8>"))
        manifest.verify_complete()

    def test_rejects_duplicate_rules(self) -> None:
        path = self.write_manifest(
            """
[[secret]]
module = "ietf-keystore"
leaf = "cleartext-private-key"
kind = "binary"
expected_matches = 1

[[secret]]
module = "ietf-keystore"
leaf = "cleartext-private-key"
kind = "binary"
expected_matches = 1
"""
        )

        with self.assertRaisesRegex(RuntimeError, "duplicate secret field annotation"):
            SecretFieldManifest.load(path)

    def test_rejects_incompatible_scalar_type(self) -> None:
        manifest = SecretFieldManifest.load(
            self.write_manifest(
                """
[[secret]]
module = "ietf-system-tacacs-plus"
leaf = "shared-secret"
kind = "binary"
expected_matches = 1
"""
            )
        )

        with self.assertRaisesRegex(RuntimeError, "requires Rust type Vec<u8>"):
            manifest.match("ietf-system-tacacs-plus", "shared-secret", "String")

    def test_rejects_unmatched_rule(self) -> None:
        manifest = SecretFieldManifest.load(
            self.write_manifest(
                """
[[secret]]
module = "ietf-keystore"
leaf = "missing-secret-leaf"
kind = "binary"
expected_matches = 1
"""
            )
        )

        with self.assertRaisesRegex(RuntimeError, r"matched 0 field\(s\); expected 1"):
            manifest.verify_complete()


if __name__ == "__main__":
    unittest.main()