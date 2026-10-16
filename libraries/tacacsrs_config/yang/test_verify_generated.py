"""Tests for the offline YANG artifact consistency check.

These tests mirror the checked-in artifacts into a temporary fixture tree, so a
corruption case never modifies a real generated file. They confirm that the
offline hash check passes for the unmodified tree and fails when one checked-in
artifact or generated output changes.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from verify_generated import SCRIPT_DIR, load_manifest, verify_artifact_hashes


class OfflineArtifactHashTests(unittest.TestCase):
    def _mirror_artifacts(self) -> tuple[dict[str, object], Path]:
        """Copy every manifest artifact into a temporary fixture tree.

        The fixture base lives one directory below the temporary root so that
        the ``../src/generated.rs`` artifact resolves inside the fixture.
        """
        manifest = load_manifest()
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        base_dir = Path(temporary_directory.name) / "yang"
        base_dir.mkdir()

        artifacts = manifest["artifacts"]
        self.assertIsInstance(artifacts, dict)
        for relative_path in artifacts:
            source = (SCRIPT_DIR / relative_path).resolve()
            destination = (base_dir / relative_path).resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        return manifest, base_dir

    def _module_relative_path(self, manifest: dict[str, object]) -> str:
        artifacts = manifest["artifacts"]
        self.assertIsInstance(artifacts, dict)
        return next(path for path in artifacts if path.startswith("modules/"))

    def test_unmodified_fixture_passes(self) -> None:
        manifest, base_dir = self._mirror_artifacts()

        verify_artifact_hashes(manifest, base_dir)

    def test_corrupted_generated_output_fails(self) -> None:
        manifest, base_dir = self._mirror_artifacts()
        generated = (base_dir / "../src/generated.rs").resolve()

        with generated.open("ab") as handle:
            handle.write(b"\n// offline-check fixture corruption\n")

        with self.assertRaisesRegex(RuntimeError, r"generated\.rs"):
            verify_artifact_hashes(manifest, base_dir)

    def test_corrupted_checked_in_module_fails(self) -> None:
        manifest, base_dir = self._mirror_artifacts()
        module_relative = self._module_relative_path(manifest)
        module_path = (base_dir / module_relative).resolve()

        with module_path.open("ab") as handle:
            handle.write(b"\n// offline-check fixture corruption\n")

        with self.assertRaisesRegex(RuntimeError, "SHA-256"):
            verify_artifact_hashes(manifest, base_dir)

    def test_real_checked_in_tree_matches_manifest(self) -> None:
        verify_artifact_hashes(load_manifest(), SCRIPT_DIR)


if __name__ == "__main__":
    unittest.main()
