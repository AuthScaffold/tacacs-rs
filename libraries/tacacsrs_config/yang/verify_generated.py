#!/usr/bin/env python3
"""Regenerate TACACS+ model artifacts and verify pinned deterministic output."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pyang

from expand_yang_tree import (
    CACHE_DIR,
    TACACS_MODULE,
    YANG_MODELS_COMMIT,
    YANG_MODELS_REPO,
)

SCRIPT_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = SCRIPT_DIR / "generation-manifest.json"


def canonical_bytes(path: Path) -> bytes:
    """Return UTF-8 file content with explicit canonical LF line endings."""
    return path.read_bytes().replace(b"\r\n", b"\n")


def sha256(path: Path) -> str:
    return hashlib.sha256(canonical_bytes(path)).hexdigest()


def load_manifest() -> dict[str, object]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def run_generator(output_path: Path, output_format: str, clean: bool = False) -> None:
    command = [
        sys.executable,
        str(SCRIPT_DIR / "expand_yang_tree.py"),
        "--features-ini",
        str(SCRIPT_DIR / "feature-flags.ini"),
        "--format",
        output_format,
        "--output",
        str(output_path),
    ]
    if clean:
        command.append("--clean")
    subprocess.run(command, cwd=SCRIPT_DIR, check=True)


def assert_equal(expected: Path, actual: Path, label: str) -> None:
    expected_content = canonical_bytes(expected)
    actual_content = canonical_bytes(actual)
    if expected_content == actual_content:
        return

    difference = "".join(
        difflib.unified_diff(
            expected_content.decode("utf-8").splitlines(keepends=True),
            actual_content.decode("utf-8").splitlines(keepends=True),
            fromfile=str(expected),
            tofile=str(actual),
            n=3,
        )
    )
    raise RuntimeError(f"{label} differs:\n{difference[:4000]}")


def verify_manifest(manifest: dict[str, object]) -> None:
    source = manifest["source"]
    tools = manifest["tools"]
    artifacts = manifest["artifacts"]
    if not isinstance(source, dict) or not isinstance(tools, dict) or not isinstance(artifacts, dict):
        raise RuntimeError("generation manifest has invalid section types")

    expected_source = {
        "repository": YANG_MODELS_REPO,
        "commit": YANG_MODELS_COMMIT,
        "module": f"standard/ietf/RFC/{TACACS_MODULE}",
    }
    for key, expected in expected_source.items():
        if source.get(key) != expected:
            raise RuntimeError(f"generation manifest source.{key} must be {expected}")

    if tools.get("pyang") != pyang.__version__:
        raise RuntimeError(
            f"pyang version {pyang.__version__} does not match manifest {tools.get('pyang')}"
        )

    for relative_path, expected_hash in artifacts.items():
        artifact_path = (SCRIPT_DIR / relative_path).resolve()
        actual_hash = sha256(artifact_path)
        if actual_hash != expected_hash:
            raise RuntimeError(
                f"{relative_path} SHA-256 {actual_hash} does not match manifest {expected_hash}"
            )


def verify_source_module(manifest: dict[str, object]) -> None:
    source = manifest["source"]
    if not isinstance(source, dict):
        raise RuntimeError("generation manifest source must be an object")
    module_path = CACHE_DIR / "yang-models" / str(source["module"])
    actual_hash = sha256(module_path)
    if actual_hash != source["moduleSha256"]:
        raise RuntimeError(
            f"pinned source module SHA-256 {actual_hash} does not match manifest "
            f"{source['moduleSha256']}"
        )


def verify_generated(clean: bool) -> None:
    manifest = load_manifest()
    verify_manifest(manifest)

    with tempfile.TemporaryDirectory(prefix="tacacsrs-yang-verify-") as temporary_directory:
        temporary_path = Path(temporary_directory)
        first_tree = temporary_path / "first-tree.txt"
        first_rust = temporary_path / "first-generated.rs"
        second_tree = temporary_path / "second-tree.txt"
        second_rust = temporary_path / "second-generated.rs"

        run_generator(first_tree, "tree", clean=clean)
        verify_source_module(manifest)
        run_generator(first_rust, "rust")
        run_generator(second_tree, "tree")
        run_generator(second_rust, "rust")

        assert_equal(first_tree, second_tree, "tree regeneration is not deterministic")
        assert_equal(first_rust, second_rust, "Rust regeneration is not deterministic")
        assert_equal(SCRIPT_DIR / "expanded-tree.txt", first_tree, "checked-in expanded tree")
        assert_equal(
            SCRIPT_DIR.parent / "src" / "generated.rs",
            first_rust,
            "checked-in generated Rust",
        )

    print(
        "PASS: pinned source, manifest hashes, deterministic regeneration, and checked-in artifacts match."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove and recreate the pinned sparse YANG cache before verification",
    )
    args = parser.parse_args()
    verify_generated(clean=args.clean)


if __name__ == "__main__":
    main()