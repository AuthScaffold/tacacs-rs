#!/usr/bin/env python3
"""Build and verify a tacacs-rs release manifest.

The release manifest records, in one offline artifact, the evidence that ties a
set of staged release archives to the source that produced them:

* the source commit,
* the computed crate versions that hydration injected,
* the SHA-256 digest of every staged release artifact,
* the YANG model and protobuf schema identities, and
* verified per-product build evidence and separate assembly tool versions.

Step order and the self-hash rule
---------------------------------

The manifest is written *before* the release checksums file. It records the
archive digests, so the later ``checksums-sha256.txt`` file can cover the
manifest while the manifest never covers itself or the checksums file. The
manifest never hashes its own output file and never hashes the checksums file,
so there is no recursive or self digest.

Offline and hermetic
---------------------

The pure functions take explicit paths and plain data. They never reach the
network, so hashing and verification run offline and the tests stay hermetic.
Symbolic links are rejected, which is the only way a file from outside the
artifacts directory could enter the digest set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Callable, Iterable

from build_provenance import ProvenanceError, collect_build_provenance

SCHEMA_VERSION = 2

# The checksums file is produced after this manifest. The manifest never hashes
# it, so the checksums file can cover the manifest without a cycle.
CHECKSUMS_FILENAME = "checksums-sha256.txt"

# Schema identity sources, relative to the workspace root.
YANG_MANIFEST_RELPATH = "libraries/tacacsrs_config/yang/generation-manifest.json"
PROTO_DIR_RELPATH = "libraries/tacacsrs_ipc/proto"

# Key of the generated Rust binding inside the YANG generation manifest.
GENERATED_RUST_ARTIFACT_KEY = "../src/generated.rs"

# One mebibyte read window keeps hashing memory bounded for large archives.
_HASH_CHUNK_BYTES = 1024 * 1024


class ManifestError(RuntimeError):
    """The manifest cannot be built or verified from the given inputs."""


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of a file, read in bounded chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_artifact_hashes(
    artifacts_dir: Path, *, exclude: Iterable[str] = ()
) -> dict:
    """Return a ``{basename: sha256}`` map for every release artifact.

    The scan never follows symbolic links. It enforces four rules:

    * Every artifact is a regular file. A symbolic link, directory link, or
      special file is rejected. Rejecting links is also how the scan keeps
      files from outside the artifacts directory out of the digest set.
    * Two artifacts must not share a basename, because the manifest and the
      checksums file key by basename.
    * The excluded names, which are the manifest output file and the checksums
      file, are skipped so the manifest never hashes itself.

    Raises ``ManifestError`` on any violation.
    """
    root = Path(artifacts_dir).resolve()
    if not root.is_dir():
        raise ManifestError(f"artifacts directory does not exist: {artifacts_dir}")
    excluded = set(exclude) | {CHECKSUMS_FILENAME}
    hashes: dict = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for dirname in sorted(dirnames):
            if (Path(dirpath) / dirname).is_symlink():
                raise ManifestError(
                    f"release path '{dirname}' is a symbolic link; "
                    "release artifacts must be regular files"
                )
        for filename in sorted(filenames):
            entry = Path(dirpath) / filename
            if entry.is_symlink():
                raise ManifestError(
                    f"release artifact '{filename}' is a symbolic link; "
                    "release artifacts must be regular files"
                )
            if not entry.is_file():
                raise ManifestError(
                    f"release artifact '{filename}' is not a regular file"
                )
            if filename in excluded:
                continue
            if filename in hashes:
                raise ManifestError(
                    f"release artifacts contain a basename collision for '{filename}'"
                )
            hashes[filename] = sha256_file(entry)
    return hashes


def read_versions(path: Path) -> dict:
    """Return the computed versions map from a JSON file.

    The file must contain a JSON object that maps crate names to versions. An
    empty object is valid and records that hydration injected no versions.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(f"cannot read versions file {path}: {error}") from error
    if not isinstance(data, dict):
        raise ManifestError("versions file must contain a JSON object")
    if not all(isinstance(name, str) and isinstance(version, str) for name, version in data.items()):
        raise ManifestError("versions must map package names to version strings")
    return data


def schema_identities(workspace: Path) -> dict:
    """Return the YANG and protobuf schema identities for a workspace.

    The YANG identity reuses the pinned generation manifest. The protobuf
    identity hashes every ``.proto`` file under the IPC contract directory.
    """
    workspace = Path(workspace)
    return {
        "yang": _yang_identity(workspace),
        "protobuf": _protobuf_identity(workspace),
    }


def _yang_identity(workspace: Path) -> dict:
    manifest_path = workspace / YANG_MANIFEST_RELPATH
    if not manifest_path.is_file():
        raise ManifestError(
            f"YANG generation manifest is missing: {YANG_MANIFEST_RELPATH}"
        )
    try:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(
            f"cannot read YANG generation manifest: {error}"
        ) from error
    source = manifest.get("source") or {}
    artifacts = manifest.get("artifacts") or {}
    return {
        "manifest": YANG_MANIFEST_RELPATH,
        "manifestSha256": sha256_file(manifest_path),
        "sourceCommit": source.get("commit"),
        "moduleSha256": source.get("moduleSha256"),
        "generatedRustSha256": artifacts.get(GENERATED_RUST_ARTIFACT_KEY),
    }


def _protobuf_identity(workspace: Path) -> dict:
    proto_dir = workspace / PROTO_DIR_RELPATH
    if not proto_dir.is_dir():
        raise ManifestError(f"protobuf directory is missing: {PROTO_DIR_RELPATH}")
    protos: dict = {}
    for proto in sorted(proto_dir.rglob("*.proto")):
        if proto.is_symlink() or not proto.is_file():
            continue
        relative = proto.relative_to(workspace).as_posix()
        protos[relative] = sha256_file(proto)
    if not protos:
        raise ManifestError(
            f"no protobuf schema files under {PROTO_DIR_RELPATH}"
        )
    return protos


def _tool_version(command: list, runner: Callable) -> str | None:
    """Return a tool version line, or ``None`` when the tool is unavailable."""
    try:
        result = runner(command, capture_output=True, text=True, check=False)
    except OSError:
        return None
    if getattr(result, "returncode", 1) != 0:
        return None
    return (result.stdout or "").strip() or None


def toolchain_provenance(runner: Callable = subprocess.run) -> dict:
    """Return best-effort assembly-host tool versions, not build evidence.

    Each tool is optional. A missing or failing tool records ``None`` instead of
    raising, so the manifest still generates in a minimal packaging job that has
    no Rust toolchain installed.
    """
    return {
        "rustc": _tool_version(["rustc", "--version"], runner),
        "cargo": _tool_version(["cargo", "--version"], runner),
        "openssl": _tool_version(["openssl", "version"], runner),
    }


def build_manifest(
    *, source: str, versions: dict, artifacts: dict, schemas: dict,
    assembly_toolchain: dict, build_provenance: dict,
) -> dict:
    """Assemble the manifest object from already-collected evidence."""
    return {
        "schemaVersion": SCHEMA_VERSION,
        "source": {"commit": source},
        "versions": versions,
        "artifacts": artifacts,
        "schemas": schemas,
        "assemblyToolchain": assembly_toolchain,
        "buildProvenance": build_provenance,
    }


def generate_manifest(
    *,
    artifacts_dir: Path,
    versions_path: Path,
    source: str,
    workspace: Path,
    output: Path,
    provenance_dir: Path,
    assembly_toolchain: dict | None = None,
) -> dict:
    """Build the manifest from the artifacts, versions, and workspace schemas.

    The output file name is excluded from the artifact digest set so the
    manifest never hashes itself, even on a re-run that overwrites an earlier
    manifest in the same directory.
    """
    output = Path(output)
    artifacts = collect_artifact_hashes(Path(artifacts_dir), exclude={output.name})
    versions = read_versions(versions_path)
    schemas = schema_identities(workspace)
    try:
        records = collect_build_provenance(
            provenance_dir=Path(provenance_dir), artifacts_dir=Path(artifacts_dir),
            source=source, versions=versions, workspace=Path(workspace),
        )
    except (ProvenanceError, OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise ManifestError(f"invalid build provenance: {error}") from error
    if assembly_toolchain is None:
        assembly_toolchain = toolchain_provenance()
    return build_manifest(
        source=source,
        versions=versions,
        artifacts=artifacts,
        schemas=schemas,
        assembly_toolchain=assembly_toolchain,
        build_provenance=records,
    )


def verify_artifact_hashes(manifest: dict, artifacts_dir: Path) -> list:
    """Recompute the recorded digests and return a list of mismatch errors.

    The check is offline. It proves a staged artifact still matches the digest
    the manifest recorded, which detects corruption or a missing file.
    """
    errors: list = []
    root = Path(artifacts_dir)
    for name, expected in sorted(manifest.get("artifacts", {}).items()):
        path = root / name
        if not path.is_file():
            errors.append(f"recorded artifact '{name}' is missing")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(
                f"artifact '{name}' digest mismatch: "
                f"expected {expected}, found {actual}"
            )
    return errors


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a tacacs-rs release manifest from staged artifacts."
    )
    parser.add_argument(
        "--artifacts",
        required=True,
        help="Directory that holds the staged release artifacts to hash.",
    )
    parser.add_argument(
        "--versions",
        required=True,
        help="Path to the computed versions JSON file.",
    )
    parser.add_argument(
        "--source",
        required=True,
        help="Source commit SHA recorded in the manifest.",
    )
    parser.add_argument(
        "--workspace",
        default=".",
        help="Workspace root used to read schema identities.",
    )
    parser.add_argument(
        "--provenance-dir",
        required=True,
        help="Directory with per-product build-provenance-*.json records.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write the release manifest JSON.",
    )
    args = parser.parse_args(argv)

    try:
        manifest = generate_manifest(
            artifacts_dir=args.artifacts,
            versions_path=args.versions,
            source=args.source,
            workspace=args.workspace,
            output=args.output,
            provenance_dir=args.provenance_dir,
        )
    except ManifestError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(f"Wrote release manifest to {output}")
    print(f"  source commit: {args.source}")
    print(f"  recorded artifacts: {len(manifest['artifacts'])}")
    print(f"  recorded versions: {len(manifest['versions'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
