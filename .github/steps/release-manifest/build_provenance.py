#!/usr/bin/env python3
"""Capture build-runner evidence and verify its binding to release archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath


PROVENANCE_FILENAME = "build-provenance.json"


class ProvenanceError(RuntimeError):
    """Build evidence is missing or inconsistent with the release inputs."""


def digest_stream(stream) -> str:
    return hashlib.file_digest(stream, "sha256").hexdigest()


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return digest_stream(stream)


def relative_name(name: str) -> str:
    if not name or "\\" in name or PurePosixPath(name).is_absolute() or any(
        part in ("", ".", "..") for part in name.split("/")
    ) or ":" in name:
        raise ProvenanceError(f"invalid relative evidence path: {name!r}")
    return name


def package_identity(workspace: Path, manifest: str) -> tuple[str, str]:
    """Read the package identity from a source or hydrated Cargo manifest."""
    path = workspace / relative_name(manifest)
    if path.is_symlink() or not path.resolve().is_relative_to(workspace.resolve()):
        raise ProvenanceError("package manifest must be inside the workspace")
    package = tomllib.loads(path.read_text(encoding="utf-8"))["package"]
    version = package["version"]
    if isinstance(version, dict) and version.get("workspace") is True:
        version = tomllib.loads((workspace / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    if not isinstance(package["name"], str) or not isinstance(version, str) or not version:
        raise ProvenanceError("package name and version must be nonempty strings")
    return package["name"], version


def tool_output(command: list[str], runner, *, required: bool = True) -> str | None:
    try:
        result = runner(command, capture_output=True, text=True, check=False)
    except OSError as error:
        if required:
            raise ProvenanceError(f"cannot inspect {command[0]}: {error}") from error
        return None
    if result.returncode != 0 or not (result.stdout or "").strip():
        if required:
            raise ProvenanceError(f"cannot inspect {command[0]}")
        return None
    return result.stdout.strip()


def capture_provenance(
    *, workspace: Path, package_root: Path, package_dir: Path, upload_dir: Path,
    asset_name: str, package_name: str, artifact_filename: str, artifact_kind: str,
    source: str, target: str, profile: str, features: str, versions: dict,
    runner=None,
) -> dict:
    """Capture evidence after staging, before archive creation, on the build host."""
    if runner is None:
        runner = subprocess.run
    workspace = workspace.resolve()
    manifest = (package_root.resolve() / "Cargo.toml").relative_to(workspace).as_posix()
    name, version = package_identity(workspace, manifest)
    if name != package_name or version != versions.get(name, version):
        raise ProvenanceError("hydrated package identity does not match the expected version")
    if not source or not target or profile not in ("release", "debug"):
        raise ProvenanceError("source, target, and build profile are required")
    if relative_name(asset_name) != package_dir.name or "/" in asset_name:
        raise ProvenanceError("the package directory must use the asset name")
    relative_name(artifact_filename)
    if artifact_kind not in ("bin", "cdylib"):
        raise ProvenanceError("artifact kind must be bin or cdylib")
    files = {}
    for path in sorted(package_dir.rglob("*")):
        if path.is_symlink():
            raise ProvenanceError(f"staged path is a symbolic link: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ProvenanceError(f"staged path is not a regular file: {path}")
        relative = relative_name(path.relative_to(package_dir).as_posix())
        if relative == PROVENANCE_FILENAME:
            raise ProvenanceError("the package already contains build provenance")
        files[relative] = file_digest(path)
    if artifact_filename not in files:
        raise ProvenanceError("the staged binary is missing")
    tools = {
        "rustc": tool_output(["rustc", "--version", "--verbose"], runner),
        "cargo": tool_output(["cargo", "--version"], runner),
        "openssl": tool_output(["openssl", "version"], runner, required=False),
    }
    binary = {"path": artifact_filename, "kind": artifact_kind}
    if artifact_kind == "bin":
        reported = tool_output([str((package_dir / artifact_filename).resolve()), "--version"], runner)
        if version not in reported.split():
            raise ProvenanceError("staged binary does not report the hydrated package version")
        binary["reportedVersion"] = reported
    extension = ".zip" if "windows" in target else ".tar.gz"
    record = {
        "schemaVersion": 1,
        "assetName": asset_name,
        "archiveName": asset_name + extension,
        "package": {"name": name, "version": version, "manifest": manifest, "manifestSha256": file_digest(workspace / manifest)},
        "source": {"commit": source, "cargoLockSha256": file_digest(workspace / "Cargo.lock")},
        "build": {"target": target, "profile": profile, "features": {"requested": sorted(set(re.split(r"[\s,]+", features.strip())) - {""}), "defaultEnabled": True}},
        "toolchain": tools,
        "binary": binary,
        "files": files,
    }
    content = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    upload_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / PROVENANCE_FILENAME).write_bytes(content)
    (upload_dir / f"build-provenance-{asset_name}.json").write_bytes(content)
    return record


def verify_archive(archive: Path, record: dict, record_bytes: bytes) -> None:
    """Compare embedded evidence and every regular file without extraction."""
    prefix = record["assetName"] + "/"
    hashes = {}
    embedded = None

    def inspect(name, stream):
        nonlocal embedded
        name = name.replace("\\", "/")
        if not name.startswith(prefix):
            raise ProvenanceError(f"archive member is outside the asset directory: {name}")
        relative = relative_name(name[len(prefix):])
        if relative in hashes or (relative == PROVENANCE_FILENAME and embedded is not None):
            raise ProvenanceError(f"duplicate archive member: {name}")
        if relative == PROVENANCE_FILENAME:
            embedded = stream.read(len(record_bytes) + 1)
        else:
            hashes[relative] = digest_stream(stream)

    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as package:
            for member in package.infolist():
                if member.is_dir():
                    continue
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ProvenanceError("archive contains a symbolic link")
                with package.open(member) as stream:
                    inspect(member.filename, stream)
    else:
        with tarfile.open(archive, "r:gz") as package:
            for member in package:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ProvenanceError("archive contains a non-regular file")
                with package.extractfile(member) as stream:
                    inspect(member.name, stream)
    if embedded != record_bytes:
        raise ProvenanceError(f"embedded provenance does not match the uploaded record: {archive.name}")
    if hashes != record["files"]:
        raise ProvenanceError(f"archived file hashes do not match build provenance: {archive.name}")


def collect_build_provenance(
    *, provenance_dir: Path, artifacts_dir: Path, source: str, versions: dict, workspace: Path,
) -> dict:
    """Require one verified record for each staged product archive."""
    archives = {path.name: path for path in artifacts_dir.iterdir() if path.name.endswith((".tar.gz", ".zip"))}
    records = {}
    for path in sorted(provenance_dir.glob("build-provenance-*.json")):
        if path.is_symlink() or not path.is_file():
            raise ProvenanceError("build provenance must be a regular file")
        content = path.read_bytes()
        record = json.loads(content)
        if record["schemaVersion"] != 1:
            raise ProvenanceError("unsupported build provenance schema")
        archive_name = relative_name(record["archiveName"])
        asset_name = relative_name(record["assetName"])
        if archive_name not in archives or archive_name in records:
            raise ProvenanceError(f"unexpected or duplicate build provenance: {archive_name}")
        if path.name != f"build-provenance-{asset_name}.json" or archive_name not in (asset_name + ".zip", asset_name + ".tar.gz"):
            raise ProvenanceError("build provenance asset names do not match")
        if record["source"]["commit"] != source:
            raise ProvenanceError(f"build provenance source mismatch: {archive_name}")
        name, source_version = package_identity(workspace, record["package"]["manifest"])
        if record["package"]["name"] != name or record["package"]["version"] != versions.get(name, source_version):
            raise ProvenanceError(f"build provenance package version mismatch: {archive_name}")
        build = record["build"]
        features = build["features"]
        if not build["target"] or build["profile"] not in ("release", "debug") or features["defaultEnabled"] is not True or not isinstance(features["requested"], list):
            raise ProvenanceError("invalid build settings in provenance")
        if not record["toolchain"]["rustc"] or not record["toolchain"]["cargo"]:
            raise ProvenanceError("build tool versions are missing")
        hashes = record["files"]
        for filename, digest in hashes.items():
            relative_name(filename)
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ProvenanceError("invalid staged file digest")
        binary = record["binary"]
        if binary["path"] not in hashes or binary["kind"] not in ("bin", "cdylib"):
            raise ProvenanceError("staged binary evidence is missing")
        if binary["kind"] == "bin" and record["package"]["version"] not in binary.get("reportedVersion", "").split():
            raise ProvenanceError("reported binary version does not match the package version")
        staged_record = artifacts_dir / path.name
        if staged_record.exists() and staged_record.read_bytes() != content:
            raise ProvenanceError("staged provenance differs from the uploaded record")
        verify_archive(archives[archive_name], record, content)
        records[archive_name] = record
    if not archives or set(records) != set(archives):
        raise ProvenanceError("every release archive must have build provenance")
    return records


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--package-dir", type=Path, required=True)
    parser.add_argument("--upload-dir", type=Path, default=Path("packaged"))
    parser.add_argument("--asset-name", required=True)
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--artifact-filename", required=True)
    parser.add_argument("--artifact-kind", choices=("bin", "cdylib"), required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", choices=("release", "debug"), required=True)
    parser.add_argument("--features", default="")
    parser.add_argument("--versions-json", required=True)
    args = vars(parser.parse_args(argv))
    try:
        args["versions"] = json.loads(args.pop("versions_json"))
        if not isinstance(args["versions"], dict) or not all(isinstance(value, str) for value in args["versions"].values()):
            raise ProvenanceError("versions must map package names to version strings")
        capture_provenance(**args)
    except (ProvenanceError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())