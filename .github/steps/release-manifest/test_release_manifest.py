"""Tests for release_manifest.py.

These tests are hermetic. They build fake release archives and a fake workspace
on a temporary directory, then exercise each code path. They never call Cargo,
never run a real toolchain, and never reach the network.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import build_provenance
from build_provenance import ProvenanceError, capture_provenance, collect_build_provenance

# Import the sibling module (pytest prepends the test directory to sys.path).
from release_manifest import (
    PROTO_DIR_RELPATH,
    YANG_MANIFEST_RELPATH,
    ManifestError,
    build_manifest,
    collect_artifact_hashes,
    generate_manifest,
    main,
    read_versions,
    schema_identities,
    toolchain_provenance,
    verify_artifact_hashes,
)


def _write(path: Path, content) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        content = content.encode("utf-8")
    path.write_bytes(content)
    return path


def _fake_workspace(root: Path) -> Path:
    _write(
        root / YANG_MANIFEST_RELPATH,
        json.dumps(
            {
                "schemaVersion": 1,
                "source": {"commit": "abc123", "moduleSha256": "deadbeef"},
                "artifacts": {"../src/generated.rs": "cafef00d"},
            }
        ),
    )
    _write(root / PROTO_DIR_RELPATH / "tacacsrs_agent.proto", 'syntax = "proto3";\n')
    return root


def _fake_artifacts(root: Path) -> Path:
    _write(root / "tacon-linux-gnu-x86_64.tar.gz", b"linux-archive-bytes")
    _write(root / "tacon-windows-msvc-x86_64.zip", b"windows-archive-bytes")
    return root


def _archive(staging: Path, archive: Path) -> None:
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive, "w") as output:
            for path in sorted(staging.rglob("*")):
                if path.is_file():
                    output.write(path, path.relative_to(staging.parent).as_posix())
    else:
        with tarfile.open(archive, "w:gz") as output:
            output.add(staging, arcname=staging.name)


def _build_records(workspace, artifacts, source="s", version="0.0.0-dev"):
    package_root = workspace / "executables/tacon"
    _write(package_root / "Cargo.toml", f'[package]\nname = "tacon"\nversion = "{version}"\n')
    _write(workspace / "Cargo.lock", "lock fixture")
    upload_dir = workspace.parent / "records"
    for archive in sorted(artifacts.iterdir()):
        if not archive.name.endswith((".zip", ".tar.gz")):
            continue
        windows = archive.suffix == ".zip"
        asset_name = archive.name.removesuffix(".zip" if windows else ".tar.gz")
        staging = workspace.parent / "staging" / asset_name
        artifact_filename = "tacon.exe" if windows else "tacon"
        _write(staging / artifact_filename, "compiled fixture")

        def runner(command, **kwargs):
            text = f"tacon {version}" if command[-1] == "--version" and command[0] not in ("rustc", "cargo") else f"{command[0]} build-host-version"
            return SimpleNamespace(returncode=0, stdout=text)

        capture_provenance(
            workspace=workspace, package_root=package_root, package_dir=staging,
            upload_dir=upload_dir, asset_name=asset_name, package_name="tacon",
            artifact_filename=artifact_filename, artifact_kind="bin", source=source,
            target="x86_64-pc-windows-msvc" if windows else "x86_64-unknown-linux-gnu",
            profile="release", features="feature-b,feature-a feature-b", versions={"tacon": version},
            runner=runner,
        )
        _archive(staging, archive)
    return upload_dir


# ---------------------------------------------------------------------------
# collect_artifact_hashes
# ---------------------------------------------------------------------------


def test_collect_records_offline_sha256(tmp_path):
    artifacts = _fake_artifacts(tmp_path / "release")
    hashes = collect_artifact_hashes(artifacts)
    assert hashes == {
        "tacon-linux-gnu-x86_64.tar.gz": hashlib.sha256(
            b"linux-archive-bytes"
        ).hexdigest(),
        "tacon-windows-msvc-x86_64.zip": hashlib.sha256(
            b"windows-archive-bytes"
        ).hexdigest(),
    }


def test_collect_excludes_manifest_and_checksums(tmp_path):
    artifacts = _fake_artifacts(tmp_path / "release")
    _write(artifacts / "checksums-sha256.txt", b"must-not-be-hashed")
    _write(artifacts / "release-manifest.json", b"self")
    hashes = collect_artifact_hashes(artifacts, exclude={"release-manifest.json"})
    assert "checksums-sha256.txt" not in hashes
    assert "release-manifest.json" not in hashes
    assert set(hashes) == {
        "tacon-linux-gnu-x86_64.tar.gz",
        "tacon-windows-msvc-x86_64.zip",
    }


def test_collect_rejects_symlink_artifact(tmp_path):
    artifacts = _fake_artifacts(tmp_path / "release")
    outside = _write(tmp_path / "outside.bin", b"outside-the-artifacts-dir")
    (artifacts / "smuggled.tar.gz").symlink_to(outside)
    with pytest.raises(ManifestError, match="symbolic link"):
        collect_artifact_hashes(artifacts)


def test_collect_rejects_basename_collision(tmp_path):
    artifacts = tmp_path / "release"
    _write(artifacts / "linux" / "package.tar.gz", b"one")
    _write(artifacts / "windows" / "package.tar.gz", b"two")
    with pytest.raises(ManifestError, match="basename collision"):
        collect_artifact_hashes(artifacts)


def test_collect_requires_existing_directory(tmp_path):
    with pytest.raises(ManifestError, match="does not exist"):
        collect_artifact_hashes(tmp_path / "absent")


# ---------------------------------------------------------------------------
# read_versions
# ---------------------------------------------------------------------------


def test_read_versions_map(tmp_path):
    versions = _write(
        tmp_path / "versions.json",
        json.dumps({"tacon": "2026.1015.1", "tacacsrs-protocol": "0.4.1"}),
    )
    assert read_versions(versions) == {
        "tacon": "2026.1015.1",
        "tacacsrs-protocol": "0.4.1",
    }


def test_read_versions_allows_empty_map(tmp_path):
    versions = _write(tmp_path / "versions.json", "{}")
    assert read_versions(versions) == {}


def test_read_versions_rejects_non_object(tmp_path):
    versions = _write(tmp_path / "versions.json", json.dumps(["tacon", "1.0"]))
    with pytest.raises(ManifestError, match="JSON object"):
        read_versions(versions)


# ---------------------------------------------------------------------------
# schema_identities
# ---------------------------------------------------------------------------


def test_schema_identities_capture_yang_and_proto(tmp_path):
    workspace = _fake_workspace(tmp_path / "ws")
    schemas = schema_identities(workspace)

    yang = schemas["yang"]
    assert yang["sourceCommit"] == "abc123"
    assert yang["moduleSha256"] == "deadbeef"
    assert yang["generatedRustSha256"] == "cafef00d"
    assert yang["manifestSha256"] == sha256_of(workspace / YANG_MANIFEST_RELPATH)

    proto_key = f"{PROTO_DIR_RELPATH}/tacacsrs_agent.proto"
    assert schemas["protobuf"][proto_key] == hashlib.sha256(
        b'syntax = "proto3";\n'
    ).hexdigest()


def test_schema_requires_yang_manifest(tmp_path):
    workspace = tmp_path / "ws"
    _write(workspace / PROTO_DIR_RELPATH / "x.proto", 'syntax = "proto3";\n')
    with pytest.raises(ManifestError, match="YANG generation manifest is missing"):
        schema_identities(workspace)


def test_schema_requires_a_proto_file(tmp_path):
    workspace = _fake_workspace(tmp_path / "ws")
    (workspace / PROTO_DIR_RELPATH / "tacacsrs_agent.proto").unlink()
    with pytest.raises(ManifestError, match="no protobuf schema files"):
        schema_identities(workspace)


# ---------------------------------------------------------------------------
# toolchain_provenance
# ---------------------------------------------------------------------------


def test_toolchain_provenance_handles_missing_tools():
    def runner(command, **_kwargs):
        raise FileNotFoundError(command[0])

    assert toolchain_provenance(runner=runner) == {
        "rustc": None,
        "cargo": None,
        "openssl": None,
    }


def test_toolchain_provenance_captures_versions():
    class Result:
        returncode = 0

        def __init__(self, stdout):
            self.stdout = stdout

    def runner(command, **_kwargs):
        return Result(f"{command[0]} 1.0\n")

    assert toolchain_provenance(runner=runner) == {
        "rustc": "rustc 1.0",
        "cargo": "cargo 1.0",
        "openssl": "openssl 1.0",
    }


# ---------------------------------------------------------------------------
# generate_manifest and verification
# ---------------------------------------------------------------------------


def test_generate_manifest_records_all_evidence(tmp_path):
    workspace = _fake_workspace(tmp_path / "ws")
    artifacts = _fake_artifacts(tmp_path / "artifacts")
    versions = _write(tmp_path / "versions.json", json.dumps({"tacon": "2026.1015.1"}))
    records = _build_records(workspace, artifacts, "feedface", "2026.1015.1")

    manifest = generate_manifest(
        artifacts_dir=artifacts,
        versions_path=versions,
        source="feedface",
        workspace=workspace,
        output=artifacts / "release-manifest.json",
        provenance_dir=records,
        assembly_toolchain={"rustc": None, "cargo": None, "openssl": None},
    )

    assert manifest["schemaVersion"] == 2
    assert manifest["source"] == {"commit": "feedface"}
    assert manifest["versions"] == {"tacon": "2026.1015.1"}
    assert set(manifest["artifacts"]) == {
        "tacon-linux-gnu-x86_64.tar.gz",
        "tacon-windows-msvc-x86_64.zip",
    }
    assert manifest["schemas"]["yang"]["sourceCommit"] == "abc123"
    assert "toolchain" not in manifest
    assert manifest["assemblyToolchain"] == {"rustc": None, "cargo": None, "openssl": None}
    assert set(manifest["buildProvenance"]) == set(manifest["artifacts"])
    for record in manifest["buildProvenance"].values():
        assert record["source"]["commit"] == "feedface"
        assert record["package"]["version"] == "2026.1015.1"
        assert record["toolchain"]["rustc"] == "rustc build-host-version"
        assert record["build"]["features"] == {"requested": ["feature-a", "feature-b"], "defaultEnabled": True}
    assert verify_artifact_hashes(manifest, artifacts) == []


def test_generate_manifest_excludes_its_own_output(tmp_path):
    workspace = _fake_workspace(tmp_path / "ws")
    artifacts = _fake_artifacts(tmp_path / "artifacts")
    versions = _write(tmp_path / "versions.json", "{}")
    output = artifacts / "release-manifest.json"
    records = _build_records(workspace, artifacts)
    # A stale manifest from a previous run must not be hashed on a re-run.
    _write(output, b"stale manifest contents")

    manifest = generate_manifest(
        artifacts_dir=artifacts,
        versions_path=versions,
        source="s",
        workspace=workspace,
        output=output,
        provenance_dir=records,
        assembly_toolchain={},
    )
    assert "release-manifest.json" not in manifest["artifacts"]


def test_verify_detects_corruption(tmp_path):
    workspace = _fake_workspace(tmp_path / "ws")
    artifacts = _fake_artifacts(tmp_path / "artifacts")
    versions = _write(tmp_path / "versions.json", "{}")
    records = _build_records(workspace, artifacts)
    manifest = generate_manifest(
        artifacts_dir=artifacts,
        versions_path=versions,
        source="s",
        workspace=workspace,
        output=tmp_path / "out.json",
        provenance_dir=records,
        assembly_toolchain={},
    )

    (artifacts / "tacon-linux-gnu-x86_64.tar.gz").write_bytes(b"tampered")
    errors = verify_artifact_hashes(manifest, artifacts)
    assert any("digest mismatch" in error for error in errors)


def test_verify_detects_missing_artifact(tmp_path):
    workspace = _fake_workspace(tmp_path / "ws")
    artifacts = _fake_artifacts(tmp_path / "artifacts")
    versions = _write(tmp_path / "versions.json", "{}")
    records = _build_records(workspace, artifacts)
    manifest = generate_manifest(
        artifacts_dir=artifacts,
        versions_path=versions,
        source="s",
        workspace=workspace,
        output=tmp_path / "out.json",
        provenance_dir=records,
        assembly_toolchain={},
    )

    (artifacts / "tacon-windows-msvc-x86_64.zip").unlink()
    errors = verify_artifact_hashes(manifest, artifacts)
    assert any("missing" in error for error in errors)


def test_build_manifest_shape():
    manifest = build_manifest(
        source="s",
        versions={"tacon": "1.0"},
        artifacts={"a.tar.gz": "00"},
        schemas={"yang": {}, "protobuf": {}},
        assembly_toolchain={"rustc": None},
        build_provenance={},
    )
    assert manifest["schemaVersion"] == 2
    assert manifest["source"]["commit"] == "s"


# ---------------------------------------------------------------------------
# Command-line entry point
# ---------------------------------------------------------------------------


def test_main_writes_manifest(tmp_path, monkeypatch):
    workspace = _fake_workspace(tmp_path / "ws")
    artifacts = _fake_artifacts(tmp_path / "artifacts")
    versions = _write(tmp_path / "versions.json", json.dumps({"tacon": "2026.1015.1"}))
    output = artifacts / "release-manifest.json"
    records = _build_records(workspace, artifacts, "abc", "2026.1015.1")
    monkeypatch.setattr("release_manifest.toolchain_provenance", lambda: {})

    exit_code = main(
        [
            "--artifacts",
            str(artifacts),
            "--versions",
            str(versions),
            "--source",
            "abc",
            "--workspace",
            str(workspace),
            "--provenance-dir",
            str(records),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    data = json.loads(output.read_text())
    assert data["source"]["commit"] == "abc"
    assert data["versions"] == {"tacon": "2026.1015.1"}
    assert "release-manifest.json" not in data["artifacts"]


def test_main_reports_corrupt_inputs(tmp_path, capsys):
    workspace = _fake_workspace(tmp_path / "ws")
    artifacts = _fake_artifacts(tmp_path / "artifacts")
    bad_versions = _write(tmp_path / "versions.json", "not json")

    exit_code = main(
        [
            "--artifacts",
            str(artifacts),
            "--versions",
            str(bad_versions),
            "--source",
            "abc",
            "--workspace",
            str(workspace),
            "--provenance-dir",
            str(tmp_path / "records"),
            "--output",
            str(tmp_path / "out.json"),
        ]
    )

    assert exit_code == 1
    assert "Error:" in capsys.readouterr().err


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def evidence(tmp_path):
    workspace = _fake_workspace(tmp_path / "ws")
    artifacts = _fake_artifacts(tmp_path / "release")
    records = _build_records(workspace, artifacts)
    return dict(provenance_dir=records, artifacts_dir=artifacts, source="s", versions={}, workspace=workspace)


def test_provenance_rejects_source_and_version_mismatches(evidence):
    with pytest.raises(ProvenanceError, match="source mismatch"):
        collect_build_provenance(**dict(evidence, source="other"))
    with pytest.raises(ProvenanceError, match="version mismatch"):
        collect_build_provenance(**dict(evidence, versions={"tacon": "9.9.9"}))


def test_provenance_checks_source_version_without_computed_override(evidence):
    manifest = evidence["workspace"] / "executables/tacon/Cargo.toml"
    manifest.write_text('[package]\nname = "tacon"\nversion = "9.9.9"\n')
    with pytest.raises(ProvenanceError, match="version mismatch"):
        collect_build_provenance(**evidence)


def test_provenance_requires_a_record_for_every_archive(evidence):
    next(evidence["provenance_dir"].iterdir()).unlink()
    with pytest.raises(ProvenanceError, match="every release archive"):
        collect_build_provenance(**evidence)


def test_provenance_rejects_stale_archive(evidence):
    (evidence["artifacts_dir"] / "stale.tar.gz").write_bytes(b"stale")
    with pytest.raises(ProvenanceError, match="every release archive"):
        collect_build_provenance(**evidence)


def test_provenance_rejects_changed_uploaded_record(evidence):
    path = next(evidence["provenance_dir"].iterdir())
    record = json.loads(path.read_text())
    record["toolchain"]["rustc"] = "another compiler"
    path.write_text(json.dumps(record))
    with pytest.raises(ProvenanceError, match="embedded provenance"):
        collect_build_provenance(**evidence)


@pytest.mark.parametrize("asset,filename,extension", [
    ("tacon-linux-gnu-x86_64", "tacon", ".tar.gz"),
    ("tacon-windows-msvc-x86_64", "tacon.exe", ".zip"),
])
def test_provenance_rejects_changed_archived_payload(evidence, asset, filename, extension):
    staging = evidence["workspace"].parent / "staging" / asset
    (staging / filename).write_bytes(b"tampered binary")
    _archive(staging, evidence["artifacts_dir"] / (asset + extension))
    with pytest.raises(ProvenanceError, match="file hashes"):
        collect_build_provenance(**evidence)


def test_provenance_rejects_changed_staged_sidecar(evidence):
    path = next(evidence["provenance_dir"].iterdir())
    (evidence["artifacts_dir"] / path.name).write_text("different record")
    with pytest.raises(ProvenanceError, match="staged provenance differs"):
        collect_build_provenance(**evidence)


def test_provenance_cli_captures_hydrated_version_and_identical_copies(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    package_root = workspace / "executables/tacon"
    _write(package_root / "Cargo.toml", '[package]\nname="tacon"\nversion="1.2.3"\n')
    _write(workspace / "Cargo.lock", "hydrated lock")
    staged = tmp_path / "staging" / "tacon-linux"
    _write(staged / "tacon", "staged binary")
    upload = tmp_path / "packaged"
    commands = []

    def runner(command, **kwargs):
        commands.append(command)
        if command[0] == "openssl":
            raise FileNotFoundError("openssl")
        return SimpleNamespace(returncode=0, stdout="tacon 1.2.3" if command[0].endswith("/tacon") else "build tool 1.0")

    monkeypatch.setattr(build_provenance.subprocess, "run", runner)
    args = [
        "--workspace", str(workspace), "--package-root", str(package_root),
        "--package-dir", str(staged), "--upload-dir", str(upload),
        "--asset-name", "tacon-linux", "--package-name", "tacon",
        "--artifact-filename", "tacon", "--artifact-kind", "bin",
        "--source", "source-commit", "--target", "x86_64-unknown-linux-gnu",
        "--profile", "release", "--features", "feature-a feature-b",
        "--versions-json", '{"tacon":"1.2.3"}',
    ]
    assert build_provenance.main(args) == 0
    embedded = staged / "build-provenance.json"
    assert embedded.read_bytes() == (upload / "build-provenance-tacon-linux.json").read_bytes()
    record = json.loads(embedded.read_text())
    assert record["files"] == {"tacon": sha256_of(staged / "tacon")}
    assert record["package"]["manifestSha256"] == sha256_of(package_root / "Cargo.toml")
    assert record["source"]["cargoLockSha256"] == sha256_of(workspace / "Cargo.lock")
    assert record["toolchain"]["openssl"] is None
    assert ["rustc", "--version", "--verbose"] in commands
    assert [str((staged / "tacon").resolve()), "--version"] in commands

    embedded.unlink()
    args[-1] = '{"tacon":"9.9.9"}'
    assert build_provenance.main(args) == 1
    assert not embedded.exists()


@pytest.mark.parametrize("tool", ["rustc", "cargo"])
def test_capture_requires_build_tool_versions(evidence, monkeypatch, tool):
    def runner(command, **kwargs):
        return SimpleNamespace(returncode=1 if command[0] == tool else 0, stdout="version")

    with pytest.raises(ProvenanceError, match="cannot inspect"):
        build_provenance.tool_output([tool, "--version"], runner)
