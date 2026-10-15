"""Tests for rehearse_linux.py.

These tests are hermetic. They exercise the pure helpers with fixture data and
drive the committed-source export through a tiny throwaway git repository. They
never build a crate, never run a real toolchain, and never reach the network.
The compiler-dependent build, SBOM, and packaging steps are driven end to end by
the main release rehearsal, not by these tests.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import build_provenance
import rehearse_linux

# Import the sibling module (pytest prepends the test directory to sys.path).
from rehearse_linux import (
    BASH_PLUGIN_EXPORTS,
    DEFAULT_TARGET,
    PRODUCTS,
    RehearsalError,
    asset_suffix,
    build_product_command,
    cyclonedx_root_component,
    export_source,
    ldd_missing_libraries,
    linux_artifact_names,
    main,
    missing_dynamic_exports,
    parse_dynamic_exports,
    preflight_tools,
    read_versions_file,
    rehearse,
    require_empty_output,
    sbom_command,
    sha256_file,
    verify_recorded_digests,
    verify_sbom_component,
    version_output_matches,
    write_checksums,
    _select_sbom,
)


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Product and naming helpers.
# ---------------------------------------------------------------------------


def test_products_are_the_four_supported_linux_products() -> None:
    names = [product["asset_name"] for product in PRODUCTS]
    assert names == [
        "tacon-linux-gnu-x86_64",
        "tacacsrs-agentd-linux-gnu-x86_64",
        "tacacsrs-agent-health-linux-gnu-x86_64",
        "tacacsrs-bash-plugin-linux-gnu-x86_64",
    ]
    # Exactly one cdylib (the Bash plugin); the rest are executables.
    kinds = [product["artifact_kind"] for product in PRODUCTS]
    assert kinds.count("cdylib") == 1
    assert kinds.count("bin") == 3


def test_linux_artifact_names_bin() -> None:
    assert linux_artifact_names("tacon", "bin") == ("tacon", "tacon")


def test_linux_artifact_names_cdylib() -> None:
    assert linux_artifact_names("tacacsrs_bash_plugin", "cdylib") == (
        "libtacacsrs_bash_plugin.so",
        "libtacacsrs_bash_plugin",
    )


def test_linux_artifact_names_rejects_unknown_kind() -> None:
    with pytest.raises(RehearsalError):
        linux_artifact_names("tacon", "staticlib")


def test_asset_suffix_strips_package_prefix() -> None:
    assert asset_suffix("tacon-linux-gnu-x86_64", "tacon") == "linux-gnu-x86_64"
    assert (
        asset_suffix("tacacsrs-agentd-linux-gnu-x86_64", "tacacsrs-agentd")
        == "linux-gnu-x86_64"
    )


def test_asset_suffix_without_prefix_returns_asset() -> None:
    assert asset_suffix("custom-asset", "tacon") == "custom-asset"


def test_asset_suffix_rejects_bare_package_name() -> None:
    with pytest.raises(RehearsalError):
        asset_suffix("tacon", "tacon")


# ---------------------------------------------------------------------------
# Versions map and preflight.
# ---------------------------------------------------------------------------


def test_read_versions_file_valid(tmp_path: Path) -> None:
    path = _write(tmp_path / "v.json", json.dumps({"tacon": "2026.424.0"}))
    assert read_versions_file(path) == {"tacon": "2026.424.0"}


def test_read_versions_file_empty_object(tmp_path: Path) -> None:
    path = _write(tmp_path / "v.json", "{}")
    assert read_versions_file(path) == {}


def test_read_versions_file_rejects_non_object(tmp_path: Path) -> None:
    path = _write(tmp_path / "v.json", "[]")
    with pytest.raises(RehearsalError):
        read_versions_file(path)


def test_read_versions_file_rejects_non_string_values(tmp_path: Path) -> None:
    path = _write(tmp_path / "v.json", json.dumps({"tacon": 1}))
    with pytest.raises(RehearsalError):
        read_versions_file(path)


def test_preflight_tools_reports_missing_in_order() -> None:
    present = {"git", "cargo", "tar"}
    missing = preflight_tools(
        ["git", "objcopy", "cargo", "nm"],
        which=lambda tool: tool if tool in present else None,
    )
    assert missing == ["objcopy", "nm"]


def test_preflight_tools_all_present() -> None:
    assert preflight_tools(["git"], which=lambda tool: "/usr/bin/git") == []


def test_output_accepts_new_or_empty_directory(tmp_path):
    output = tmp_path / "output"
    require_empty_output(output)
    output.mkdir()
    require_empty_output(output)


@pytest.mark.parametrize("existing", ["release/stale.tar.gz", "source/Cargo.toml", ".hidden"])
def test_rehearsal_rejects_repeated_output_before_tools(tmp_path, monkeypatch, existing):
    output = tmp_path / "output"
    stale = _write(output / existing, "keep this file")

    def unexpected(*args, **kwargs):
        pytest.fail("a tool ran before the output guard")

    monkeypatch.setattr("rehearse_linux.preflight_tools", unexpected)
    with pytest.raises(RehearsalError, match="new or empty directory"):
        rehearse(source=str(tmp_path), revision="HEAD", versions_path="unused", output=str(output))
    assert stale.read_text() == "keep this file"


def test_output_rejects_file_and_symlink(tmp_path):
    regular = _write(tmp_path / "file", "keep")
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "absent", target_is_directory=True)
    for output in (regular, link):
        with pytest.raises(RehearsalError, match="new or empty directory"):
            require_empty_output(output)


# ---------------------------------------------------------------------------
# Build and SBOM command construction.
# ---------------------------------------------------------------------------


def test_build_product_command_bin_release() -> None:
    command = build_product_command(PRODUCTS[0], DEFAULT_TARGET, ["--release"])
    assert command == [
        "cargo",
        "build",
        "--release",
        "--locked",
        "--target",
        DEFAULT_TARGET,
        "--package",
        "tacon",
        "--bins",
    ]


def test_build_product_command_cdylib_debug() -> None:
    command = build_product_command(PRODUCTS[3], DEFAULT_TARGET, [])
    assert command == [
        "cargo",
        "build",
        "--locked",
        "--target",
        DEFAULT_TARGET,
        "--package",
        "tacacsrs-bash-plugin",
        "--lib",
    ]


def test_build_product_command_adds_features() -> None:
    product = dict(PRODUCTS[0], features="extra feature")
    command = build_product_command(product, DEFAULT_TARGET, ["--release"])
    assert command[-2:] == ["--features", "extra feature"]


def test_sbom_command_matches_generate_sbom_flags() -> None:
    command = sbom_command(
        Path("/w/executables/tacon/Cargo.toml"), "binaries", DEFAULT_TARGET, "json"
    )
    assert command == [
        "cargo",
        "cyclonedx",
        "--format",
        "json",
        "--manifest-path",
        "/w/executables/tacon/Cargo.toml",
        "--describe",
        "binaries",
        "--target",
        DEFAULT_TARGET,
    ]


# ---------------------------------------------------------------------------
# SBOM parsing and verification.
# ---------------------------------------------------------------------------


def test_cyclonedx_root_component_json(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "sbom.cdx.json",
        json.dumps(
            {
                "metadata": {
                    "component": {
                        "type": "application",
                        "name": "tacon",
                        "version": "2026.424.0",
                    }
                }
            }
        ),
    )
    assert cyclonedx_root_component(path) == ("tacon", "2026.424.0")


def test_cyclonedx_root_component_xml(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "sbom.cdx.xml",
        """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <metadata>
    <component type="application">
      <name>tacacsrs-bash-plugin</name>
      <version>0.1.3</version>
    </component>
  </metadata>
</bom>
""",
    )
    assert cyclonedx_root_component(path) == ("tacacsrs-bash-plugin", "0.1.3")


def test_cyclonedx_root_component_rejects_unknown_format(tmp_path: Path) -> None:
    path = _write(tmp_path / "sbom.txt", "nope")
    with pytest.raises(RehearsalError):
        cyclonedx_root_component(path)


def test_verify_sbom_component_matches() -> None:
    assert verify_sbom_component("tacon", "2026.424.0", "tacon", "2026.424.0") == []


def test_verify_sbom_component_detects_version_mismatch() -> None:
    errors = verify_sbom_component("tacon", "1.0.0", "tacon", "2026.424.0")
    assert errors and "does not match the computed version" in errors[0]


def test_verify_sbom_component_detects_name_mismatch() -> None:
    errors = verify_sbom_component("other", "2026.424.0", "tacon", "2026.424.0")
    assert errors and "does not match" in errors[0]


def test_verify_sbom_component_requires_a_version() -> None:
    errors = verify_sbom_component("tacon", None, "tacon", "2026.424.0")
    assert errors and "no root component version" in errors[0]


def test_verify_sbom_component_skips_unknown_expected_version() -> None:
    # The package is absent from the computed map, so only presence is required.
    assert verify_sbom_component("tacon", "0.0.0-dev", "tacon", None) == []


def test_select_sbom_prefers_matching_root(tmp_path: Path) -> None:
    other = _write(
        tmp_path / "dep.cdx.json",
        json.dumps({"metadata": {"component": {"name": "dep", "version": "1.0"}}}),
    )
    product = _write(
        tmp_path / "tacon.cdx.json",
        json.dumps({"metadata": {"component": {"name": "tacon", "version": "2.0"}}}),
    )
    assert _select_sbom([other, product], "tacon") == product


def test_select_sbom_falls_back_to_single_file(tmp_path: Path) -> None:
    only = _write(
        tmp_path / "only.cdx.json",
        json.dumps({"metadata": {"component": {"name": "x", "version": "1"}}}),
    )
    assert _select_sbom([only], "tacon") == only


# ---------------------------------------------------------------------------
# Native inspection parsing.
# ---------------------------------------------------------------------------


_NM_SAMPLE = """\
0000000000003a10 T on_shell_execve
0000000000003990 T plugin_init
00000000000039d0 T plugin_uninit
                 U __errno_location
                 w __cxa_finalize
0000000000004000 D some_data
"""


def test_parse_dynamic_exports_keeps_defined_symbols() -> None:
    exports = parse_dynamic_exports(_NM_SAMPLE)
    assert {"on_shell_execve", "plugin_init", "plugin_uninit", "some_data"} <= exports
    assert "__errno_location" not in exports
    assert "__cxa_finalize" not in exports


def test_missing_dynamic_exports_none_when_all_present() -> None:
    assert missing_dynamic_exports(_NM_SAMPLE, BASH_PLUGIN_EXPORTS) == []


def test_missing_dynamic_exports_reports_absent() -> None:
    nm_output = "0000000000003990 T plugin_init\n"
    missing = missing_dynamic_exports(nm_output, BASH_PLUGIN_EXPORTS)
    assert missing == ["plugin_uninit", "on_shell_execve"]


def test_ldd_missing_libraries_detects_not_found() -> None:
    ldd_output = (
        "\tlinux-vdso.so.1 (0x00007fff)\n"
        "\tlibssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x00007f00)\n"
        "\tlibmissing.so.1 => not found\n"
    )
    assert ldd_missing_libraries(ldd_output) == ["libmissing.so.1 => not found"]


def test_ldd_missing_libraries_empty_when_resolved() -> None:
    ldd_output = "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f00)\n"
    assert ldd_missing_libraries(ldd_output) == []


def test_version_output_matches() -> None:
    assert version_output_matches("tacon 2026.424.0\n", "2026.424.0")
    assert not version_output_matches("tacon 2026.424.0\n", "2026.424.1")


# ---------------------------------------------------------------------------
# Offline digests and checksums.
# ---------------------------------------------------------------------------


def test_verify_recorded_digests_matches(tmp_path: Path) -> None:
    release = tmp_path / "release"
    archive = _write(release / "tacon-linux-gnu-x86_64.tar.gz", "archive-bytes")
    manifest = _write(
        tmp_path / "manifest.json",
        json.dumps({"artifacts": {archive.name: sha256_file(archive)}}),
    )
    assert verify_recorded_digests(manifest, release) == []


def test_verify_recorded_digests_detects_corruption(tmp_path: Path) -> None:
    release = tmp_path / "release"
    archive = _write(release / "a.tar.gz", "original")
    manifest = _write(
        tmp_path / "manifest.json",
        json.dumps({"artifacts": {archive.name: sha256_file(archive)}}),
    )
    archive.write_text("tampered", encoding="utf-8")
    errors = verify_recorded_digests(manifest, release)
    assert errors and "digest mismatch" in errors[0]


def test_verify_recorded_digests_detects_missing(tmp_path: Path) -> None:
    release = tmp_path / "release"
    release.mkdir()
    manifest = _write(
        tmp_path / "manifest.json",
        json.dumps({"artifacts": {"gone.tar.gz": "0" * 64}}),
    )
    errors = verify_recorded_digests(manifest, release)
    assert errors and "is missing" in errors[0]


def test_write_checksums_covers_other_files_only(tmp_path: Path) -> None:
    release = tmp_path / "release"
    first = _write(release / "a.tar.gz", "alpha")
    second = _write(release / "b.tar.gz", "bravo")
    checksums = write_checksums(release)
    assert checksums.name == "checksums-sha256.txt"
    lines = checksums.read_text(encoding="utf-8").splitlines()
    assert f"{sha256_file(first)}  a.tar.gz" in lines
    assert f"{sha256_file(second)}  b.tar.gz" in lines
    # The checksums file never lists itself.
    assert all("checksums-sha256.txt" not in line for line in lines)
    assert lines == sorted(lines)


# ---------------------------------------------------------------------------
# Committed-source export.
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("tar") is None,
    reason="git and tar are required for the export test",
)
def test_export_source_excludes_untracked(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "rehearsal@example.com")
    _git(repo, "config", "user.name", "Rehearsal Test")
    _write(repo / "committed.txt", "tracked content")
    _write(repo / "nested" / "keep.txt", "tracked nested")
    _git(repo, "add", "committed.txt", "nested/keep.txt")
    _git(repo, "commit", "-q", "-m", "initial commit")

    # An untracked file that must never reach the export.
    _write(repo / "untracked.txt", "working tree only")

    destination = tmp_path / "export"
    export_source(repo, "HEAD", destination)

    assert (destination / "committed.txt").read_text(encoding="utf-8") == "tracked content"
    assert (destination / "nested" / "keep.txt").is_file()
    assert not (destination / "untracked.txt").exists()


# ---------------------------------------------------------------------------
# CLI error handling.
# ---------------------------------------------------------------------------


def test_main_reports_rehearsal_error(monkeypatch, capsys, tmp_path: Path) -> None:
    def _fail(**_kwargs):
        raise RehearsalError("boom")

    monkeypatch.setattr("rehearse_linux.rehearse", _fail)
    versions = _write(tmp_path / "v.json", "{}")
    code = main(
        [
            "--source",
            str(tmp_path),
            "--revision",
            "HEAD",
            "--versions",
            str(versions),
            "--output",
            str(tmp_path / "out"),
        ]
    )
    assert code == 1
    assert "Error: boom" in capsys.readouterr().err


@pytest.mark.parametrize("output", ["not a dynamic executable", "statically linked", "inspection failed", ""])
def test_validate_artifact_rejects_every_ldd_failure(tmp_path, monkeypatch, output):
    _write(tmp_path / "tacon", "binary")
    monkeypatch.setattr(rehearse_linux, "_capture_lenient", lambda *args, **kwargs: (1, output))
    with pytest.raises(RehearsalError, match="native dependency inspection failed"):
        rehearse_linux.validate_artifact(PRODUCTS[0], staging_dir=tmp_path, artifact_filename="tacon", versions={})


@pytest.mark.parametrize("missing", [None, "json-name", "xml"])
def test_local_sbom_cli_contract_and_required_formats(tmp_path, monkeypatch, missing):
    export = tmp_path / "source"
    package_root = export / PRODUCTS[0]["package_root"]
    package_root.mkdir(parents=True)
    commands = []
    product = dict(PRODUCTS[0], features="feature-a")

    def run(command, **kwargs):
        commands.append(command)
        if command[:2] != ["cargo", "cyclonedx"]:
            return
        output_format = command[command.index("--format") + 1]
        if output_format == "json":
            component = {"version": "1.2.3"}
            if missing != "json-name":
                component["name"] = "tacon"
            _write(package_root / "product.cdx.json", json.dumps({"metadata": {"component": component}}))
        elif missing != "xml":
            _write(package_root / "product.cdx.xml", '<bom><metadata><component><name>tacon</name><version>1.2.3</version></component></metadata></bom>')

    monkeypatch.setattr(rehearse_linux, "_run", run)
    args = dict(
        product=product, export_dir=export, staging_dir=tmp_path / "staged",
        suffix="linux", target=DEFAULT_TARGET, versions={"tacon": "1.2.3"},
        env={"GITHUB_WORKSPACE": "/private/checkout", "GITHUB_REPOSITORY": "AuthScaffold/tacacs-rs"},
        python="python-fixture",
    )
    if missing:
        with pytest.raises(RehearsalError):
            rehearse_linux.generate_and_stage_sbom(**args)
        assert all(command[:2] == ["cargo", "cyclonedx"] for command in commands)
        return
    staged = rehearse_linux.generate_and_stage_sbom(**args)
    assert {path.suffix for path in staged} == {".json", ".xml"}
    assert all(command[-2:] == ["--features", "feature-a"] for command in commands[:2])
    helper = commands[-1]
    assert helper[:2] == ["python-fixture", str(export / rehearse_linux.SBOM_STAGE_TOOL_RELPATH)]
    assert helper[helper.index("--package-name") + 1] == "tacon"
    assert helper[helper.index("--expected-version") + 1] == "1.2.3"
    assert helper.count("--workspace") == 2
    assert str(export) in helper and "/private/checkout" in helper


def test_local_product_uses_capture_cli_before_archive(tmp_path, monkeypatch):
    export = tmp_path / "source"
    output = tmp_path / "output"
    release = output / "release"
    release.mkdir(parents=True)
    product = PRODUCTS[0]
    _write(export / product["package_root"] / "Cargo.toml", '[package]\nname="tacon"\nversion="1.2.3"\n')
    _write(export / "Cargo.lock", "hydrated lock")
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        env = kwargs.get("env", {})
        if command[0] == "bash" and command[1].endswith(rehearse_linux.STAGE_SCRIPT_RELPATH):
            _write(Path(env["PACKAGE_DIR"]) / "tacon", "binary")
        elif command[0] == "python-fixture":
            assert command[1] == str(export / rehearse_linux.PROVENANCE_TOOL_RELPATH)
            assert kwargs["cwd"] == export
            assert build_provenance.main(command[2:]) == 0
        elif command[0] == "bash" and command[1].endswith(rehearse_linux.ARCHIVE_SCRIPT_RELPATH):
            assert (Path(env["PACKAGE_DIR"]) / "build-provenance.json").is_file()
            _write(output / "packaged" / f'{product["asset_name"]}.tar.gz', "archive fixture")

    monkeypatch.setattr(rehearse_linux, "_run", run)
    monkeypatch.setattr(rehearse_linux, "generate_and_stage_sbom", lambda *args, **kwargs: [])
    monkeypatch.setattr(rehearse_linux, "validate_artifact", lambda *args, **kwargs: None)
    monkeypatch.setattr(build_provenance, "tool_output", lambda *args, **kwargs: "tacon 1.2.3")
    archive = rehearse_linux.process_product(
        product, export_dir=export, output_dir=output, build_dir=output / "build",
        release_dir=release, target=DEFAULT_TARGET, profile="release", versions={"tacon": "1.2.3"},
        base_env={}, commit="committed-source", python="python-fixture",
    )
    assert archive.is_file()
    sidecar = release / f'build-provenance-{product["asset_name"]}.json'
    record = json.loads(sidecar.read_text())
    assert record["source"]["commit"] == "committed-source"
    assert record["package"]["version"] == "1.2.3"
    assert record["build"] == {"target": DEFAULT_TARGET, "profile": "release", "features": {"requested": [], "defaultEnabled": True}}
    embedded = output / "staging" / product["asset_name"] / "build-provenance.json"
    assert sidecar.read_bytes() == embedded.read_bytes()
    capture_index = next(index for index, command in enumerate(commands) if command[0] == "python-fixture")
    assert commands[capture_index + 1][1].endswith(rehearse_linux.ARCHIVE_SCRIPT_RELPATH)


def test_local_manifest_cli_receives_staged_records(tmp_path, monkeypatch):
    export = tmp_path / "source"
    _write(export / rehearse_linux.MANIFEST_TOOL_RELPATH, "fixture")
    commands = []
    monkeypatch.setattr(rehearse_linux, "_run", lambda command: commands.append(command))
    release = tmp_path / "release"
    rehearse_linux.generate_manifest(export, release, tmp_path / "versions.json", "source-commit", python="python-fixture")
    command = commands[0]
    assert command[command.index("--provenance-dir") + 1] == str(release)
    assert command[command.index("--source") + 1] == "source-commit"
