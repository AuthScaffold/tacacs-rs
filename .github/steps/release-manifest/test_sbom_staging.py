"""Test the shared SBOM helper.

Cargo is the authority for the accepted root component names and the version.
The acceptance and rejection cases use a fake metadata loader so they stay fast
and deterministic. A few end-to-end cases build a real minimal manifest and run
Cargo; they are skipped when Cargo is absent.
"""

import importlib.util
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from textwrap import dedent
from urllib.parse import parse_qs, urlsplit

import pytest


HELPER = Path(__file__).resolve().parents[1] / "stage-sbom-files/stage_sbom.py"
SPEC = importlib.util.spec_from_file_location("stage_sbom", HELPER)
sbom = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sbom)
REPOSITORY = "https://github.com/AuthScaffold/tacacs-rs"


@pytest.mark.parametrize("root", ["/tmp/export.[1]+/source", "D:\\a\\repo\\repo", "/home/runner/work/repo/repo"])
def test_sanitizes_literal_paths_and_file_purl_without_changing_identity(root):
    purl = "pkg:cargo/tacon@2026.1015.1?download_url=file%3A%2F%2F%2Fprivate%2Fsource&checksum=sha256%3Aabc"
    value = {"name": "tacon", "version": "2026.1015.1", "purl": purl, "path": root + "/src/main.rs", "count": 3}
    result = sbom.sanitize_json(value, [root], REPOSITORY)
    assert result["name"] == value["name"]
    assert result["version"] == value["version"]
    assert result["count"] == 3
    assert result["path"] == "/workspace/src/main.rs"
    parts = urlsplit(result["purl"])
    assert parts.path == "cargo/tacon@2026.1015.1"
    assert parse_qs(parts.query) == {"download_url": [REPOSITORY], "checksum": ["sha256:abc"]}
    assert sbom.sanitize_string(root, [root], REPOSITORY) == "/workspace"
    assert sbom.sanitize_string(root + "-other/file", [root], REPOSITORY) == root + "-other/file"
    assert sbom.sanitize_string("file:///private/source", [root], REPOSITORY) == REPOSITORY


def loader_for(package_name, version, targets):
    """Return a metadata loader shaped like ``cargo metadata --no-deps``.

    ``targets`` is a list of ``(target_name, kinds)`` pairs for the package.
    """
    metadata = {
        "workspace_members": [f"id::{package_name}"],
        "packages": [
            {
                "id": f"id::{package_name}",
                "name": package_name,
                "version": version,
                "targets": [
                    {"name": name, "kind": list(kinds)} for name, kinds in targets
                ],
            }
        ],
    }
    return lambda _package_root: metadata


def write_inputs(root, *, name="tacon", version="1.2.3", xml=True, xml_name=None):
    """Write the JSON and XML SBOM fixtures, with local paths to sanitize."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "product.cdx.json").write_text(json.dumps({
        "metadata": {"component": {"name": name, "version": version}},
        "path": "/private/export/src",
        "url": "file:///private/export",
    }))
    if xml:
        xname = name if xml_name is None else xml_name
        (root / "product.cdx.xml").write_text(
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><metadata><component>'
            f'<name>{xname or ""}</name><version>{version}</version></component></metadata>'
            '<property value="/private/export/src">/private/export/src</property>'
            '<url>pkg:cargo/tacon@1.2.3?download_url=file:///private/export&amp;other=keep</url></bom>'
        )


def stage(tmp_path, *, package_name, loader, expected_version="1.2.3"):
    """Stage from ``tmp_path/input`` into ``tmp_path/staged`` with a fake loader."""
    kwargs = dict(
        package_root=tmp_path / "input",
        package_dir=tmp_path / "staged",
        basename="sbom-linux",
        package_name=package_name,
        workspaces=["/private/export"],
        repository=REPOSITORY,
        metadata_loader=loader,
    )
    if expected_version is not None:
        kwargs["expected_version"] = expected_version
    return sbom.stage_sboms(**kwargs)


def staged_identities(staged_dir):
    """Return the ``(name, version)`` identities of staged JSON and XML copies."""
    identities = {}
    for path in sorted(staged_dir.iterdir()):
        document = (
            json.loads(path.read_text())
            if path.suffix == ".json"
            else ET.fromstring(path.read_text())
        )
        identities[path.suffix] = sbom.component_identity(document, path.suffix[1:])
    return identities


def test_stages_both_formats_with_one_sanitization_policy(tmp_path):
    write_inputs(tmp_path / "input", name="tacon", version="1.2.3")
    staged = stage(
        tmp_path, package_name="tacon",
        loader=loader_for("tacon", "1.2.3", [("tacon", ["bin"])]),
    )
    assert sorted(path.suffix for path in staged) == [".json", ".xml"]
    for path in sorted((tmp_path / "staged").iterdir()):
        content = path.read_text()
        assert "/private/export" not in content
        assert "file://" not in content
    assert staged_identities(tmp_path / "staged") == {
        ".json": ("tacon", "1.2.3"),
        ".xml": ("tacon", "1.2.3"),
    }
    root = ET.parse(tmp_path / "staged" / "sbom-linux.xml").getroot()
    prop = next(element for element in root.iter() if sbom.local_tag(element.tag) == "property")
    assert prop.text == prop.attrib["value"] == "/workspace/src"


def test_accepts_underscore_library_target_for_hyphen_package(tmp_path):
    # The Bash plugin: package tacacsrs-bash-plugin, cdylib target tacacsrs_bash_plugin.
    write_inputs(tmp_path / "input", name="tacacsrs_bash_plugin", version="0.1.0")
    staged = stage(
        tmp_path, package_name="tacacsrs-bash-plugin", expected_version="0.1.0",
        loader=loader_for("tacacsrs-bash-plugin", "0.1.0", [("tacacsrs_bash_plugin", ["cdylib"])]),
    )
    assert sorted(path.suffix for path in staged) == [".json", ".xml"]
    assert staged_identities(tmp_path / "staged") == {
        ".json": ("tacacsrs_bash_plugin", "0.1.0"),
        ".xml": ("tacacsrs_bash_plugin", "0.1.0"),
    }


def test_accepts_custom_library_target_not_derived_from_package(tmp_path):
    # A lazy hyphen-to-underscore rule would reject this; Cargo metadata is the authority.
    write_inputs(tmp_path / "input", name="totally_custom", version="2.0.0")
    staged = stage(
        tmp_path, package_name="weird-pkg", expected_version="2.0.0",
        loader=loader_for("weird-pkg", "2.0.0", [("totally_custom", ["lib", "cdylib"])]),
    )
    assert sorted(path.suffix for path in staged) == [".json", ".xml"]


def test_rejects_unrelated_root_name(tmp_path):
    write_inputs(tmp_path / "input", name="unrelated", version="1.2.3")
    with pytest.raises(sbom.SbomError, match="expected one json SBOM root component"):
        stage(
            tmp_path, package_name="weird-pkg",
            loader=loader_for("weird-pkg", "1.2.3", [("weird_pkg", ["cdylib"])]),
        )
    assert not (tmp_path / "staged").exists()


def test_rejects_root_version_mismatch(tmp_path):
    # The root name is accepted, but its version is not the package version.
    write_inputs(tmp_path / "input", name="tacon", version="9.9.9")
    with pytest.raises(sbom.SbomError, match="SBOM version does not match"):
        stage(
            tmp_path, package_name="tacon", expected_version=None,
            loader=loader_for("tacon", "1.2.3", [("tacon", ["bin"])]),
        )
    assert not (tmp_path / "staged").exists()


def test_derives_version_from_metadata_when_expected_version_absent(tmp_path):
    write_inputs(tmp_path / "input", name="tacon", version="3.4.5")
    staged = stage(
        tmp_path, package_name="tacon", expected_version=None,
        loader=loader_for("tacon", "3.4.5", [("tacon", ["bin"])]),
    )
    assert sorted(path.suffix for path in staged) == [".json", ".xml"]


def test_rejects_expected_version_not_matching_package(tmp_path):
    write_inputs(tmp_path / "input", name="tacon", version="1.2.3")
    with pytest.raises(sbom.SbomError, match="does not match the tacon package version"):
        stage(
            tmp_path, package_name="tacon", expected_version="9.9.9",
            loader=loader_for("tacon", "1.2.3", [("tacon", ["bin"])]),
        )
    assert not (tmp_path / "staged").exists()


def test_requires_both_json_and_xml(tmp_path):
    write_inputs(tmp_path / "input", name="tacon", version="1.2.3", xml=False)
    with pytest.raises(sbom.SbomError, match="expected one xml SBOM root component"):
        stage(
            tmp_path, package_name="tacon",
            loader=loader_for("tacon", "1.2.3", [("tacon", ["bin"])]),
        )
    assert not (tmp_path / "staged").exists()


def test_rejects_when_json_and_xml_roots_differ(tmp_path):
    # Both roots are accepted targets at the right version, but they disagree.
    write_inputs(tmp_path / "input", name="multi", version="1.2.3", xml_name="multi_lib")
    with pytest.raises(sbom.SbomError, match="JSON and XML SBOM root components do not match"):
        stage(
            tmp_path, package_name="multi",
            loader=loader_for("multi", "1.2.3", [("multi", ["bin"]), ("multi_lib", ["cdylib"])]),
        )
    assert not (tmp_path / "staged").exists()


requires_cargo = pytest.mark.skipif(
    shutil.which("cargo") is None,
    reason="cargo is required for the metadata-backed end-to-end tests",
)


def write_real_package(root, *, package_name, version, lib_name):
    """Write a minimal cdylib package so real ``cargo metadata`` can read it.

    The crate type mirrors the real Bash plugin, whose library target is a
    ``cdylib`` with an ``rlib`` companion.
    """
    root.mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(dedent(f"""\
        [package]
        name = "{package_name}"
        version = "{version}"
        edition = "2021"

        [lib]
        name = "{lib_name}"
        crate-type = ["cdylib", "rlib"]
    """))
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "lib.rs").write_text("// minimal\n")


@requires_cargo
def test_cli_accepts_bash_library_target_with_real_metadata(tmp_path):
    package_root = tmp_path / "input"
    write_real_package(
        package_root, package_name="tacacsrs-bash-plugin",
        version="0.1.0", lib_name="tacacsrs_bash_plugin",
    )
    write_inputs(package_root, name="tacacsrs_bash_plugin", version="0.1.0")
    code = sbom.main([
        "--package-root", str(package_root),
        "--package-dir", str(tmp_path / "staged"),
        "--basename", "sbom-linux",
        "--package-name", "tacacsrs-bash-plugin",
        "--workspace", "/private/export",
        "--repository", REPOSITORY,
    ])
    assert code == 0
    assert staged_identities(tmp_path / "staged") == {
        ".json": ("tacacsrs_bash_plugin", "0.1.0"),
        ".xml": ("tacacsrs_bash_plugin", "0.1.0"),
    }


@requires_cargo
def test_cli_rejects_unrelated_root_with_real_metadata(tmp_path):
    package_root = tmp_path / "input"
    write_real_package(
        package_root, package_name="tacacsrs-bash-plugin",
        version="0.1.0", lib_name="tacacsrs_bash_plugin",
    )
    write_inputs(package_root, name="not-a-real-target", version="0.1.0")
    code = sbom.main([
        "--package-root", str(package_root),
        "--package-dir", str(tmp_path / "staged"),
        "--basename", "sbom-linux",
        "--package-name", "tacacsrs-bash-plugin",
        "--workspace", "/private/export",
        "--repository", REPOSITORY,
    ])
    assert code == 1
    assert not (tmp_path / "staged").exists()