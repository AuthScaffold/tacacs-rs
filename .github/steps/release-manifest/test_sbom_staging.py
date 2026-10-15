"""Test the shared SBOM helper without Cargo or shell commands."""

import importlib.util
import json
import xml.etree.ElementTree as ET
from pathlib import Path
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


def write_inputs(root, *, name="tacon", xml=True):
    root.mkdir()
    component = {"name": name, "version": "1.2.3"}
    (root / "product.cdx.json").write_text(json.dumps({
        "metadata": {"component": component},
        "path": "/private/export/src",
        "url": "file:///private/export",
    }))
    if xml:
        (root / "product.cdx.xml").write_text(
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><metadata><component>'
            f'<name>{name or ""}</name><version>1.2.3</version></component></metadata>'
            '<property value="/private/export/src">/private/export/src</property>'
            '<url>pkg:cargo/tacon@1.2.3?download_url=file:///private/export&amp;other=keep</url></bom>'
        )


def arguments(tmp_path):
    return [
        "--package-root", str(tmp_path / "input"), "--package-dir", str(tmp_path / "staged"),
        "--basename", "sbom-linux", "--package-name", "tacon",
        "--workspace", "/private/export", "--repository", REPOSITORY,
        "--expected-version", "1.2.3",
    ]


def test_cli_stages_both_structured_formats_with_same_policy(tmp_path):
    write_inputs(tmp_path / "input")
    assert sbom.main(arguments(tmp_path)) == 0
    outputs = sorted((tmp_path / "staged").iterdir())
    assert [path.suffix for path in outputs] == [".json", ".xml"]
    for path in outputs:
        content = path.read_text()
        assert "/private/export" not in content
        assert "file://" not in content
        parsed = json.loads(content) if path.suffix == ".json" else ET.fromstring(content)
        assert sbom.component_identity(parsed, path.suffix[1:]) == ("tacon", "1.2.3")
    root = ET.parse(outputs[1]).getroot()
    prop = next(element for element in root.iter() if sbom.local_tag(element.tag) == "property")
    assert prop.text == prop.attrib["value"] == "/workspace/src"


@pytest.mark.parametrize("name,xml", [(None, True), ("other", True), ("tacon", False)])
def test_cli_rejects_missing_name_wrong_name_and_missing_xml(tmp_path, name, xml):
    write_inputs(tmp_path / "input", name=name, xml=xml)
    assert sbom.main(arguments(tmp_path)) == 1
    assert not (tmp_path / "staged").exists()


def test_cli_rejects_version_mismatch(tmp_path):
    write_inputs(tmp_path / "input")
    args = arguments(tmp_path)
    args[-1] = "9.9.9"
    assert sbom.main(args) == 1
    assert not (tmp_path / "staged").exists()