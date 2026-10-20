"""Compare TOML Kit edits with release hydration and independent goldens."""

from __future__ import annotations

import tomllib
import importlib.util
from pathlib import Path

import pytest

import predecessor as BASELINE
from candidate import lock_text, manifest_text


MANIFEST = """# manifest header
[package]
name = "demo"
version = "0.0.0-dev"
edition = "2021"

[dependencies.remote]
package = "demo"
version = "9.9.9"

[package.metadata.custom]
keep = { version = "0.0.0-dev", source = "operator data" } # keep this
"""

LOCK = """# lock header
version = 4

[[package]]
name = "demo"
version = "0.0.0-dev"
dependencies = ["remote"]

[[package]]
name = "demo"
version = "9.9.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "remote"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""


def expected_edit(text):
    for literal in ('"""0.0.0-dev"""', "'0.0.0-dev'", '"0.0.0-dev"'):
        if literal in text:
            return text.replace(literal, '"1.2.3"', 1)
    raise AssertionError("fixture has no version literal")


def test_existing_outputs_match_semantic_and_unaffected_goldens(tmp_path):
    manifest = tmp_path / "Cargo.toml"
    lock = tmp_path / "Cargo.lock"
    manifest.write_text(MANIFEST)
    lock.write_text(LOCK)
    BASELINE.replace_manifest_version(manifest, "demo", "1.2.3")
    BASELINE.replace_lock_versions(lock, {"demo": "1.2.3"})
    for original, baseline, result in (
        (MANIFEST, manifest.read_text(), manifest_text(MANIFEST, "1.2.3")),
        (LOCK, lock.read_text(), lock_text(LOCK, {"demo": "1.2.3"})[0]),
    ):
        expected = original.replace('version = "0.0.0-dev"', 'version = "1.2.3"', 1)
        assert tomllib.loads(result) == tomllib.loads(baseline) == tomllib.loads(expected)
        assert result == expected
        assert baseline == expected


@pytest.mark.parametrize("text", [
    MANIFEST.replace('[package]', '[ "package" ] # table comment')
    .replace('version = "0.0.0-dev"', "  'version' = '0.0.0-dev' # version comment", 1),
    "# dotted keys\npackage.name='demo'\npackage.version='0.0.0-dev'\n",
    "# inline table\npackage = { name = 'demo', version = '0.0.0-dev' } # keep\n",
    MANIFEST.replace('version = "0.0.0-dev"', 'version = """0.0.0-dev""" # multiline', 1),
    MANIFEST.replace("\n", "\r\n"),
])
def test_manifest_alternate_toml_preserves_unaffected_content_and_idempotence(text):
    result = manifest_text(text, "1.2.3")
    expected = tomllib.loads(text)
    expected["package"]["version"] = "1.2.3"
    assert tomllib.loads(result) == expected
    assert manifest_text(result, "1.2.3") == result
    assert result == expected_edit(text)


@pytest.mark.parametrize("text", [
    LOCK,
    LOCK.replace("[[package]]", '[[ "package" ]] # table comment')
    .replace('version = "0.0.0-dev"', "'version'='0.0.0-dev' # keep version comment", 1),
    LOCK.replace("\n", "\r\n"),
])
def test_lock_source_identity_comments_and_idempotence(text):
    result, hydrated = lock_text(text, {"demo": "1.2.3"})
    expected = tomllib.loads(text)
    expected["package"][0]["version"] = "1.2.3"
    assert hydrated == {"demo"}
    assert tomllib.loads(result) == expected
    assert lock_text(result, {"demo": "1.2.3"})[0] == result
    assert result == expected_edit(text)


def test_lock_dependencies_keep_their_package_identity():
    text = LOCK.replace(
        'dependencies = ["remote"]',
        'dependencies = ["demo 0.0.0-dev", "demo 9.9.9 (registry+https://github.com/rust-lang/crates.io-index)", "remote"]',
    )
    result, _ = lock_text(text, {"demo": "1.2.3"})
    expected = text.replace('version = "0.0.0-dev"', 'version = "1.2.3"', 1)
    expected = expected.replace('"demo 0.0.0-dev"', '"demo 1.2.3"')
    assert tomllib.loads(result) == tomllib.loads(expected)
    assert result == expected
    assert lock_text(result, {"demo": "1.2.3"})[0] == result


def test_duplicate_source_free_entry_is_an_error():
    with pytest.raises(ValueError, match="more than one source-free"):
        lock_text(LOCK + '\n[[package]]\nname="demo"\nversion="2.0.0"\n', {"demo": "1.2.3"})


def test_real_workspace_outputs_match_the_predecessor(tmp_path):
    root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location(
        "hydrator", root / ".github/steps/inject-versions/hydrate_versions.py"
    )
    hydrator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hydrator)
    packages = hydrator.manifest_packages(root)
    assert len(packages) == 17
    versions = {name: "1.2.3" for name in packages}
    for name, manifest in packages.items():
        original = manifest.read_text()
        baseline = tmp_path / f"{name}.toml"
        baseline.write_text(original)
        BASELINE.replace_manifest_version(baseline, name, versions[name])
        result = manifest_text(original, versions[name])
        assert tomllib.loads(result) == tomllib.loads(baseline.read_text())
        assert result == baseline.read_text()
    original = (root / "Cargo.lock").read_text()
    baseline = tmp_path / "Cargo.lock"
    baseline.write_text(original)
    assert BASELINE.replace_lock_versions(baseline, versions) == set(packages)
    result, hydrated = lock_text(original, versions)
    assert hydrated == set(packages)
    assert tomllib.loads(result) == tomllib.loads(baseline.read_text())
    assert result == baseline.read_text()
