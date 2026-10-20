"""Semantic goldens and unaffected-content checks for structured version edits."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from hydrate_versions import (
    HydrationError,
    replace_lock_versions,
    replace_manifest_version,
)


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


def expected_edit(text: str) -> str:
    """Allow a new quote style only for the edited version literal."""
    for literal in ('"""0.0.0-dev"""', "'0.0.0-dev'", '"0.0.0-dev"'):
        if literal in text:
            return text.replace(literal, '"1.2.3"', 1)
    raise AssertionError("fixture has no version literal")


def edit_manifest(path: Path, text: str) -> str:
    path.write_bytes(text.encode())
    replace_manifest_version(path, "demo", "1.2.3")
    return path.read_bytes().decode()


def edit_lock(path: Path, text: str) -> str:
    path.write_bytes(text.encode())
    assert replace_lock_versions(path, {"demo": "1.2.3"}) == {"demo"}
    return path.read_bytes().decode()


def test_predecessor_output_goldens(tmp_path: Path) -> None:
    """The prototype compared these goldens against the predecessor functions."""
    for original, result in (
        (MANIFEST, edit_manifest(tmp_path / "Cargo.toml", MANIFEST)),
        (LOCK, edit_lock(tmp_path / "Cargo.lock", LOCK)),
    ):
        expected = expected_edit(original)
        assert tomllib.loads(result) == tomllib.loads(expected)
        assert result == expected


@pytest.mark.parametrize("text", [
    MANIFEST.replace('[package]', '[ "package" ] # table comment')
    .replace('version = "0.0.0-dev"', "  'version' = '0.0.0-dev' # version comment", 1),
    "# dotted keys\npackage.name='demo'\npackage.version='0.0.0-dev'\n",
    "# inline table\npackage = { name = 'demo', version = '0.0.0-dev' } # keep\n",
    MANIFEST.replace('version = "0.0.0-dev"', 'version = """0.0.0-dev""" # multiline', 1),
    MANIFEST.replace("\n", "\r\n"),
])
def test_manifest_alternate_toml_and_idempotence(tmp_path: Path, text: str) -> None:
    path = tmp_path / "Cargo.toml"
    result = edit_manifest(path, text)
    expected = tomllib.loads(text)
    expected["package"]["version"] = "1.2.3"
    assert tomllib.loads(result) == expected
    assert result == expected_edit(text)
    replace_manifest_version(path, "demo", "1.2.3")
    assert path.read_bytes().decode() == result


@pytest.mark.parametrize("text", [
    LOCK,
    LOCK.replace("[[package]]", '[[ "package" ]] # table comment')
    .replace('version = "0.0.0-dev"', "'version'='0.0.0-dev' # keep version comment", 1),
    LOCK.replace("\n", "\r\n"),
    LOCK.replace('dependencies = ["remote"]', 'dependencies = [\n  "remote", # retain\n]'),
    LOCK.replace('dependencies = ["remote"]', '[package.metadata]\nsource = "not a package source"\nkeep = true'),
])
def test_lock_source_identity_and_idempotence(tmp_path: Path, text: str) -> None:
    path = tmp_path / "Cargo.lock"
    result = edit_lock(path, text)
    expected = tomllib.loads(text)
    expected["package"][0]["version"] = "1.2.3"
    assert tomllib.loads(result) == expected
    assert result == expected_edit(text)
    replace_lock_versions(path, {"demo": "1.2.3"})
    assert path.read_bytes().decode() == result


def test_lock_dependencies_keep_their_package_identity(tmp_path: Path) -> None:
    text = LOCK + (
        '\n[[package]]\nname = "demo"\nversion = "0.0.0-dev"\n'
        'source = "git+https://example.invalid/demo#abc"\n'
        '\n[[package]]\nname = "consumer"\nversion = "1.0.0"\n'
        'dependencies = [\n'
        '  "demo 0.0.0-dev", # workspace reference\n'
        '  "demo 9.9.9 (registry+https://github.com/rust-lang/crates.io-index)",\n'
        '  "demo 0.0.0-dev (git+https://example.invalid/demo#abc)",\n'
        '  "remote",\n'
        ']'
    )
    result = edit_lock(tmp_path / "Cargo.lock", text)
    expected = expected_edit(text).replace('"demo 0.0.0-dev"', '"demo 1.2.3"')
    assert tomllib.loads(result) == tomllib.loads(expected)
    assert result == expected
    assert edit_lock(tmp_path / "Cargo.lock", result) == result


@pytest.mark.parametrize("text", [
    '[[package]]\nname="demo"\nversion="0.0.0-dev"\nversion="2.0.0"\n',
    '[[package]\n',
])
def test_invalid_toml_is_a_hydration_error(tmp_path: Path, text: str) -> None:
    path = tmp_path / "Cargo.lock"
    path.write_text(text)
    with pytest.raises(HydrationError, match="invalid TOML"):
        replace_lock_versions(path, {"demo": "1.2.3"})
    assert path.read_text() == text
