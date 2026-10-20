"""Tests for release version hydration."""

from __future__ import annotations

import textwrap
import tomllib
from pathlib import Path

import pytest

from hydrate_versions import HydrationError, hydrate, manifest_packages


def write_workspace(workspace: Path) -> None:
    """Create a small real Cargo workspace fixture."""
    (workspace / "Cargo.toml").write_text(
        textwrap.dedent(
            """\
            [workspace]
            resolver = "2"
            members = ["crates/demo"]
            """
        ),
        encoding="utf-8",
    )
    crate = workspace / "crates" / "demo"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        textwrap.dedent(
            """\
            [package]
            name = "demo"
            version = "0.0.0-dev"
            edition = "2021"
            """
        ),
        encoding="utf-8",
    )
    src = crate / "src"
    src.mkdir()
    (src / "lib.rs").write_text("// demo\n", encoding="utf-8")
    (workspace / "Cargo.lock").write_text(
        textwrap.dedent(
            """\
            version = 4

            [[package]]
            name = "demo"
            version = "0.0.0-dev"

            [[package]]
            name = "demo"
            version = "9.9.9"
            source = "registry+https://github.com/rust-lang/crates.io-index"

            [[package]]
            name = "third-party"
            version = "1.2.3"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "abc"
            """
        ),
        encoding="utf-8",
    )


def test_hydrates_manifest_and_workspace_lock_entry(tmp_path: Path) -> None:
    write_workspace(tmp_path)

    hydrate(tmp_path, {"demo": "2026.817.1"})

    manifest = (tmp_path / "crates" / "demo" / "Cargo.toml").read_text()
    lock = (tmp_path / "Cargo.lock").read_text()
    assert 'version = "2026.817.1"' in manifest
    assert lock.count('version = "2026.817.1"') == 1
    assert 'version = "9.9.9"' in lock
    assert 'version = "1.2.3"' in lock


def test_rejects_unknown_package(tmp_path: Path) -> None:
    write_workspace(tmp_path)

    with pytest.raises(HydrationError, match="no Cargo.toml exists"):
        hydrate(tmp_path, {"missing": "1.0.0"})


def test_rejects_missing_workspace_lock_entry(tmp_path: Path) -> None:
    write_workspace(tmp_path)
    lock = (tmp_path / "Cargo.lock").read_text()
    (tmp_path / "Cargo.lock").write_text(
        lock.replace(
            'name = "demo"\nversion = "0.0.0-dev"\n\n',
            "",
            1,
        )
    )

    with pytest.raises(HydrationError, match="no source-free package entry"):
        hydrate(tmp_path, {"demo": "1.0.0"})


def test_rejects_duplicate_source_free_lock_entries(tmp_path: Path) -> None:
    write_workspace(tmp_path)
    lock_path = tmp_path / "Cargo.lock"
    lock = lock_path.read_text()
    lock_path.write_text(
        lock
        + textwrap.dedent(
            """\

            [[package]]
            name = "demo"
            version = "8.8.8"
            """
        )
    )

    with pytest.raises(HydrationError, match="more than one source-free entry"):
        hydrate(tmp_path, {"demo": "1.0.0"})


def test_empty_map_does_not_require_lockfile(tmp_path: Path) -> None:
    hydrate(tmp_path, {})


def test_excludes_non_member_manifests(tmp_path: Path) -> None:
    """Only workspace members are hydration targets. Non-members are excluded."""
    write_workspace(tmp_path)

    # An excluded fuzz crate must never become a hydration target.
    fuzz = tmp_path / "fuzz"
    (fuzz / "src").mkdir(parents=True)
    (fuzz / "Cargo.toml").write_text(
        textwrap.dedent(
            """\
            [package]
            name = "demo-fuzz"
            version = "0.0.0"
            edition = "2021"

            [[bin]]
            name = "demo-fuzz"
            path = "src/main.rs"
            """
        ),
        encoding="utf-8",
    )
    (fuzz / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    root = tmp_path / "Cargo.toml"
    root.write_text(root.read_text() + 'exclude = ["fuzz"]\n', encoding="utf-8")

    # A nested manifest under the build directory must never appear.
    build_manifest = tmp_path / "target" / "nested" / "Cargo.toml"
    build_manifest.parent.mkdir(parents=True)
    build_manifest.write_text(
        '[package]\nname = "ignored"\nversion = "0.0.0"\n', encoding="utf-8"
    )

    packages = manifest_packages(tmp_path)
    assert set(packages) == {"demo"}

    with pytest.raises(HydrationError, match="no Cargo.toml exists"):
        hydrate(tmp_path, {"demo-fuzz": "1.0.0"})


@pytest.mark.parametrize("manifest", [
    '[ "package" ] # table comment\nname="demo"\nversion="0.0.0-dev" # keep\nedition="2021"\n',
    "package.name='demo'\npackage.version='0.0.0-dev'\npackage.edition='2021'\n",
    "package = { name = 'demo', version = '0.0.0-dev', edition = '2021' }\n",
])
def test_hydrates_cargo_valid_alternate_formatting(tmp_path: Path, manifest: str) -> None:
    write_workspace(tmp_path)
    path = tmp_path / "crates/demo/Cargo.toml"
    path.write_text(manifest)

    assert set(manifest_packages(tmp_path)) == {"demo"}
    hydrate(tmp_path, {"demo": "1.2.3"})
    first = path.read_bytes()
    assert tomllib.loads(first.decode())["package"]["version"] == "1.2.3"
    hydrate(tmp_path, {"demo": "1.2.3"})
    assert path.read_bytes() == first
