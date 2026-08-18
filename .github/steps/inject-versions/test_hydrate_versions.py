"""Tests for release version hydration."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from hydrate_versions import HydrationError, hydrate


def write_workspace(workspace: Path) -> None:
    """Create a small Cargo workspace fixture."""
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
