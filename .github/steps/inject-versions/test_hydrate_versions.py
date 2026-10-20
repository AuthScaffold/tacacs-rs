"""Tests for release version hydration."""

from __future__ import annotations

import json
import os
import subprocess
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


@pytest.mark.parametrize("kind", ["registry", "git"])
@pytest.mark.parametrize("old_version,new_version,spelling", [
    ("0.0.0-dev", "1.2.3", "minimal"),
    ("0.0.0-dev", "9.9.9", "minimal"),
    ("9.9.9", "1.2.3", "minimal"),
    ("9.9.9", "9.9.9", "minimal"),
    ("0.0.0-dev", "9.9.9", "explicit"),
    ("9.9.9", "1.2.3", "explicit"),
])
def test_cargo_resolves_local_and_external_dependencies_after_hydration(
    tmp_path: Path, kind: str, old_version: str, new_version: str, spelling: str
) -> None:
    write_workspace(tmp_path)
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nresolver="2"\nmembers=["crates/demo", "crates/consumer"]\n'
    )
    manifest = tmp_path / "crates/demo/Cargo.toml"
    manifest.write_text(manifest.read_text().replace("0.0.0-dev", old_version))
    external = tmp_path / ("vendor/demo" if kind == "registry" else "git/demo")
    (external / "src").mkdir(parents=True)
    (external / "src/lib.rs").write_text("")
    (external / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="9.9.9"\nedition="2021"\n'
    )
    if kind == "registry":
        (external / ".cargo-checksum.json").write_text('{"files":{},"package":null}')
        remote = 'remote={package="demo",version="=9.9.9"}\n'
        remote_source = "registry+https://github.com/rust-lang/crates.io-index"
    else:
        for command in (
            ["init", "-q"],
            ["add", "."],
            ["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture"],
        ):
            subprocess.run(["git", *command], cwd=external, check=True, capture_output=True)
        remote = f'remote={{package="demo",git="{external.as_uri()}"}}\n'
        remote_source = f"git+{external.as_uri()}#"
    consumer = tmp_path / "crates/consumer"
    (consumer / "src").mkdir(parents=True)
    (consumer / "src/lib.rs").write_text("")
    (consumer / "Cargo.toml").write_text(
        '[package]\nname="consumer"\nversion="1.0.0"\nedition="2021"\n'
        '[dependencies]\nlocal={package="demo",path="../demo"}\n' + remote
    )
    (tmp_path / "vendor").mkdir(exist_ok=True)
    (tmp_path / ".cargo").mkdir()
    (tmp_path / ".cargo/config.toml").write_text(
        '[source.crates-io]\nreplace-with="fixture"\n'
        '[source.fixture]\ndirectory="vendor"\n'
    )
    # The private Cargo home keeps the local Git checkout out of shared state.
    cargo = {
        "cwd": tmp_path, "check": True, "capture_output": True, "text": True,
        "env": {**os.environ, "CARGO_HOME": str(tmp_path / "cargo-home")},
    }
    offline = ["--offline"] if kind == "registry" else []
    subprocess.run(["cargo", "generate-lockfile", *offline], **cargo)
    if spelling == "explicit":
        lock_path = tmp_path / "Cargo.lock"
        text = lock_path.read_text()
        source = next(
            package["source"] for package in tomllib.loads(text)["package"]
            if package.get("source") is not None
        )
        reference = "demo 9.9.9"
        if old_version == "9.9.9":
            text = text.replace(' "demo 9.9.9",', ' "demo",')
            reference += f" ({source.split('#', 1)[0]})"
        text = text.replace(f' "{reference}",', f' "demo 9.9.9 ({source})",')
        lock_path.write_text(text)
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"],
            **cargo,
        )

    hydrate(tmp_path, {"demo": new_version})
    lock = (tmp_path / "Cargo.lock").read_bytes()
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"], **cargo
    )
    metadata = json.loads(result.stdout)
    packages = {package["id"]: package for package in metadata["packages"]}
    consumer_id = next(key for key, package in packages.items() if package["name"] == "consumer")
    node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == consumer_id)
    dependencies = {dependency["name"]: packages[dependency["pkg"]] for dependency in node["deps"]}
    assert dependencies["local"]["version"] == new_version
    assert dependencies["local"]["source"] is None
    assert dependencies["remote"]["version"] == "9.9.9"
    assert dependencies["remote"]["source"].startswith(remote_source)
    # Without --locked, Cargo rewrites any lockfile that differs from its own output.
    subprocess.run(["cargo", "metadata", "--format-version", "1", "--offline"], **cargo)
    assert (tmp_path / "Cargo.lock").read_bytes() == lock
    hydrate(tmp_path, {"demo": new_version})
    assert (tmp_path / "Cargo.lock").read_bytes() == lock


def test_cargo_accepts_explicit_version_for_a_unique_local_dependency(tmp_path: Path) -> None:
    write_workspace(tmp_path)
    root = tmp_path / "Cargo.toml"
    root.write_text(
        root.read_text()
        + '[package]\nname="consumer"\nversion="1.0.0"\nedition="2021"\n'
        + '[dependencies]\ndemo={path="crates/demo"}\n'
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src/lib.rs").write_text("")
    cargo = {"cwd": tmp_path, "check": True, "capture_output": True, "text": True}
    subprocess.run(["cargo", "generate-lockfile", "--offline"], **cargo)
    path = tmp_path / "Cargo.lock"
    path.write_text(path.read_text().replace(' "demo",', ' "demo 0.0.0-dev",'))
    subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"], **cargo
    )

    hydrate(tmp_path, {"demo": "1.2.3"})
    result = path.read_bytes()
    subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"], **cargo
    )
    subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--offline"], **cargo
    )
    assert path.read_bytes() == result
    hydrate(tmp_path, {"demo": "1.2.3"})
    assert path.read_bytes() == result
