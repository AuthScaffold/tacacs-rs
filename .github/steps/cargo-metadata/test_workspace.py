"""Tests for the Cargo-derived workspace inventory.

The ``inventory`` tests use synthetic ``cargo metadata`` objects, so they do not
run Cargo. The ``load_metadata`` tests build a real minimal Cargo workspace and
run Cargo through the helper.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from workspace import MetadataError, inventory, load_metadata


# ---------------------------------------------------------------------------
# Synthetic cargo metadata builders
# ---------------------------------------------------------------------------

def _dep(
    name: str,
    *,
    path: str | None = None,
    kind: str | None = None,
    target: str | None = None,
    rename: str | None = None,
    optional: bool = False,
    source: str | None = None,
) -> dict:
    return {
        "name": name,
        "source": source,
        "req": "*",
        "kind": kind,
        "rename": rename,
        "optional": optional,
        "uses_default_features": True,
        "features": [],
        "target": target,
        "path": path,
        "registry": None,
    }


def _pkg(
    name: str,
    version: str,
    directory: str,
    *,
    kinds: list[str] | None = None,
    deps: list[dict] | None = None,
    root: str = "/ws",
    package_id: str | None = None,
) -> dict:
    manifest_path = (
        f"{root}/Cargo.toml" if directory == "." else f"{root}/{directory}/Cargo.toml"
    )
    if package_id is None:
        package_id = f"path+file://{root}/{directory}#{name}@{version}"
    target_kinds = kinds if kinds is not None else ["lib"]
    return {
        "id": package_id,
        "name": name,
        "version": version,
        "manifest_path": manifest_path,
        "source": None,
        "dependencies": deps or [],
        "targets": [
            {
                "kind": target_kinds,
                "crate_types": target_kinds,
                "name": name,
                "src_path": f"{root}/{directory}/src/lib.rs",
            }
        ],
    }


def _metadata(
    packages: list[dict],
    members: list[str],
    *,
    default_members: list[str] | None = None,
    root: str = "/ws",
) -> dict:
    return {
        "packages": packages,
        "workspace_members": members,
        "workspace_default_members": (
            default_members if default_members is not None else list(members)
        ),
        "workspace_root": root,
        "resolve": None,
        "target_directory": f"{root}/target",
        "version": 1,
        "metadata": None,
    }


# ---------------------------------------------------------------------------
# Inventory field extraction
# ---------------------------------------------------------------------------

class TestInventory:
    def test_members_only(self) -> None:
        """Only workspace members appear, even when metadata lists more packages."""
        member = _pkg("member-lib", "0.1.0", "libraries/member")
        external = _pkg("anyhow", "1.0.0", "vendor/anyhow", package_id="registry+anyhow")
        metadata = _metadata([member, external], [member["id"]])

        inv = inventory(metadata)

        names = [package["name"] for package in inv["packages"]]
        assert names == ["member-lib"]

    def test_relative_paths_from_workspace_root(self) -> None:
        member = _pkg("member-lib", "0.1.0", "libraries/member")
        inv = inventory(_metadata([member], [member["id"]]))

        package = inv["packages"][0]
        assert package["manifest_path"] == "libraries/member/Cargo.toml"
        assert package["directory"] == "libraries/member"
        assert inv["workspace_root"] == "/ws"

    def test_root_package_directory_is_dot(self) -> None:
        """A workspace member at the root resolves to directory '.'."""
        member = _pkg("root-crate", "0.1.0", ".")
        inv = inventory(_metadata([member], [member["id"]]))

        package = inv["packages"][0]
        assert package["manifest_path"] == "Cargo.toml"
        assert package["directory"] == "."

    def test_dual_library_target_kinds_are_sorted(self) -> None:
        member = _pkg(
            "bash-plugin", "0.1.0", "libraries/bash_plugin",
            kinds=["cdylib", "rlib"],
        )
        inv = inventory(_metadata([member], [member["id"]]))

        assert inv["packages"][0]["target_kinds"] == ["cdylib", "rlib"]

    def test_binary_target_kind(self) -> None:
        member = _pkg("tacon", "0.1.0", "executables/tacon", kinds=["bin"])
        inv = inventory(_metadata([member], [member["id"]]))

        assert inv["packages"][0]["target_kinds"] == ["bin"]

    def test_default_member_flag(self) -> None:
        core = _pkg("core-lib", "0.1.0", "libraries/core")
        extra = _pkg("extra-lib", "0.1.0", "libraries/extra")
        metadata = _metadata(
            [core, extra],
            [core["id"], extra["id"]],
            default_members=[core["id"]],
        )

        inv = inventory(metadata)
        by_name = {package["name"]: package for package in inv["packages"]}
        assert by_name["core-lib"]["default_member"] is True
        assert by_name["extra-lib"]["default_member"] is False

    def test_absent_default_members_marks_all(self) -> None:
        """When Cargo omits default members, every member is a default member."""
        member = _pkg("member-lib", "0.1.0", "libraries/member")
        metadata = _metadata([member], [member["id"]])
        del metadata["workspace_default_members"]

        inv = inventory(metadata)
        assert inv["packages"][0]["default_member"] is True

    def test_dependency_identity_via_path(self) -> None:
        base = _pkg("base-lib", "0.1.0", "libraries/base")
        top = _pkg(
            "top-lib", "0.1.0", "libraries/top",
            deps=[_dep("base-lib", path="/ws/libraries/base")],
        )
        inv = inventory(_metadata([base, top], [base["id"], top["id"]]))

        top_entry = next(p for p in inv["packages"] if p["name"] == "top-lib")
        dependency = top_entry["dependencies"][0]
        assert dependency["name"] == "base-lib"
        assert dependency["workspace_member"] == "base-lib"
        assert dependency["kind"] is None

    def test_renamed_dependency_resolves_real_identity(self) -> None:
        """A renamed edge maps to its real member, not the local alias."""
        base = _pkg("base-lib", "0.1.0", "libraries/base")
        top = _pkg(
            "top-lib", "0.1.0", "libraries/top",
            deps=[_dep("base-lib", path="/ws/libraries/base", rename="aliased")],
        )
        inv = inventory(_metadata([base, top], [base["id"], top["id"]]))

        top_entry = next(p for p in inv["packages"] if p["name"] == "top-lib")
        dependency = top_entry["dependencies"][0]
        assert dependency["name"] == "base-lib"
        assert dependency["rename"] == "aliased"
        assert dependency["workspace_member"] == "base-lib"

    def test_non_member_path_dependency_has_no_member(self) -> None:
        base = _pkg("base-lib", "0.1.0", "libraries/base")
        top = _pkg(
            "top-lib", "0.1.0", "libraries/top",
            deps=[_dep("vendored", path="/ws/vendor/vendored")],
        )
        inv = inventory(_metadata([base, top], [base["id"], top["id"]]))

        top_entry = next(p for p in inv["packages"] if p["name"] == "top-lib")
        dependency = top_entry["dependencies"][0]
        assert dependency["workspace_member"] is None

    def test_registry_dependency_has_no_member(self) -> None:
        member = _pkg(
            "member-lib", "0.1.0", "libraries/member",
            deps=[_dep("anyhow", source="registry+https://example/index")],
        )
        inv = inventory(_metadata([member], [member["id"]]))

        dependency = inv["packages"][0]["dependencies"][0]
        assert dependency["workspace_member"] is None
        assert dependency["source"] == "registry+https://example/index"

    def test_preserves_kind_target_and_optional(self) -> None:
        base = _pkg("base-lib", "0.1.0", "libraries/base")
        top = _pkg(
            "top-lib", "0.1.0", "libraries/top",
            deps=[
                _dep("base-lib", path="/ws/libraries/base", kind="build"),
                _dep(
                    "base-lib", path="/ws/libraries/base",
                    target="cfg(unix)", optional=True,
                ),
                _dep("base-lib", path="/ws/libraries/base", kind="dev"),
            ],
        )
        inv = inventory(_metadata([base, top], [base["id"], top["id"]]))

        top_entry = next(p for p in inv["packages"] if p["name"] == "top-lib")
        kinds = [d["kind"] for d in top_entry["dependencies"]]
        # Sorted by (name, kind, ...) with a normal kind of None sorting as "".
        assert kinds == [None, "build", "dev"]
        normal = next(
            d for d in top_entry["dependencies"]
            if d["kind"] is None
        )
        assert normal["target"] == "cfg(unix)"
        assert normal["optional"] is True

    def test_packages_sorted_by_name(self) -> None:
        zeta = _pkg("zeta", "0.1.0", "libraries/zeta")
        alpha = _pkg("alpha", "0.1.0", "libraries/alpha")
        inv = inventory(_metadata([zeta, alpha], [zeta["id"], alpha["id"]]))

        assert [p["name"] for p in inv["packages"]] == ["alpha", "zeta"]


# ---------------------------------------------------------------------------
# Inventory error handling
# ---------------------------------------------------------------------------

class TestInventoryErrors:
    def test_missing_fields(self) -> None:
        with pytest.raises(MetadataError, match="required field"):
            inventory({})

    def test_member_absent_from_packages(self) -> None:
        member = _pkg("member-lib", "0.1.0", "libraries/member")
        metadata = _metadata([member], [member["id"], "path+file:///ws/ghost#ghost@0.1.0"])

        with pytest.raises(MetadataError, match="absent from the package list"):
            inventory(metadata)


# ---------------------------------------------------------------------------
# Real workspace integration
# ---------------------------------------------------------------------------

def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(text), encoding="utf-8")


def _minimal_workspace(root: Path) -> None:
    """Create a real minimal Cargo workspace with an inherited path edge."""
    _write(
        root / "Cargo.toml",
        """\
        [workspace]
        resolver = "2"
        members = ["libraries/base", "libraries/top"]

        [workspace.dependencies]
        base = { path = "libraries/base" }
        """,
    )
    _write(
        root / "libraries" / "base" / "Cargo.toml",
        """\
        [package]
        name = "base"
        version = "0.0.0-dev"
        edition = "2021"
        """,
    )
    _write(root / "libraries" / "base" / "src" / "lib.rs", "// base\n")
    _write(
        root / "libraries" / "top" / "Cargo.toml",
        """\
        [package]
        name = "top"
        version = "0.0.0-dev"
        edition = "2021"

        [dependencies]
        base = { workspace = true }
        """,
    )
    _write(root / "libraries" / "top" / "src" / "lib.rs", "// top\n")


class TestLoadMetadataReal:
    def test_inventory_from_real_workspace(self, tmp_path: Path) -> None:
        _minimal_workspace(tmp_path)

        inv = inventory(load_metadata(tmp_path, no_deps=True, locked=False))

        names = {package["name"] for package in inv["packages"]}
        assert names == {"base", "top"}

        top = next(package for package in inv["packages"] if package["name"] == "top")
        assert top["manifest_path"] == "libraries/top/Cargo.toml"
        dependency = next(d for d in top["dependencies"] if d["name"] == "base")
        # The inherited `base = { workspace = true }` edge resolves by path.
        assert dependency["workspace_member"] == "base"

    def test_rejects_non_workspace_directory(self, tmp_path: Path) -> None:
        with pytest.raises(MetadataError):
            load_metadata(tmp_path, no_deps=True)
