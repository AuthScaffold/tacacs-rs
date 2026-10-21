"""Run tests for compute_versions.py.

These tests use a temporary Git repository and a simulated workspace. They run
version computations without changes to the real repository.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

# Import the sibling module.
from api_analysis import ApiAnalysisError, ApiBump
from compute_versions import (
    Crate,
    GitError,
    VersionResult,
    bump_breaking,
    bump_minor,
    bump_patch,
    commit_count_since,
    compute_all_versions,
    compute_calver,
    compute_library_versions,
    compute_prerelease_calver,
    compute_prerelease_library_versions,
    discover_libraries,
    git,
    has_changes_since,
    parse_semver,
    source_ref_for_tag,
    topological_sort,
    write_github_output,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_workspace(tmp_path: Path) -> Path:
    """Create a minimal Git repository and workspace."""
    ws = tmp_path / "workspace"
    ws.mkdir()

    # Initialize the Git repository.
    subprocess.run(["git", "init"], cwd=ws, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=ws, check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=ws, check=True, capture_output=True,
    )

    return ws


def _put(path: Path, text: str) -> None:
    """Write a dedented file and its parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


def _workspace_member_dirs(ws: Path) -> list[str]:
    """Return every member directory that currently holds a manifest."""
    members: list[str] = []
    for base in ("libraries", "executables"):
        base_dir = ws / base
        if base_dir.is_dir():
            for sub in sorted(base_dir.iterdir()):
                if (sub / "Cargo.toml").is_file():
                    members.append(f"{base}/{sub.name}")
    return members


def write_workspace_manifest(ws: Path) -> None:
    """Write the virtual workspace manifest for the current member set."""
    lines = ["[workspace]", 'resolver = "2"', "members = ["]
    lines += [f'    "{member}",' for member in _workspace_member_dirs(ws)]
    lines.append("]")
    (ws / "Cargo.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_library(
    ws: Path,
    name: str,
    dir_name: str,
    deps: dict[str, str] | None = None,
) -> Path:
    """Create a real library crate and refresh the workspace manifest."""
    lib_dir = ws / "libraries" / dir_name
    lib_dir.mkdir(parents=True, exist_ok=True)

    cargo_toml = lib_dir / "Cargo.toml"
    lines = [
        "[package]",
        f'name = "{name}"',
        'version = "0.0.0-dev"',
        'edition = "2021"',
        "",
        "[dependencies]",
    ]
    if deps:
        for dep_name, dep_path in deps.items():
            lines.append(f'{dep_name} = {{ path = "{dep_path}" }}')

    cargo_toml.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Create a source file. The tests can change this file.
    src = lib_dir / "src"
    src.mkdir(exist_ok=True)
    (src / "lib.rs").write_text("// placeholder\n", encoding="utf-8")

    write_workspace_manifest(ws)
    return lib_dir


def make_executable(ws: Path, name: str, dir_name: str) -> Path:
    """Create a real executable crate and refresh the workspace manifest."""
    exe_dir = ws / "executables" / dir_name
    exe_dir.mkdir(parents=True, exist_ok=True)

    cargo_toml = exe_dir / "Cargo.toml"
    cargo_toml.write_text(
        textwrap.dedent(f"""\
        [package]
        name = "{name}"
        version = "0.0.0-dev"
        edition = "2021"
        """),
        encoding="utf-8",
    )

    src = exe_dir / "src"
    src.mkdir(exist_ok=True)
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    write_workspace_manifest(ws)
    return exe_dir


def git_commit(ws: Path, message: str = "commit") -> str:
    """Stage all changes and commit. Return the commit hash."""
    subprocess.run(["git", "add", "-A"], cwd=ws, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", message, "--allow-empty"],
        cwd=ws, check=True, capture_output=True,
    )
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ws, check=True, capture_output=True, text=True,
    )
    return result.stdout.strip()


def git_tag(ws: Path, tag: str) -> None:
    """Create an annotated tag."""
    subprocess.run(
        ["git", "tag", "-a", tag, "-m", f"tag {tag}"],
        cwd=ws, check=True, capture_output=True,
    )


def git_release_commit(ws: Path, source_commit: str) -> str:
    """Create a generated release commit with a source trailer."""
    manifest = ws / "libraries" / "my_lib" / "Cargo.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            'version = "0.0.0-dev"',
            'version = "0.1.0"',
        ),
        encoding="utf-8",
    )
    return git_commit(
        ws,
        f"chore: hydrate release versions\n\nSource-Commit: {source_commit}",
    )


# ---------------------------------------------------------------------------
# Unit tests: parsing
# ---------------------------------------------------------------------------

class TestParseSemver:
    def test_basic(self) -> None:
        assert parse_semver("1.2.3") == (1, 2, 3)

    def test_zero(self) -> None:
        assert parse_semver("0.1.0") == (0, 1, 0)

    def test_large(self) -> None:
        assert parse_semver("12.34.56") == (12, 34, 56)


class TestBumpPatch:
    def test_basic(self) -> None:
        assert bump_patch(0, 1, 2) == "0.1.3"

    def test_zero(self) -> None:
        assert bump_patch(1, 0, 0) == "1.0.1"


class TestBumpBreaking:
    def test_pre_1_0(self) -> None:
        assert bump_breaking(0, 1, 5) == "0.2.0"

    def test_pre_1_0_zero_minor(self) -> None:
        assert bump_breaking(0, 0, 3) == "0.1.0"

    def test_post_1_0(self) -> None:
        assert bump_breaking(1, 2, 3) == "2.0.0"

    def test_major_2(self) -> None:
        assert bump_breaking(2, 5, 1) == "3.0.0"


class TestBumpMinor:
    def test_post_1_0(self) -> None:
        assert bump_minor(1, 2, 3) == "1.3.0"

    def test_major_2(self) -> None:
        assert bump_minor(2, 0, 5) == "2.1.0"

    def test_pre_1_0_takes_patch(self) -> None:
        # Before 1.0 the minor position is reserved for breaking changes, so an
        # additive change is a patch-level bump within the same range.
        assert bump_minor(0, 3, 4) == "0.3.5"

    def test_pre_1_0_zero_minor(self) -> None:
        assert bump_minor(0, 0, 2) == "0.0.3"


class TestDiscoverLibraries:
    def test_library_targets_discovered_executables_excluded(
        self, tmp_path: Path,
    ) -> None:
        """Discovery keeps library members and drops binary-only members."""
        make_library(tmp_path, "my-lib", "my_lib")
        make_executable(tmp_path, "my-app", "my_app")

        crates = discover_libraries(tmp_path)

        assert set(crates) == {"my-lib"}
        assert crates["my-lib"].relative_dir == "libraries/my_lib"

    def test_dual_type_library_discovered(self, tmp_path: Path) -> None:
        """A crate-type = ["cdylib", "rlib"] member is a library."""
        _put(tmp_path / "Cargo.toml", """\
            [workspace]
            resolver = "2"
            members = ["libraries/plugin"]
            """)
        _put(tmp_path / "libraries" / "plugin" / "Cargo.toml", """\
            [package]
            name = "plugin"
            version = "0.0.0-dev"
            edition = "2021"

            [lib]
            crate-type = ["cdylib", "rlib"]
            """)
        _put(tmp_path / "libraries" / "plugin" / "src" / "lib.rs", "// plugin\n")

        crates = discover_libraries(tmp_path)

        assert set(crates) == {"plugin"}

    def test_renamed_dependency_resolves_real_identity(self, tmp_path: Path) -> None:
        """A renamed path edge cascades to the real member, not the alias."""
        _put(tmp_path / "Cargo.toml", """\
            [workspace]
            resolver = "2"
            members = ["libraries/base", "libraries/top"]
            """)
        _put(tmp_path / "libraries" / "base" / "Cargo.toml", """\
            [package]
            name = "base-lib"
            version = "0.0.0-dev"
            edition = "2021"
            """)
        _put(tmp_path / "libraries" / "base" / "src" / "lib.rs", "// base\n")
        _put(tmp_path / "libraries" / "top" / "Cargo.toml", """\
            [package]
            name = "top-lib"
            version = "0.0.0-dev"
            edition = "2021"

            [dependencies]
            aliased = { package = "base-lib", path = "../base" }
            """)
        _put(tmp_path / "libraries" / "top" / "src" / "lib.rs", "// top\n")

        crates = discover_libraries(tmp_path)

        assert crates["top-lib"].workspace_deps == ["base-lib"]

    def test_inherited_workspace_dependency_cascades(self, tmp_path: Path) -> None:
        """An inherited ``workspace = true`` path edge cascades."""
        _put(tmp_path / "Cargo.toml", """\
            [workspace]
            resolver = "2"
            members = ["libraries/base", "libraries/top"]

            [workspace.dependencies]
            base-lib = { path = "libraries/base" }
            """)
        _put(tmp_path / "libraries" / "base" / "Cargo.toml", """\
            [package]
            name = "base-lib"
            version = "0.0.0-dev"
            edition = "2021"
            """)
        _put(tmp_path / "libraries" / "base" / "src" / "lib.rs", "// base\n")
        _put(tmp_path / "libraries" / "top" / "Cargo.toml", """\
            [package]
            name = "top-lib"
            version = "0.0.0-dev"
            edition = "2021"

            [dependencies]
            base-lib = { workspace = true }
            """)
        _put(tmp_path / "libraries" / "top" / "src" / "lib.rs", "// top\n")

        crates = discover_libraries(tmp_path)

        assert crates["top-lib"].workspace_deps == ["base-lib"]

    def test_target_specific_dependency_cascades(self, tmp_path: Path) -> None:
        """A platform-conditioned normal edge still cascades."""
        _put(tmp_path / "Cargo.toml", """\
            [workspace]
            resolver = "2"
            members = ["libraries/base", "libraries/top"]
            """)
        _put(tmp_path / "libraries" / "base" / "Cargo.toml", """\
            [package]
            name = "base-lib"
            version = "0.0.0-dev"
            edition = "2021"
            """)
        _put(tmp_path / "libraries" / "base" / "src" / "lib.rs", "// base\n")
        _put(tmp_path / "libraries" / "top" / "Cargo.toml", """\
            [package]
            name = "top-lib"
            version = "0.0.0-dev"
            edition = "2021"

            [target.'cfg(unix)'.dependencies]
            base-lib = { path = "../base" }
            """)
        _put(tmp_path / "libraries" / "top" / "src" / "lib.rs", "// top\n")

        crates = discover_libraries(tmp_path)

        assert crates["top-lib"].workspace_deps == ["base-lib"]

    def test_reverse_dev_dependency_does_not_create_release_cycle(
        self, tmp_path: Path,
    ) -> None:
        """A reverse development edge supports examples, not release order."""
        _put(tmp_path / "Cargo.toml", """\
            [workspace]
            resolver = "2"
            members = ["libraries/networking", "libraries/flows"]
            """)
        _put(tmp_path / "libraries" / "networking" / "Cargo.toml", """\
            [package]
            name = "networking"
            version = "0.0.0-dev"
            edition = "2021"

            [dev-dependencies]
            flows = { path = "../flows" }
            """)
        _put(tmp_path / "libraries" / "networking" / "src" / "lib.rs", "// net\n")
        _put(tmp_path / "libraries" / "flows" / "Cargo.toml", """\
            [package]
            name = "flows"
            version = "0.0.0-dev"
            edition = "2021"

            [dependencies]
            networking = { path = "../networking" }
            """)
        _put(tmp_path / "libraries" / "flows" / "src" / "lib.rs", "// flows\n")

        crates = discover_libraries(tmp_path)

        assert crates["networking"].workspace_deps == []
        assert crates["flows"].workspace_deps == ["networking"]
        assert topological_sort(crates) == ["networking", "flows"]

    def test_members_outside_libraries_directory(self, tmp_path: Path) -> None:
        """Discovery follows Cargo membership, not the libraries/ directory."""
        _put(tmp_path / "Cargo.toml", """\
            [workspace]
            resolver = "2"
            members = ["crates/alpha", "tools/beta"]

            [package]
            name = "root-crate"
            version = "0.0.0-dev"
            edition = "2021"
            """)
        _put(tmp_path / "src" / "lib.rs", "// root\n")
        _put(tmp_path / "crates" / "alpha" / "Cargo.toml", """\
            [package]
            name = "alpha"
            version = "0.0.0-dev"
            edition = "2021"
            """)
        _put(tmp_path / "crates" / "alpha" / "src" / "lib.rs", "// alpha\n")
        _put(tmp_path / "tools" / "beta" / "Cargo.toml", """\
            [package]
            name = "beta"
            version = "0.0.0-dev"
            edition = "2021"
            """)
        _put(tmp_path / "tools" / "beta" / "src" / "lib.rs", "// beta\n")

        crates = discover_libraries(tmp_path)

        assert set(crates) == {"root-crate", "alpha", "beta"}
        assert crates["root-crate"].relative_dir == "."
        assert crates["alpha"].relative_dir == "crates/alpha"


# ---------------------------------------------------------------------------
# Unit tests: dependency graph
# ---------------------------------------------------------------------------

class TestTopologicalSort:
    def test_no_deps(self) -> None:
        crates = {
            "a": Crate(name="a", directory=Path("a")),
            "b": Crate(name="b", directory=Path("b")),
        }
        order = topological_sort(crates)
        assert set(order) == {"a", "b"}

    def test_linear_chain(self) -> None:
        crates = {
            "a": Crate(name="a", directory=Path("a")),
            "b": Crate(name="b", directory=Path("b"), workspace_deps=["a"]),
            "c": Crate(name="c", directory=Path("c"), workspace_deps=["b"]),
        }
        order = topological_sort(crates)
        assert order.index("a") < order.index("b") < order.index("c")

    def test_diamond(self) -> None:
        crates = {
            "base": Crate(name="base", directory=Path("base")),
            "left": Crate(name="left", directory=Path("left"), workspace_deps=["base"]),
            "right": Crate(name="right", directory=Path("right"), workspace_deps=["base"]),
            "top": Crate(name="top", directory=Path("top"), workspace_deps=["left", "right"]),
        }
        order = topological_sort(crates)
        assert order.index("base") < order.index("left")
        assert order.index("base") < order.index("right")
        assert order.index("left") < order.index("top")
        assert order.index("right") < order.index("top")

    def test_cycle_raises(self) -> None:
        crates = {
            "a": Crate(name="a", directory=Path("a"), workspace_deps=["b"]),
            "b": Crate(name="b", directory=Path("b"), workspace_deps=["a"]),
        }
        with pytest.raises(ValueError, match="cycle"):
            topological_sort(crates)

    def test_matches_real_workspace(self) -> None:
        """The topological sort matches the actual tacacs-rs dependency graph."""
        crates = {
            "tacacsrs-protocol": Crate(
                name="tacacsrs-protocol", directory=Path("libraries/tacacsrs_protocol"),
            ),
            "tacacsrs-ipc": Crate(
                name="tacacsrs-ipc", directory=Path("libraries/tacacsrs_ipc"),
            ),
            "tacacsrs-networking": Crate(
                name="tacacsrs-networking", directory=Path("libraries/tacacsrs_networking"),
                workspace_deps=["tacacsrs-protocol"],
            ),
            "tacacsrs-agent": Crate(
                name="tacacsrs-agent", directory=Path("libraries/tacacsrs_agent"),
                workspace_deps=["tacacsrs-protocol", "tacacsrs-networking", "tacacsrs-ipc"],
            ),
        }
        order = topological_sort(crates)

        # Messages and agent-client have no dependencies. They come first.
        assert order.index("tacacsrs-protocol") < order.index("tacacsrs-networking")
        assert order.index("tacacsrs-protocol") < order.index("tacacsrs-agent")
        assert order.index("tacacsrs-ipc") < order.index("tacacsrs-agent")
        assert order.index("tacacsrs-networking") < order.index("tacacsrs-agent")


# ---------------------------------------------------------------------------
# Integration tests: library version computation
# ---------------------------------------------------------------------------

class TestComputeLibraryVersions:
    def test_initial_release(self, tmp_workspace: Path) -> None:
        """The first library release is 0.1.0."""
        make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "initial")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_library_versions(
            crates, order, cwd=tmp_workspace, skip_semver_checks=True,
        )
        assert len(results) == 1
        assert results[0].version == "0.1.0"
        assert results[0].tag == "my-lib-v0.1.0"
        assert results[0].reason == "initial release"

    def test_unchanged_after_tag(self, tmp_workspace: Path) -> None:
        """A library without changes since its tag keeps its version."""
        make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "my-lib-v0.1.0")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_library_versions(
            crates, order, cwd=tmp_workspace, skip_semver_checks=True,
        )
        assert len(results) == 1
        assert results[0].version == "0.1.0"
        assert results[0].tag is None
        assert results[0].reason == "unchanged"

    def test_ignores_hydration_in_generated_release_tag(
        self,
        tmp_workspace: Path,
    ) -> None:
        """A generated manifest version does not cause another release."""
        make_library(tmp_workspace, "my-lib", "my_lib")
        source_commit = git_commit(tmp_workspace, "initial")
        release_commit = git_release_commit(tmp_workspace, source_commit)
        git_tag(tmp_workspace, "my-lib-v0.1.0")
        subprocess.run(
            ["git", "checkout", "--detach", source_commit],
            cwd=tmp_workspace,
            check=True,
            capture_output=True,
        )

        crates = discover_libraries(tmp_workspace)
        results = compute_library_versions(
            crates,
            topological_sort(crates),
            cwd=tmp_workspace,
            skip_semver_checks=True,
        )

        assert source_ref_for_tag(
            "my-lib-v0.1.0",
            cwd=tmp_workspace,
        ) == source_commit
        assert release_commit != source_commit
        assert results[0].version == "0.1.0"
        assert results[0].tag is None

    def test_detects_source_change_after_generated_release_tag(
        self,
        tmp_workspace: Path,
    ) -> None:
        """A source change after a generated tag causes a new release."""
        lib = make_library(tmp_workspace, "my-lib", "my_lib")
        source_commit = git_commit(tmp_workspace, "initial")
        git_release_commit(tmp_workspace, source_commit)
        git_tag(tmp_workspace, "my-lib-v0.1.0")
        subprocess.run(
            ["git", "checkout", "--detach", source_commit],
            cwd=tmp_workspace,
            check=True,
            capture_output=True,
        )
        (lib / "src" / "lib.rs").write_text("// changed\n", encoding="utf-8")
        git_commit(tmp_workspace, "change")

        crates = discover_libraries(tmp_workspace)
        results = compute_library_versions(
            crates,
            topological_sort(crates),
            cwd=tmp_workspace,
            skip_semver_checks=True,
        )

        assert results[0].version == "0.1.1"
        assert results[0].tag == "my-lib-v0.1.1"

    def test_patch_bump_on_change(self, tmp_workspace: Path) -> None:
        """A changed library gets a patch increment."""
        lib = make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "my-lib-v0.1.0")

        # Make a change.
        (lib / "src" / "lib.rs").write_text("// changed\n", encoding="utf-8")
        git_commit(tmp_workspace, "change")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_library_versions(
            crates, order, cwd=tmp_workspace, skip_semver_checks=True,
        )
        assert results[0].version == "0.1.1"
        assert results[0].tag == "my-lib-v0.1.1"

    def test_cascading_bump(self, tmp_workspace: Path) -> None:
        """A new dependency version also increments each dependent."""
        make_library(tmp_workspace, "base-lib", "base_lib")
        make_library(
            tmp_workspace, "top-lib", "top_lib",
            deps={"base-lib": "../base_lib"},
        )
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "base-lib-v0.1.0")
        git_tag(tmp_workspace, "top-lib-v0.1.0")

        # Change only the base library.
        base_src = tmp_workspace / "libraries" / "base_lib" / "src" / "lib.rs"
        base_src.write_text("// changed base\n", encoding="utf-8")
        git_commit(tmp_workspace, "change base")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_library_versions(
            crates, order, cwd=tmp_workspace, skip_semver_checks=True,
        )

        by_name = {r.name: r for r in results}

        # The base library gets a new version.
        assert by_name["base-lib"].version == "0.1.1"
        assert by_name["base-lib"].tag is not None

        # The dependent library also gets a new version from the cascade.
        assert by_name["top-lib"].version == "0.1.1"
        assert by_name["top-lib"].tag is not None
        assert "skipped" in by_name["top-lib"].reason

    def test_no_cascade_when_dep_unchanged(self, tmp_workspace: Path) -> None:
        """No cascade occurs when the dependency keeps its version."""
        make_library(tmp_workspace, "base-lib", "base_lib")
        make_library(
            tmp_workspace, "top-lib", "top_lib",
            deps={"base-lib": "../base_lib"},
        )
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "base-lib-v0.1.0")
        git_tag(tmp_workspace, "top-lib-v0.1.0")

        # Do not make changes.
        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_library_versions(
            crates, order, cwd=tmp_workspace, skip_semver_checks=True,
        )

        by_name = {r.name: r for r in results}
        assert by_name["base-lib"].tag is None  # unchanged
        assert by_name["top-lib"].tag is None  # unchanged

    def test_deep_cascade(self, tmp_workspace: Path) -> None:
        """Three-level cascade: a → b → c."""
        make_library(tmp_workspace, "a", "a")
        make_library(tmp_workspace, "b", "b", deps={"a": "../a"})
        make_library(tmp_workspace, "c", "c", deps={"b": "../b"})
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "a-v0.1.0")
        git_tag(tmp_workspace, "b-v0.1.0")
        git_tag(tmp_workspace, "c-v0.2.0")

        # Change only 'a'.
        (tmp_workspace / "libraries" / "a" / "src" / "lib.rs").write_text(
            "// deep change\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "change a")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_library_versions(
            crates, order, cwd=tmp_workspace, skip_semver_checks=True,
        )
        by_name = {r.name: r for r in results}

        assert by_name["a"].version == "0.1.1"
        assert by_name["b"].version == "0.1.1"
        assert by_name["c"].version == "0.2.1"  # The prior version is 0.2.0.


# ---------------------------------------------------------------------------
# Integration tests: structured API classification
# ---------------------------------------------------------------------------

class TestComputeLibraryVersionsApiClassification:
    """The non-skip path maps a structured ApiBump to a version increment.

    These tests mock ``classify_api_change`` so they do not build any crate or
    run the api-classifier tool. They assert the mapping from the structured
    enum to the SemVer arithmetic, the hydrated-tag baseline, and fail-closed
    propagation of analysis errors.
    """

    def _changed_library(self, ws: Path, baseline_tag: str) -> Path:
        lib = make_library(ws, "my-lib", "my_lib")
        git_commit(ws, "initial")
        git_tag(ws, baseline_tag)
        (lib / "src" / "lib.rs").write_text("// changed\n", encoding="utf-8")
        git_commit(ws, "change")
        return lib

    def test_additive_change_is_minor(self, tmp_workspace: Path) -> None:
        self._changed_library(tmp_workspace, "my-lib-v1.0.0")
        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        with patch(
            "compute_versions.classify_api_change", return_value=ApiBump.MINOR,
        ) as classify:
            results = compute_library_versions(
                crates, order, cwd=tmp_workspace, skip_semver_checks=False,
            )

        assert results[0].version == "1.1.0"
        assert "minor" in results[0].reason
        # The API baseline is the hydrated release tag, not the source commit.
        assert classify.call_args.args[1] == "my-lib-v1.0.0"

    def test_breaking_change_is_major(self, tmp_workspace: Path) -> None:
        self._changed_library(tmp_workspace, "my-lib-v1.2.3")
        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        with patch("compute_versions.classify_api_change", return_value=ApiBump.MAJOR):
            results = compute_library_versions(
                crates, order, cwd=tmp_workspace, skip_semver_checks=False,
            )

        assert results[0].version == "2.0.0"
        assert results[0].reason == "breaking"

    def test_pre_1_0_breaking_bumps_minor_position(self, tmp_workspace: Path) -> None:
        """A removed function is a major API change; before 1.0 it bumps 0.x."""
        self._changed_library(tmp_workspace, "my-lib-v0.1.5")
        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        with patch("compute_versions.classify_api_change", return_value=ApiBump.MAJOR):
            results = compute_library_versions(
                crates, order, cwd=tmp_workspace, skip_semver_checks=False,
            )

        assert results[0].version == "0.2.0"
        assert results[0].reason == "breaking"

    def test_compatible_change_is_patch(self, tmp_workspace: Path) -> None:
        self._changed_library(tmp_workspace, "my-lib-v1.0.0")
        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        with patch("compute_versions.classify_api_change", return_value=ApiBump.PATCH):
            results = compute_library_versions(
                crates, order, cwd=tmp_workspace, skip_semver_checks=False,
            )

        assert results[0].version == "1.0.1"
        assert results[0].reason == "patch"

    def test_analysis_error_fails_closed(self, tmp_workspace: Path) -> None:
        """A tool error aborts the computation; it never becomes a bump."""
        self._changed_library(tmp_workspace, "my-lib-v1.0.0")
        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        with patch(
            "compute_versions.classify_api_change",
            side_effect=ApiAnalysisError("api-classifier build failed"),
        ):
            with pytest.raises(ApiAnalysisError, match="build failed"):
                compute_library_versions(
                    crates, order, cwd=tmp_workspace, skip_semver_checks=False,
                )

    def test_dependency_only_bump_is_classified(self, tmp_workspace: Path) -> None:
        """A dependent with unchanged source is still classified.

        A re-exported dependency item is part of this crate's public API, so a
        dependency-only revision must be analyzed, not assumed to be a patch.
        """
        make_library(tmp_workspace, "base-lib", "base_lib")
        make_library(
            tmp_workspace, "top-lib", "top_lib", deps={"base-lib": "../base_lib"},
        )
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "base-lib-v1.0.0")
        git_tag(tmp_workspace, "top-lib-v1.0.0")
        (tmp_workspace / "libraries" / "base_lib" / "src" / "lib.rs").write_text(
            "// changed base\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "change base")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        analyzed: list[str] = []

        def record(package: str, baseline: str, **kwargs: object) -> ApiBump:
            analyzed.append(package)
            return ApiBump.PATCH

        with patch("compute_versions.classify_api_change", side_effect=record):
            results = compute_library_versions(
                crates, order, cwd=tmp_workspace, skip_semver_checks=False,
            )

        by_name = {r.name: r for r in results}
        assert by_name["base-lib"].version == "1.0.1"
        assert by_name["top-lib"].version == "1.0.1"
        assert by_name["top-lib"].reason == "patch"
        # Both the changed crate and the dependency-only dependent are analyzed.
        assert analyzed == ["base-lib", "top-lib"]

    def test_dependency_only_bump_can_be_major(self, tmp_workspace: Path) -> None:
        """A dependency-only change can be breaking when a re-export changes."""
        make_library(tmp_workspace, "base-lib", "base_lib")
        make_library(
            tmp_workspace, "top-lib", "top_lib", deps={"base-lib": "../base_lib"},
        )
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "base-lib-v1.0.0")
        git_tag(tmp_workspace, "top-lib-v1.0.0")
        (tmp_workspace / "libraries" / "base_lib" / "src" / "lib.rs").write_text(
            "// changed base\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "change base")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        def classify(package: str, baseline: str, **kwargs: object) -> ApiBump:
            return ApiBump.MAJOR if package == "top-lib" else ApiBump.PATCH

        with patch("compute_versions.classify_api_change", side_effect=classify):
            results = compute_library_versions(
                crates, order, cwd=tmp_workspace, skip_semver_checks=False,
            )

        by_name = {r.name: r for r in results}
        assert by_name["base-lib"].version == "1.0.1"
        # The dependent's own source did not change, but the dependency's
        # re-exported surface broke, so it takes a major bump.
        assert by_name["top-lib"].version == "2.0.0"
        assert by_name["top-lib"].reason == "breaking"

    def test_skip_semver_checks_never_calls_analysis(self, tmp_workspace: Path) -> None:
        self._changed_library(tmp_workspace, "my-lib-v1.0.0")
        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        with patch(
            "compute_versions.classify_api_change",
            side_effect=AssertionError("classify_api_change must not be called"),
        ):
            results = compute_library_versions(
                crates, order, cwd=tmp_workspace, skip_semver_checks=True,
            )

        assert results[0].version == "1.0.1"
        assert "skipped" in results[0].reason


# ---------------------------------------------------------------------------
# Integration tests: CalVer
# ---------------------------------------------------------------------------

class TestComputeCalver:
    def test_namespace_migration_uses_numeric_order_and_both_counters(self, tmp_workspace):
        make_executable(tmp_workspace, "tacon", "tacon")
        git_commit(tmp_workspace, "initial")
        for tag in ("tacon-2026.424.9", "tacacs-rs-2026.424.10", "tacacs-rs-not-a-version"):
            git_tag(tmp_workspace, tag)
        (tmp_workspace / "executables/tacon/src/main.rs").write_text("fn main() { }\n")
        git_commit(tmp_workspace, "change")
        result = compute_calver("tacon", ["executables/"], cwd=tmp_workspace,
                                now=datetime(2026, 4, 24, tzinfo=timezone.utc))
        assert result.previous_tag == "tacacs-rs-2026.424.10"
        assert result.tag == "tacacs-rs-2026.424.11"
        prerelease = compute_prerelease_calver("tacon", cwd=tmp_workspace)
        assert prerelease.version.startswith("2026.424.10-dev.")

    def test_timestamp_is_converted_to_utc(self, tmp_workspace):
        make_executable(tmp_workspace, "tacon", "tacon")
        git_commit(tmp_workspace, "initial")
        result = compute_calver("tacon", ["executables/"], cwd=tmp_workspace,
                                now=datetime(2026, 4, 25, 1, tzinfo=timezone(timedelta(hours=10))))
        assert result.tag == "tacacs-rs-2026.424.0"

    def test_legacy_baseline_is_not_hidden_by_an_older_repository_tag(self, tmp_workspace):
        make_executable(tmp_workspace, "tacon", "tacon")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "tacon-2026.425.2")
        git_tag(tmp_workspace, "tacacs-rs-2026.424.9")
        result = compute_calver("tacon", ["executables/"], cwd=tmp_workspace)
        assert result.version == "2026.425.2"
        assert result.previous_tag == "tacon-2026.425.2"
        assert result.tag is None

    def test_first_calver(self, tmp_workspace: Path) -> None:
        make_executable(tmp_workspace, "tacon", "tacon")
        make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "initial")

        now = datetime(2026, 4, 24, tzinfo=timezone.utc)
        result = compute_calver(
            "tacon",
            ["executables/tacon/", "libraries/"],
            cwd=tmp_workspace,
            now=now,
        )
        assert result is not None
        assert result.version == "2026.424.0"
        assert result.tag == "tacacs-rs-2026.424.0"

    def test_calver_increment(self, tmp_workspace: Path) -> None:
        make_executable(tmp_workspace, "tacon", "tacon")
        make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "tacon-2026.424.0")

        # Make a change.
        src = tmp_workspace / "executables" / "tacon" / "src" / "main.rs"
        src.write_text("fn main() { println!(\"v2\"); }\n", encoding="utf-8")
        git_commit(tmp_workspace, "change")

        now = datetime(2026, 4, 24, tzinfo=timezone.utc)
        result = compute_calver(
            "tacon",
            ["executables/tacon/", "libraries/"],
            cwd=tmp_workspace,
            now=now,
        )
        assert result is not None
        assert result.version == "2026.424.1"

    def test_ignores_hydration_in_generated_release_tag(
        self,
        tmp_workspace: Path,
    ) -> None:
        make_executable(tmp_workspace, "tacon", "tacon")
        make_library(tmp_workspace, "my-lib", "my_lib")
        source_commit = git_commit(tmp_workspace, "initial")
        git_release_commit(tmp_workspace, source_commit)
        git_tag(tmp_workspace, "tacon-2026.424.0")
        subprocess.run(
            ["git", "checkout", "--detach", source_commit],
            cwd=tmp_workspace,
            check=True,
            capture_output=True,
        )

        result = compute_calver(
            "tacon",
            ["executables/tacon/", "libraries/"],
            cwd=tmp_workspace,
            now=datetime(2026, 4, 25, tzinfo=timezone.utc),
        )

        # The generated hydration commit is not a source change, so the
        # executable stays at its existing CalVer with no new tag.
        assert result is not None
        assert result.version == "2026.424.0"
        assert result.tag is None
        assert result.reason == "unchanged"

    def test_calver_no_changes(self, tmp_workspace: Path) -> None:
        make_executable(tmp_workspace, "tacon", "tacon")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "tacon-2026.424.0")

        result = compute_calver(
            "tacon",
            ["executables/tacon/", "libraries/"],
            cwd=tmp_workspace,
        )
        # An unchanged executable keeps its existing CalVer and creates no tag,
        # so the version map still carries it at its released version.
        assert result is not None
        assert result.version == "2026.424.0"
        assert result.tag is None
        assert result.reason == "unchanged"
        assert result.previous_tag == "tacon-2026.424.0"

    def test_calver_new_day(self, tmp_workspace: Path) -> None:
        make_executable(tmp_workspace, "tacon", "tacon")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "tacon-2026.424.0")

        src = tmp_workspace / "executables" / "tacon" / "src" / "main.rs"
        src.write_text("fn main() { println!(\"v2\"); }\n", encoding="utf-8")
        git_commit(tmp_workspace, "change")

        # Use a different day.
        now = datetime(2026, 4, 25, tzinfo=timezone.utc)
        result = compute_calver(
            "tacon",
            ["executables/tacon/", "libraries/"],
            cwd=tmp_workspace,
            now=now,
        )
        assert result is not None
        assert result.version == "2026.425.0"


# ---------------------------------------------------------------------------
# Integration tests: full compute
# ---------------------------------------------------------------------------

class TestComputeAllVersions:
    def test_full_initial(self, tmp_workspace: Path) -> None:
        make_library(tmp_workspace, "base-lib", "base_lib")
        make_library(
            tmp_workspace, "top-lib", "top_lib",
            deps={"base-lib": "../base_lib"},
        )
        make_executable(tmp_workspace, "myapp", "myapp")
        git_commit(tmp_workspace, "initial")

        now = datetime(2026, 4, 24, tzinfo=timezone.utc)
        result = compute_all_versions(
            tmp_workspace,
            binary_name="myapp",
            skip_semver_checks=True,
            now=now,
        )

        assert result["versions"]["base-lib"] == "0.1.0"
        assert result["versions"]["top-lib"] == "0.1.0"
        assert result["versions"]["myapp"] == "2026.424.0"
        assert result["has_release"] is True
        assert len(result["new_tags"]) == 3

    def test_shared_executable_uses_primary_calver_and_watch_paths(self, tmp_workspace: Path) -> None:
        make_executable(tmp_workspace, "tacon", "tacon")
        make_executable(tmp_workspace, "tacacsrs-agentd", "tacacsrs_agentd")
        make_executable(tmp_workspace, "tacacsrs-agent-health", "tacacsrs_agent_health")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "tacon-2026.424.0")

        (tmp_workspace / "executables" / "tacacsrs_agentd" / "src" / "main.rs").write_text(
            "fn main() { println!(\"agentd update\"); }\n",
            encoding="utf-8",
        )
        git_commit(tmp_workspace, "update agentd")

        now = datetime(2026, 4, 24, tzinfo=timezone.utc)
        result = compute_all_versions(
            tmp_workspace,
            binary_name="tacon",
            shared_executable_names=["tacacsrs-agentd", "tacacsrs-agent-health"],
            skip_semver_checks=True,
            now=now,
        )

        assert result["versions"]["tacon"] == "2026.424.1"
        assert result["versions"]["tacacsrs-agentd"] == "2026.424.1"
        assert result["versions"]["tacacsrs-agent-health"] == "2026.424.1"
        assert result["calver_tag"] == "tacacs-rs-2026.424.1"
        assert "tacacs-rs-2026.424.1" in result["new_tags"]
        assert result["has_release"] is True

    def test_full_mixed_changes(self, tmp_workspace: Path) -> None:
        """Only changed crates get new tags."""
        make_library(tmp_workspace, "stable", "stable")
        make_library(tmp_workspace, "active", "active")
        make_executable(tmp_workspace, "myapp", "myapp")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "stable-v0.1.0")
        git_tag(tmp_workspace, "active-v0.1.0")
        git_tag(tmp_workspace, "myapp-2026.424.0")

        # Change only "active".
        (tmp_workspace / "libraries" / "active" / "src" / "lib.rs").write_text(
            "// updated\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "update active")

        now = datetime(2026, 4, 24, tzinfo=timezone.utc)
        result = compute_all_versions(
            tmp_workspace,
            binary_name="myapp",
            skip_semver_checks=True,
            now=now,
        )

        assert result["versions"]["stable"] == "0.1.0"
        assert result["versions"]["active"] == "0.1.1"
        # myapp also gets a new CalVer because libraries/ changed.
        assert result["versions"]["myapp"] == "2026.424.1"
        assert result["has_release"] is True

        # stable does not get a new tag.
        new_tag_names = result["new_tags"]
        assert "stable-v0.1.0" not in new_tag_names
        assert "active-v0.1.1" in new_tag_names


# ---------------------------------------------------------------------------
# Output tests
# ---------------------------------------------------------------------------

class TestSourceRefForTag:
    def test_rejects_missing_source_commit(self, tmp_workspace: Path) -> None:
        make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(
            tmp_workspace,
            "release\n\nSource-Commit: ffffffffffffffffffffffffffffffffffffffff",
        )
        git_tag(tmp_workspace, "my-lib-v0.1.0")

        with pytest.raises(ValueError, match="invalid Source-Commit"):
            source_ref_for_tag("my-lib-v0.1.0", cwd=tmp_workspace)


class TestWriteGithubOutput:
    def test_writes_to_file(self, tmp_path: Path) -> None:
        output_file = tmp_path / "output.txt"
        with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output_file)}):
            write_github_output("foo", "bar")
            write_github_output("baz", "qux")

        content = output_file.read_text(encoding="utf-8")
        assert "foo=bar\n" in content
        assert "baz=qux\n" in content

    def test_no_file_no_crash(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            # Print to standard output. Do not stop.
            write_github_output("key", "value")


# ---------------------------------------------------------------------------
# Unit tests: commit_count_since
# ---------------------------------------------------------------------------

class TestCommitCountSince:
    def test_counts_commits(self, tmp_workspace: Path) -> None:
        make_library(tmp_workspace, "lib", "lib")
        git_commit(tmp_workspace, "first")
        git_tag(tmp_workspace, "lib-v0.1.0")

        (tmp_workspace / "libraries" / "lib" / "src" / "lib.rs").write_text(
            "// c1\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "second")
        (tmp_workspace / "libraries" / "lib" / "src" / "lib.rs").write_text(
            "// c2\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "third")

        assert commit_count_since("lib-v0.1.0", cwd=tmp_workspace) == 2

    def test_zero_when_at_tag(self, tmp_workspace: Path) -> None:
        make_library(tmp_workspace, "lib", "lib")
        git_commit(tmp_workspace, "first")
        git_tag(tmp_workspace, "lib-v0.1.0")

        assert commit_count_since("lib-v0.1.0", cwd=tmp_workspace) == 0


# ---------------------------------------------------------------------------
# Integration tests: pre-release library versions
# ---------------------------------------------------------------------------

class TestComputePrereleaseLibraryVersions:
    def test_prerelease_with_tag(self, tmp_workspace: Path) -> None:
        """The pre-release version is {current}-dev.{N}."""
        lib = make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "my-lib-v0.1.2")

        (lib / "src" / "lib.rs").write_text("// c1\n", encoding="utf-8")
        git_commit(tmp_workspace, "change 1")
        (lib / "src" / "lib.rs").write_text("// c2\n", encoding="utf-8")
        git_commit(tmp_workspace, "change 2")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_prerelease_library_versions(
            crates, order, pre_release_label="dev", cwd=tmp_workspace,
        )
        assert len(results) == 1
        assert results[0].version == "0.1.2-dev.2"
        assert results[0].tag is None  # Do not create tags.

    def test_prerelease_no_tag(self, tmp_workspace: Path) -> None:
        """Without any tag, use 0.0.0-dev.{total_commits}."""
        make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "first")
        git_commit(tmp_workspace, "second")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_prerelease_library_versions(
            crates, order, pre_release_label="dev", cwd=tmp_workspace,
        )
        assert results[0].version == "0.0.0-dev.2"

    def test_prerelease_at_tag(self, tmp_workspace: Path) -> None:
        """At the tag commit, the version is {version}-dev.0."""
        make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "my-lib-v0.3.0")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_prerelease_library_versions(
            crates, order, pre_release_label="dev", cwd=tmp_workspace,
        )
        assert results[0].version == "0.3.0-dev.0"

    def test_prerelease_custom_label(self, tmp_workspace: Path) -> None:
        make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "my-lib-v1.0.0")

        (tmp_workspace / "libraries" / "my_lib" / "src" / "lib.rs").write_text(
            "// changed\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "change")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_prerelease_library_versions(
            crates, order, pre_release_label="alpha", cwd=tmp_workspace,
        )
        assert results[0].version == "1.0.0-alpha.1"


# ---------------------------------------------------------------------------
# Integration tests: pre-release CalVer
# ---------------------------------------------------------------------------

class TestComputePrereleaseCalver:
    def test_prerelease_calver_with_tag(self, tmp_workspace: Path) -> None:
        make_executable(tmp_workspace, "tacon", "tacon")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "tacon-2026.424.0")

        (tmp_workspace / "executables" / "tacon" / "src" / "main.rs").write_text(
            "// v2\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "change 1")
        git_commit(tmp_workspace, "change 2")

        result = compute_prerelease_calver("tacon", pre_release_label="dev", cwd=tmp_workspace)
        assert result.version == "2026.424.0-dev.2"
        assert result.tag is None

    def test_prerelease_calver_no_tag(self, tmp_workspace: Path) -> None:
        make_executable(tmp_workspace, "tacon", "tacon")
        git_commit(tmp_workspace, "initial")

        result = compute_prerelease_calver("tacon", pre_release_label="dev", cwd=tmp_workspace)
        assert result.version == "0.0.0-dev.1"
        assert result.tag is None


# ---------------------------------------------------------------------------
# Integration tests: full compute in pre-release mode
# ---------------------------------------------------------------------------

class TestComputeAllVersionsPrerelease:
    def test_prerelease_mode(self, tmp_workspace: Path) -> None:
        make_library(tmp_workspace, "base-lib", "base_lib")
        make_library(
            tmp_workspace, "top-lib", "top_lib",
            deps={"base-lib": "../base_lib"},
        )
        make_executable(tmp_workspace, "myapp", "myapp")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "base-lib-v0.1.0")
        git_tag(tmp_workspace, "top-lib-v0.2.0")
        git_tag(tmp_workspace, "myapp-2026.424.0")

        (tmp_workspace / "libraries" / "base_lib" / "src" / "lib.rs").write_text(
            "// pr change\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "pr commit 1")
        git_commit(tmp_workspace, "pr commit 2")

        result = compute_all_versions(
            tmp_workspace,
            binary_name="myapp",
            pre_release="dev",
        )

        assert result["versions"]["base-lib"] == "0.1.0-dev.2"
        assert result["versions"]["top-lib"] == "0.2.0-dev.2"
        assert result["versions"]["myapp"] == "2026.424.0-dev.2"
        assert result["new_tags"] == []  # The pre-release mode creates no tags.
        assert result["has_release"] is False


# ---------------------------------------------------------------------------
# Unit tests: the git helper fails loud, never silently empty
# ---------------------------------------------------------------------------

class TestGitRaisesOnFailure:
    """A failed Git command raises instead of returning empty output.

    A silent empty result could look like "no diff" or "no tag" and skip a
    release or mis-derive a version, so every non-zero exit must raise.
    """

    def test_git_rev_parse_bad_ref_raises(self, tmp_workspace: Path) -> None:
        git_commit(tmp_workspace, "initial")
        with pytest.raises(GitError, match="failed"):
            git("rev-parse", "--verify", "no-such-ref^{commit}", cwd=tmp_workspace)

    def test_git_log_unknown_tag_raises(self, tmp_workspace: Path) -> None:
        git_commit(tmp_workspace, "initial")
        with pytest.raises(GitError):
            git("log", "-1", "--format=%B", "no-such-tag", cwd=tmp_workspace)

    def test_has_changes_since_bad_ref_raises(self, tmp_workspace: Path) -> None:
        git_commit(tmp_workspace, "initial")
        with pytest.raises(GitError):
            has_changes_since("no-such-ref", ["."], cwd=tmp_workspace)

    def test_commit_count_since_bad_ref_raises(self, tmp_workspace: Path) -> None:
        git_commit(tmp_workspace, "initial")
        with pytest.raises(GitError):
            commit_count_since("no-such-ref", cwd=tmp_workspace)

    def test_source_ref_for_tag_unknown_tag_raises(self, tmp_workspace: Path) -> None:
        git_commit(tmp_workspace, "initial")
        with pytest.raises(GitError):
            source_ref_for_tag("no-such-tag", cwd=tmp_workspace)


# ---------------------------------------------------------------------------
# Integration tests: workspace-wide (root) watch paths
# ---------------------------------------------------------------------------

class TestRootPathWatch:
    """A change to a root file selects dependents for release.

    The root manifest, lockfile, and Cargo configuration can change a crate's
    build inputs or resolved dependencies without touching its own directory.
    """

    def _write_lock(self, ws: Path, extra: str = "") -> None:
        (ws / "Cargo.lock").write_text(
            textwrap.dedent(
                """\
                version = 4

                [[package]]
                name = "my-lib"
                version = "0.0.0-dev"
                """
            )
            + extra,
            encoding="utf-8",
        )

    def test_lockfile_only_change_triggers_library_release(
        self, tmp_workspace: Path,
    ) -> None:
        make_library(tmp_workspace, "my-lib", "my_lib")
        self._write_lock(tmp_workspace)
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "my-lib-v0.1.0")

        # Change ONLY the lockfile, as a transitive security update would.
        self._write_lock(
            tmp_workspace,
            '\n[[package]]\nname = "somedep"\nversion = "1.0.1"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        )
        git_commit(tmp_workspace, "lockfile security update")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)
        results = compute_library_versions(
            crates, order, cwd=tmp_workspace, skip_semver_checks=True,
        )
        assert results[0].version == "0.1.1"
        assert results[0].tag == "my-lib-v0.1.1"

    def test_root_manifest_change_triggers_library_release(
        self, tmp_workspace: Path,
    ) -> None:
        make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "my-lib-v0.1.0")

        # Change ONLY the root manifest, for example a workspace-wide profile.
        root = tmp_workspace / "Cargo.toml"
        root.write_text(
            root.read_text(encoding="utf-8") + "\n[profile.release]\nlto = true\n",
            encoding="utf-8",
        )
        git_commit(tmp_workspace, "root manifest change")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)
        results = compute_library_versions(
            crates, order, cwd=tmp_workspace, skip_semver_checks=True,
        )
        assert results[0].version == "0.1.1"
        assert results[0].tag == "my-lib-v0.1.1"

    def test_lockfile_only_update_produces_full_version_map_and_tags(
        self, tmp_workspace: Path,
    ) -> None:
        make_library(tmp_workspace, "my-lib", "my_lib")
        make_executable(tmp_workspace, "tacon", "tacon")
        self._write_lock(tmp_workspace)
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "my-lib-v0.1.0")
        git_tag(tmp_workspace, "tacon-2026.424.0")

        self._write_lock(
            tmp_workspace,
            '\n[[package]]\nname = "somedep"\nversion = "1.0.1"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        )
        git_commit(tmp_workspace, "lockfile security update")

        now = datetime(2026, 4, 24, tzinfo=timezone.utc)
        result = compute_all_versions(
            tmp_workspace, binary_name="tacon", skip_semver_checks=True, now=now,
        )

        # The lock-only update still selects the library and the executable.
        assert result["versions"]["my-lib"] == "0.1.1"
        assert result["versions"]["tacon"] == "2026.424.1"
        assert result["has_release"] is True
        assert "my-lib-v0.1.1" in result["new_tags"]
        assert "tacacs-rs-2026.424.1" in result["new_tags"]


# ---------------------------------------------------------------------------
# Integration tests: unchanged executables stay in the version map
# ---------------------------------------------------------------------------

class TestUnchangedExecutableInVersionMap:
    def test_unchanged_executable_carries_existing_calver(
        self, tmp_workspace: Path,
    ) -> None:
        make_library(tmp_workspace, "my-lib", "my_lib")
        make_executable(tmp_workspace, "tacon", "tacon")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "my-lib-v0.3.0")
        git_tag(tmp_workspace, "tacon-2026.424.0")

        # Nothing changes, so no crate gets a new tag.
        now = datetime(2026, 4, 24, tzinfo=timezone.utc)
        result = compute_all_versions(
            tmp_workspace, binary_name="tacon", skip_semver_checks=True, now=now,
        )

        # The executable and the library both stay in the map at their existing
        # versions, with no new tags.
        assert result["versions"]["tacon"] == "2026.424.0"
        assert result["versions"]["my-lib"] == "0.3.0"
        assert result["new_tags"] == []
        assert result["has_release"] is False
        assert result["calver_tag"] == ""

    def test_unchanged_shared_executables_carry_same_calver(
        self, tmp_workspace: Path,
    ) -> None:
        make_executable(tmp_workspace, "tacon", "tacon")
        make_executable(tmp_workspace, "tacacsrs-agentd", "tacacsrs_agentd")
        make_executable(
            tmp_workspace, "tacacsrs-agent-health", "tacacsrs_agent_health",
        )
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "tacon-2026.424.0")

        now = datetime(2026, 4, 24, tzinfo=timezone.utc)
        result = compute_all_versions(
            tmp_workspace,
            binary_name="tacon",
            shared_executable_names=["tacacsrs-agentd", "tacacsrs-agent-health"],
            skip_semver_checks=True,
            now=now,
        )

        # The shared executables carry the same existing CalVer, with no tags.
        assert result["versions"]["tacon"] == "2026.424.0"
        assert result["versions"]["tacacsrs-agentd"] == "2026.424.0"
        assert result["versions"]["tacacsrs-agent-health"] == "2026.424.0"
        assert result["new_tags"] == []
        assert result["has_release"] is False


class TestUnchangedMapHydration:
    """The version map for an unchanged executable still hydrates cleanly.

    This feeds a map that carries an unchanged executable at its existing CalVer
    into the real hydration step, proving the two sides agree.
    """

    def test_unchanged_map_hydrates_manifests_and_lock(self, tmp_path: Path) -> None:
        # Import the sibling hydration step without editing it.
        inject_dir = Path(__file__).resolve().parent.parent / "inject-versions"
        sys.path.insert(0, str(inject_dir))
        try:
            from hydrate_versions import hydrate
        finally:
            sys.path.remove(str(inject_dir))

        ws = tmp_path / "ws"
        (ws / "libraries" / "my_lib" / "src").mkdir(parents=True)
        (ws / "executables" / "tacon" / "src").mkdir(parents=True)
        (ws / "Cargo.toml").write_text(
            textwrap.dedent(
                """\
                [workspace]
                resolver = "2"
                members = ["libraries/my_lib", "executables/tacon"]
                """
            ),
            encoding="utf-8",
        )
        (ws / "libraries" / "my_lib" / "Cargo.toml").write_text(
            '[package]\nname = "my-lib"\nversion = "0.0.0-dev"\nedition = "2021"\n',
            encoding="utf-8",
        )
        (ws / "libraries" / "my_lib" / "src" / "lib.rs").write_text(
            "// my-lib\n", encoding="utf-8",
        )
        (ws / "executables" / "tacon" / "Cargo.toml").write_text(
            '[package]\nname = "tacon"\nversion = "0.0.0-dev"\nedition = "2021"\n',
            encoding="utf-8",
        )
        (ws / "executables" / "tacon" / "src" / "main.rs").write_text(
            "fn main() {}\n", encoding="utf-8",
        )
        (ws / "Cargo.lock").write_text(
            textwrap.dedent(
                """\
                version = 4

                [[package]]
                name = "my-lib"
                version = "0.0.0-dev"

                [[package]]
                name = "tacon"
                version = "0.0.0-dev"
                """
            ),
            encoding="utf-8",
        )

        # The library changed (new patch) but the executable did not. The map
        # still carries the executable at its existing CalVer.
        hydrate(ws, {"my-lib": "0.3.1", "tacon": "2026.424.0"})

        lib_manifest = (ws / "libraries" / "my_lib" / "Cargo.toml").read_text()
        exe_manifest = (ws / "executables" / "tacon" / "Cargo.toml").read_text()
        lock = (ws / "Cargo.lock").read_text()
        assert 'version = "0.3.1"' in lib_manifest
        assert 'version = "2026.424.0"' in exe_manifest
        assert lock.count('version = "0.3.1"') == 1
        assert lock.count('version = "2026.424.0"') == 1


# ---------------------------------------------------------------------------
# Integration tests: conservative breaking floor for normal dependencies
# ---------------------------------------------------------------------------

class TestNormalDependencyBreakingFloor:
    """A breaking normal dependency floors a dependent to a major bump.

    A normal dependency's incompatible bump can break a re-export of its items
    even when the dependent's own analyzed surface looks compatible, so the
    dependent takes a conservative major bump. A build dependency cannot reach
    the public API, so it never floors.
    """

    def test_discover_separates_normal_and_build_deps(self, tmp_path: Path) -> None:
        _put(tmp_path / "Cargo.toml", """\
            [workspace]
            resolver = "2"
            members = ["libraries/base", "libraries/top"]
            """)
        _put(tmp_path / "libraries" / "base" / "Cargo.toml", """\
            [package]
            name = "base-lib"
            version = "0.0.0-dev"
            edition = "2021"
            """)
        _put(tmp_path / "libraries" / "base" / "src" / "lib.rs", "// base\n")
        _put(tmp_path / "libraries" / "top" / "Cargo.toml", """\
            [package]
            name = "top-lib"
            version = "0.0.0-dev"
            edition = "2021"

            [build-dependencies]
            base-lib = { path = "../base" }
            """)
        _put(tmp_path / "libraries" / "top" / "src" / "lib.rs", "// top\n")
        _put(tmp_path / "libraries" / "top" / "build.rs", "fn main() {}\n")

        crates = discover_libraries(tmp_path)

        # A build edge propagates a release but is not a public-API edge.
        assert crates["top-lib"].workspace_deps == ["base-lib"]
        assert crates["top-lib"].normal_deps == []

    def test_normal_dependency_breaking_floors_dependent_to_major(
        self, tmp_workspace: Path,
    ) -> None:
        make_library(tmp_workspace, "base-lib", "base_lib")
        make_library(
            tmp_workspace, "top-lib", "top_lib", deps={"base-lib": "../base_lib"},
        )
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "base-lib-v1.0.0")
        git_tag(tmp_workspace, "top-lib-v1.0.0")
        (tmp_workspace / "libraries" / "base_lib" / "src" / "lib.rs").write_text(
            "// changed base\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "change base")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        # base breaks; top's own surface looks compatible. The floor still forces
        # top to a major bump because base is a normal dependency.
        def classify(package: str, baseline: str, **kwargs: object) -> ApiBump:
            return ApiBump.MAJOR if package == "base-lib" else ApiBump.PATCH

        with patch("compute_versions.classify_api_change", side_effect=classify):
            results = compute_library_versions(
                crates, order, cwd=tmp_workspace, skip_semver_checks=False,
            )

        by_name = {r.name: r for r in results}
        assert by_name["base-lib"].version == "2.0.0"
        assert by_name["top-lib"].version == "2.0.0"
        assert "normal dependency" in by_name["top-lib"].reason

    def test_pre_1_0_normal_dependency_breaking_floors_dependent(
        self, tmp_workspace: Path,
    ) -> None:
        make_library(tmp_workspace, "base-lib", "base_lib")
        make_library(
            tmp_workspace, "top-lib", "top_lib", deps={"base-lib": "../base_lib"},
        )
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "base-lib-v0.1.0")
        git_tag(tmp_workspace, "top-lib-v0.4.2")
        (tmp_workspace / "libraries" / "base_lib" / "src" / "lib.rs").write_text(
            "// changed base\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "change base")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        def classify(package: str, baseline: str, **kwargs: object) -> ApiBump:
            return ApiBump.MAJOR if package == "base-lib" else ApiBump.PATCH

        with patch("compute_versions.classify_api_change", side_effect=classify):
            results = compute_library_versions(
                crates, order, cwd=tmp_workspace, skip_semver_checks=False,
            )

        by_name = {r.name: r for r in results}
        # A 0.x breaking bump moves the minor position. Both the broken base and
        # the floored dependent move their minor positions.
        assert by_name["base-lib"].version == "0.2.0"
        assert by_name["top-lib"].version == "0.5.0"
        assert "normal dependency" in by_name["top-lib"].reason

    def test_build_dependency_breaking_does_not_floor_dependent(
        self, tmp_workspace: Path,
    ) -> None:
        _put(tmp_workspace / "Cargo.toml", """\
            [workspace]
            resolver = "2"
            members = ["libraries/base_lib", "libraries/top_lib"]
            """)
        _put(tmp_workspace / "libraries" / "base_lib" / "Cargo.toml", """\
            [package]
            name = "base-lib"
            version = "0.0.0-dev"
            edition = "2021"
            """)
        _put(tmp_workspace / "libraries" / "base_lib" / "src" / "lib.rs", "// base\n")
        _put(tmp_workspace / "libraries" / "top_lib" / "Cargo.toml", """\
            [package]
            name = "top-lib"
            version = "0.0.0-dev"
            edition = "2021"

            [build-dependencies]
            base-lib = { path = "../base_lib" }
            """)
        _put(tmp_workspace / "libraries" / "top_lib" / "src" / "lib.rs", "// top\n")
        _put(tmp_workspace / "libraries" / "top_lib" / "build.rs", "fn main() {}\n")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "base-lib-v1.0.0")
        git_tag(tmp_workspace, "top-lib-v1.0.0")
        (tmp_workspace / "libraries" / "base_lib" / "src" / "lib.rs").write_text(
            "// changed base\n", encoding="utf-8",
        )
        git_commit(tmp_workspace, "change base")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        def classify(package: str, baseline: str, **kwargs: object) -> ApiBump:
            return ApiBump.MAJOR if package == "base-lib" else ApiBump.PATCH

        with patch("compute_versions.classify_api_change", side_effect=classify):
            results = compute_library_versions(
                crates, order, cwd=tmp_workspace, skip_semver_checks=False,
            )

        by_name = {r.name: r for r in results}
        assert by_name["base-lib"].version == "2.0.0"
        # A build dependency never reaches the public API, so no floor applies.
        assert by_name["top-lib"].version == "1.0.1"
        assert by_name["top-lib"].reason == "patch"
