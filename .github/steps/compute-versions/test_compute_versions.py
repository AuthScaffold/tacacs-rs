"""Run tests for compute_versions.py.

These tests use a temporary Git repository and a simulated workspace. They run
version computations without changes to the real repository.
"""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

# Import the sibling module.
from compute_versions import (
    Crate,
    VersionResult,
    bump_breaking,
    bump_patch,
    commit_count_since,
    compute_all_versions,
    compute_calver,
    compute_library_versions,
    compute_prerelease_calver,
    compute_prerelease_library_versions,
    discover_libraries,
    parse_cargo_toml,
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


def make_library(
    ws: Path,
    name: str,
    dir_name: str,
    deps: dict[str, str] | None = None,
) -> Path:
    """Create a library crate in the workspace."""
    lib_dir = ws / "libraries" / dir_name
    lib_dir.mkdir(parents=True, exist_ok=True)

    cargo_toml = lib_dir / "Cargo.toml"
    lines = [
        "[package]",
        f'name = "{name}"',
        'version = "0.0.0-dev"',
        'edition = "2024"',
        "",
        "[dependencies]",
    ]
    if deps:
        for dep_name, dep_path in deps.items():
            lines.append(f'{dep_name} = {{ path = "{dep_path}" }}')

    cargo_toml.write_text("\n".join(lines), encoding="utf-8")

    # Create a source file. The tests can change this file.
    src = lib_dir / "src"
    src.mkdir(exist_ok=True)
    (src / "lib.rs").write_text("// placeholder\n", encoding="utf-8")

    return lib_dir


def make_executable(ws: Path, name: str, dir_name: str) -> Path:
    """Create an executable crate in the workspace."""
    exe_dir = ws / "executables" / dir_name
    exe_dir.mkdir(parents=True, exist_ok=True)

    cargo_toml = exe_dir / "Cargo.toml"
    cargo_toml.write_text(
        textwrap.dedent(f"""\
        [package]
        name = "{name}"
        version = "0.0.0-dev"
        edition = "2024"
        """),
        encoding="utf-8",
    )

    src = exe_dir / "src"
    src.mkdir(exist_ok=True)
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

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


class TestParseCargoToml:
    def test_simple(self, tmp_path: Path) -> None:
        toml = tmp_path / "Cargo.toml"
        toml.write_text(textwrap.dedent("""\
            [package]
            name = "my-crate"
            version = "0.1.0"

            [dependencies]
            anyhow = "1.0"
        """), encoding="utf-8")

        name, deps = parse_cargo_toml(toml)
        assert name == "my-crate"
        assert deps == []

    def test_path_dep(self, tmp_path: Path) -> None:
        # Create the directory structure for path resolution.
        libs = tmp_path / "libraries"
        lib_a = libs / "lib_a"
        lib_b = libs / "lib_b"
        lib_a.mkdir(parents=True)
        lib_b.mkdir(parents=True)

        toml = lib_b / "Cargo.toml"
        toml.write_text(textwrap.dedent("""\
            [package]
            name = "lib-b"
            version = "0.1.0"

            [dependencies]
            lib-a = { path = "../lib_a" }
            external = "1.0"
        """), encoding="utf-8")

        name, deps = parse_cargo_toml(toml)
        assert name == "lib-b"
        assert deps == ["lib-a"]

    def test_non_library_path_dep_excluded(self, tmp_path: Path) -> None:
        """The parser excludes path dependencies outside libraries/."""
        lib = tmp_path / "libraries" / "lib_a"
        lib.mkdir(parents=True)
        ext = tmp_path / "external" / "ext_crate"
        ext.mkdir(parents=True)

        toml = lib / "Cargo.toml"
        toml.write_text(textwrap.dedent("""\
            [package]
            name = "lib-a"
            version = "0.1.0"

            [dependencies]
            ext-crate = { path = "../../external/ext_crate" }
        """), encoding="utf-8")

        name, deps = parse_cargo_toml(toml)
        assert name == "lib-a"
        assert deps == []

    def test_reverse_dev_dependency_does_not_create_release_cycle(
        self, tmp_path: Path,
    ) -> None:
        """A reverse development edge supports examples. It does not change release order."""
        libs = tmp_path / "libraries"
        networking = libs / "networking"
        flows = libs / "flows"
        networking.mkdir(parents=True)
        flows.mkdir(parents=True)

        (networking / "Cargo.toml").write_text(textwrap.dedent("""\
            [package]
            name = "networking"
            version = "0.1.0"

            [dev-dependencies]
            flows = { path = "../flows" }
        """), encoding="utf-8")
        (flows / "Cargo.toml").write_text(textwrap.dedent("""\
            [package]
            name = "flows"
            version = "0.1.0"

            [dependencies]
            networking = { path = "../networking" }
        """), encoding="utf-8")

        crates = discover_libraries(tmp_path)
        assert crates["networking"].workspace_deps == []
        assert crates["flows"].workspace_deps == ["networking"]
        assert topological_sort(crates) == ["networking", "flows"]


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
            "tacacsrs-messages": Crate(
                name="tacacsrs-messages", directory=Path("libraries/tacacsrs_messages"),
            ),
            "tacacsrs-agent-client": Crate(
                name="tacacsrs-agent-client", directory=Path("libraries/tacacsrs_agent_client"),
            ),
            "tacacsrs-networking": Crate(
                name="tacacsrs-networking", directory=Path("libraries/tacacsrs_networking"),
                workspace_deps=["tacacsrs-messages"],
            ),
            "tacacsrs-agent": Crate(
                name="tacacsrs-agent", directory=Path("libraries/tacacsrs_agent"),
                workspace_deps=["tacacsrs-messages", "tacacsrs-networking", "tacacsrs-agent-client"],
            ),
        }
        order = topological_sort(crates)

        # Messages and agent-client have no dependencies. They come first.
        assert order.index("tacacsrs-messages") < order.index("tacacsrs-networking")
        assert order.index("tacacsrs-messages") < order.index("tacacsrs-agent")
        assert order.index("tacacsrs-agent-client") < order.index("tacacsrs-agent")
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

        # The dependent library also gets a new version.
        assert by_name["top-lib"].version == "0.1.1"
        assert by_name["top-lib"].tag is not None
        assert "dependency version changed" in by_name["top-lib"].reason

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
# Integration tests: CalVer
# ---------------------------------------------------------------------------

class TestComputeCalver:
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
        assert result.tag == "tacon-2026.424.0"

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

        assert result is None

    def test_calver_no_changes(self, tmp_workspace: Path) -> None:
        make_executable(tmp_workspace, "tacon", "tacon")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "tacon-2026.424.0")

        result = compute_calver(
            "tacon",
            ["executables/tacon/", "libraries/"],
            cwd=tmp_workspace,
        )
        assert result is None

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
        assert result["calver_tag"] == "tacon-2026.424.1"
        assert "tacon-2026.424.1" in result["new_tags"]
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
