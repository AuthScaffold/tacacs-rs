"""Tests for compute_versions.py.

These tests use a temporary git repo with simulated workspace structure
to exercise version computation logic without touching the real repo.
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

# Import from sibling module
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
    topological_sort,
    write_github_output,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_workspace(tmp_path: Path) -> Path:
    """Create a minimal git repo with workspace structure."""
    ws = tmp_path / "workspace"
    ws.mkdir()

    # Initialize git repo
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

    # Create a source file so there's something to change
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
        # Set up directory structure so path resolution works
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
        """Path deps outside libraries/ should be excluded."""
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
        """A reverse dev edge may support examples without changing release order."""
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
        """Verify topological sort matches the actual tacacs-rs dep graph."""
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

        # Messages and agent-client have no deps — they come first
        assert order.index("tacacsrs-messages") < order.index("tacacsrs-networking")
        assert order.index("tacacsrs-messages") < order.index("tacacsrs-agent")
        assert order.index("tacacsrs-agent-client") < order.index("tacacsrs-agent")
        assert order.index("tacacsrs-networking") < order.index("tacacsrs-agent")


# ---------------------------------------------------------------------------
# Integration tests: library version computation
# ---------------------------------------------------------------------------

class TestComputeLibraryVersions:
    def test_initial_release(self, tmp_workspace: Path) -> None:
        """First release of a library should be 0.1.0."""
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
        """Library with no changes since tag should keep its version."""
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

    def test_patch_bump_on_change(self, tmp_workspace: Path) -> None:
        """Changed library should get a patch bump."""
        lib = make_library(tmp_workspace, "my-lib", "my_lib")
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "my-lib-v0.1.0")

        # Make a change
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
        """When a dependency is bumped, dependents should also be checked."""
        make_library(tmp_workspace, "base-lib", "base_lib")
        make_library(
            tmp_workspace, "top-lib", "top_lib",
            deps={"base-lib": "../base_lib"},
        )
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "base-lib-v0.1.0")
        git_tag(tmp_workspace, "top-lib-v0.1.0")

        # Change only the base library
        base_src = tmp_workspace / "libraries" / "base_lib" / "src" / "lib.rs"
        base_src.write_text("// changed base\n", encoding="utf-8")
        git_commit(tmp_workspace, "change base")

        crates = discover_libraries(tmp_workspace)
        order = topological_sort(crates)

        results = compute_library_versions(
            crates, order, cwd=tmp_workspace, skip_semver_checks=True,
        )

        by_name = {r.name: r for r in results}

        # Base should be bumped
        assert by_name["base-lib"].version == "0.1.1"
        assert by_name["base-lib"].tag is not None

        # Top should also be bumped (dependency cascade)
        assert by_name["top-lib"].version == "0.1.1"
        assert by_name["top-lib"].tag is not None
        assert "dependency bumped" in by_name["top-lib"].reason

    def test_no_cascade_when_dep_unchanged(self, tmp_workspace: Path) -> None:
        """No cascade when the dependency itself wasn't bumped."""
        make_library(tmp_workspace, "base-lib", "base_lib")
        make_library(
            tmp_workspace, "top-lib", "top_lib",
            deps={"base-lib": "../base_lib"},
        )
        git_commit(tmp_workspace, "initial")
        git_tag(tmp_workspace, "base-lib-v0.1.0")
        git_tag(tmp_workspace, "top-lib-v0.1.0")

        # No changes at all
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

        # Change only 'a'
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
        assert by_name["c"].version == "0.2.1"  # bumps from 0.2.0


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

        # Make a change
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

        # Different day
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
            shared_executable_names=["tacacsrs-agentd"],
            skip_semver_checks=True,
            now=now,
        )

        assert result["versions"]["tacon"] == "2026.424.1"
        assert result["versions"]["tacacsrs-agentd"] == "2026.424.1"
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

        # Change only "active"
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
        # myapp should also get a new CalVer since libraries/ changed
        assert result["versions"]["myapp"] == "2026.424.1"
        assert result["has_release"] is True

        # stable should NOT have a new tag
        new_tag_names = result["new_tags"]
        assert "stable-v0.1.0" not in new_tag_names
        assert "active-v0.1.1" in new_tag_names


# ---------------------------------------------------------------------------
# Output tests
# ---------------------------------------------------------------------------

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
            # Should print to stdout, not crash
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
        """Pre-release version should be {current}-dev.{N}."""
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
        assert results[0].tag is None  # never create tags

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
        """At the tag commit itself, should be {version}-dev.0."""
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
        assert result["new_tags"] == []  # no tags in pre-release mode
        assert result["has_release"] is False
