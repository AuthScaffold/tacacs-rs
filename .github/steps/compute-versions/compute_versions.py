"""Compute crate versions from Git tags, the dependency graph, and SemVer
validation.

The script finds all library crates in the ``libraries/`` directory. It builds
the workspace dependency graph from ``path = "..."`` entries in each
``Cargo.toml``. Then it sorts the crates by dependency. The script compares the
current HEAD to the last release tag. This comparison determines the next
SemVer version for each crate.

The script computes CalVer (``YYYY.MMDD.BUILD``) for the configured executable
in the ``executables/`` directory.

The script writes JSON-encoded results to ``$GITHUB_OUTPUT``. If this variable
is unset, the script writes the results to standard output. Downstream GitHub
Actions jobs use these results.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Crate:
    """A workspace crate discovered from a Cargo.toml."""

    name: str
    directory: Path
    workspace_deps: list[str] = field(default_factory=list)


@dataclass
class VersionResult:
    """The computed version for a single crate."""

    name: str
    version: str
    tag: str | None = None  # This field contains a tag when the release creates one.
    reason: str = ""
    previous_tag: str | None = None  # The release uses this baseline tag.


# ---------------------------------------------------------------------------
# Cargo.toml parsing is intentionally simple. No TOML library is necessary.
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"')
_PATH_DEP_RE = re.compile(
    r'^([a-zA-Z0-9_-]+)\s*=\s*\{.*?path\s*=\s*"([^"]+)"'
)


def parse_cargo_toml(path: Path) -> tuple[str, list[str]]:
    """Return ``(crate_name, [workspace_dep_names])`` from a Cargo.toml.

    Normal and build ``path = "..."`` dependencies in the workspace
    ``libraries/`` directory are workspace dependencies. Development
    dependencies do not propagate releases. Cargo also permits reverse
    development-dependency edges.
    """
    text = path.read_text(encoding="utf-8")
    name = ""
    deps: list[str] = []
    in_deps = False

    for line in text.splitlines():
        stripped = line.strip()

        # Get the package name, which is always before [dependencies].
        if not name:
            m = _NAME_RE.match(stripped)
            if m:
                name = m.group(1)

        # Track the section headers.
        if stripped.startswith("["):
            in_deps = stripped in (
                "[dependencies]",
                "[build-dependencies]",
            ) or stripped.startswith("[dependencies.")
            continue

        if in_deps:
            m = _PATH_DEP_RE.match(stripped)
            if m:
                dep_path = (path.parent / m.group(2)).resolve()
                # Count only dependencies in libraries/.
                if "libraries" in dep_path.parts:
                    deps.append(m.group(1))

    return name, deps


# ---------------------------------------------------------------------------
# Library discovery and dependency graph
# ---------------------------------------------------------------------------

def discover_libraries(workspace_root: Path) -> dict[str, Crate]:
    """Discover all library crates under ``workspace_root/libraries/``."""
    libs_dir = workspace_root / "libraries"
    crates: dict[str, Crate] = {}

    for cargo_toml in sorted(libs_dir.glob("*/Cargo.toml")):
        name, deps = parse_cargo_toml(cargo_toml)
        if not name:
            print(f"WARNING: No crate name in {cargo_toml}", file=sys.stderr)
            continue
        crates[name] = Crate(
            name=name,
            directory=cargo_toml.parent,
            workspace_deps=deps,
        )

    return crates


def topological_sort(crates: dict[str, Crate]) -> list[str]:
    """Return crate names in dependency order (leaves first).

    Raises ``ValueError`` on cycles.
    """
    in_degree: dict[str, int] = {name: 0 for name in crates}
    dependents: dict[str, list[str]] = defaultdict(list)

    for name, crate in crates.items():
        for dep in crate.workspace_deps:
            if dep in crates:
                in_degree[name] += 1
                dependents[dep].append(name)

    queue = sorted(n for n, d in in_degree.items() if d == 0)
    order: list[str] = []

    while queue:
        node = queue.pop(0)
        order.append(node)
        for dependent in sorted(dependents[node]):
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)

    if len(order) != len(crates):
        raise ValueError(
            f"Dependency cycle detected among: "
            f"{set(crates) - set(order)}"
        )

    return order


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def git(*args: str, cwd: Path | None = None) -> str:
    """Run a Git command and return standard output without surrounding whitespace."""
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        check=False,
    )
    return result.stdout.strip()


def latest_tag(prefix: str, cwd: Path | None = None) -> str | None:
    """Return the latest Git tag that matches ``prefix*``, or ``None``."""
    result = git(
        "tag", "--list", f"{prefix}*", "--sort=-v:refname",
        cwd=cwd,
    )
    if not result:
        return None
    return result.splitlines()[0]


def source_ref_for_tag(tag: str, cwd: Path | None = None) -> str:
    """Return the main source commit recorded by a generated release tag."""
    message = git("log", "-1", "--format=%B", tag, cwd=cwd)
    matches = re.findall(r"(?m)^Source-Commit:\s*([0-9a-fA-F]{40})\s*$", message)
    if len(matches) > 1:
        raise ValueError(f"Tag {tag} has more than one Source-Commit trailer")
    if not matches:
        return tag

    source_ref = git(
        "rev-parse",
        "--verify",
        f"{matches[0]}^{{commit}}",
        cwd=cwd,
    )
    if not source_ref:
        raise ValueError(f"Tag {tag} records an invalid Source-Commit")
    return source_ref


def has_changes_since(ref: str, paths: Sequence[str], cwd: Path | None = None) -> bool:
    """Return ``True`` if a file under ``paths`` changed since ``ref``."""
    args = ["diff", "--name-only", f"{ref}..HEAD", "--"]
    args.extend(paths)
    result = git(*args, cwd=cwd)
    return bool(result)


def tags_matching(prefix: str, cwd: Path | None = None) -> list[str]:
    """Return all tags matching ``prefix*``."""
    result = git("tag", "--list", f"{prefix}*", cwd=cwd)
    if not result:
        return []
    return result.splitlines()


def commit_count_since(ref: str, cwd: Path | None = None) -> int:
    """Return the number of commits from ``ref`` to HEAD."""
    result = git("rev-list", "--count", f"{ref}..HEAD", cwd=cwd)
    return int(result) if result else 0


# ---------------------------------------------------------------------------
# SemVer helpers
# ---------------------------------------------------------------------------

def parse_semver(version: str) -> tuple[int, int, int]:
    """Parse a ``MAJOR.MINOR.PATCH`` version string."""
    parts = version.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])


def bump_patch(major: int, minor: int, patch: int) -> str:
    return f"{major}.{minor}.{patch + 1}"


def bump_breaking(major: int, minor: int, _patch: int) -> str:
    """Increment the minor part before 1.0. Increment the major part at or after 1.0."""
    if major == 0:
        return f"0.{minor + 1}.0"
    return f"{major + 1}.0.0"


def run_semver_checks(
    package: str,
    baseline_rev: str,
    cwd: Path | None = None,
) -> bool:
    """Run ``cargo semver-checks`` and return ``True`` for a compatible API."""
    result = subprocess.run(
        [
            "cargo", "semver-checks", "check-release",
            "--package", package,
            "--baseline-rev", baseline_rev,
        ],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# CalVer computation
# ---------------------------------------------------------------------------

def compute_calver(
    binary_name: str,
    watch_paths: Sequence[str],
    cwd: Path | None = None,
    now: datetime | None = None,
) -> VersionResult | None:
    """Compute CalVer for an executable, or ``None`` if unchanged."""
    tag_prefix = f"{binary_name}-"
    latest = latest_tag(tag_prefix, cwd=cwd)

    if latest is not None:
        source_ref = source_ref_for_tag(latest, cwd=cwd)
        if not has_changes_since(source_ref, list(watch_paths), cwd=cwd):
            return None

    if now is None:
        now = datetime.now(timezone.utc)

    year = now.year
    mmdd = now.month * 100 + now.day

    build_prefix = f"{tag_prefix}{year}.{mmdd}."
    existing = tags_matching(build_prefix, cwd=cwd)

    if not existing:
        build = 0
    else:
        builds = []
        for t in existing:
            suffix = t[len(build_prefix):]
            if suffix.isdigit():
                builds.append(int(suffix))
        build = max(builds) + 1 if builds else 0

    version = f"{year}.{mmdd}.{build}"
    tag = f"{tag_prefix}{version}"

    return VersionResult(
        name=binary_name,
        version=version,
        tag=tag,
        reason="calver",
        previous_tag=latest,
    )


# ---------------------------------------------------------------------------
# Pre-release version computation
# ---------------------------------------------------------------------------

def compute_prerelease_library_versions(
    crates: dict[str, Crate],
    order: list[str],
    pre_release_label: str = "dev",
    cwd: Path | None = None,
) -> list[VersionResult]:
    """Compute pre-release versions for all libraries.

    Each library uses ``{latest_tag_version}-{label}.{N}``. N is the number of
    commits since the last tag. If no tag exists, the version uses
    ``0.0.0-{label}.{N}``. In this case, N is the total commit count.
    """
    results: list[VersionResult] = []

    for name in order:
        crate = crates[name]
        tag_prefix = f"{name}-v"
        latest = latest_tag(tag_prefix, cwd=cwd)

        if latest is None:
            n = commit_count_since("", cwd=cwd)  # The total commit count.
            # Use git rev-list --count HEAD instead.
            count_str = git("rev-list", "--count", "HEAD", cwd=cwd)
            n = int(count_str) if count_str else 0
            version = f"0.0.0-{pre_release_label}.{n}"
            reason = f"pre-release (no tag, {n} commits)"
        else:
            current = latest[len(tag_prefix):]
            n = commit_count_since(latest, cwd=cwd)
            version = f"{current}-{pre_release_label}.{n}"
            reason = f"pre-release ({n} commits since {current})"

        results.append(VersionResult(
            name=name,
            version=version,
            tag=None,  # Do not create tags for pre-releases.
            reason=reason,
        ))

    return results


def compute_prerelease_calver(
    binary_name: str,
    pre_release_label: str = "dev",
    cwd: Path | None = None,
) -> VersionResult:
    """Compute a pre-release version for an executable.

    Returns ``{latest_calver}-{label}.{N}`` or
    ``0.0.0-{label}.{N}`` if no CalVer tag exists.
    """
    tag_prefix = f"{binary_name}-"
    latest = latest_tag(tag_prefix, cwd=cwd)

    if latest is None:
        count_str = git("rev-list", "--count", "HEAD", cwd=cwd)
        n = int(count_str) if count_str else 0
        version = f"0.0.0-{pre_release_label}.{n}"
        reason = f"pre-release (no tag, {n} commits)"
    else:
        current = latest[len(tag_prefix):]
        n = commit_count_since(latest, cwd=cwd)
        version = f"{current}-{pre_release_label}.{n}"
        reason = f"pre-release ({n} commits since {current})"

    return VersionResult(
        name=binary_name,
        version=version,
        tag=None,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# Library version computation (with dependency-aware cascading)
# ---------------------------------------------------------------------------

def compute_library_versions(
    crates: dict[str, Crate],
    order: list[str],
    cwd: Path | None = None,
    skip_semver_checks: bool = False,
) -> list[VersionResult]:
    """Compute versions for all libraries in dependency order.

    If a dependency gets a new version, the script also makes sure that each
    dependent remains compatible. This occurs even if its source files do not change.
    """
    results: list[VersionResult] = []
    bumped: set[str] = set()

    for name in order:
        crate = crates[name]
        tag_prefix = f"{name}-v"
        latest = latest_tag(tag_prefix, cwd=cwd)

        # Determine whether a workspace dependency received a new version.
        dep_bumped = any(d in bumped for d in crate.workspace_deps)

        if latest is None:
            # This is the first release.
            version = "0.1.0"
            results.append(VersionResult(
                name=name,
                version=version,
                tag=f"{tag_prefix}{version}",
                reason="initial release",
            ))
            bumped.add(name)
            continue

        current = latest[len(tag_prefix):]
        dir_rel = str(crate.directory.relative_to(crate.directory.parents[1]))
        source_ref = source_ref_for_tag(latest, cwd=cwd)
        source_changed = has_changes_since(source_ref, [f"{dir_rel}/"], cwd=cwd)

        if not source_changed and not dep_bumped:
            # Nothing changed. Keep the current version.
            results.append(VersionResult(
                name=name,
                version=current,
                tag=None,
                reason="unchanged",
            ))
            continue

        # Something changed. Determine the increment level.
        major, minor, patch = parse_semver(current)

        if skip_semver_checks:
            # If semver-checks is unavailable, use a patch increment.
            is_compatible = True
        else:
            is_compatible = run_semver_checks(name, latest, cwd=cwd)

        if is_compatible:
            version = bump_patch(major, minor, patch)
            reason = "patch"
            if dep_bumped and not source_changed:
                reason = "patch (dependency version changed)"
        else:
            version = bump_breaking(major, minor, patch)
            reason = "breaking"

        results.append(VersionResult(
            name=name,
            version=version,
            tag=f"{tag_prefix}{version}",
            reason=reason,
        ))
        bumped.add(name)

    return results


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def compute_all_versions(
    workspace_root: Path,
    binary_name: str = "tacon",
    shared_executable_names: Sequence[str] | None = None,
    executable_watch_paths: Sequence[str] | None = None,
    skip_semver_checks: bool = False,
    now: datetime | None = None,
    pre_release: str = "",
) -> dict:
    """Compute all versions and return a result dict.

    If ``pre_release`` is not empty, all versions become pre-release
    identifiers. For example, ``"dev"`` produces ``0.1.2-dev.5`` after five
    commits from the ``v0.1.2`` tag. The pre-release mode does not create tags.

    Returns::

        {
            "versions": {"crate-name": "version", ...},
            "new_tags": ["tag1", "tag2", ...],
            "has_release": True/False,
            "calver_tag": "tacon-YYYY.MMDD.BUILD" or "",
        }
    """
    if shared_executable_names is None:
        shared_executable_names = []

    if executable_watch_paths is None:
        executable_watch_paths = [f"executables/{binary_name}/"]
        executable_watch_paths.extend(
            f"executables/{name.replace('-', '_')}/"
            for name in shared_executable_names
        )
        executable_watch_paths.append("libraries/")

    # Discover and sort libraries
    crates = discover_libraries(workspace_root)
    order = topological_sort(crates)

    if pre_release:
        # ── Pre-release mode: commit-distance versions and no tags ──
        lib_results = compute_prerelease_library_versions(
            crates, order,
            pre_release_label=pre_release,
            cwd=workspace_root,
        )
        calver_result: VersionResult | None = compute_prerelease_calver(
            binary_name,
            pre_release_label=pre_release,
            cwd=workspace_root,
        )
    else:
        # ── Release mode: SemVer increments, CalVer, and tags ──
        lib_results = compute_library_versions(
            crates, order,
            cwd=workspace_root,
            skip_semver_checks=skip_semver_checks,
        )
        calver_result = compute_calver(
            binary_name,
            executable_watch_paths,
            cwd=workspace_root,
            now=now,
        )

    # Assemble outputs
    versions: dict[str, str] = {}
    new_tags: list[str] = []

    for r in lib_results:
        versions[r.name] = r.version
        if r.tag is not None:
            new_tags.append(r.tag)
        print(f"  {r.name}: {r.version} ({r.reason})")

    calver_tag = ""
    previous_calver_tag = ""
    if calver_result is not None:
        versions[calver_result.name] = calver_result.version
        for shared_name in shared_executable_names:
            versions[shared_name] = calver_result.version
        if calver_result.tag:
            new_tags.append(calver_result.tag)
            calver_tag = calver_result.tag
            previous_calver_tag = calver_result.previous_tag or ""
        print(f"  {calver_result.name}: {calver_result.version} ({calver_result.reason})")
        for shared_name in shared_executable_names:
            print(f"  {shared_name}: {calver_result.version} (shared executable version)")
    else:
        print(f"  {binary_name}: unchanged (no CalVer)")

    return {
        "versions": versions,
        "new_tags": new_tags,
        "has_release": len(new_tags) > 0,
        "calver_tag": calver_tag,
        "previous_calver_tag": previous_calver_tag,
    }


def write_github_output(key: str, value: str) -> None:
    """Append a key=value pair to $GITHUB_OUTPUT."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(f"{key}={value}\n")
    else:
        print(f"  Output value: {key}={value}")


def main() -> None:
    workspace_root = Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve()
    binary_name = os.environ.get("INPUT_BINARY_NAME", "tacon")
    shared_executables_raw = os.environ.get("INPUT_SHARED_EXECUTABLES", "")
    skip_semver = os.environ.get("INPUT_SKIP_SEMVER_CHECKS", "false").lower() == "true"
    pre_release = os.environ.get("INPUT_PRE_RELEASE", "")
    shared_executable_names = [
        name.strip()
        for name in shared_executables_raw.split(",")
        if name.strip()
    ]

    print(f"Workspace: {workspace_root}")
    print(f"Binary: {binary_name}")
    print(f"Shared executables: {shared_executable_names or ['(none)']}")
    print(f"Skip SemVer validation: {skip_semver}")
    print(f"Pre-release label: {pre_release or '(none — release mode)'}")
    print()

    result = compute_all_versions(
        workspace_root,
        binary_name=binary_name,
        shared_executable_names=shared_executable_names,
        skip_semver_checks=skip_semver,
        pre_release=pre_release,
    )

    print()
    print(f"Versions: {json.dumps(result['versions'], indent=2)}")
    print(f"New tags: {result['new_tags']}")
    print(f"Has release: {result['has_release']}")

    write_github_output("versions", json.dumps(result["versions"]))
    write_github_output("new_tags", json.dumps(result["new_tags"]))
    write_github_output("has_release", json.dumps(result["has_release"]))
    write_github_output("calver_tag", result["calver_tag"])
    write_github_output("previous_calver_tag", result["previous_calver_tag"])


if __name__ == "__main__":
    main()
