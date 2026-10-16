"""Cargo-derived workspace inventory.

Cargo is the package authority. This module runs ``cargo metadata`` and turns
its JSON into a deterministic inventory of workspace members. Release
discovery, manifest hydration, and CI reporting all read the same inventory.
Directory names and regular expressions decide nothing.

Public API:

``load_metadata(workspace, *, target=None, all_features=False, locked=True,
no_deps=False)``
    Run ``cargo metadata`` and return the parsed JSON object. ``no_deps=True``
    omits the resolved dependency graph. Version discovery and hydration use it
    because it does not need a native build or network access. The architecture
    gate uses the resolved graph with a platform filter instead.

``inventory(metadata)``
    Return a deterministic inventory built only from the workspace members in a
    ``cargo metadata`` object. Each package records its manifest path relative
    to the workspace root, its library and binary target kinds, its
    default-member status, and its declared dependencies with kind, platform
    condition, rename alias, optional flag, and real package identity.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path, PurePath


class MetadataError(RuntimeError):
    """``cargo metadata`` failed or returned unusable output."""


def load_metadata(
    workspace: Path,
    *,
    target: str | None = None,
    all_features: bool = False,
    locked: bool = True,
    no_deps: bool = False,
) -> dict:
    """Return the parsed ``cargo metadata`` JSON object for a workspace.

    ``target`` filters the resolved graph to one target triple. ``all_features``
    enables every feature. ``locked`` asserts an up-to-date ``Cargo.lock``.
    ``no_deps`` omits dependency resolution, so Cargo reads only the workspace
    manifests.

    Raises ``MetadataError`` when Cargo fails or returns output that is not a
    JSON object.
    """
    command = ["cargo", "metadata", "--format-version", "1"]
    if locked:
        command.append("--locked")
    if all_features:
        command.append("--all-features")
    if no_deps:
        command.append("--no-deps")
    if target is not None:
        command.extend(["--filter-platform", target])

    result = subprocess.run(
        command,
        cwd=str(workspace),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise MetadataError(
            f"`{' '.join(command)}` failed in {workspace} "
            f"(exit {result.returncode}):\n{result.stderr.strip()}"
        )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise MetadataError(f"cargo metadata returned invalid JSON: {error}") from error
    if not isinstance(data, dict):
        raise MetadataError("cargo metadata did not return a JSON object")
    return data


def inventory(metadata: dict) -> dict:
    """Return a deterministic inventory of workspace members.

    The inventory contains only workspace members, even when ``metadata``
    includes resolved dependency packages. The result is stable: packages sort
    by name then package id, and each package's dependencies sort by identity.
    """
    try:
        workspace_root = metadata["workspace_root"]
        packages = metadata["packages"]
        member_ids = list(metadata["workspace_members"])
    except (KeyError, TypeError) as error:
        raise MetadataError(
            f"cargo metadata is missing a required field: {error}"
        ) from error

    default_raw = metadata.get("workspace_default_members")
    default_ids = set(default_raw) if default_raw else set(member_ids)

    packages_by_id: dict[str, dict] = {}
    for package in packages:
        packages_by_id[package["id"]] = package

    # Index members by canonical manifest path. Dependency identity resolves
    # through this index, so a renamed or inherited path edge still maps to its
    # real member regardless of the directory name.
    member_id_by_manifest: dict[str, str] = {}
    for member_id in member_ids:
        package = packages_by_id.get(member_id)
        if package is None:
            raise MetadataError(
                f"workspace member {member_id!r} is absent from the package list"
            )
        member_id_by_manifest[_path_key(package["manifest_path"])] = member_id

    root = PurePath(workspace_root)
    members: list[dict] = []
    for member_id in member_ids:
        package = packages_by_id[member_id]
        manifest_path = PurePath(package["manifest_path"])
        relative_manifest, relative_directory = _relative_paths(manifest_path, root)

        target_kinds = sorted(
            {
                kind
                for target in package.get("targets", [])
                for kind in target.get("kind", [])
            }
        )

        dependencies = [
            _dependency_entry(dependency, packages_by_id, member_id_by_manifest)
            for dependency in package.get("dependencies", [])
        ]
        dependencies.sort(
            key=lambda entry: (
                entry["name"],
                entry["kind"] or "",
                entry["target"] or "",
                entry["rename"] or "",
                entry["source"] or "",
            )
        )

        members.append(
            {
                "id": member_id,
                "name": package["name"],
                "version": package["version"],
                "manifest_path": relative_manifest,
                "directory": relative_directory,
                "default_member": member_id in default_ids,
                "target_kinds": target_kinds,
                "dependencies": dependencies,
            }
        )

    members.sort(key=lambda package: (package["name"], package["id"]))
    return {"workspace_root": str(root), "packages": members}


def _dependency_entry(
    dependency: dict,
    packages_by_id: dict[str, dict],
    member_id_by_manifest: dict[str, str],
) -> dict:
    """Return one inventory dependency with its resolved workspace identity."""
    workspace_member = None
    dependency_path = dependency.get("path")
    if dependency_path is not None:
        manifest_key = _path_key(str(PurePath(dependency_path) / "Cargo.toml"))
        member_id = member_id_by_manifest.get(manifest_key)
        if member_id is not None:
            workspace_member = packages_by_id[member_id]["name"]
    return {
        "name": dependency["name"],
        "source": dependency.get("source"),
        "rename": dependency.get("rename"),
        "kind": dependency.get("kind"),
        "target": dependency.get("target"),
        "optional": bool(dependency.get("optional", False)),
        "workspace_member": workspace_member,
    }


def _path_key(path: str) -> str:
    """Return a comparable string for a Cargo-emitted absolute path."""
    return str(PurePath(path))


def _relative_paths(manifest_path: PurePath, root: PurePath) -> tuple[str, str]:
    """Return the manifest and directory paths relative to the workspace root."""
    try:
        relative_manifest = manifest_path.relative_to(root).as_posix()
        relative_directory = manifest_path.parent.relative_to(root).as_posix()
    except ValueError:
        relative_manifest = manifest_path.as_posix()
        relative_directory = manifest_path.parent.as_posix()
    return relative_manifest, relative_directory


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Print a deterministic Cargo workspace inventory as JSON.",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("."),
        help="Workspace root directory (default: current directory).",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Filter the resolved graph to one target triple.",
    )
    parser.add_argument(
        "--all-features",
        action="store_true",
        help="Enable every feature when resolving.",
    )
    parser.add_argument(
        "--no-locked",
        dest="locked",
        action="store_false",
        help="Do not require an up-to-date Cargo.lock.",
    )
    parser.add_argument(
        "--resolved",
        dest="no_deps",
        action="store_false",
        help="Resolve the full dependency graph instead of reading only members.",
    )
    parser.set_defaults(locked=True, no_deps=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Print the workspace inventory as JSON for CI reporting."""
    args = _build_parser().parse_args(argv)
    try:
        metadata = load_metadata(
            args.workspace.resolve(),
            target=args.target,
            all_features=args.all_features,
            locked=args.locked,
            no_deps=args.no_deps,
        )
        result = inventory(metadata)
    except MetadataError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
