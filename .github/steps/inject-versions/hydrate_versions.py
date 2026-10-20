"""Hydrate workspace package versions in Cargo manifests and Cargo.lock."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import tomlkit
from tomlkit.exceptions import TOMLKitError

# The Cargo metadata helper lives in a sibling step directory.
_CARGO_METADATA_DIR = Path(__file__).resolve().parent.parent / "cargo-metadata"
if str(_CARGO_METADATA_DIR) not in sys.path:
    sys.path.insert(0, str(_CARGO_METADATA_DIR))

from workspace import inventory, load_metadata  # noqa: E402


VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]*$")


class HydrationError(ValueError):
    """A release version cannot be applied safely."""


def read_document(path: Path) -> tomlkit.TOMLDocument:
    """Parse TOML without newline conversion."""
    try:
        with path.open(encoding="utf-8", newline="") as source:
            return tomlkit.parse(source.read())
    except TOMLKitError as error:
        raise HydrationError(f"{path} contains invalid TOML: {error}") from error


def write_document(path: Path, document: tomlkit.TOMLDocument) -> None:
    """Write TOML without newline conversion."""
    with path.open("w", encoding="utf-8", newline="") as destination:
        destination.write(tomlkit.dumps(document))


def replace_manifest_version(path: Path, package: str, version: str) -> None:
    """Replace only the package version and retain unrelated TOML content."""
    document = read_document(path)
    table = document.get("package")
    if not isinstance(table, dict) or not isinstance(table.get("version"), str):
        raise HydrationError(f"{path} must contain one package version")
    table["version"] = version
    write_document(path, document)
    print(f"  {package} -> {version} ({path})")


def manifest_packages(workspace: Path) -> dict[str, Path]:
    """Return each workspace member package and its manifest path.

    Cargo decides workspace membership. Non-members never appear: the excluded
    fuzz crate, the build directory, and nested manifests outside the workspace
    are all absent. The metadata uses ``--no-deps``, so it reads only the
    workspace manifests and does not depend on ``Cargo.lock``.
    """
    inv = inventory(load_metadata(workspace, no_deps=True, locked=False))
    root = Path(inv["workspace_root"])
    packages: dict[str, Path] = {}
    for package in inv["packages"]:
        name = package["name"]
        manifest = root / package["manifest_path"]
        if name in packages:
            raise HydrationError(
                f"duplicate package name {name!r}: {packages[name]} and {manifest}"
            )
        packages[name] = manifest
    return packages


def replace_lock_versions(
    lock_path: Path,
    versions: dict[str, str],
) -> set[str]:
    """Update source-free packages and their version-qualified lock references."""
    document = read_document(lock_path)
    packages = document.get("package", [])
    if not isinstance(packages, list) or any(
        not isinstance(package, dict) for package in packages
    ):
        raise HydrationError(f"{lock_path} must contain package tables")
    hydrated: set[str] = set()
    references: dict[str, str] = {}
    for package in packages:
        name = package.get("name")
        if name in versions and "source" not in package:
            if name in hydrated:
                raise HydrationError(
                    f"{lock_path} has more than one source-free entry for {name!r}"
                )
            old_version = package.get("version")
            if not isinstance(old_version, str):
                raise HydrationError(
                    f"{lock_path} package {name!r} must contain one version"
                )
            references[f"{name} {old_version}"] = f"{name} {versions[name]}"
            package["version"] = versions[name]
            hydrated.add(name)
    for package in packages:
        dependencies = package.get("dependencies", [])
        for index, dependency in enumerate(dependencies):
            if dependency in references:
                dependencies[index] = references[dependency]
    write_document(lock_path, document)
    return hydrated


def hydrate(workspace: Path, versions: dict[str, str]) -> None:
    """Apply all release versions to the workspace."""
    if not versions:
        print("No versions to inject. Skip version injection.")
        return

    for package, version in versions.items():
        if not isinstance(package, str) or not isinstance(version, str):
            raise HydrationError("the version map must contain string keys and values")
        if not VERSION_RE.fullmatch(version):
            raise HydrationError(f"invalid version for {package!r}: {version!r}")

    packages = manifest_packages(workspace)
    missing_manifests = sorted(set(versions) - set(packages))
    if missing_manifests:
        raise HydrationError(
            "no Cargo.toml exists for: " + ", ".join(missing_manifests)
        )

    for package, version in sorted(versions.items()):
        replace_manifest_version(packages[package], package, version)

    lock_path = workspace / "Cargo.lock"
    if not lock_path.is_file():
        raise HydrationError(f"{lock_path} does not exist")

    hydrated_lock_packages = replace_lock_versions(lock_path, versions)
    missing_lock_packages = sorted(set(versions) - hydrated_lock_packages)
    if missing_lock_packages:
        raise HydrationError(
            "Cargo.lock has no source-free package entry for: "
            + ", ".join(missing_lock_packages)
        )


def main() -> int:
    """Run release version hydration."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--versions", required=True)
    args = parser.parse_args()

    try:
        versions = json.loads(args.versions)
        if not isinstance(versions, dict):
            raise HydrationError("the version input must be a JSON object")
        hydrate(args.workspace.resolve(), versions)
    except (HydrationError, json.JSONDecodeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
