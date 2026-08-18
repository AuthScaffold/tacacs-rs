"""Hydrate workspace package versions in Cargo manifests and Cargo.lock."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]*$")
PACKAGE_SECTION_RE = re.compile(
    r"(?ms)^\[package\]\r?\n(?P<body>.*?)(?=^\[|\Z)"
)
VERSION_LINE_RE = re.compile(r'(?m)^version\s*=\s*"[^"]*"\s*$')
NAME_LINE_RE = re.compile(r'(?m)^name\s*=\s*"([^"]+)"\s*$')
LOCK_PACKAGE_RE = re.compile(
    r"(?ms)^\[\[package\]\]\r?\n(?P<body>.*?)(?=^\[\[package\]\]|\Z)"
)


class HydrationError(ValueError):
    """A release version cannot be applied safely."""


def replace_manifest_version(path: Path, package: str, version: str) -> None:
    """Replace the package version in one Cargo manifest."""
    text = path.read_text(encoding="utf-8")
    section = PACKAGE_SECTION_RE.search(text)
    if section is None:
        raise HydrationError(f"{path} has no [package] section")

    body = section.group("body")
    matches = list(VERSION_LINE_RE.finditer(body))
    if len(matches) != 1:
        raise HydrationError(
            f"{path} must contain one package version, found {len(matches)}"
        )

    match = matches[0]
    new_body = body[: match.start()] + f'version = "{version}"' + body[match.end() :]
    path.write_text(
        text[: section.start("body")] + new_body + text[section.end("body") :],
        encoding="utf-8",
    )
    print(f"  {package} -> {version} ({path})")


def manifest_packages(workspace: Path) -> dict[str, Path]:
    """Return each workspace package and its manifest path."""
    packages: dict[str, Path] = {}
    for path in sorted(workspace.rglob("Cargo.toml")):
        if "target" in path.parts:
            continue

        text = path.read_text(encoding="utf-8")
        section = PACKAGE_SECTION_RE.search(text)
        if section is None:
            continue

        match = NAME_LINE_RE.search(section.group("body"))
        if match is None:
            raise HydrationError(f"{path} has no valid package name")
        name = match.group(1)
        if name in packages:
            raise HydrationError(
                f"duplicate package name {name!r}: {packages[name]} and {path}"
            )
        packages[name] = path
    return packages


def lock_package_name(body: str) -> str | None:
    """Return the package name from a Cargo.lock package body."""
    match = re.search(r'(?m)^name\s*=\s*"([^"]+)"\s*$', body)
    return match.group(1) if match else None


def replace_lock_versions(
    lock_path: Path,
    versions: dict[str, str],
) -> set[str]:
    """Replace source-free workspace package versions in Cargo.lock."""
    text = lock_path.read_text(encoding="utf-8")
    hydrated: set[str] = set()
    parts: list[str] = []
    cursor = 0

    for section in LOCK_PACKAGE_RE.finditer(text):
        parts.append(text[cursor : section.start()])
        block = section.group(0)
        body = section.group("body")
        name = lock_package_name(body)

        if name in versions and not re.search(r"(?m)^source\s*=", body):
            if name in hydrated:
                raise HydrationError(
                    f"{lock_path} has more than one source-free entry for {name!r}"
                )
            matches = list(VERSION_LINE_RE.finditer(body))
            if len(matches) != 1:
                raise HydrationError(
                    f"{lock_path} package {name!r} must contain one version"
                )
            match = matches[0]
            new_body = (
                body[: match.start()]
                + f'version = "{versions[name]}"'
                + body[match.end() :]
            )
            block = (
                block[: section.start("body") - section.start()]
                + new_body
            )
            hydrated.add(name)

        parts.append(block)
        cursor = section.end()

    parts.append(text[cursor:])
    lock_path.write_text("".join(parts), encoding="utf-8")
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
