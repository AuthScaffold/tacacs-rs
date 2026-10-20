"""Bounded TOML Kit prototype. This file is not a production entry point."""

from __future__ import annotations

import tomlkit


def manifest_text(text: str, version: str) -> str:
    document = tomlkit.parse(text)
    package = document.get("package")
    if not isinstance(package, dict) or not isinstance(package.get("version"), str):
        raise ValueError("manifest must contain one package version")
    package["version"] = version
    return tomlkit.dumps(document)


def lock_text(text: str, versions: dict[str, str]) -> tuple[str, set[str]]:
    document = tomlkit.parse(text)
    hydrated = set()
    references = {}
    for package in document.get("package", []):
        name = package["name"]
        if name not in versions or "source" in package:
            continue
        if name in hydrated:
            raise ValueError(f"more than one source-free entry for {name!r}")
        old = package["version"]
        references[f"{name} {old}"] = f"{name} {versions[name]}"
        package["version"] = versions[name]
        hydrated.add(name)
    for package in document.get("package", []):
        dependencies = package.get("dependencies", [])
        for index, dependency in enumerate(dependencies):
            if dependency in references:
                dependencies[index] = references[dependency]
    return tomlkit.dumps(document), hydrated
