"""Unchanged text-editing functions from predecessor 4d1ce532."""

import re
from pathlib import Path


PACKAGE_SECTION_RE = re.compile(
    r"(?ms)^\[package\]\r?\n(?P<body>.*?)(?=^\[|\Z)"
)
VERSION_LINE_RE = re.compile(r'(?m)^version\s*=\s*"[^"]*"\s*$')
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


def lock_package_name(body: str) -> str | None:
    """Return the package name from a Cargo.lock package body."""
    match = re.search(r'(?m)^name\s*=\s*"([^"]+)"\s*$', body)
    return match.group(1) if match else None


def replace_lock_versions(lock_path: Path, versions: dict[str, str]) -> set[str]:
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
            block = block[: section.start("body") - section.start()] + new_body
            hydrated.add(name)

        parts.append(block)
        cursor = section.end()

    parts.append(text[cursor:])
    lock_path.write_text("".join(parts), encoding="utf-8")
    return hydrated
