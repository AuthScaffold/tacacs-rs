#!/usr/bin/env python3
"""Stage required CycloneDX formats with one path-sanitization policy."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit


class SbomError(RuntimeError):
    """The required SBOM files are missing or invalid."""


def sanitize_string(value: str, workspaces: list[str], repository: str) -> str:
    """Replace local paths and file download URLs, including PURL qualifiers."""
    if value.lower().startswith("file://"):
        return repository
    if "?" in value:
        parts = urlsplit(value)
        query = parse_qsl(parts.query, keep_blank_values=True)
        rewritten = [
            (key, repository if key == "download_url" and item.lower().startswith("file://") else item)
            for key, item in query
        ]
        if rewritten != query:
            value = urlunsplit(parts._replace(query=urlencode(rewritten, quote_via=quote)))
    value = re.sub(r"download_url=file://[^\s\"'&<>]*", lambda _match: f"download_url={repository}", value)
    roots = set()
    for workspace in workspaces:
        for root in (workspace, workspace.replace("\\", "/")):
            root = root.rstrip("/\\")
            if root:
                roots.update((root, quote(root, safe="/"), quote(root, safe="")))
    for root in sorted(roots, key=len, reverse=True):
        value = re.sub(
            re.escape(root) + r"(?=$|[/\\\s\"'<>?#&]|%2[fF]|%5[cC])",
            "/workspace",
            value,
        )
    return value


def sanitize_json(value, workspaces: list[str], repository: str):
    """Sanitize JSON string values without changing keys or scalar types."""
    if isinstance(value, str):
        return sanitize_string(value, workspaces, repository)
    if isinstance(value, list):
        return [sanitize_json(item, workspaces, repository) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_json(item, workspaces, repository) for key, item in value.items()}
    return value


def local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def component_identity(document, output_format: str) -> tuple[str | None, str | None]:
    """Read the root component identity from parsed JSON or XML."""
    if output_format == "json":
        if not isinstance(document, dict) or not isinstance(document.get("metadata"), dict):
            raise SbomError("JSON SBOM must contain root component metadata")
        component = (document.get("metadata") or {}).get("component") or {}
        if not isinstance(component, dict):
            raise SbomError("JSON SBOM root component must be an object")
        return component.get("name"), component.get("version")
    metadata = next((child for child in document if local_tag(child.tag) == "metadata"), None)
    if metadata is None:
        return None, None
    component = next((child for child in metadata if local_tag(child.tag) == "component"), None)
    if component is None:
        return None, None
    fields = {local_tag(child.tag): (child.text or "").strip() for child in component}
    return fields.get("name"), fields.get("version")


def stage_sboms(
    *, package_root: Path, package_dir: Path, basename: str, package_name: str,
    workspaces: list[str], repository: str, expected_version: str | None = None,
) -> list[Path]:
    """Validate both required formats before writing sanitized copies."""
    if not basename or Path(basename).name != basename or "\\" in basename:
        raise SbomError("SBOM basename must be a file name")
    prepared = []
    identities = []
    for output_format in ("json", "xml"):
        candidates = []
        for path in sorted(Path(package_root).glob(f"*.cdx.{output_format}")):
            if path.is_symlink() or not path.is_file():
                raise SbomError(f"SBOM must be a regular file: {path}")
            document = json.loads(path.read_text(encoding="utf-8")) if output_format == "json" else ET.parse(path).getroot()
            identity = component_identity(document, output_format)
            if identity[0] == package_name:
                candidates.append((document, identity))
        if len(candidates) != 1:
            raise SbomError(f"expected one {output_format} SBOM root component for {package_name}, found {len(candidates)}")
        document, identity = candidates[0]
        if not identity[1] or (expected_version is not None and identity[1] != expected_version):
            raise SbomError(f"SBOM version does not match {package_name}: {identity[1]!r}")
        identities.append(identity)
        if output_format == "json":
            content = (json.dumps(sanitize_json(document, workspaces, repository), indent=2) + "\n").encode()
        else:
            for element in document.iter():
                if element.text:
                    element.text = sanitize_string(element.text, workspaces, repository)
                if element.tail:
                    element.tail = sanitize_string(element.tail, workspaces, repository)
                for key, value in element.attrib.items():
                    element.set(key, sanitize_string(value, workspaces, repository))
            content = ET.tostring(document, encoding="utf-8", xml_declaration=True)
        prepared.append((Path(package_dir) / f"{basename}.{output_format}", content))
    if identities[0] != identities[1]:
        raise SbomError("JSON and XML SBOM root components do not match")
    Path(package_dir).mkdir(parents=True, exist_ok=True)
    for destination, content in prepared:
        destination.write_bytes(content)
    return [destination for destination, _content in prepared]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", required=True, type=Path)
    parser.add_argument("--package-dir", required=True, type=Path)
    parser.add_argument("--basename", required=True)
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--workspace", action="append", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected-version")
    args = parser.parse_args(argv)
    try:
        stage_sboms(
            package_root=args.package_root, package_dir=args.package_dir,
            basename=args.basename, package_name=args.package_name,
            workspaces=args.workspace, repository=args.repository,
            expected_version=args.expected_version,
        )
    except (SbomError, OSError, ValueError, ET.ParseError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())