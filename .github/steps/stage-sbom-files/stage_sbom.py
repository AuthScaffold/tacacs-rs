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

# The Cargo metadata helper lives in a sibling step directory. Cargo is the
# package authority, so this module uses it to resolve the target names and the
# version that a product SBOM root component may carry.
_CARGO_METADATA_DIR = Path(__file__).resolve().parent.parent / "cargo-metadata"
if str(_CARGO_METADATA_DIR) not in sys.path:
    sys.path.insert(0, str(_CARGO_METADATA_DIR))

from workspace import MetadataError, load_metadata  # noqa: E402


class SbomError(RuntimeError):
    """The required SBOM files are missing or invalid."""


# Cargo target kinds whose target name can be an SBOM root component name.
# Example, test, bench, and build-script targets are never a release SBOM root.
_COMPONENT_TARGET_KINDS = frozenset(
    {"bin", "lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}
)


def _default_metadata_loader(package_root: Path) -> dict:
    """Return Cargo metadata for the workspace that owns ``package_root``.

    ``--no-deps`` keeps this hermetic: Cargo reads the workspace manifests only,
    so it never resolves dependencies or reaches the network.
    """
    return load_metadata(Path(package_root), no_deps=True, locked=False)


def package_identity(metadata: dict, package_name: str) -> tuple[set[str], str]:
    """Return the accepted SBOM root names and the version for a package.

    The accepted names are the package name and every non-example binary or
    library target name. Cargo derives a library crate name from the package
    name by replacing hyphens, so ``tacacsrs-bash-plugin`` owns the library
    target ``tacacsrs_bash_plugin``. Because Cargo metadata is the authority, a
    custom target name is accepted and an unrelated name is rejected.
    """
    packages = metadata.get("packages") if isinstance(metadata, dict) else None
    if not isinstance(packages, list):
        raise SbomError("cargo metadata did not return a package list")
    matches = [
        package
        for package in packages
        if isinstance(package, dict) and package.get("name") == package_name
    ]
    if len(matches) != 1:
        raise SbomError(
            f"cargo metadata did not identify exactly one package named "
            f"{package_name!r} (found {len(matches)})"
        )
    package = matches[0]
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise SbomError(f"cargo metadata has no version for {package_name!r}")
    accepted = {package_name}
    for target in package.get("targets") or []:
        if not isinstance(target, dict):
            continue
        name = target.get("name")
        kinds = target.get("kind") or []
        if isinstance(name, str) and any(
            kind in _COMPONENT_TARGET_KINDS for kind in kinds
        ):
            accepted.add(name)
    return accepted, version


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
    metadata_loader=_default_metadata_loader,
) -> list[Path]:
    """Validate both required formats before writing sanitized copies.

    Cargo metadata is the authority for the accepted root component names and
    the version. An SBOM root may be the package name or a non-example target
    name. When ``expected_version`` is given it must equal the package version;
    otherwise the package version from Cargo metadata is used.
    """
    if not basename or Path(basename).name != basename or "\\" in basename:
        raise SbomError("SBOM basename must be a file name")
    accepted_names, package_version = package_identity(
        metadata_loader(Path(package_root)), package_name
    )
    if expected_version is not None and expected_version != package_version:
        raise SbomError(
            f"--expected-version {expected_version!r} does not match the "
            f"{package_name} package version {package_version!r}"
        )
    prepared = []
    identities = []
    for output_format in ("json", "xml"):
        candidates = []
        for path in sorted(Path(package_root).glob(f"*.cdx.{output_format}")):
            if path.is_symlink() or not path.is_file():
                raise SbomError(f"SBOM must be a regular file: {path}")
            document = json.loads(path.read_text(encoding="utf-8")) if output_format == "json" else ET.parse(path).getroot()
            identity = component_identity(document, output_format)
            if identity[0] in accepted_names:
                candidates.append((document, identity))
        if len(candidates) != 1:
            raise SbomError(f"expected one {output_format} SBOM root component for {package_name}, found {len(candidates)}")
        document, identity = candidates[0]
        if identity[1] != package_version:
            raise SbomError(
                f"SBOM version does not match {package_name}: {identity[1]!r} "
                f"(expected {package_version!r})"
            )
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
    except (SbomError, MetadataError, OSError, ValueError, ET.ParseError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())