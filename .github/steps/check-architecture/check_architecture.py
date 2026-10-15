#!/usr/bin/env python3
"""Enforce the tacacs-rs production dependency architecture from Cargo metadata.

This validator reads resolved, platform-filtered Cargo metadata and checks it
against the rules in ``rules.json``. It enforces three things:

1. A strict allowlist of production (normal) workspace-to-workspace edges. Any
   unknown workspace package or any production edge that is not in the
   allowlist is an error.
2. The external and transitive dependency guards that previously lived in
   ``.github/steps/run-tests/action.yml``. For example, the protocol package
   must not reach Tokio or OpenSSL, and the IPC package must not reach the
   agent.
3. The supported-core exclusion. The production closure of the workspace
   default members must not reach the experimental crates, Rego, or libseccomp.

The pure validation functions take standard ``cargo metadata`` JSON as a plain
dict. They have no Cargo or filesystem side effects, so synthetic tests can
inject metadata directly. The command-line entry point loads real metadata
through the sibling ``cargo-metadata`` helper.

Design notes:

* Edges come from ``resolve.nodes[].deps[].dep_kinds`` and the platform-filtered
  resolve graph, not from the declared manifest dependency list. Only normal
  edges count for production rules. Development-only and build-only edges are
  ignored.
* Dependency identity resolves through the package id in ``deps[].pkg``, so an
  aliased or renamed dependency still maps to its real crate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Metadata accessors
# ---------------------------------------------------------------------------

def _index_packages(metadata: dict) -> dict:
    """Map every package id to its package record."""
    return {pkg["id"]: pkg for pkg in metadata.get("packages", [])}


def _workspace_ids(metadata: dict) -> set:
    """Return the set of workspace member package ids."""
    return set(metadata.get("workspace_members", []))


def _default_member_ids(metadata: dict) -> set:
    """Return the set of workspace default-member package ids."""
    return set(metadata.get("workspace_default_members", []))


def _nodes_by_id(metadata: dict) -> dict:
    """Map every resolve-node id to its node."""
    resolve = metadata.get("resolve") or {}
    return {node["id"]: node for node in resolve.get("nodes", [])}


def _dep_is_normal(dep: dict) -> bool:
    """Return True when a resolved dependency has a normal (runtime) edge.

    Development-only and build-only edges are excluded. When a metadata source
    omits ``dep_kinds`` the edge is treated as normal.
    """
    kinds = dep.get("dep_kinds")
    if not kinds:
        return True
    return any(kind.get("kind") is None for kind in kinds)


def workspace_member_names(metadata: dict) -> set:
    """Return the set of workspace member package names."""
    packages = _index_packages(metadata)
    names = set()
    for pkg_id in _workspace_ids(metadata):
        pkg = packages.get(pkg_id)
        if pkg is not None:
            names.add(pkg["name"])
    return names


def production_workspace_edges(metadata: dict) -> dict:
    """Map each workspace package name to its production workspace dependencies.

    Only normal edges to other workspace members are included. The metadata is
    already platform filtered, so target-specific edges appear only for the
    resolved platform.
    """
    packages = _index_packages(metadata)
    workspace_ids = _workspace_ids(metadata)
    edges: dict = {}
    for node in (metadata.get("resolve") or {}).get("nodes", []):
        node_id = node.get("id")
        if node_id not in workspace_ids:
            continue
        source = packages[node_id]["name"]
        targets = edges.setdefault(source, set())
        for dep in node.get("deps", []):
            if not _dep_is_normal(dep):
                continue
            target_id = dep.get("pkg")
            if target_id in workspace_ids and target_id in packages:
                targets.add(packages[target_id]["name"])
    # Every workspace member appears, even leaf packages with no production edge.
    for name in workspace_member_names(metadata):
        edges.setdefault(name, set())
    return edges


def normal_dependency_closure(metadata: dict, root_ids: Iterable[str]) -> set:
    """Return the names of every package reachable through normal edges.

    The roots are included. Development and build edges are not followed, so
    development-only dependency cycles do not affect the result.
    """
    nodes = _nodes_by_id(metadata)
    packages = _index_packages(metadata)
    visited: set = set()
    stack = list(root_ids)
    while stack:
        node_id = stack.pop()
        if node_id in visited:
            continue
        visited.add(node_id)
        node = nodes.get(node_id)
        if node is None:
            continue
        for dep in node.get("deps", []):
            if not _dep_is_normal(dep):
                continue
            target_id = dep.get("pkg")
            if target_id and target_id not in visited:
                stack.append(target_id)
    names = set()
    for node_id in visited:
        pkg = packages.get(node_id)
        if pkg is not None:
            names.add(pkg["name"])
    return names


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_rules_coverage(metadata: dict, rules: dict) -> list:
    """Check that the rules cover exactly the workspace members."""
    errors: list = []
    allowed = rules.get("allowed_workspace_edges", {})
    known = set(allowed.keys())
    members = workspace_member_names(metadata)
    for name in sorted(members - known):
        errors.append(
            f"workspace package '{name}' has no architecture rule; "
            "add it to allowed_workspace_edges in rules.json"
        )
    for name in sorted(known - members):
        errors.append(
            f"architecture rule names '{name}', which is not a workspace member; "
            "update rules.json to match the workspace"
        )
    return errors


def validate_workspace_edges(metadata: dict, rules: dict) -> list:
    """Reject production workspace edges that are not in the allowlist."""
    errors: list = []
    allowed = rules.get("allowed_workspace_edges", {})
    known = set(allowed.keys())
    edges = production_workspace_edges(metadata)
    for source in sorted(edges):
        if source not in known:
            continue  # reported by validate_rules_coverage
        allowed_targets = set(allowed.get(source, []))
        for target in sorted(edges[source]):
            if target not in known:
                errors.append(
                    f"production edge '{source}' -> '{target}' targets an "
                    "unknown workspace package"
                )
            elif target not in allowed_targets:
                errors.append(
                    f"production edge '{source}' -> '{target}' is not in the "
                    f"allowlist for '{source}'"
                )
    return errors


def _forbidden_match(name: str, token: str) -> bool:
    """Return True when a package name matches a forbidden token.

    The match is the package name itself or any crate under the ``token-``
    prefix. This mirrors the ``^token[ -]`` word boundary that the previous awk
    guards used, so ``tonic`` also matches ``tonic-health``.
    """
    return name == token or name.startswith(token + "-")


def _resolve_guard_roots(guard: dict, metadata: dict) -> tuple:
    """Resolve the root ids and a label for one guard and collect root errors."""
    errors: list = []
    names_to_ids: dict = {}
    for pkg in metadata.get("packages", []):
        names_to_ids.setdefault(pkg["name"], []).append(pkg["id"])
    roots_spec = guard.get("roots")
    name = guard.get("name", "<unnamed>")
    if isinstance(roots_spec, str):
        if roots_spec in ("default-members", "@default-members"):
            label = "the supported core (workspace default members)"
            return set(_default_member_ids(metadata)), label, errors
        ids = names_to_ids.get(roots_spec, [])
        if not ids:
            errors.append(
                f"[{name}] guard root package '{roots_spec}' is not in the metadata"
            )
        return set(ids), f"'{roots_spec}'", errors
    root_ids: set = set()
    labels = []
    for root_name in roots_spec or []:
        ids = names_to_ids.get(root_name, [])
        if not ids:
            errors.append(
                f"[{name}] guard root package '{root_name}' is not in the metadata"
            )
        root_ids.update(ids)
        labels.append(f"'{root_name}'")
    return root_ids, ", ".join(labels), errors


def validate_forbidden_guards(metadata: dict, rules: dict) -> list:
    """Run the external and transitive dependency guards."""
    errors: list = []
    for guard in rules.get("forbidden_dependency_guards", []):
        name = guard.get("name", "<unnamed>")
        root_ids, root_label, root_errors = _resolve_guard_roots(guard, metadata)
        errors.extend(root_errors)
        reachable = normal_dependency_closure(metadata, root_ids)
        matched: dict = {}
        for token in guard.get("forbidden", []):
            for pkg_name in reachable:
                if pkg_name and _forbidden_match(pkg_name, token):
                    matched.setdefault(pkg_name, token)
        for pkg_name in sorted(matched):
            errors.append(
                f"[{name}] forbidden dependency '{pkg_name}' "
                f"(matched rule '{matched[pkg_name]}') is reachable through "
                f"production edges from {root_label}"
            )
    return errors


_LIBRARY_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}


def _has_product_target(pkg: dict, artifact_name: str, artifact_kind: str) -> bool:
    """Return True when a package builds the requested artifact target.

    ``bin`` requires a binary target. Any other kind requires a library target
    of that exact crate type, for example ``cdylib``.
    """
    for target in pkg.get("targets", []):
        if target.get("name") != artifact_name:
            continue
        kinds = set(target.get("kind", [])) | set(target.get("crate_types", []))
        if artifact_kind == "bin":
            if "bin" in target.get("kind", []):
                return True
        elif artifact_kind in kinds:
            return True
    return False


def verify_product_matrix(products: Iterable[dict], metadata: dict) -> list:
    """Verify each release product against the workspace metadata.

    The caller supplies the product set. This function does not generate it.
    Each product must name a workspace member that builds a target of the
    requested artifact kind (``bin`` or a library crate type such as
    ``cdylib``).
    """
    errors: list = []
    packages = _index_packages(metadata)
    members: dict = {}
    for pkg_id in _workspace_ids(metadata):
        pkg = packages.get(pkg_id)
        if pkg is not None:
            members[pkg["name"]] = pkg
    for product in products:
        package_name = product.get("package_name")
        artifact_name = product.get("artifact_name")
        artifact_kind = product.get("artifact_kind")
        pkg = members.get(package_name)
        if pkg is None:
            errors.append(
                f"product package '{package_name}' is not a workspace member"
            )
            continue
        if not _has_product_target(pkg, artifact_name, artifact_kind):
            errors.append(
                f"product '{package_name}' has no {artifact_kind} target named "
                f"'{artifact_name}'"
            )
    return errors


def validate_all(
    metadata: dict, rules: dict, products: Iterable[dict] | None = None
) -> list:
    """Run every architecture validation and return a flat list of errors."""
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        return ["architecture validation requires resolved Cargo metadata, not --no-deps output"]
    members = _workspace_ids(metadata)
    nodes = _nodes_by_id(metadata)
    packages = _index_packages(metadata)
    if not members or not metadata.get("workspace_default_members"):
        return ["Cargo metadata must identify workspace members and default members"]
    if not members.issubset(nodes) or not members.issubset(packages):
        return ["Cargo metadata is missing workspace package records or resolved nodes"]
    for node in nodes.values():
        if node["id"] not in packages:
            return ["Cargo metadata has a resolved node without a package record"]
        for dependency in node.get("deps", []):
            if dependency.get("pkg") not in packages or dependency.get("pkg") not in nodes:
                return ["Cargo metadata has an unresolved dependency identity"]
            for kind in dependency.get("dep_kinds", []):
                if kind.get("kind") not in (None, "dev", "build"):
                    return ["Cargo metadata has an unknown dependency kind"]
    errors: list = []
    errors.extend(validate_rules_coverage(metadata, rules))
    errors.extend(validate_workspace_edges(metadata, rules))
    errors.extend(validate_forbidden_guards(metadata, rules))
    if products is not None:
        errors.extend(verify_product_matrix(products, metadata))
    return errors


def architecture_summary(metadata: dict, rules: dict, products: Any) -> str:
    """Return a short success summary."""
    members = workspace_member_names(metadata)
    edges = production_workspace_edges(metadata)
    edge_count = sum(len(targets) for targets in edges.values())
    guard_count = len(rules.get("forbidden_dependency_guards", []))
    lines = [
        "Architecture validation passed.",
        f"  workspace packages: {len(members)}",
        f"  production workspace edges: {edge_count}",
        f"  external dependency guards: {guard_count}",
    ]
    if products is not None:
        lines.append(f"  verified products: {len(list(products))}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Command-line entry point
# ---------------------------------------------------------------------------

def load_rules(path: str | Path) -> dict:
    """Load the architecture rules from a JSON file."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_sibling_metadata_helper():
    """Import the cargo-metadata helper from the sibling step directory."""
    helper_dir = Path(__file__).resolve().parent.parent / "cargo-metadata"
    if str(helper_dir) not in sys.path:
        sys.path.insert(0, str(helper_dir))
    try:
        import workspace as workspace_helper  # noqa: E402  deferred sibling import
    except ImportError as exc:
        raise SystemExit(
            f"error: cannot import the cargo-metadata helper from {helper_dir}: {exc}"
        )
    return workspace_helper


def load_workspace_metadata(
    workspace: str | Path, target: str | None, all_features: bool
) -> dict:
    """Load resolved, platform-filtered metadata through the sibling helper."""
    helper = _load_sibling_metadata_helper()
    return helper.load_metadata(
        Path(workspace), target=target, all_features=all_features, locked=True
    )


def _read_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Enforce the tacacs-rs production dependency allowlist and the "
            "external dependency guards from resolved Cargo metadata."
        )
    )
    parser.add_argument("--workspace", default=".", help="Workspace root directory.")
    parser.add_argument("--target", help="Rust target triple for platform filtering.")
    parser.add_argument(
        "--all-features",
        action="store_true",
        help="Resolve metadata with all features.",
    )
    parser.add_argument(
        "--rules",
        default=str(Path(__file__).resolve().parent / "rules.json"),
        help="Path to the architecture rules JSON file.",
    )
    parser.add_argument(
        "--products",
        help="Path to a JSON file with the release product matrix to verify.",
    )
    parser.add_argument(
        "--metadata-file",
        help="Path to pre-resolved cargo metadata JSON. Bypasses the helper.",
    )
    parser.add_argument(
        "--metadata-report",
        help="Path to write the resolved metadata as plain JSON.",
    )
    args = parser.parse_args(argv)

    rules = load_rules(args.rules)

    if args.metadata_file:
        metadata = _read_json_file(args.metadata_file)
    else:
        if not args.target:
            parser.error("--target is required unless --metadata-file is given")
        metadata = load_workspace_metadata(args.workspace, args.target, args.all_features)

    if args.metadata_report:
        with open(args.metadata_report, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, sort_keys=True)

    products = _read_json_file(args.products) if args.products else None

    errors = validate_all(metadata, rules, products=products)

    if errors:
        print("Architecture validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(architecture_summary(metadata, rules, products))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
