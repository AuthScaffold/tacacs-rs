"""Tests for check_architecture.py.

These tests are hermetic. They build synthetic Cargo metadata that mirrors the
real workspace shape and inject each failure category. They do not call Cargo
and do not import the sibling ``cargo-metadata`` helper.

The golden metadata is derived from the real ``rules.json`` allowlist, so the
positive case stays in step with the shipped rules.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

# Import the sibling module (pytest prepends the test directory to sys.path).
from check_architecture import (
    load_rules,
    normal_dependency_closure,
    production_workspace_edges,
    validate_all,
    validate_forbidden_guards,
    validate_rules_coverage,
    validate_workspace_edges,
)

RULES_PATH = Path(__file__).resolve().parent / "rules.json"


def test_unknown_resolved_dependency_kind_is_rejected():
    metadata = build_metadata({"demo": [dep("other", kind="unknown")], "other": []}, default_members=["demo"])
    rules = {"allowed_workspace_edges": {"demo": [], "other": []}}
    assert any("unknown dependency kind" in error for error in validate_all(metadata, rules))


@pytest.mark.parametrize("metadata", [{}, {"resolve": None}, {"resolve": {"nodes": []}}])
def test_incomplete_metadata_cannot_pass(metadata):
    assert validate_all(metadata, {"allowed_workspace_edges": {}})

# The 14 supported-core default members, as in the root Cargo.toml.
CORE_DEFAULT_MEMBERS = [
    "tacacsrs-protocol",
    "tacacsrs-secrets",
    "tacacsrs-networking",
    "tacacsrs-ipc",
    "tacacsrs-unix-socket",
    "tacacsrs-agent",
    "tacacsrs-config",
    "tacacsrs-credential-resolution",
    "tacacsrs-credential-http",
    "tacacsrs-sonic",
    "tacacsrs-bash-plugin",
    "tacon",
    "tacacsrs-agentd",
    "tacacsrs-agent-health",
]


# ---------------------------------------------------------------------------
# Synthetic metadata builder
# ---------------------------------------------------------------------------

_WS_PREFIX = "path+file:///workspace/"
_EXT_PREFIX = "registry+https://github.com/rust-lang/crates.io-index#"


def _ws_id(name: str) -> str:
    return f"{_WS_PREFIX}{name}#0.0.0"


def _ext_id(name: str) -> str:
    return f"{_EXT_PREFIX}{name}@1.0.0"


def _lib_name(name: str) -> str:
    return name.replace("-", "_")


def dep(name, *, kind=None, alias=None, target=None, external=False):
    """Describe one dependency edge for the metadata builder."""
    return {
        "_dep": name,
        "_kind": kind,
        "_alias": alias,
        "_target": target,
        "_external": external,
    }


def build_metadata(edges, *, default_members, targets=None):
    """Build standard Cargo metadata from an edge specification.

    ``edges`` maps each workspace package name to a list of edges. A plain
    string is a normal workspace edge. A ``dep(...)`` dict can set the kind,
    alias, platform, or mark an external crate.
    """
    targets = targets or {}
    member_names = list(edges.keys())

    external_names = set()
    for edge_list in edges.values():
        for edge in edge_list:
            if isinstance(edge, dict) and edge["_external"]:
                external_names.add(edge["_dep"])

    packages = []
    for name in member_names:
        packages.append(
            {
                "id": _ws_id(name),
                "name": name,
                "version": "0.0.0-dev",
                "targets": targets.get(
                    name,
                    [{"kind": ["lib"], "crate_types": ["lib"], "name": _lib_name(name)}],
                ),
            }
        )
    for name in sorted(external_names):
        packages.append(
            {
                "id": _ext_id(name),
                "name": name,
                "version": "1.0.0",
                "targets": [
                    {"kind": ["lib"], "crate_types": ["lib"], "name": _lib_name(name)}
                ],
            }
        )

    def make_dep(edge):
        if isinstance(edge, str):
            edge = dep(edge)
        pkg_id = _ext_id(edge["_dep"]) if edge["_external"] else _ws_id(edge["_dep"])
        return {
            "name": edge["_alias"] or _lib_name(edge["_dep"]),
            "pkg": pkg_id,
            "dep_kinds": [{"kind": edge["_kind"], "target": edge["_target"]}],
        }

    nodes = []
    for name in member_names:
        node_deps = [make_dep(edge) for edge in edges[name]]
        nodes.append(
            {
                "id": _ws_id(name),
                "deps": node_deps,
                "dependencies": [nd["pkg"] for nd in node_deps],
            }
        )
    for name in sorted(external_names):
        nodes.append({"id": _ext_id(name), "deps": [], "dependencies": []})

    return {
        "packages": packages,
        "workspace_members": [_ws_id(name) for name in member_names],
        "workspace_default_members": [_ws_id(name) for name in default_members],
        "resolve": {"root": None, "nodes": nodes},
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rules():
    return load_rules(RULES_PATH)


@pytest.fixture()
def golden_edges(rules):
    """A normal-edge graph that exactly matches the allowlist."""
    return {name: list(targets) for name, targets in rules["allowed_workspace_edges"].items()}


@pytest.fixture()
def golden_metadata(golden_edges):
    return build_metadata(golden_edges, default_members=CORE_DEFAULT_MEMBERS)


# ---------------------------------------------------------------------------
# Positive case
# ---------------------------------------------------------------------------

def test_golden_metadata_passes(golden_metadata, rules):
    assert validate_all(golden_metadata, rules) == []


def test_rules_cover_seventeen_packages(rules):
    assert len(rules["allowed_workspace_edges"]) == 17


# ---------------------------------------------------------------------------
# Workspace-edge allowlist
# ---------------------------------------------------------------------------

def test_unknown_workspace_member_is_rejected(golden_edges, rules):
    edges = copy.deepcopy(golden_edges)
    edges["tacacsrs-sneaky"] = ["tacacsrs-secrets"]
    metadata = build_metadata(
        edges, default_members=CORE_DEFAULT_MEMBERS + ["tacacsrs-sneaky"]
    )
    errors = validate_all(metadata, rules)
    assert any("tacacsrs-sneaky" in error for error in errors)


def test_unlisted_production_edge_is_rejected(golden_edges, rules):
    edges = copy.deepcopy(golden_edges)
    # protocol must not depend on networking.
    edges["tacacsrs-protocol"] = ["tacacsrs-secrets", "tacacsrs-networking"]
    errors = validate_workspace_edges(
        build_metadata(edges, default_members=CORE_DEFAULT_MEMBERS), rules
    )
    assert any(
        "'tacacsrs-protocol' -> 'tacacsrs-networking'" in error for error in errors
    )


def test_missing_workspace_member_flags_rule_drift(golden_edges, rules):
    edges = copy.deepcopy(golden_edges)
    del edges["tacacsrs-sonic"]
    for source in edges:
        edges[source] = [
            edge
            for edge in edges[source]
            if (edge if isinstance(edge, str) else edge["_dep"]) != "tacacsrs-sonic"
        ]
    default_members = [m for m in CORE_DEFAULT_MEMBERS if m != "tacacsrs-sonic"]
    errors = validate_rules_coverage(
        build_metadata(edges, default_members=default_members), rules
    )
    assert any("tacacsrs-sonic" in error for error in errors)


# ---------------------------------------------------------------------------
# Development and build edges are ignored for production rules
# ---------------------------------------------------------------------------

def test_dev_and_build_edges_are_ignored(golden_edges, rules):
    edges = copy.deepcopy(golden_edges)
    # The real agent has a development-only edge to the IPC crate.
    edges["tacacsrs-agent"].append(dep("tacacsrs-ipc", kind="dev"))
    # Forbidden crates are fine on development and build edges.
    edges["tacacsrs-protocol"].append(dep("tokio", kind="dev", external=True))
    edges["tacacsrs-protocol"].append(dep("tonic", kind="build", external=True))
    metadata = build_metadata(edges, default_members=CORE_DEFAULT_MEMBERS)
    assert validate_all(metadata, rules) == []


def test_production_edges_exclude_dev_and_build(golden_edges):
    edges = copy.deepcopy(golden_edges)
    edges["tacacsrs-agent"].append(dep("tacacsrs-ipc", kind="dev"))
    metadata = build_metadata(edges, default_members=CORE_DEFAULT_MEMBERS)
    assert "tacacsrs-ipc" not in production_workspace_edges(metadata)["tacacsrs-agent"]


# ---------------------------------------------------------------------------
# Platform filtering: a declared edge that resolves away is not required
# ---------------------------------------------------------------------------

def test_platform_filtered_edges_are_not_required(golden_edges, rules):
    edges = copy.deepcopy(golden_edges)
    # Windows resolves tacon without its Linux-only IPC edge, and session-wrapper
    # with no dependencies at all.
    edges["tacon"] = [edge for edge in edges["tacon"] if edge != "tacacsrs-ipc"]
    edges["session-wrapper"] = []
    metadata = build_metadata(edges, default_members=CORE_DEFAULT_MEMBERS)
    assert validate_all(metadata, rules) == []


def test_linux_only_edge_is_allowed_when_present(golden_edges, rules):
    # The golden graph includes tacon -> tacacsrs-ipc, the Linux-only edge.
    assert "tacacsrs-ipc" in golden_edges["tacon"]
    metadata = build_metadata(golden_edges, default_members=CORE_DEFAULT_MEMBERS)
    assert validate_workspace_edges(metadata, rules) == []


# ---------------------------------------------------------------------------
# External and transitive dependency guards
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "source,token,guard",
    [
        ("tacacsrs-protocol", "tokio", "pure-protocol"),
        ("tacacsrs-protocol", "openssl", "pure-protocol"),
        ("tacacsrs-credential-resolution", "openssl", "provider-neutral-credentials"),
        ("tacacsrs-networking", "tonic", "schema-free-networking"),
        ("tacacsrs-config", "clap", "configuration-adapter"),
        ("tacacsrs-agent", "tonic", "ipc-independent-agent"),
        ("tacacsrs-ipc", "redis", "runtime-independent-ipc"),
        ("tacacsrs-unix-socket", "openssl", "unix-socket-leaf"),
        ("tacon", "regorus", "supported-core"),
    ],
)
def test_forbidden_dependency_is_rejected(golden_edges, rules, source, token, guard):
    edges = copy.deepcopy(golden_edges)
    edges[source].append(dep(token, external=True))
    errors = validate_forbidden_guards(
        build_metadata(edges, default_members=CORE_DEFAULT_MEMBERS), rules
    )
    assert any(f"[{guard}]" in error and token in error for error in errors)


def test_forbidden_prefix_match_catches_related_crate(golden_edges, rules):
    # The protocol guard forbids "tonic", which must also match "tonic-health".
    edges = copy.deepcopy(golden_edges)
    edges["tacacsrs-protocol"].append(dep("tonic-health", external=True))
    errors = validate_forbidden_guards(
        build_metadata(edges, default_members=CORE_DEFAULT_MEMBERS), rules
    )
    assert any("[pure-protocol]" in error and "tonic-health" in error for error in errors)


def test_forbidden_dependency_is_detected_transitively(golden_edges, rules):
    edges = copy.deepcopy(golden_edges)
    # protocol -> secrets -> tokio.
    edges["tacacsrs-secrets"].append(dep("tokio", external=True))
    errors = validate_forbidden_guards(
        build_metadata(edges, default_members=CORE_DEFAULT_MEMBERS), rules
    )
    assert any("[pure-protocol]" in error and "tokio" in error for error in errors)


def test_supported_core_ignores_experimental_crates(golden_metadata, rules):
    # session-wrapper, the emulator, and the emulatord are members but not
    # default members, so the supported-core guard must stay quiet.
    errors = validate_forbidden_guards(golden_metadata, rules)
    assert errors == []


def test_supported_core_rejects_experimental_edge_from_core(golden_edges, rules):
    edges = copy.deepcopy(golden_edges)
    # A core default member must not reach an experimental crate in production.
    edges["tacacsrs-agentd"].append("session-wrapper")
    errors = validate_forbidden_guards(
        build_metadata(edges, default_members=CORE_DEFAULT_MEMBERS), rules
    )
    assert any("[supported-core]" in error and "session-wrapper" in error for error in errors)


# ---------------------------------------------------------------------------
# Renamed dependencies resolve through the package id
# ---------------------------------------------------------------------------

def test_renamed_workspace_dependency_resolves_by_id(golden_edges, rules):
    edges = copy.deepcopy(golden_edges)
    edges["tacacsrs-agent"] = [
        edge for edge in edges["tacacsrs-agent"] if edge != "tacacsrs-config"
    ]
    edges["tacacsrs-agent"].append(dep("tacacsrs-config", alias="cfg"))
    metadata = build_metadata(edges, default_members=CORE_DEFAULT_MEMBERS)
    assert validate_all(metadata, rules) == []


def test_renamed_forbidden_dependency_is_still_detected(golden_edges, rules):
    edges = copy.deepcopy(golden_edges)
    edges["tacacsrs-protocol"].append(dep("tokio", alias="async_rt", external=True))
    errors = validate_forbidden_guards(
        build_metadata(edges, default_members=CORE_DEFAULT_MEMBERS), rules
    )
    assert any("[pure-protocol]" in error and "tokio" in error for error in errors)


# ---------------------------------------------------------------------------
# Closure helper
# ---------------------------------------------------------------------------

def test_normal_closure_includes_roots_and_transitive(golden_metadata):
    root = _ws_id("tacacsrs-agentd")
    reachable = normal_dependency_closure(golden_metadata, [root])
    assert "tacacsrs-agentd" in reachable
    assert "tacacsrs-protocol" in reachable
    assert "tacacsrs-secrets" in reachable
