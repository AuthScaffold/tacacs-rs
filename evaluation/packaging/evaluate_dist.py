#!/usr/bin/env python3
"""Evaluate local cargo-dist plans against the committed product registry."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

import tomlkit


SOURCE = "d3629b2ee0f78c862e7a4d8fb7558622c6f6591a"
VERSION = "0.33.0"
BINARY_SHA256 = "1ecb03737291ce5abf0e08b411f34812b974de4e405a33cdc53e8db39d70ee98"


def run(argv: list[str], cwd: Path, output: Path) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    output.with_suffix(".stdout").write_text(result.stdout)
    output.with_suffix(".stderr").write_text(result.stderr)
    output.with_suffix(".exit").write_text(f"{result.returncode}\n")
    return result


def configure(workspace: Path, products: list[dict]) -> None:
    root_path = workspace / "Cargo.toml"
    root = tomlkit.parse(root_path.read_text())
    root["profile"]["dist"] = {"inherits": "release"}
    root["workspace"]["metadata"] = {
        "dist": {
            "cargo-dist-version": VERSION,
            "dist": False,
            "ci": [],
            "hosting": [],
            "installers": [],
            "source-tarball": False,
            "cargo-cyclonedx": True,
            "auto-includes": False,
            "unix-archive": ".tar.gz",
            "windows-archive": ".zip",
        }
    }
    root_path.write_text(tomlkit.dumps(root))
    packages = sorted({product["package_root"] for product in products})
    for package in packages:
        records = [product for product in products if product["package_root"] == package]
        manifest_path = workspace / package / "Cargo.toml"
        manifest = tomlkit.parse(manifest_path.read_text())
        # This fixture override exercises the documented internal-package route.
        manifest["package"]["publish"] = False
        metadata = manifest["package"].setdefault("metadata", {})
        metadata["dist"] = {
            "dist": True,
            "targets": sorted({record["target"] for record in records}),
            "package-libraries": sorted(
                {record["artifact_kind"] for record in records if record["artifact_kind"] == "cdylib"}
            ),
        }
        manifest_path.write_text(tomlkit.dumps(manifest))


def summarize(plan: dict) -> dict:
    return {
        "releases": [
            {key: release.get(key) for key in ("app_name", "app_version", "artifacts", "hosting")}
            for release in plan.get("releases", [])
        ],
        "artifacts": {
            name: {key: artifact.get(key) for key in ("kind", "target_triples", "assets")}
            for name, artifact in plan.get("artifacts", {}).items()
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source_root = Path(__file__).resolve().parents[2]
    tool = args.tool.resolve(strict=True)
    output = args.output.resolve()
    if output == source_root or source_root in output.parents:
        raise SystemExit("The evidence directory must be outside the source checkout.")
    output.mkdir(parents=True, exist_ok=False)
    version = subprocess.run([str(tool), "--version"], capture_output=True, text=True, check=True)
    assert version.stdout.strip() == f"cargo-dist {VERSION}", version.stdout
    binary_hash = hashlib.sha256(tool.read_bytes()).hexdigest()
    assert binary_hash == BINARY_SHA256, binary_hash
    workspace = output / "source"
    workspace.mkdir()
    archive = subprocess.run(
        ["git", "archive", SOURCE], cwd=source_root, capture_output=True, check=True
    )
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as contents:
        contents.extractall(workspace, filter="data")
    registry_result = run(
        ["python", ".github/steps/cargo-metadata/products.py", "--workspace", "."],
        workspace,
        output / "registry",
    )
    assert registry_result.returncode == 0, registry_result.stderr
    products = json.loads(registry_result.stdout)
    registry = json.loads((workspace / ".github/products.json").read_text())
    assert len(products) == len(registry["products"]) == 5
    configure(workspace, registry["products"])
    configured = run(
        [str(tool), "plan", "--allow-dirty", "--output-format=json"],
        workspace,
        output / "configured-plan",
    )
    assert configured.returncode == 0, configured.stderr
    plan = json.loads(configured.stdout)
    (output / "plan-summary.json").write_text(json.dumps(summarize(plan), indent=2) + "\n")
    releases = plan["releases"]
    expected_packages = {product["package_name"] for product in products}
    assert {release["app_name"] for release in releases} == expected_packages
    assert all(not release.get("hosting") for release in releases)
    artifacts = plan["artifacts"]
    archives = {
        name: artifact for name, artifact in artifacts.items()
        if artifact["kind"] == "executable-zip"
    }
    expected_archives = {
        f'{product["package_name"]}-{product["target"]}.'
        + ("zip" if product["target"].endswith("windows-msvc") else "tar.gz")
        for product in products
    }
    assert set(archives) == expected_archives, set(archives)
    expected_payloads = {
        (
            product["target"], product["artifact_name"],
            "c_dynamic_library" if product["artifact_kind"] == "cdylib" else "executable",
        )
        for product in products
    }
    actual_payloads = {
        (target, asset["name"], asset["kind"])
        for artifact in archives.values()
        for target in artifact["target_triples"]
        for asset in artifact["assets"]
    }
    assert actual_payloads == expected_payloads, actual_payloads
    sboms = {name for name, artifact in artifacts.items() if artifact["kind"] == "sbom"}
    assert sboms == {f"{package}.cdx.xml" for package in expected_packages}, sboms
    assert not any(name.endswith(".cdx.json") for name in artifacts)
    assert not any(artifact["kind"] == "symbols" for artifact in artifacts.values())
    assert not any(
        "build-provenance" in asset["name"]
        for artifact in archives.values() for asset in artifact["assets"]
    )
    assert not (workspace / ".github/workflows/release.yml").exists()
    versions = {
        "tacon": "2026.1020.18",
        "tacacsrs-agentd": "2026.1020.18",
        "tacacsrs-agent-health": "2026.1020.18",
        "tacacsrs-bash-plugin": "1.2.3",
    }
    hydrated = run(
        [
            "python",
            ".github/steps/inject-versions/hydrate_versions.py",
            "--workspace",
            ".",
            "--versions",
            json.dumps(versions),
        ],
        workspace,
        output / "hydrate",
    )
    assert hydrated.returncode == 0, hydrated.stderr
    for package, version in versions.items():
        # This argument simulates version selection. It creates no Git tag.
        tag = f"{package}-v{version}" if package == "tacacsrs-bash-plugin" else f"{package}-{version}"
        result = run(
            [
                str(tool), "plan", "--allow-dirty", "--output-format=json",
                "--tag", tag,
            ],
            workspace,
            output / f"hydrated-{package}",
        )
        assert result.returncode == 0, result.stderr
        selected = json.loads(result.stdout)["releases"]
        assert len(selected) == 1, selected
        assert selected[0]["app_name"] == package, selected
        assert selected[0]["app_version"] == version, selected
    summary = {
        "source": SOURCE,
        "tool_version": VERSION,
        "tool_sha256": binary_hash,
        "registry_records": len(products),
        "planned_archives": len(archives),
        "planned_xml_sboms": len(sboms),
        "planned_json_sboms": 0,
        "planned_symbol_artifacts": 0,
        "planned_embedded_provenance": 0,
        "hydrated_singular_plans": len(versions),
        "acceptance": "NON-ADOPTION: built-in plans lack required symbols and JSON SBOMs.",
        "scope": "Local plans only. No Git refs, compilation, publication, or equivalence proof.",
    }
    (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
