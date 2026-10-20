"""Independent release policy goldens and product registry contracts."""

import copy
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[3]

# This policy is independent of the production registry.
EXPECTED = [
    {"os": "ubuntu-latest", "target": "x86_64-unknown-linux-gnu", "asset_name": "tacon-linux-gnu-x86_64", "package_name": "tacon", "package_root": "executables/tacon", "artifact_name": "tacon", "artifact_kind": "bin", "features": "", "sbom_describe": "binaries"},
    {"os": "ubuntu-latest", "target": "x86_64-unknown-linux-gnu", "asset_name": "tacacsrs-agentd-linux-gnu-x86_64", "package_name": "tacacsrs-agentd", "package_root": "executables/tacacsrs_agentd", "artifact_name": "tacacsrs-agentd", "artifact_kind": "bin", "features": "", "sbom_describe": "binaries"},
    {"os": "ubuntu-latest", "target": "x86_64-unknown-linux-gnu", "asset_name": "tacacsrs-agent-health-linux-gnu-x86_64", "package_name": "tacacsrs-agent-health", "package_root": "executables/tacacsrs_agent_health", "artifact_name": "tacacsrs-agent-health", "artifact_kind": "bin", "features": "", "sbom_describe": "binaries"},
    {"os": "ubuntu-latest", "target": "x86_64-unknown-linux-gnu", "asset_name": "tacacsrs-bash-plugin-linux-gnu-x86_64", "package_name": "tacacsrs-bash-plugin", "package_root": "libraries/tacacsrs_bash_plugin", "artifact_name": "tacacsrs_bash_plugin", "artifact_kind": "cdylib", "features": "", "sbom_describe": "all-cargo-targets"},
    {"os": "windows-latest", "target": "x86_64-pc-windows-msvc", "asset_name": "tacon-windows-msvc-x86_64", "package_name": "tacon", "package_root": "executables/tacon", "artifact_name": "tacon", "artifact_kind": "bin", "features": "", "sbom_describe": "binaries"},
]


def test_every_workflow_uses_the_registry_without_product_overrides():
    for name in ("ci.yml", "pullrequest_workflow.yml", "reusable-pipeline.yml"):
        workflow = yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)
        if name == "reusable-pipeline.yml":
            assert "products" not in workflow["on"]["workflow_call"]["inputs"]
            jobs = workflow["jobs"]
            assert jobs["official-build"]["strategy"]["matrix"]["config"] == "${{ fromJson(needs.product-registry.outputs.products) }}"
            assert set(jobs["official-build"]["needs"]) == {"testing", "product-registry"}
            assert jobs["product-registry"]["outputs"]["products"] == "${{ steps.registry.outputs.products }}"
            step = jobs["product-registry"]["steps"][-1]
            assert step["id"] == "registry"
            assert step["uses"] == "./.github/steps/product-registry"
            assert set(jobs["testing"]["needs"]) == {"pre-tests", "product-registry"}
            run = next(step for step in jobs["testing"]["steps"] if step.get("uses") == "./.github/steps/run-tests")
            assert run["with"]["products"] == "${{ needs.product-registry.outputs.products }}"
            assert "inputs.products" not in json.dumps(workflow)
        else:
            assert "products" not in workflow["jobs"]["pipeline"]["with"]


def metadata():
    packages = {}
    for product in EXPECTED:
        name = product["package_name"]
        packages[name] = {
            "id": name,
            "name": name,
            "version": "0.0.0-dev",
            "manifest_path": f'/ws/{product["package_root"]}/Cargo.toml',
            "targets": [{
                "name": product["artifact_name"],
                "kind": [product["artifact_kind"]],
                "crate_types": [product["artifact_kind"]],
            }],
            "features": {"default": [], "extra": []},
            "dependencies": [],
        }
    return {
        "workspace_root": "/ws",
        "workspace_members": list(packages),
        "packages": list(packages.values()),
    }


def registry():
    return json.loads((ROOT / ".github/products.json").read_text())


def test_registry_preserves_exact_matrix():
    from products import registry_products

    assert registry_products(registry(), metadata()) == EXPECTED


def test_independent_packaging_policy():
    products = registry()["products"]
    assert [product["packaging"] for product in products] == [
        {"archive": "tar.gz", "debug_symbols": "split", "openssl_runtime": "system", "linkage": "dynamic"},
        {"archive": "tar.gz", "debug_symbols": "split", "openssl_runtime": "system", "linkage": "dynamic"},
        {"archive": "tar.gz", "debug_symbols": "split", "openssl_runtime": "system", "linkage": "dynamic"},
        {"archive": "tar.gz", "debug_symbols": "split", "openssl_runtime": "system", "linkage": "dynamic"},
        {"archive": "zip", "debug_symbols": "pdb", "openssl_runtime": "bundled-dlls", "linkage": "dynamic"},
    ]
    assert [product["default_features"] for product in products] == [True] * 5
    assert [product["sbom_formats"] for product in products] == [["json", "xml"]] * 5


@pytest.mark.parametrize("field,value", [
    ("package_name", "stale-package"),
    ("artifact_name", "stale-target"),
    ("artifact_kind", "cdylib"),
    ("package_root", "executables/stale"),
    ("features", "unknown"),
    ("os", "macos-latest"),
    ("target", "aarch64-unknown-linux-gnu"),
    ("sbom_describe", "all-cargo-targets"),
    ("default_features", False),
    ("sbom_formats", ["json"]),
])
def test_registry_rejects_stale_or_unsupported_policy(field, value):
    from products import RegistryError, registry_products

    data = registry()
    data["products"][0][field] = value
    with pytest.raises(RegistryError):
        registry_products(data, metadata())


def test_every_policy_field_is_required():
    from products import RegistryError, registry_products

    for field in registry()["products"][0]:
        data = registry()
        del data["products"][0][field]
        with pytest.raises(RegistryError, match="fields"):
            registry_products(data, metadata())


def test_workspace_enrollment_does_not_enroll_a_product():
    from products import registry_products

    data = metadata()
    extra = copy.deepcopy(data["packages"][0])
    extra.update(id="experimental", name="experimental")
    data["packages"].append(extra)
    data["workspace_members"].append(extra["id"])
    assert registry_products(registry(), data) == EXPECTED


@pytest.mark.parametrize("data", [
    None, [], {}, {"schema_version": 2, "products": []},
    {"schema_version": True, "products": []},
    {"schema_version": 1, "products": []},
    {"schema_version": 1, "products": {}},
    {"schema_version": 1, "products": [None]},
])
def test_invalid_registry_shapes(data):
    from products import RegistryError, registry_products

    with pytest.raises(RegistryError):
        registry_products(data, metadata())


@pytest.mark.parametrize("mutation", ["unknown-field", "duplicate-asset", "duplicate-target", "packaging", "control", "bad-type"])
def test_rejects_ambiguous_or_incomplete_records(mutation):
    from products import RegistryError, registry_products

    data = registry()
    first = data["products"][0]
    if mutation == "unknown-field":
        first["typo"] = True
    elif mutation == "duplicate-asset":
        data["products"][1]["asset_name"] = first["asset_name"]
    elif mutation == "duplicate-target":
        data["products"].append(dict(first, asset_name="another-asset"))
    elif mutation == "packaging":
        del first["packaging"]["openssl_runtime"]
    elif mutation == "control":
        first["features"] = "\nproducts=[]"
    else:
        first["features"] = []
    with pytest.raises(RegistryError):
        registry_products(data, metadata())


@pytest.mark.parametrize("mutation", ["not-member", "kind", "crate-type", "required-feature"])
def test_cargo_target_contract(mutation):
    from products import RegistryError, registry_products

    meta = metadata()
    package = meta["packages"][0]
    if mutation == "not-member":
        meta["workspace_members"].remove(package["id"])
    elif mutation == "kind":
        package["targets"][0]["kind"] = ["example"]
    elif mutation == "crate-type":
        package["targets"][0]["crate_types"] = ["rlib"]
    else:
        package["targets"][0]["required-features"] = ["extra"]
    with pytest.raises(RegistryError):
        registry_products(registry(), meta)


def test_declared_features_and_default_feature_closure():
    from products import registry_products

    data = registry()
    data["products"][0]["features"] = "extra"
    meta = metadata()
    meta["packages"][0]["features"]["default"] = ["extra"]
    meta["packages"][0]["targets"][0]["required-features"] = ["extra"]
    expected = copy.deepcopy(EXPECTED)
    expected[0]["features"] = "extra"
    assert registry_products(data, meta) == expected
    assert registry_products(registry(), meta) == EXPECTED


@pytest.mark.parametrize("target,linux_only,expected", [
    (None, False, EXPECTED),
    (None, True, EXPECTED[:4]),
    ("x86_64-unknown-linux-gnu", True, EXPECTED[:4]),
    ("x86_64-pc-windows-msvc", False, EXPECTED[4:]),
])
def test_selection_and_metadata_helper_contract(monkeypatch, target, linux_only, expected):
    import products

    calls = []
    monkeypatch.setattr(products, "load_metadata", lambda workspace, **kwargs: calls.append((workspace, kwargs)) or metadata())
    assert products.load_products(ROOT, target=target, linux_only=linux_only) == expected
    assert calls == [(ROOT, {"target": target, "no_deps": True, "locked": True})]


@pytest.mark.parametrize("target,linux_only", [("unknown", False), ("x86_64-pc-windows-msvc", True)])
def test_empty_selection_is_an_error(monkeypatch, target, linux_only):
    import products

    monkeypatch.setattr(products, "load_metadata", lambda *args, **kwargs: metadata())
    with pytest.raises(products.RegistryError, match="no registered products"):
        products.load_products(ROOT, target=target, linux_only=linux_only)


@pytest.mark.parametrize("content", ['{"products":[],"products":[]}', "invalid", ""])
def test_read_rejects_duplicate_or_invalid_json(tmp_path, content):
    from products import RegistryError, read_registry

    path = tmp_path / "registry.json"
    path.write_text(content)
    with pytest.raises(RegistryError):
        read_registry(path)


def test_cli_and_action_output_shape(tmp_path, monkeypatch, capsys):
    import products

    monkeypatch.setattr(products, "load_metadata", lambda *args, **kwargs: metadata())
    output = tmp_path / "github-output"
    assert products.main(["--workspace", str(ROOT), "--github-output", str(output)]) == 0
    assert json.loads(capsys.readouterr().out) == EXPECTED
    lines = output.read_text().splitlines()
    assert len(lines) == 1
    key, value = lines[0].split("=", 1)
    assert key == "products"
    assert json.loads(value) == EXPECTED
    action = yaml.load((ROOT / ".github/steps/product-registry/action.yml").read_text(), Loader=yaml.BaseLoader)
    assert action["outputs"]["products"]["value"] == "${{ steps.registry.outputs.products }}"
    step = action["runs"]["steps"][0]
    assert step["id"] == "registry"
    assert step["shell"] == "bash"
    assert '--github-output "$GITHUB_OUTPUT"' in step["run"]
    assert "../cargo-metadata/products.py" in step["run"]


def test_cli_failure_never_emits_an_empty_matrix(tmp_path, monkeypatch, capsys):
    import products

    monkeypatch.setattr(products, "read_registry", lambda path: {"schema_version": 1, "products": []})
    monkeypatch.setattr(products, "load_metadata", lambda *args, **kwargs: metadata())
    output = tmp_path / "github-output"
    assert products.main(["--workspace", str(ROOT), "--github-output", str(output)]) == 1
    assert not output.exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "nonempty array" in captured.err


def test_composite_action_runs_against_real_cargo_metadata(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".github").mkdir()
    (workspace / ".github/products.json").write_text(json.dumps(registry()))
    directories = []
    for product in EXPECTED[:4]:
        directory = workspace / product["package_root"]
        (directory / "src").mkdir(parents=True)
        directories.append(product["package_root"])
        manifest = f'[package]\nname="{product["package_name"]}"\nversion="0.0.0-dev"\nedition="2021"\n'
        if product["artifact_kind"] == "cdylib":
            manifest += f'[lib]\nname="{product["artifact_name"]}"\ncrate-type=["cdylib", "rlib"]\n'
            (directory / "src/lib.rs").write_text("")
        else:
            (directory / "src/main.rs").write_text("fn main() {}")
        (directory / "Cargo.toml").write_text(manifest)
    (workspace / "Cargo.toml").write_text(f'[workspace]\nresolver="2"\nmembers={json.dumps(directories)}\n')
    action = yaml.load((ROOT / ".github/steps/product-registry/action.yml").read_text(), Loader=yaml.BaseLoader)
    output = tmp_path / "output"
    result = subprocess.run(
        ["bash", "-c", action["runs"]["steps"][0]["run"]], text=True, capture_output=True,
        env={**os.environ, "ACTION_PATH": str(ROOT / ".github/steps/product-registry"),
             "WORKSPACE": str(workspace), "GITHUB_OUTPUT": str(output)},
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == EXPECTED
    assert json.loads(output.read_text().removeprefix("products=")) == EXPECTED
