"""Keep the hydration dependency pin consistent across its environments."""

from importlib.metadata import version
import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[3]
REQUIREMENTS = ROOT / ".github/steps/inject-versions/requirements.txt"


def test_installed_toml_tool_matches_the_pin():
    assert REQUIREMENTS.read_text().strip() == f"tomlkit=={version('tomlkit')}"


def test_development_image_uses_the_same_pin():
    dockerfile = (ROOT / ".devcontainer/Dockerfile").read_text()
    assert REQUIREMENTS.read_text().strip() in dockerfile.split()


def test_composite_action_installs_before_hydration():
    action = yaml.safe_load((REQUIREMENTS.parent / "action.yml").read_text())
    steps = action["runs"]["steps"]
    assert 'python -m pip install --disable-pip-version-check -r "${{ github.action_path }}/requirements.txt"' == steps[0]["run"]
    assert "hydrate_versions.py" in steps[1]["run"]


def test_hydration_can_require_an_unchanged_candidate():
    action = yaml.safe_load((REQUIREMENTS.parent / "action.yml").read_text())
    assert action["inputs"]["require-hydrated"]["default"] == "false"
    guard = action["runs"]["steps"][2]
    assert guard["if"] == "inputs.require-hydrated == 'true'"
    assert guard["run"] == "git diff --exit-code -- Cargo.lock ':(glob)**/Cargo.toml'"


@pytest.mark.parametrize("build_release,drift", [
    ("false", False),
    ("true", False),
    ("false", True),
])
def test_actual_test_runner_uses_hydrated_versions(tmp_path, build_release, drift):
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "Cargo.toml").write_text(
        '[package]\nname = "hydration-probe"\nversion = "0.0.0-dev"\nedition = "2021"\n'
    )
    (workspace / "src/lib.rs").write_text(
        '#[test]\nfn uses_hydrated_version() {\n'
        '    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");\n}\n'
    )
    env = {**os.environ, "CARGO_TARGET_DIR": str(tmp_path / "target"), "CARGO_NET_OFFLINE": "true"}
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=workspace, env=env, check=True, capture_output=True)
    subprocess.run(["git", "init", "--initial-branch=main"], cwd=workspace, check=True, capture_output=True)
    for key, value in (("user.name", "Hydration Test"), ("user.email", "test@example.invalid")):
        subprocess.run(["git", "config", key, value], cwd=workspace, check=True)

    def commit():
        subprocess.run(["git", "add", "."], cwd=workspace, check=True)
        subprocess.run(["git", "commit", "-m", "test fixture"], cwd=workspace, check=True, capture_output=True)

    commit()
    hydration_action = yaml.safe_load((REQUIREMENTS.parent / "action.yml").read_text())
    hydration = hydration_action["runs"]["steps"][1]["run"]
    hydration = hydration.replace("${{ github.action_path }}", str(REQUIREMENTS.parent))
    hydration = hydration.replace("${{ github.workspace }}", str(workspace))
    hydration = hydration.replace("${{ inputs.versions }}", json.dumps({"hydration-probe": "0.1.0"}))
    subprocess.run(["bash", "-e", "-c", hydration], cwd=workspace, env=env, check=True, capture_output=True)
    guard = hydration_action["runs"]["steps"][2]["run"]
    result = subprocess.run(["bash", "-e", "-c", guard], cwd=workspace, env=env, capture_output=True)
    assert result.returncode != 0
    commit()
    subprocess.run(["bash", "-e", "-c", guard], cwd=workspace, env=env, check=True, capture_output=True)

    lock = workspace / "Cargo.lock"
    if drift:
        lock.write_text(lock.read_text().replace('version = "0.1.0"', 'version = "0.2.0"'))
    expected_lock = lock.read_bytes()
    action = yaml.safe_load((ROOT / ".github/steps/run-tests/action.yml").read_text())
    script = next(step["run"] for step in action["runs"]["steps"]
                  if step.get("name") == "Run unit, integration, and doc tests")
    assert "cargo test --locked" in script
    host = subprocess.run(["rustc", "-vV"], env=env, check=True, capture_output=True, text=True).stdout
    host = next(line.removeprefix("host: ") for line in host.splitlines() if line.startswith("host: "))
    for name, value in (("package-args", "--workspace"), ("target", host),
                        ("feature-args", "--all-features"), ("build-release", build_release)):
        script = script.replace("${{ inputs." + name + " }}", value)
    result = subprocess.run(["bash", "-e", "-c", script], cwd=workspace, env=env, capture_output=True, text=True)
    if drift:
        assert result.returncode != 0
        assert "--locked" in result.stderr
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "uses_hydrated_version ... ok" in result.stdout
        subprocess.run(["git", "diff", "--exit-code"], cwd=workspace, check=True, capture_output=True)
    assert lock.read_bytes() == expected_lock


def test_delivery_tests_install_the_canonical_requirements():
    workflow = yaml.safe_load((ROOT / ".github/workflows/reusable-pipeline.yml").read_text())
    steps = workflow["jobs"]["automation-tests"]["steps"]
    install = next(step for step in steps if step.get("name") == "Install pinned test prerequisites")
    assert "-r .github/steps/inject-versions/requirements.txt" in install["run"]
