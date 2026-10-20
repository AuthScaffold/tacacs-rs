"""Keep the hydration dependency pin consistent across its environments."""

from importlib.metadata import version
from pathlib import Path

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


def test_delivery_tests_install_the_canonical_requirements():
    workflow = yaml.safe_load((ROOT / ".github/workflows/reusable-pipeline.yml").read_text())
    steps = workflow["jobs"]["automation-tests"]["steps"]
    install = next(step for step in steps if step.get("name") == "Install pinned test prerequisites")
    assert "-r .github/steps/inject-versions/requirements.txt" in install["run"]
