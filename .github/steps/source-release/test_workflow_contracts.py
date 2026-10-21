"""Check source publication boundaries and required validation gates."""

from pathlib import Path
import json
import os
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[3]


def workflow(name):
    return yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)


def test_latest_main_push_cancels_older_release_runs():
    data = workflow("ci.yml")
    assert data["on"]["push"]["branches"] == ["main"]
    concurrency = data["concurrency"]
    assert concurrency["cancel-in-progress"] == "true"
    assert concurrency["group"] == (
        "ci-${{ github.workflow }}-${{ github.ref }}"
        "${{ github.event_name != 'push' && '-validation' || '' }}"
    )


def test_publication_requires_the_validated_candidate():
    jobs = workflow("ci.yml")["jobs"]
    assert set(jobs["release"]["needs"]) == {"ci-success", "prepare-release"}
    assert "needs.prepare-release.result == 'success'" in jobs["release"]["if"]
    assert "needs.ci-success.result == 'success'" in jobs["release"]["if"]
    publish = next(step for step in jobs["release"]["steps"]
                   if step.get("uses") == "./.github/steps/source-release")
    assert publish["with"]["command"] == "publish"
    assert publish["with"]["candidate"] == "${{ needs.prepare-release.outputs.candidate }}"
    prepare = jobs["prepare-release"]
    for condition in ("github.event_name == 'push'", "github.repository_owner == 'AuthScaffold'",
                      "skip-release != 'true'", "has-release == 'true'"):
        assert condition in prepare["if"]
    inputs = jobs["pipeline"]["with"]
    assert inputs["validation-ref"] == "${{ needs.prepare-release.outputs.candidate || github.sha }}"
    assert inputs["require-hydrated"] == "${{ needs.prepare-release.result == 'success' }}"
    assert "prepare-release" in jobs["pipeline"]["needs"]
    assert "needs.prepare-release.result" in jobs["pipeline"]["if"]
    assert set(jobs["ci-success"]["needs"]) == {"pipeline", "compute-versions", "release-policy", "prepare-release"}


def test_recovery_precedes_version_computation():
    steps = workflow("ci.yml")["jobs"]["compute-versions"]["steps"]
    names = [step.get("id") for step in steps]
    assert names.index("recover") < names.index("compute")
    assert steps[names.index("compute")]["if"] == "steps.recover.outputs.candidate == ''"
    condition = workflow("ci.yml")["jobs"]["compute-versions"]["if"]
    assert condition == "github.event_name == 'push' || github.event_name == 'workflow_dispatch'"
    assert steps[names.index("recover")]["if"] == "github.event_name == 'push'"


def test_manual_rehearsal_validates_a_candidate_without_publication():
    data = workflow("ci.yml")
    assert "workflow_dispatch" in data["on"]
    jobs = data["jobs"]
    assert "github.event_name == 'workflow_dispatch'" in jobs["prepare-release"]["if"]
    assert "github.event_name == 'workflow_dispatch'" not in jobs["release"]["if"]
    assert "github.event_name == 'push'" in jobs["release"]["if"]
    steps = jobs["ci-success"]["steps"]
    assert any("workflow_dispatch" in step.get("if", "") and "prepare-release.result" in step["if"] for step in steps)
    compute = next(step for step in jobs["compute-versions"]["steps"] if step.get("id") == "compute")
    assert compute["with"]["skip-semver-checks"] == "${{ github.event_name == 'workflow_dispatch' && 'true' || 'false' }}"


@pytest.mark.parametrize("message,labels,event,expected", [
    ("docs [no-release]", [], "push", "true"),
    ("docs [norelease]", [], "push", "true"),
    ("docs [skip-release]", [], "push", "true"),
    ("docs", ["no-release"], "push", "true"),
    ("docs", ["skip_release"], "push", "true"),
    ("docs", ["ordinary-label"], "push", "false"),
    ("feat: not-no-release", [], "push", "false"),
    ("", [], "schedule", "false"),
])
def test_release_policy_markers_and_labels(tmp_path, message, labels, event, expected):
    executable = tmp_path / "gh"
    executable.write_text('#!/bin/sh\nprintf "%s" "$FIXTURE_PRS"\n')
    executable.chmod(0o755)
    output = tmp_path / "output"
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "GITHUB_OUTPUT": str(output),
           "GITHUB_REPOSITORY": "fixture/repository", "EVENT_NAME": event, "COMMIT_SHA": "a" * 40,
           "HEAD_COMMIT_MESSAGE": message,
           "FIXTURE_PRS": json.dumps([{"labels": [{"name": name} for name in labels]}])}
    script = workflow("ci.yml")["jobs"]["release-policy"]["steps"][0]["run"]
    subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True)
    assert output.read_text().strip() == f"skip_release={expected}"


def test_release_policy_api_failure_is_not_release_enabled(tmp_path):
    executable = tmp_path / "gh"
    executable.write_text("#!/bin/sh\nexit 1\n")
    executable.chmod(0o755)
    output = tmp_path / "output"
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "GITHUB_OUTPUT": str(output),
           "GITHUB_REPOSITORY": "fixture/repository", "EVENT_NAME": "push", "COMMIT_SHA": "a" * 40,
           "HEAD_COMMIT_MESSAGE": "ordinary change"}
    script = workflow("ci.yml")["jobs"]["release-policy"]["steps"][0]["run"]
    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True)
    assert result.returncode != 0
    assert not output.exists()


def test_every_validation_checkout_uses_the_exact_sha():
    jobs = workflow("reusable-pipeline.yml")["jobs"]
    for job in jobs.values():
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["ref"] == "${{ inputs.validation-ref || github.sha }}"
    assert set(jobs["ci-success"]["needs"]) == set(jobs) - {"ci-success"}
    condition = jobs["ci-success"]["steps"][-1]["if"]
    for result in ("failure", "cancelled", "skipped"):
        assert f"'{result}'" in condition
    assert len(jobs["consumer-profiles"]["strategy"]["matrix"]["config"]) == 3


def test_build_validation_preserves_default_feature_products():
    build = workflow("reusable-pipeline.yml")["jobs"]["build-validation"]
    configs = build["strategy"]["matrix"]["config"]
    assert configs == [
        {"os": "ubuntu-latest", "target": "x86_64-unknown-linux-gnu",
         "packages": "tacon tacacsrs-agentd tacacsrs-agent-health tacacsrs-bash-plugin"},
        {"os": "windows-latest", "target": "x86_64-pc-windows-msvc", "packages": "tacon"},
    ]
    commands = "\n".join(step.get("run", "") for step in build["steps"])
    assert "cargo build --locked --release" in commands
    assert "--no-default-features" not in commands
    assert "--all-features" not in commands
    assert 'for package in $PACKAGES' in commands
    assert '--package "$package"' in commands
    required = next(step for step in build["steps"] if step.get("if") == "inputs.require-hydrated")
    assert "git diff --exit-code" in required["run"]


def test_no_distribution_jobs_or_registry_permissions_remain():
    for name in ("ci.yml", "pullrequest_workflow.yml", "reusable-pipeline.yml"):
        data = workflow(name)
        assert "packages" not in data.get("permissions", {})
        for job in data["jobs"].values():
            assert "packages" not in job.get("permissions", {})
            for step in job.get("steps", []):
                if step.get("uses", "").startswith("./"):
                    assert (ROOT / step["uses"] / "action.yml").is_file()
        text = (ROOT / ".github/workflows" / name).read_text()
        for retired in ("release-assets", "product-registry", "container-image", "official-build", "softprops/action-gh-release"):
            assert retired not in text
    assert not (ROOT / ".github/products.json").exists()
    jobs = workflow("ci.yml")["jobs"]
    assert {name for name, job in jobs.items() if job.get("permissions", {}).get("contents") == "write"} == {"prepare-release", "release"}
    assert workflow("pullrequest_workflow.yml")["permissions"]["contents"] == "read"
    required = workflow("reusable-pipeline.yml")["permissions"]
    for name in ("ci.yml", "pullrequest_workflow.yml"):
        granted = workflow(name)["jobs"]["pipeline"]["permissions"]
        for permission, level in required.items():
            assert granted.get(permission) in (level, "write")


def test_yaml_files_have_no_duplicate_keys():
    class UniqueLoader(yaml.BaseLoader):
        pass

    def mapping(loader, node):
        keys = [loader.construct_object(key) for key, _ in node.value]
        assert len(keys) == len(set(keys)), f"Duplicate YAML keys: {keys}"
        return dict(loader.construct_pairs(node))

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    paths = list((ROOT / ".github/workflows").glob("*.yml"))
    paths += list((ROOT / ".github/steps").glob("*/action.yml"))
    for path in paths:
        yaml.load(path.read_text(), Loader=UniqueLoader)


def test_armhf_execution_is_a_required_unconditional_gate():
    jobs = workflow("reusable-pipeline.yml")["jobs"]
    armhf = jobs["armhf"]
    assert "if" not in armhf
    assert armhf.get("continue-on-error", "false") == "false"
    assert 60 <= int(armhf["timeout-minutes"]) <= 120
    assert "armhf" in jobs["ci-success"]["needs"]
    required = next(step for step in jobs["ci-success"]["steps"]
                    if step.get("name") == "Require executed ARMhf coverage")
    assert required["if"] == "needs.armhf.result != 'success'"
    assert required["run"] == "exit 1"
    build = next(step for step in armhf["steps"]
                 if step.get("name") == "Build and execute ARMhf coverage")
    assert "--no-cache-filter verify" in build["run"]
    assert ".github/steps/armhf/Dockerfile" in build["run"]
    for step in armhf["steps"]:
        assert step.get("continue-on-error", "false") == "false"


def test_pull_request_validation_targets_main_without_stack_allowlists():
    branches = workflow("pullrequest_workflow.yml")["on"]["pull_request"]["branches"]
    assert branches == ["main"]


def test_armhf_helper_builds_and_executes_the_affected_packages():
    helper = (ROOT / ".github/steps/armhf/verify.sh").read_text()
    assert "cargo build --locked --release --bins" in helper
    assert "cargo test --locked" in helper
    assert "--no-run" not in helper
    for package in ("tacacsrs-agentd", "tacacsrs-agent-health", "tacon",
                    "tacacsrs-networking", "tacacsrs-config", "tacacsrs-agent",
                    "tacacsrs-sonic", "tacacsrs-ipc", "tacacsrs-agent-ipc-emulator"):
        assert f"-p {package} " in helper
    for check in ("ELF32", "Machine: +ARM", "hard-float ABI", '"${binary}" --help'):
        assert check in helper
    dockerfile = (ROOT / ".github/steps/armhf/Dockerfile").read_text()
    assert "CARGO_BUILD_TARGET=armv7-unknown-linux-gnueabihf" in dockerfile
    assert "PROTOC=/usr/bin/protoc" in dockerfile
    assert "libssl-dev:armhf" in dockerfile
    assert 'RUNNER="qemu-arm -L /"' in dockerfile
    assert "test_protoc.py" in helper
    context = (ROOT / ".dockerignore").read_text()
    for included in ("libraries/*/tests/**", "executables/*/tests/**",
                     "lde/containers/config/certificates/**",
                     "libraries/tacacsrs_agent_ipc_emulator/examples/policy.rego",
                     "libraries/tacacsrs_agent_ipc_emulator/examples/policy_data.json"):
        assert f"!{included}" in context
