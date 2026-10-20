"""Check the publication boundary and required delivery gates in real workflows."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]


def workflow(name):
    return yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)


def test_no_release_computes_and_hydrates_without_publication():
    jobs = workflow("ci.yml")["jobs"]
    assert jobs["compute-versions"]["if"] == "github.event_name == 'push'"
    assert "skip-release" not in jobs["pipeline"]["with"]["versions"]
    assert "compute-versions.outputs.versions" in jobs["pipeline"]["with"]["versions"]
    assert "skip-release == 'true'" in jobs["pipeline"]["with"]["include-container-build"]
    for name in ("release", "container-stage"):
        assert "skip-release != 'true'" in jobs[name]["if"]
        assert "github.event_name == 'push'" in jobs[name]["if"]
    assert {"compute-versions", "release-policy"} <= set(jobs["ci-success"]["needs"])


def test_delivery_gates_and_profiles_are_required():
    jobs = workflow("reusable-pipeline.yml")["jobs"]
    assert {"automation-tests", "msrv", "consumer-profiles", "finalize-release-assets", "product-registry"} <= set(jobs["ci-success"]["needs"])
    registry = jobs["product-registry"]
    assert "if" not in registry
    assert registry.get("continue-on-error", "false") == "false"
    required = next(step for step in jobs["ci-success"]["steps"]
                    if step.get("name") == "Require the validated product matrix")
    assert required["if"] == "needs.product-registry.result != 'success'"
    assert required["run"] == "exit 1"
    profiles = jobs["consumer-profiles"]["strategy"]["matrix"]["config"]
    assert len(profiles) == 3
    steps = jobs["finalize-release-assets"]["steps"]
    uses = [step.get("uses", "") for step in steps]
    assert uses.index("./.github/steps/release-manifest") < uses.index("./.github/steps/generate-checksums")


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


def test_pull_requests_run_on_the_diagnostics_stack_base():
    branches = workflow("pullrequest_workflow.yml")["on"]["pull_request"]["branches"]
    assert {"main", "review/yang-toolkit/**", "feature/agent-diagnostics"} <= set(branches)


def test_pull_requests_run_on_the_armhf_stack_base():
    branches = workflow("pullrequest_workflow.yml")["on"]["pull_request"]["branches"]
    assert "fix/262-armhf" in branches


def test_pull_requests_run_on_general_iteration_stack_bases():
    branches = workflow("pullrequest_workflow.yml")["on"]["pull_request"]["branches"]
    assert "refactor/general-iterations/**" in branches


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


def test_rehearsal_container_does_not_publish_by_default():
    action = yaml.load((ROOT / ".github/steps/container-image/action.yml").read_text(), Loader=yaml.BaseLoader)
    assert action["inputs"]["publish"]["default"] == "false"
    container_steps = workflow("reusable-pipeline.yml")["jobs"]["container-build"]["steps"]
    for step in container_steps:
        if step.get("uses") == "./.github/steps/container-image":
            assert step["with"].get("publish", "false") == "false"


def test_build_provenance_precedes_archives_and_uses_build_inputs():
    steps = workflow("reusable-pipeline.yml")["jobs"]["official-build"]["steps"]
    names = [step.get("name", "") for step in steps]
    capture_index = names.index("Capture build provenance")
    assert names.index("Package SBOMs") < capture_index
    assert names.index("Package debug symbols") < capture_index
    assert names.index("Collect OpenSSL runtime DLLs") < capture_index
    assert capture_index < names.index("Create Linux archive")
    assert capture_index < names.index("Create Windows archive")
    capture = steps[capture_index]
    assert ".github/steps/release-manifest/build_provenance.py" in capture["run"]
    for flag in ("--package-dir", "--package-root", "--source", "--target", "--profile", "--features", "--versions-json", "--upload-dir packaged"):
        assert flag in capture["run"]
    assert capture["env"]["PROVENANCE_SOURCE"] == "${{ github.sha }}"
    assert capture["env"]["PROVENANCE_VERSIONS"] == "${{ inputs.versions }}"
    upload = next(step for step in steps if step.get("name") == "Upload packaged artifact")
    assert upload["with"]["path"] == "packaged/*"


def test_manifest_receives_records_between_staging_and_checksums():
    steps = workflow("reusable-pipeline.yml")["jobs"]["finalize-release-assets"]["steps"]
    uses = [step.get("uses", "") for step in steps]
    index = uses.index("./.github/steps/release-manifest")
    assert uses.index("./.github/steps/stage-release-assets") < index < uses.index("./.github/steps/generate-checksums")
    assert steps[index]["with"]["provenance-directory"] == "raw/packages"
    action = yaml.load((ROOT / ".github/steps/release-manifest/action.yml").read_text(), Loader=yaml.BaseLoader)
    assert action["inputs"]["provenance-directory"]["required"] == "true"
    assert '--provenance-dir "$INPUT_PROVENANCE_DIRECTORY"' in action["runs"]["steps"][0]["run"]


def test_ci_uses_shared_sbom_helper():
    action = yaml.load((ROOT / ".github/steps/stage-sbom-files/action.yml").read_text(), Loader=yaml.BaseLoader)
    command = action["runs"]["steps"][0]["run"]
    assert '"$ACTION_PATH/stage_sbom.py"' in command
    assert "jq " not in command
    assert "sed " not in command


def test_product_packaging_and_sbom_scripts_keep_the_supported_policy():
    steps = workflow("reusable-pipeline.yml")["jobs"]["official-build"]["steps"]
    by_name = {step.get("name"): step for step in steps}
    for name in ("Collect OpenSSL runtime DLLs", "Create Windows archive"):
        assert by_name[name]["if"] == "runner.os == 'Windows'"
    assert by_name["Create Linux archive"]["if"] == "runner.os == 'Linux'"
    action = yaml.load((ROOT / ".github/steps/package-sboms/action.yml").read_text(), Loader=yaml.BaseLoader)
    formats = [step["with"]["output-format"] for step in action["runs"]["steps"]
               if step.get("uses") == "./.github/steps/generate-sbom"]
    assert formats == ["json", "xml"]
    for step in action["runs"]["steps"]:
        if step.get("uses") == "./.github/steps/generate-sbom":
            assert step["with"]["target-in-filename"] == "true"
    build = (ROOT / ".github/steps/build-binary/action.yml").read_text()
    assert "--no-default-features" not in build