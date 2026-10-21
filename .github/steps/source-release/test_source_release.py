"""Exercise source release objects and atomic refs with local Git repositories."""

import base64
import copy
import io
import json
import os
import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

import source_release as release


@pytest.fixture
def repository(tmp_path, monkeypatch):
    count = int(os.environ.get("GIT_CONFIG_COUNT", "0"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", str(count + 1))
    monkeypatch.setenv(f"GIT_CONFIG_KEY_{count}", "safe.bareRepository")
    monkeypatch.setenv(f"GIT_CONFIG_VALUE_{count}", "all")
    remote, checkout = tmp_path / "remote.git", tmp_path / "checkout"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    subprocess.run(["git", "init", "--initial-branch=main", str(checkout)], check=True, capture_output=True)
    for directory in (remote, checkout):
        release.git(directory, "config", "user.name", "Release Test")
        release.git(directory, "config", "user.email", "test@example.invalid")
    (checkout / "Cargo.toml").write_text('[workspace]\nresolver="2"\nmembers=["base","tacon","experimental"]\n')
    for name, target in (("base", "lib"), ("tacon", "main"), ("experimental", "main")):
        crate = checkout / name
        (crate / "src").mkdir(parents=True)
        package = "base-lib" if name == "base" else name
        (crate / "Cargo.toml").write_text(f'[package]\nname="{package}"\nversion="0.0.0-dev"\nedition="2021"\n')
        (crate / "src" / f"{target}.rs").write_text("pub fn demo() {}\n" if target == "lib" else "fn main() {}\n")
    release.run(["cargo", "generate-lockfile", "--offline"], checkout)
    release.git(checkout, "add", ".")
    release.git(checkout, "commit", "-m", "initial")
    source = release.git(checkout, "rev-parse", "HEAD")
    release.git(checkout, "remote", "add", "origin", str(remote))
    release.git(checkout, "push", "origin", "main")
    monkeypatch.setenv("GITHUB_REPOSITORY", "fixture/repository")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "output"))
    monkeypatch.setenv("VALIDATION_RUN_URL", "https://example.invalid/run/1")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(checkout))
    plan = {
        "schema": 1, "source": source, "release_head": None,
        "versions": {"base-lib": "0.1.0", "tacon": "2026.1021.0"},
        "new_tags": ["base-lib-v0.1.0", "tacacs-rs-2026.1021.0"],
        "calver_tag": "tacacs-rs-2026.1021.0", "previous_calver_tag": "",
    }
    return checkout, remote, plan


@pytest.fixture
def api(repository, monkeypatch, tmp_path):
    checkout, remote, _ = repository
    state = {"calls": [], "verified": True, "page": None, "creates": []}
    original_run = release.run

    def github(workspace, path, data=None, **kwargs):
        state["calls"].append((path, data))
        if path == "git/blobs":
            sha = original_run(["git", "hash-object", "-w", "--stdin"], remote,
                               data=base64.b64decode(data["content"]).decode())
            return {"sha": sha}
        if path == "git/trees":
            env = {**os.environ, "GIT_INDEX_FILE": str(tmp_path / "api-index")}
            subprocess.run(["git", "read-tree", data["base_tree"]], cwd=remote, env=env, check=True)
            for entry in data["tree"]:
                subprocess.run(["git", "update-index", "--add", "--cacheinfo",
                                f"{entry['mode']},{entry['sha']},{entry['path']}"], cwd=remote, env=env, check=True)
            result = subprocess.run(["git", "write-tree"], cwd=remote, env=env, check=True, capture_output=True, text=True)
            return {"sha": result.stdout.strip()}
        if path == "git/commits":
            args = ["git", "commit-tree", data["tree"]]
            for parent in data["parents"]:
                args += ["-p", parent]
            sha = original_run(args, remote, data=data["message"])
            return {"sha": sha, "verification": {"verified": state["verified"]}}
        if path.startswith("git/commits/"):
            sha = path.rsplit("/", 1)[1]
            return {
                "sha": sha, "verification": {"verified": state["verified"]},
                "tree": {"sha": release.git(remote, "rev-parse", f"{sha}^{{tree}}")},
                "parents": [{"sha": parent} for parent in release.git(remote, "show", "-s", "--format=%P", sha).split()],
            }
        if path.startswith("releases/tags/"):
            return state["page"]
        if path == "releases/generate-notes":
            return {"body": "## Changes\n\nFixture change notes."}
        raise AssertionError(f"Unexpected API operation: {path}")

    def run(args, workspace, **kwargs):
        if args[:3] == ["gh", "release", "create"]:
            assert "--verify-tag" in args
            release.git(remote, "rev-parse", "--verify", f"refs/tags/{args[3]}^{{commit}}")
            if state.pop("fail_page", False):
                raise release.ReleaseError("GitHub Release creation failed")
            body = Path(args[args.index("--notes-file") + 1]).read_text()
            state["creates"].append((args, body))
            state["page"] = {"name": args[args.index("--title") + 1], "body": body,
                             "assets": [], "draft": False, "prerelease": False}
            return ""
        return original_run(args, workspace, **kwargs)

    monkeypatch.setattr(release, "github", github)
    monkeypatch.setattr(release, "run", run)
    return state


def candidate(repository):
    path = Path(os.environ["GITHUB_OUTPUT"])
    return dict(line.split("=", 1) for line in path.read_text().splitlines())["candidate"]


def prepare(repository):
    checkout, _, plan = repository
    release.prepare(checkout, copy.deepcopy(plan), "")
    return candidate(repository)


def test_preparation_is_verified_and_does_not_publish_refs(repository, api):
    checkout, remote, plan = repository
    sha = prepare(repository)
    assert release.verify(checkout, sha, plan["source"]) == plan
    assert release.git(remote, "for-each-ref", "--format=%(refname)") == "refs/heads/main"
    assert release.git(checkout, "show", "-s", "--format=%P", sha) == plan["source"]
    creation = next(data for path, data in api["calls"] if path == "git/commits")
    assert set(creation) == {"message", "tree", "parents"}
    assert "Co-authored-by: Copilot" in creation["message"]
    assert release.git(checkout, "status", "--porcelain") == ""
    release.prepare(checkout, copy.deepcopy(plan), sha)
    assert sum(path == "git/commits" for path, _ in api["calls"]) == 1


def test_two_parent_history_and_source_tree_replacement(repository, api):
    checkout, remote, first = repository
    first_sha = prepare(repository)
    release.publish_refs(checkout, first, first_sha)
    (checkout / "base/src/lib.rs").write_text("pub fn changed() {}\n")
    release.git(checkout, "add", ".")
    release.git(checkout, "commit", "-m", "change")
    release.git(checkout, "push", "origin", "main")
    second = {**first, "source": release.git(checkout, "rev-parse", "HEAD"), "release_head": first_sha,
              "versions": {"base-lib": "0.1.1", "tacon": "2026.1021.1"},
              "new_tags": ["base-lib-v0.1.1", "tacacs-rs-2026.1021.1"],
              "calver_tag": "tacacs-rs-2026.1021.1", "previous_calver_tag": first["calver_tag"]}
    release.prepare(checkout, copy.deepcopy(second), "")
    sha = candidate(repository)
    assert release.git(checkout, "show", "-s", "--format=%P", sha).split() == [first_sha, second["source"]]
    assert "changed" in release.git(checkout, "show", f"{sha}:base/src/lib.rs")
    release.publish_refs(checkout, second, sha)
    assert release.git(remote, "rev-parse", "release") == sha
    release.publish_refs(checkout, first, first_sha)
    assert release.git(remote, "rev-parse", "release") == sha


def test_atomic_publication_recovery_and_release_page_retry(repository, api):
    checkout, remote, plan = repository
    sha = prepare(repository)
    release.publish_refs(checkout, plan, sha)
    for ref in ("release", *plan["new_tags"]):
        assert release.git(remote, "rev-parse", f"{ref}^{{commit}}") == sha
    Path(os.environ["GITHUB_OUTPUT"]).write_text("")
    release.recover(checkout, plan["source"])
    assert candidate(repository) == sha
    recovered = release.read_plan(checkout, sha)
    release.prepare(checkout, copy.deepcopy(recovered), sha)
    release.publish_refs(checkout, recovered, sha)
    release.publish_page(checkout, recovered, sha)
    args, body = api["creates"][0]
    assert "--verify-tag" in args
    assert "TACACS-RS 2026.1021.0" in args
    assert "--notes-file" in args
    assert "| `base-lib` | `0.1.0` |" in body
    assert "| `experimental` | `0.0.0-dev` |" in body
    assert "| `tacon` | `2026.1021.0` |" in body
    assert body.index("`base-lib`") < body.index("`experimental`") < body.index("`tacon`")
    assert sha in body and plan["source"] in body
    release.publish_page(checkout, recovered, sha)
    assert len(api["creates"]) == 1


@pytest.mark.parametrize("archive_format", ["tar.gz", "zip"])
def test_automatic_source_archives_use_the_hydrated_tag(repository, api, monkeypatch, archive_format):
    checkout, remote, plan = repository
    sha = prepare(repository)
    monkeypatch.setenv("RELEASE_COMMAND", "publish")
    monkeypatch.setenv("SOURCE_SHA", plan["source"])
    monkeypatch.setenv("CANDIDATE_SHA", sha)
    assert release.main() == 0

    tag = plan["calver_tag"]
    assert release.git(remote, "rev-parse", "refs/heads/main") == plan["source"]
    assert release.git(remote, "rev-parse", "refs/heads/release") == sha
    assert release.git(remote, "rev-parse", f"refs/tags/{tag}^{{commit}}") == sha
    source_manifest = release.git(remote, "show", f"{plan['source']}:tacon/Cargo.toml")
    assert tomllib.loads(source_manifest)["package"]["version"] == "0.0.0-dev"

    args, _ = api["creates"][0]
    assert args == [
        "gh", "release", "create", tag, "--verify-tag", "--target", sha,
        "--title", "TACACS-RS 2026.1021.0", "--notes-file", args[-1],
    ]
    archive = subprocess.run(
        ["git", "archive", f"--format={archive_format}", tag],
        cwd=remote, capture_output=True, check=True,
    ).stdout
    paths = ["base/Cargo.toml", "tacon/Cargo.toml", "experimental/Cargo.toml", "Cargo.lock"]
    if archive_format == "zip":
        with zipfile.ZipFile(io.BytesIO(archive)) as contents:
            files = {path: contents.read(path) for path in paths}
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as contents:
            files = {}
            for path in paths:
                stream = contents.extractfile(path)
                assert stream is not None
                files[path] = stream.read()

    for path, name in (("base/Cargo.toml", "base-lib"), ("tacon/Cargo.toml", "tacon")):
        assert tomllib.loads(files[path].decode())["package"]["version"] == plan["versions"][name]
    assert tomllib.loads(files["experimental/Cargo.toml"].decode())["package"]["version"] == "0.0.0-dev"
    lock = tomllib.loads(files["Cargo.lock"].decode())
    local_versions = {package["name"]: package["version"] for package in lock["package"] if "source" not in package}
    assert {name: local_versions[name] for name in plan["versions"]} == plan["versions"]


def test_page_failure_recovers_without_allocating_or_moving_refs(repository, api):
    checkout, remote, plan = repository
    sha = prepare(repository)
    release.publish_refs(checkout, plan, sha)
    refs = release.git(remote, "show-ref")
    api["fail_page"] = True
    with pytest.raises(release.ReleaseError, match="creation failed"):
        release.publish_page(checkout, plan, sha)
    Path(os.environ["GITHUB_OUTPUT"]).write_text("")
    release.recover(checkout, plan["source"])
    assert candidate(repository) == sha
    recovered = release.verify(checkout, sha, plan["source"])
    release.publish_refs(checkout, recovered, sha)
    release.publish_page(checkout, recovered, sha)
    assert release.git(remote, "show-ref") == refs
    assert len(api["creates"]) == 1
    assert sum(path == "git/commits" for path, _ in api["calls"]) == 1


def test_unsigned_creation_never_publishes(repository, api):
    checkout, remote, _ = repository
    api["verified"] = False
    with pytest.raises(release.ReleaseError, match="did not sign"):
        prepare(repository)
    assert release.git(remote, "for-each-ref", "--format=%(refname)") == "refs/heads/main"


def test_tagless_rehearsal_can_be_verified_but_not_published(repository, api):
    checkout, remote, plan = repository
    plan["new_tags"] = []
    plan["calver_tag"] = ""
    sha = prepare(repository)
    assert release.verify(checkout, sha, plan["source"]) == plan
    with pytest.raises(release.ReleaseError, match="tagless rehearsal"):
        release.publish_refs(checkout, plan, sha)
    assert release.git(remote, "for-each-ref", "--format=%(refname)") == "refs/heads/main"


def test_unverified_candidate_cannot_reach_publication(repository, api, monkeypatch, capsys):
    _, remote, plan = repository
    sha = prepare(repository)
    api["verified"] = False
    monkeypatch.setenv("RELEASE_COMMAND", "publish")
    monkeypatch.setenv("SOURCE_SHA", plan["source"])
    monkeypatch.setenv("CANDIDATE_SHA", sha)
    assert release.main() == 1
    assert "did not verify" in capsys.readouterr().err
    assert release.git(remote, "for-each-ref", "--format=%(refname)") == "refs/heads/main"


@pytest.mark.parametrize("change,match", [
    ("tree", "deterministic"), ("extra-file", "deterministic"),
    ("parents", "parent order"), ("source", "triggering source"),
    ("duplicate", "one release plan"), ("versions", "version trailer"),
])
def test_forged_candidate_metadata_is_not_authority(repository, api, change, match):
    checkout, remote, plan = repository
    sha = prepare(repository)
    message = release.git(checkout, "show", "-s", "--format=%B", sha)
    tree = release.git(checkout, "rev-parse", f"{sha}^{{tree}}")
    parents = [plan["source"]]
    source = plan["source"]
    if change == "tree":
        tree = release.git(checkout, "rev-parse", f"{source}^{{tree}}")
    elif change == "extra-file":
        blob = release.github(checkout, "git/blobs", {"content": base64.b64encode(b"unexpected").decode()})
        tree = release.github(checkout, "git/trees", {
            "base_tree": tree, "tree": [{"mode": "100644", "sha": blob["sha"], "path": "unexpected", "type": "blob"}],
        })["sha"]
    elif change == "parents":
        parents = []
    elif change == "source":
        source = sha
    elif change == "duplicate":
        message += "\nRelease-Plan: {}\n"
    else:
        message = message.replace('Versions: {"base-lib": "0.1.0"', 'Versions: {"base-lib": "9.0.0"')
    args = ["git", "commit-tree", tree]
    for parent in parents:
        args += ["-p", parent]
    forged = release.run(args, remote, data=message)
    with pytest.raises(release.ReleaseError, match=match):
        release.verify(checkout, forged, source)


@pytest.mark.parametrize("scenario", ["partial", "conflict", "branch-moved"])
def test_conflicting_refs_do_not_publish(repository, api, scenario):
    checkout, remote, plan = repository
    sha = prepare(repository)
    if scenario == "branch-moved":
        release.git(remote, "update-ref", "refs/heads/release", plan["source"])
    else:
        for tag in plan["new_tags"][:1] if scenario == "partial" else plan["new_tags"]:
            release.git(remote, "tag", "-a", tag, plan["source"], "-m", "conflict")
    before = release.git(remote, "show-ref")
    with pytest.raises(release.ReleaseError):
        release.publish_refs(checkout, plan, sha)
    assert release.git(remote, "show-ref") == before


def test_publication_lease_rejects_a_concurrent_first_branch(repository, api, monkeypatch):
    checkout, remote, plan = repository
    sha = prepare(repository)
    original = release.git

    def git(workspace, *args):
        if args[:2] == ("push", "--atomic"):
            original(remote, "update-ref", "refs/heads/release", plan["source"])
        return original(workspace, *args)

    monkeypatch.setattr(release, "git", git)
    with pytest.raises(release.ReleaseError):
        release.publish_refs(checkout, plan, sha)
    assert original(remote, "rev-parse", "release") == plan["source"]
    assert original(remote, "tag", "--list") == ""


def test_incomplete_version_map_is_rejected(repository, api):
    checkout, _, plan = repository
    del plan["versions"]["base-lib"]
    plan["new_tags"] = [plan["calver_tag"]]
    with pytest.raises(release.ReleaseError, match="exactly the managed"):
        release.prepare(checkout, plan, "")


@pytest.mark.parametrize("mutation", [
    lambda plan: plan.update(schema=True),
    lambda plan: plan.update(source="not-a-sha"),
    lambda plan: plan.update(new_tags=["wrong-tag"]),
    lambda plan: plan["new_tags"].append(plan["new_tags"][0]),
    lambda plan: plan.update(previous_calver_tag="unrelated-v1"),
    lambda plan: plan["versions"].update(tacon="0.0.0-dev"),
])
def test_invalid_release_plans_fail(repository, mutation):
    plan = repository[2]
    mutation(plan)
    with pytest.raises(release.ReleaseError):
        release.validate_plan(plan)


def test_duplicate_json_keys_are_rejected():
    with pytest.raises(release.ReleaseError, match="Duplicate JSON"):
        release.decode('{"schema":1,"schema":1}')


def test_api_errors_do_not_publish(repository, api, monkeypatch):
    checkout, remote, _ = repository
    def fail(*args, **kwargs):
        raise release.ReleaseError("GitHub API is unavailable")
    monkeypatch.setattr(release, "github", fail)
    with pytest.raises(release.ReleaseError, match="unavailable"):
        prepare(repository)
    assert release.git(remote, "for-each-ref", "--format=%(refname)") == "refs/heads/main"


def test_release_with_assets_is_rejected(repository, api):
    checkout, _, plan = repository
    sha = prepare(repository)
    release.publish_refs(checkout, plan, sha)
    release.publish_page(checkout, plan, sha)
    api["page"]["assets"] = [{"name": "unexpected-binary"}]
    with pytest.raises(release.ReleaseError, match="source-only"):
        release.publish_page(checkout, plan, sha)


@pytest.mark.parametrize("stderr,missing_ok,allowed", [
    ("gh: Not Found (HTTP 404)", True, True),
    ("gh: Not Found (HTTP 404)", False, False),
    ("gh: Bad credentials (HTTP 401)", True, False),
    ("gh: API unavailable (HTTP 503)", True, False),
])
def test_api_errors_are_explicit(tmp_path, monkeypatch, stderr, missing_ok, allowed):
    monkeypatch.setenv("GITHUB_REPOSITORY", "fixture/repository")
    monkeypatch.setattr(release.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, "", stderr))
    if allowed:
        assert release.github(tmp_path, "releases/tags/test", missing_ok=missing_ok) is None
    else:
        with pytest.raises(release.ReleaseError, match="GitHub API"):
            release.github(tmp_path, "releases/tags/test", missing_ok=missing_ok)


def test_api_payload_uses_stdin_not_shell_interpolation(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "fixture/repository")
    calls = []
    def request(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, '{"sha":"value"}', "")
    monkeypatch.setattr(release.subprocess, "run", request)
    data = {"message": "'$message`with quotes", "parents": ["a", "b"]}
    assert release.github(tmp_path, "git/commits", data) == {"sha": "value"}
    args, kwargs = calls[0]
    assert args == ["gh", "api", "repos/fixture/repository/git/commits", "--method", "POST", "--input", "-"]
    assert json.loads(kwargs["input"]) == data
    assert "shell" not in kwargs


def test_cli_rejects_unknown_operations(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("RELEASE_COMMAND", "not-an-operation")
    assert release.main() == 1
    assert "Unknown release operation" in capsys.readouterr().err
