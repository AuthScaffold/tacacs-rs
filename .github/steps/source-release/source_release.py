"""Prepare signed hydrated commits, then promote validated source releases."""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

STEPS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(STEPS / "inject-versions"))
from hydrate_versions import HydrationError, hydrate  # noqa: E402
from workspace import MetadataError, inventory, load_metadata  # noqa: E402

SHA = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"\d+\.\d+\.\d+")
CALVER_PACKAGES = {"tacon", "tacacsrs-agentd", "tacacsrs-agent-health"}
PLAN_FIELDS = {
    "schema", "source", "release_head", "versions", "new_tags",
    "calver_tag", "previous_calver_tag",
}


class ReleaseError(ValueError):
    """The source release cannot be prepared or promoted safely."""


def run(args, workspace: Path, *, data: str | None = None) -> str:
    result = subprocess.run(args, cwd=workspace, input=data, text=True, capture_output=True)
    if result.returncode:
        raise ReleaseError(f"{args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def git(workspace: Path, *args: str) -> str:
    return run(["git", *args], workspace)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(text: str):
    return json.loads(text, object_pairs_hook=unique_object)


def github(workspace: Path, path: str, data=None, *, missing_ok=False):
    args = ["gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/{path}"]
    if data is not None:
        args += ["--method", "POST", "--input", "-"]
    result = subprocess.run(
        args, cwd=workspace, text=True, capture_output=True,
        input=json.dumps(data) if data is not None else None,
    )
    if result.returncode:
        if missing_ok and "(HTTP 404)" in result.stderr:
            return None
        raise ReleaseError(f"GitHub API {path} failed: {result.stderr.strip()}")
    response = decode(result.stdout)
    if not isinstance(response, dict):
        raise ReleaseError(f"GitHub API {path} did not return an object")
    return response


def require_sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ReleaseError(f"Invalid commit or tree SHA: {value!r}")
    return value


def validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != PLAN_FIELDS or type(plan["schema"]) is not int or plan["schema"] != 1:
        raise ReleaseError("Invalid source release plan schema")
    require_sha(plan["source"])
    if plan["release_head"] is not None:
        require_sha(plan["release_head"])
    versions, tags = plan["versions"], plan["new_tags"]
    if not isinstance(versions, dict) or not versions or any(
        not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name)
        or not isinstance(version, str) or not VERSION.fullmatch(version)
        for name, version in versions.items()
    ):
        raise ReleaseError("Release versions must map crate names to numeric release versions")
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags) or len(set(tags)) != len(tags):
        raise ReleaseError("Release tags must be a unique string array")
    allowed = {f"{name}-v{version}" for name, version in versions.items() if name not in CALVER_PACKAGES}
    calver = f"tacacs-rs-{versions['tacon']}" if "tacon" in versions else ""
    if calver:
        allowed.add(calver)
    if not set(tags) <= allowed or plan["calver_tag"] != (calver if calver in tags else ""):
        raise ReleaseError("Release tags do not match the version map")
    previous = plan["previous_calver_tag"]
    if not isinstance(previous, str) or (previous and not re.fullmatch(r"(?:tacon|tacacs-rs)-\d{4}\.\d{3,4}\.\d+", previous)):
        raise ReleaseError("Invalid previous CalVer tag")
    return plan


def read_plan(workspace: Path, candidate: str):
    message = git(workspace, "show", "-s", "--format=%B", require_sha(candidate))
    records = re.findall(r"^Release-Plan: (.+)$", message, re.MULTILINE)
    sources = re.findall(r"^Source-Commit: (.+)$", message, re.MULTILINE)
    if len(records) != 1 or len(sources) != 1:
        raise ReleaseError("Candidate must contain one release plan and one Source-Commit")
    plan = validate_plan(decode(records[0]))
    if sources[0] != plan["source"]:
        raise ReleaseError("Candidate source trailer does not match its release plan")
    versions = re.findall(r"^Versions: (.+)$", message, re.MULTILINE)
    if len(versions) != 1 or decode(versions[0]) != plan["versions"]:
        raise ReleaseError("Candidate version trailer does not match its release plan")
    return plan


def remote_release(workspace: Path):
    head = git(workspace, "ls-remote", "--heads", "origin", "refs/heads/release")
    if not head:
        return None
    sha = require_sha(head.split()[0])
    git(workspace, "fetch", "origin", "refs/heads/release:refs/remotes/origin/release")
    if git(workspace, "rev-parse", "refs/remotes/origin/release") != sha:
        raise ReleaseError("Release branch changed while fetching")
    return sha


def outputs(plan, candidate: str):
    values = {"candidate": candidate, "has_release": "true" if plan["new_tags"] else "false"}
    values.update({key: plan[key] for key in ("versions", "new_tags", "calver_tag", "previous_calver_tag")})
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            stream.write(f"{key}={json.dumps(value, separators=(',', ':')) if isinstance(value, (dict, list)) else value}\n")


def recover(workspace: Path, source: str):
    head = remote_release(workspace)
    if head is None:
        return
    matches = git(
        workspace, "log", "--first-parent", "--format=%H", "--fixed-strings",
        "--grep", f"Source-Commit: {source}", head,
    )
    recovered = []
    for candidate in matches.splitlines():
        message = git(workspace, "show", "-s", "--format=%B", candidate)
        if "Release-Plan:" not in message:
            continue  # Historical unsigned releases use the old message format.
        plan = read_plan(workspace, candidate)
        if plan["source"] == source:
            recovered.append((plan, candidate))
    if len(recovered) > 1:
        raise ReleaseError("More than one generated release records this source")
    if recovered:
        outputs(*recovered[0])


@contextmanager
def hydrated_source(workspace: Path, plan):
    with tempfile.TemporaryDirectory(prefix="tacacs-source-release-") as directory:
        checkout = Path(directory) / "source"
        git(workspace, "worktree", "add", "--detach", str(checkout), plan["source"])
        try:
            packages = inventory(load_metadata(checkout, no_deps=True, locked=False))["packages"]
            managed = {
                package["name"] for package in packages
                if set(package["target_kinds"]) & {"lib", "rlib", "cdylib"}
                or package["name"] in CALVER_PACKAGES
            }
            if set(plan["versions"]) != managed:
                raise ReleaseError("Version map does not cover exactly the managed workspace crates")
            hydrate(checkout, plan["versions"])
            manifests = [package["manifest_path"] for package in packages]
            git(checkout, "add", "--", "Cargo.lock", *manifests)
            if not git(checkout, "diff", "--cached", "--name-only"):
                raise ReleaseError("Release hydration did not change the source tree")
            yield checkout, git(checkout, "write-tree")
        finally:
            git(workspace, "worktree", "remove", "--force", str(checkout))


def verify(workspace: Path, candidate: str, source: str):
    require_sha(candidate)
    git(workspace, "fetch", "origin", candidate)
    plan = read_plan(workspace, candidate)
    if plan["source"] != source:
        raise ReleaseError("Candidate does not match the triggering source")
    response = github(workspace, f"git/commits/{candidate}")
    if response.get("sha") != candidate:
        raise ReleaseError("GitHub returned a different candidate SHA")
    if response.get("verification", {}).get("verified") is not True:
        raise ReleaseError("GitHub did not verify the candidate signature")
    parents = ([plan["release_head"]] if plan["release_head"] else []) + [source]
    actual_parents = git(workspace, "show", "-s", "--format=%P", candidate).split()
    if actual_parents != parents or [parent.get("sha") for parent in response.get("parents", [])] != parents:
        raise ReleaseError("Candidate parent order does not match the release plan")
    with hydrated_source(workspace, plan) as (_, tree):
        if git(workspace, "rev-parse", f"{candidate}^{{tree}}") != tree or response.get("tree", {}).get("sha") != tree:
            raise ReleaseError("Candidate tree is not the deterministic hydrated source tree")
    return plan


def prepare(workspace: Path, plan, candidate: str):
    if candidate:
        recovered = verify(workspace, candidate, plan["source"])
        if any(recovered[key] != plan[key] for key in ("versions", "new_tags", "calver_tag", "previous_calver_tag")):
            raise ReleaseError("Recovered candidate differs from computed release inputs")
        outputs(recovered, candidate)
        return
    plan["release_head"] = remote_release(workspace)
    validate_plan(plan)
    with hydrated_source(workspace, plan) as (checkout, expected_tree):
        changes = git(checkout, "diff", "--cached", "--name-only", "-z").split("\0")
        entries = []
        for path in filter(None, changes):
            blob = github(workspace, "git/blobs", {
                "encoding": "base64",
                "content": base64.b64encode((checkout / path).read_bytes()).decode("ascii"),
            })
            mode = git(checkout, "ls-files", "--stage", "--", path).split()[0]
            entries.append({"path": path, "mode": mode, "type": "blob", "sha": require_sha(blob.get("sha"))})
        tree = github(workspace, "git/trees", {
            "base_tree": git(workspace, "rev-parse", f"{plan['source']}^{{tree}}"),
            "tree": entries,
        })
        if tree.get("sha") != expected_tree:
            raise ReleaseError("GitHub tree differs from local hydration")
        message = (
            "chore: hydrate release versions\n\n"
            f"Versions: {json.dumps(plan['versions'], sort_keys=True)}\n"
            f"Source-Commit: {plan['source']}\n"
            f"Release-Plan: {json.dumps(plan, sort_keys=True, separators=(',', ':'))}\n"
            "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>\n"
        )
        response = github(workspace, "git/commits", {
            "message": message, "tree": expected_tree,
            "parents": ([plan["release_head"]] if plan["release_head"] else []) + [plan["source"]],
        })
        if response.get("verification", {}).get("verified") is not True:
            raise ReleaseError("GitHub did not sign and verify the hydrated commit")
        candidate = require_sha(response.get("sha"))
    verify(workspace, candidate, plan["source"])
    outputs(plan, candidate)


def publish_refs(workspace: Path, plan, candidate: str):
    if not plan["new_tags"]:
        raise ReleaseError("A tagless rehearsal candidate cannot be published")
    head = remote_release(workspace)
    refs = {}
    for line in git(workspace, "ls-remote", "--tags", "origin").splitlines():
        sha, ref = line.split()
        refs[ref] = sha
    existing = [tag for tag in plan["new_tags"] if f"refs/tags/{tag}" in refs]
    if existing:
        if len(existing) != len(plan["new_tags"]):
            raise ReleaseError("Only some intended release tags exist")
        for tag in existing:
            if refs.get(f"refs/tags/{tag}^{{}}") != candidate:
                raise ReleaseError(f"Existing annotated tag {tag} does not match the candidate")
        if head is None:
            raise ReleaseError("Release tags exist without the release branch")
        git(workspace, "merge-base", "--is-ancestor", candidate, head)
        return
    if head != plan["release_head"]:
        raise ReleaseError("Release branch changed after candidate preparation")
    git(workspace, "config", "user.name", "github-actions[bot]")
    git(workspace, "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    for tag in plan["new_tags"]:
        git(workspace, "tag", "-a", tag, candidate, "-m", f"Release {tag}")
    # The candidate contains this head as its first parent. The lease prevents
    # concurrent ref changes, including creation of the first release branch.
    git(workspace, "push", "--atomic", f"--force-with-lease=refs/heads/release:{head or ''}",
        "origin", f"{candidate}:refs/heads/release",
        *(f"refs/tags/{tag}" for tag in plan["new_tags"]))


def crate_table(workspace: Path) -> str:
    packages = inventory(load_metadata(workspace, no_deps=True, locked=False))["packages"]
    rows = ["| Crate | Version |", "| --- | --- |"]
    rows.extend(f"| `{package['name']}` | `{package['version']}` |" for package in sorted(packages, key=lambda package: package["name"]))
    return "\n".join(rows)


def publish_page(workspace: Path, plan, candidate: str):
    tag = plan["calver_tag"]
    if not tag:
        return
    title = f"TACACS-RS {tag.removeprefix('tacacs-rs-')}"
    marker = f"<!-- tacacs-rs-source:{candidate} -->"
    existing = github(workspace, f"releases/tags/{tag}", missing_ok=True)
    if existing is not None:
        if existing.get("name") != title or marker not in (existing.get("body") or "") or existing.get("assets") != [] or existing.get("draft") or existing.get("prerelease"):
            raise ReleaseError("Existing GitHub Release does not match this source-only release")
        return
    data = {"tag_name": tag, "target_commitish": candidate}
    if plan["previous_calver_tag"]:
        data["previous_tag_name"] = plan["previous_calver_tag"]
    notes = github(workspace, "releases/generate-notes", data)
    if not isinstance(notes.get("body"), str):
        raise ReleaseError("GitHub did not generate release notes")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repository = os.environ["GITHUB_REPOSITORY"]
    with hydrated_source(workspace, plan) as (checkout, _):
        body = (
            f"{marker}\nSource-only release. Consumers build the components they need.\n\n"
            f"- Source commit: [{plan['source']}]({server}/{repository}/commit/{plan['source']})\n"
            f"- Verified hydrated commit: [{candidate}]({server}/{repository}/commit/{candidate})\n"
            f"- [Validation run]({os.environ['VALIDATION_RUN_URL']})\n\n"
            f"## Crate versions\n\n{crate_table(checkout)}\n\n{notes['body']}\n"
        )
    with tempfile.TemporaryDirectory(prefix="tacacs-release-notes-") as directory:
        path = Path(directory) / "notes.md"
        path.write_text(body, encoding="utf-8")
        run(["gh", "release", "create", tag, "--verify-tag", "--target", candidate,
             "--title", title, "--notes-file", str(path)], workspace)


def main() -> int:
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve()
    try:
        source = require_sha(os.environ["SOURCE_SHA"])
        command = os.environ["RELEASE_COMMAND"]
        if command == "recover":
            recover(workspace, source)
        elif command == "prepare":
            plan = {
                "schema": 1, "source": source, "release_head": None,
                "versions": decode(os.environ["VERSIONS"]),
                "new_tags": decode(os.environ["NEW_TAGS"]),
                "calver_tag": os.environ["CALVER_TAG"],
                "previous_calver_tag": os.environ["PREVIOUS_CALVER_TAG"],
            }
            prepare(workspace, validate_plan(plan), os.environ.get("CANDIDATE_SHA", ""))
        elif command == "publish":
            candidate = require_sha(os.environ["CANDIDATE_SHA"])
            plan = verify(workspace, candidate, source)
            publish_refs(workspace, plan, candidate)
            publish_page(workspace, plan, candidate)
        else:
            raise ReleaseError(f"Unknown release operation: {command}")
    except (ReleaseError, HydrationError, MetadataError, OSError, json.JSONDecodeError, KeyError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
