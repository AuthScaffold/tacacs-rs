# Source release automation

`source_release.py` prepares signed hydrated commits and promotes validated source releases.
It reuses the Cargo inventory and the pinned TOML hydrator.
The composite action installs the same hydration requirements file.
GitHub operations use the existing `gh` CLI.

## Operations

- `recover` reads the release branch for a generated commit that records the triggering source.
  It emits the stored plan before version computation.
- `prepare` hydrates a temporary source worktree and creates blobs, a tree, and a signed commit through the Git Database REST API.
  It publishes no refs.
  A recovered candidate must pass the same verification.
- `publish` verifies the supplied candidate, atomically publishes its refs, then creates the source-only GitHub Release.
  The caller must first run every required CI job against the candidate SHA.

The workflow supplies `SOURCE_SHA`, `CANDIDATE_SHA`, the version map, and tag inputs through environment variables.
The helper writes outputs through `GITHUB_OUTPUT`.
No JSON input is interpolated into a shell command.
Candidate creation and publication require `contents: write`.
Recovery and validation require read access only.

## Commit contract

The candidate contains one `Source-Commit`, one `Versions`, and one `Release-Plan` trailer.
The plan has schema version 1 and records the source, previous release head, versions, intended tags, and previous CalVer tag.
Duplicate JSON keys and duplicate metadata are errors.
The version map must cover exactly the library crates and the three managed executable crates.
Unmanaged executable versions remain unchanged.
An empty tag array permits a validation-only candidate.
The publish operation rejects such a candidate before any ref update.

The first candidate has one source parent.
Later candidates use `[previous_release, source]`.
The complete tree must match a fresh hydration of that source.
Both preparation and publication require GitHub's `verification.verified` value to be `true`.
The API request omits author, committer, and signature fields.
There is no unsigned fallback.

The publish operation requires every existing intended tag to be annotated and to resolve to the same candidate.
It rejects partial or conflicting tag sets.
The release branch update uses an expected-head lease and an atomic push with the tags.
The verified parent relationship makes the update append-only.
Recovery can complete a missing release page without moving an already published release branch.

Repository tags use `tacacs-rs-YYYY.MMDD.BUILD`.
Release titles use `TACACS-RS YYYY.MMDD.BUILD`.
Release notes include the actual version of every workspace crate and links to the source, candidate, and validation run.
No assets are uploaded.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider .github/steps/source-release
```

The tests use real local Git objects and refs, with mocked GitHub API responses.
They never create a real remote release.
GitHub-token signing and checkout of an unreferenced candidate require separate validation in Actions.
The CI workflow's manual rehearsal mode performs this validation without publishing release refs.
