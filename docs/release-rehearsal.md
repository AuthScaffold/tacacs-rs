# Source Release Validation

TACACS-RS releases contain versioned source.
CI does not publish binaries, archive SBOMs, debug symbols, checksums, or product container images.
GitHub supplies source ZIP and TAR downloads for each release tag.
Consumers such as SONiC build the components they need.

## Release sequence

Main-branch CI owns validation and publication in one workflow:

1. Apply the no-release policy.
2. Recover an interrupted publication for the same source, or compute versions from existing tags.
3. Hydrate the selected Cargo manifests and `Cargo.lock`.
4. Create a GitHub-signed commit object without changing branches or tags.
5. Require GitHub to report a verified signature.
6. Run the validation pipeline against that exact commit SHA.
7. Verify the candidate again.
8. Atomically advance `release` and create the intended tags.
9. Create the source-only GitHub Release.

The first generated commit has the source commit as its parent.
Later commits have two parents: the previous release head first, then the source commit.
The tree comes from the current source with hydrated versions, not a merge of old release files.
The release branch retains its history and never merges into `main`.

New main pushes cancel older release runs instead of queuing another release.
Checks within the latest run can still run in parallel.
Manual and scheduled validation use a separate concurrency group, so they cannot cancel a release run.
Cancellation does not undo refs that an earlier run already published.

## Automatic source downloads

The workflow starts on `main`, but the release does not use that triggering commit as its tag target.
CI first creates and validates the signed hydrated commit object.
The final publication step then atomically advances `release` and creates tags at that hydrated SHA.
Only after this push succeeds does it create the GitHub Release for the existing tag.

GitHub generates the automatic **Source code (zip)** and **Source code (tar.gz)** downloads from the tag's commit.
These downloads therefore contain the hydrated manifests and `Cargo.lock`.
The workflow does not create or upload an additional source archive.
The `source` input identifies the triggering commit for provenance validation.
The `candidate` input identifies the hydrated commit to publish.

See [GitHub's release documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases) for the automatic archive behavior.

## Version names

Library tags retain the form `<crate>-vX.Y.Z`.
Repository tags use `tacacs-rs-YYYY.MMDD.BUILD`.
GitHub Release titles use `TACACS-RS YYYY.MMDD.BUILD`.
Historical `tacon-*` tags remain valid CalVer baselines.
The same-day build counter includes both tag namespaces.

The `tacon`, `tacacsrs-agentd`, and `tacacsrs-agent-health` packages share the executable CalVer.
The release description lists every workspace crate version from the hydrated source.
Unchanged and experimental crates appear too.
An unmanaged experimental executable can retain `0.0.0-dev`.
The release description also links to the source commit, hydrated commit, and validation run.

## Candidate verification

The [source-release helper](../.github/steps/source-release/README.md) requires more than a commit subject or marker.
It compares the complete candidate tree against deterministic hydration of the recorded source.
It also verifies the parent order, version map, release metadata, and GitHub signature status.
An unsigned commit or inconsistent tree stops publication.
The workflow separately requires successful validation of the candidate SHA.
A verified signature does not certify the test results.

The workflow uses the Git Database REST API with `GITHUB_TOKEN`.
It does not require a PAT, a private signing key, or another commit action.
It omits explicit author and committer fields so GitHub can sign the bot commit.
An API or signature error has no unsigned fallback.

## Required validation

The reusable pipeline retains:

- AMD64 Linux builds and executed tests.
- ARMhf builds, executed QEMU tests, ABI validation, and startup checks.
- Windows direct-mode and portable-library tests.
- The minimum Rust version and default-feature compilation checks.
- Formatting, Clippy, documentation, coverage, and architecture guards.
- Dependency audit, unused/outdated dependency checks, and automation tests.
- Protobuf compatibility, pinned YANG validation, Miri, and fuzz smoke tests.

Existing event-specific settings and advisory lints remain unchanged.
Required jobs cannot fail, cancel, or unexpectedly skip.
CI diagnostic artifacts remain separate from release downloads.
Local product-container recipes and development containers remain available.

Linux and Windows each use one platform validation job.
Hydration precedes linting, documentation, default-feature checks, and tests in that same checkout.
The jobs own their metadata reports and toolchain caches.
There is no separate cache-warming or product-build job.

Unit and integration tests compile their required binaries.
Independent `cargo check` commands retain default-feature coverage without another full product build.
The Linux test step selects the complete workspace with all features, including experimental members.
It runs unit, integration, and documentation tests.
Windows also selects the workspace, but excludes the ten Linux-only packages.
It tests `tacon`, configuration, credential resolution, HTTP credentials, networking, protocol, and secrets.
The platform selection also applies to linting, documentation, and unused-dependency checks.
There is no separate job that repeats these tests for individual crate groups.
Architecture validation continues to enforce the dependency boundaries.
ARMhf, minimum-version, and automation checks also hydrate before validation.
An already hydrated candidate must remain unchanged by the hydration action.
Unit tests use `--locked` to reject an inconsistent prepared lockfile.

## Nonpublishing paths

PRs compute prerelease versions for their local build validation.
Scheduled runs validate the source without release version computation.
A push without a version change does not force a release.

To suppress publication, use a `[norelease]`, `[no-release]`, or `[skip-release]` head-commit marker.
Matching pull request labels also suppress publication.
CI still computes versions and tests the hydrated validation worktrees.
It does not create a remote candidate, move `release`, create tags, or create a GitHub Release.

## Manual signed rehearsal

Run a manual rehearsal against the selected branch:

```bash
gh workflow run ci.yml --ref main
```

This mode creates a signed commit object and runs the retained pipeline against its exact SHA.
It never runs the publication job, even when the version computation finds new tags.
The rehearsal uses patch-only version computation instead of public-API classification.
Production releases retain the normal API classification.
A candidate with no new tags remains valid for validation, but the publication helper rejects it.
PRs and scheduled runs do not gain write permissions.

## Retry and conflict behavior

The generated commit records `Source-Commit`, `Versions`, and a versioned `Release-Plan` JSON trailer.
Recovery reads this plan before fresh version computation.
It revalidates the recovered candidate and runs CI against its SHA again.
It does not allocate another version for an interrupted GitHub Release operation.

The final atomic push uses a lease for the captured release head.
The candidate contains that head as its first parent.
The lease rejects concurrent changes, including creation of the first release branch.
Existing tags must all point to the candidate.
A partial tag set, conflicting tag, or changed release head stops publication.
Automation never replaces release tags or rewrites release history.

Git ref publication and GitHub Release creation are separate operations.
If page creation fails, rerun the same workflow run.
Recovery retains the existing refs and completes the page.
An existing page must identify the same candidate and contain no uploaded assets.
Investigate conflicting refs instead of deleting tags to force a retry.

## Local automation tests

```bash
python3 -m pip install -r .github/steps/inject-versions/requirements.txt
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider \
  .github/steps/cargo-metadata .github/steps/check-architecture \
  .github/steps/compute-versions .github/steps/inject-versions \
  .github/steps/source-release
actionlint
```

The source-release tests use temporary Git repositories and mocked API responses.
They exercise hydration, atomic refs, conflict rejection, and retry behavior without real publication.
These tests do not prove GitHub signing or hosted-runner behavior.
Actual signing, checkout of the unreferenced candidate SHA, and platform validation require a GitHub Actions run.
