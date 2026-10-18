# Release manifest

`release_manifest.py` records, in one offline artifact, the evidence that ties a
set of staged release archives to the source that produced them. The reusable
pipeline runs this step on every push, including the no-release rehearsal path,
so each build keeps a reviewable provenance record without enabling publication.

## What the manifest records

- **Source commit.** The caller passes the triggering commit SHA explicitly
  (`github.sha`), rather than reading Git in the packaging job.
- **Computed versions.** The crate-name to version map that hydration injected
  into the manifests for this build.
- **Artifact digests.** The SHA-256 digest of every staged release artifact.
- **Schema identities.** The pinned YANG generation manifest identity
  (manifest digest, upstream source commit, module digest, and generated Rust
  digest) and the SHA-256 digest of every protobuf IPC schema file.
- **Build provenance.** Schema version 2 includes `buildProvenance`, keyed by
  archive name. Each record comes from the build host after staging. It records
  the source, package identity, target, profile, requested features, tool versions,
  and staged file hashes.
- **Assembly tools.** `assemblyToolchain` contains optional tool versions from
  the finalizer host. These are not binary build provenance.

`build_provenance.py` writes `build-provenance.json` inside each package and an
identical `packaged/build-provenance-<asset>.json` upload copy. The finalizer
requires one record per archive. It checks the expected source and package
version, the embedded copy, and every archived payload hash without extraction.
For packages absent from the computed versions map, it uses the source manifest
version. Executable capture also checks `--version` against the hydrated manifest.

The records include hydrated package manifest and lockfile hashes. Tool versions
describe the build host. The `openssl` value describes the CLI, not the linked
library ABI. Requested features do not claim a resolved dependency feature graph.
These records are not signed attestations.

## Step order and the self-hash rule

The manifest is generated **after** staging the release assets and **before**
generating the checksums file:

```text
stage-release-assets  ->  release-manifest  ->  generate-checksums
```

The manifest records the archive and provenance file digests. The later `checksums-sha256.txt` file
then covers the manifest, because the manifest is just another file in the
release directory by the time checksums run. The manifest never hashes its own
output file and never hashes the checksums file, so there is no recursive or
self digest.

## Offline and safe scanning

Digest collection never follows symbolic links and enforces three rules:

- Every artifact must be a regular file. A symbolic link is rejected, which is
  also how the scan keeps a file from outside the artifacts directory out of the
  digest set.
- Two artifacts must not share a basename, because the manifest and the
  checksums file key by basename.
- The manifest output file and the checksums file are excluded.

`verify_artifact_hashes(manifest, artifacts_dir)` recomputes the recorded
digests offline and reports corruption or a missing file.

## Command-line usage

```bash
python release_manifest.py \
  --artifacts release \
  --versions versions.json \
  --source "$GITHUB_SHA" \
  --workspace . \
  --provenance-dir raw/packages \
  --output release/release-manifest.json
```

The `--versions` argument is a path to a JSON object file. The action
materializes the versions map into a file through an environment variable, so
JSON quoting never reaches the shell command line.

## Action usage

```yaml
- name: Stage release assets
  uses: ./.github/steps/stage-release-assets

- name: Generate the release manifest
  uses: ./.github/steps/release-manifest
  with:
    source-commit: ${{ github.sha }}
    versions: ${{ inputs.versions }}
    provenance-directory: raw/packages

- name: Generate checksums
  uses: ./.github/steps/generate-checksums
```

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider .github/steps/release-manifest
```

The tests are hermetic. They build fake archives and a fake workspace on a
temporary directory, then cover the digest map, symbolic-link rejection,
basename collisions, the versions map, schema identities, and assembly tools.
They also check build evidence against TAR and ZIP contents, reject inconsistent
records, and preserve the self-hash exclusion. The shared SBOM tests cover JSON
and XML sanitization. Identity tests use Cargo metadata with temporary manifests.
The tests never compile crates or reach the network.

## Linux release rehearsal

`rehearse_linux.py` runs the Linux release packaging path offline from a
committed source revision. It exports the revision with `git archive`, hydrates
the computed versions with the `inject-versions` tool, builds the four supported
Linux products, and drives the same `stage-binary-package`,
`package-debug-symbols`, and `create-linux-archive` scripts that CI runs. It then
generates and verifies SBOMs, validates each artifact, calls this manifest tool
through its CLI, writes the checksums file, and rehearses an offline rollback.
See `docs/release-rehearsal.md` for the full guide.

The rehearsal and CI share `stage-sbom-files/stage_sbom.py` and
`build_provenance.py`. JSON and XML SBOMs are required. The output directory must
be new or empty. Existing files are never deleted. The helpers require Python
3.11 or later.

The output directory must be outside the source checkout. `--build-cache` accepts
a trusted Cargo target directory for repeated builds. The default is
`<output>/build`. The cache cannot overlap source, staging, packaged, release,
or rollback directories. Release output remains separate and must be empty.

```bash
python3 .github/steps/release-manifest/rehearse_linux.py \
  --source . --revision HEAD --versions versions.json \
  --output /tmp/tacacs-rs-rehearsal
```

Its hermetic tests run with the same command as the manifest tests:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider .github/steps/release-manifest
```

The rehearsal test suite covers the pure helpers and the committed-source export
with a throwaway git repository. It never builds a crate and never reaches the
network.
