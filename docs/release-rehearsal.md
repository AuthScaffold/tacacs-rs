# Release Rehearsal

The no-release CI path is the release rehearsal. It runs the full build,
hydrates versions, and records release evidence. It does not publish anything.
There is no second release pipeline.

The CI matrix and the local Linux rehearsal use
[`.github/products.json`](../.github/products.json). The
[registry validator](../.github/steps/cargo-metadata/README.md#release-product-registry)
checks each product against Cargo metadata and the supported packaging policy.
Workspace membership alone does not enroll a release product. Independent
golden tests preserve the supported product and platform records.

This guide explains how the rehearsal runs, what evidence it produces, and how to
read that evidence. It does not change how a real release publishes.

## When the rehearsal runs

The rehearsal runs on these events:

- A push to `main` that carries a no-release marker. The marker is a
  `[no-release]` or `[skip-release]` token in the head commit message, or a
  `no-release`/`skip-release` label on the associated pull request.
- A push to `main` that does not change any computed version.
- The weekly scheduled run.

On a real release push, the same build runs, and then the publish jobs tag the
source, push the generated release branch, and promote the container image.

## What the rehearsal does

The rehearsal runs every build and packaging operation that a real release runs:

1. **Compute versions.** CI computes the SemVer and CalVer versions from Git
   tags on every push, including a no-release push. The marker suppresses
   publication, not version computation.
2. **Hydrate manifests.** The official build injects the computed versions into
   the `Cargo.toml` files and `Cargo.lock` before it compiles each product.
3. **Build products.** CI builds every product in the matrix for its target.
4. **Package SBOMs and debug symbols.** Each product carries its SBOM files and
   debug symbols.
5. **Stage and record.** CI stages the archives, writes the release manifest,
   and writes the checksums file.
6. **Build the container.** On a no-release push, CI builds the `tacacsrs-agentd`
   container image without pushing it.

The rehearsal never runs the publish jobs. It never pushes a tag, the generated
release branch, a GitHub release, or a container image.

## Release evidence

The rehearsal uploads a `release-assets` artifact. It contains the product
archives, the SBOM files, the debug symbols, the release manifest, and the
checksums file. Each archive contains `build-provenance.json`. Each product also
has a separate `build-provenance-<asset>.json` file outside its archive.

### Order of the digests

The steps run in this order:

```text
stage-release-assets  ->  release-manifest  ->  generate-checksums
```

The release manifest records the digest of every archive and provenance file. The checksums file
then records the digest of every file, including the manifest. The manifest
never hashes itself and never hashes the checksums file.

### Reading the release manifest

`release-manifest.json` uses schema version 2 and records the release evidence:

- `source.commit`: the source commit SHA, passed from `github.sha`.
- `versions`: the crate-name to version map that hydration injected.
- `artifacts`: the SHA-256 digest of every staged archive and provenance file.
- `buildProvenance`: verified build records, keyed by archive name.
- `schemas.yang`: the pinned YANG generation manifest identity.
- `schemas.protobuf`: the SHA-256 digest of every IPC schema file.
- `assemblyToolchain`: optional tool versions from the finalizer host. These
   values do not describe the tools that compiled the products.

The official build captures each product record after staging and before archive
creation. CI uploads a copy as `packaged/build-provenance-<asset>.json`.
The record contains the source commit, hydrated package identity, target,
profile, requested features, and build-host tool versions. The feature record
states whether default features are enabled. It does not claim a resolved
dependency feature graph.

Each record includes hashes of the staged files, hydrated package manifest, and
lockfile. Executables must report the hydrated version through `--version`.
Shared libraries use the hydrated manifest version and staged file hash.
The `openssl` tool value describes the CLI, not the linked library ABI.

The finalizer requires a record for every archive. It checks the source against
`github.sha` and package versions against the computed map. For packages absent
from that map, it checks the source manifest version. It also checks the embedded
record against the uploaded copy and verifies every archived payload hash.

These records are build evidence, not signed attestations. Offline checks confirm
file consistency. They do not authenticate the producer.

Verify the digests offline. Recompute the SHA-256 of each archive and compare it
to the manifest. The checksums file must list the manifest with a matching
digest.

### Confirming hydration

An archive name alone does not prove hydration. Confirm the embedded version:

```bash
tar -xzf tacon-linux-gnu-x86_64.tar.gz
./tacon-linux-gnu-x86_64/tacon --version
```

The reported version must match the `tacon` entry in the manifest `versions`
map.

### Confirming native dependencies

The Linux archives link against the system OpenSSL. The Windows archive bundles
the OpenSSL runtime DLLs. Confirm the shared library needs:

```bash
ldd ./tacon-linux-gnu-x86_64/tacon
```

### Confirming the debug symbols

Each Linux archive carries a separate debug file next to its stripped binary.
The release build keeps the full binary through staging, then the debug step
splits it in three operations:

- `objcopy --only-keep-debug` writes the DWARF debug info to `<artifact>.debug`.
- `strip` removes the debug info from the staged binary. The dynamic symbol
  table stays, so a shared object still exports its symbols.
- `objcopy --add-gnu-debuglink` records the base name of the `.debug` file in
  the stripped binary.

A debugger that opens the stripped binary finds `<artifact>.debug` in the same
directory and loads full symbols:

```bash
tar -xzf tacon-linux-gnu-x86_64.tar.gz
gdb ./tacon-linux-gnu-x86_64/tacon
```

A debug build keeps the unstripped binary and writes no separate file.

## Run the rehearsal locally

`rehearse_linux.py` runs the Linux packaging path on a developer machine from a
committed source revision. It drives the same `stage-binary-package`,
`package-debug-symbols`, and `create-linux-archive` scripts that CI runs.
It also uses the same SBOM staging and build provenance CLIs.

The output directory must be new or empty. The tool rejects nonempty directories,
including directories from failed or completed rehearsals. It never deletes their
contents. Use a new directory for each run to exclude stale archives.

The output directory must be outside the source checkout. The default Cargo
target directory is `<output>/build`. For repeated builds, `--build-cache` accepts
a trusted existing Cargo target directory. It cannot overlap the source checkout
or the exported source, staging, packaged, release, or rollback directories.
The tool does not delete the cache. A shared cache does not permit existing
release output.

```bash
python3 .github/steps/release-manifest/rehearse_linux.py \
  --source . \
  --revision HEAD \
  --versions versions.json \
  --output /tmp/tacacs-rs-rehearsal \
  --target x86_64-unknown-linux-gnu \
  --profile release
```

The tool does the following:

1. It checks the output directory, then preflights its tools. A missing tool is
   a clear failure. The tool never installs anything.
2. It exports the committed revision with `git archive` into `<output>/source`.
   Only tracked files take part. The working tree is never changed, and an
   uncommitted file is never built.
   The exported registry tool validates all product records, then selects the
   Linux records for the requested target. Missing or invalid records fail
   before hydration or builds.
3. It hydrates the computed versions into the exported tree with the committed
   `inject-versions` tool. The source workspace `Cargo.lock` is never written.
4. It builds the four supported Linux products with `--locked` and `--target`:
   `tacon`, `tacacsrs-agentd`, `tacacsrs-agent-health`, and the
   `tacacsrs-bash-plugin` shared object.
5. It stages the binaries, extracts debug symbols, and generates CycloneDX SBOMs.
   JSON and XML are both required. The shared staging helper checks package
   identities and versions before it writes sanitized copies.
6. It validates each artifact. An executable must report the computed
   `--version`. The Bash plugin must export `plugin_init`, `plugin_uninit`, and
   `on_shell_execve`. Every native ELF must resolve its shared libraries. Any
   `ldd` failure stops the rehearsal. It then captures build provenance.
7. It archives each product and stages the archives and provenance copies.
   It writes the manifest, then the checksums file, and verifies the archive digests.
8. It rehearses a rollback. It redeploys one archive into a scratch directory
   and runs it. It never contacts a host and never changes a credential.

The versions file is a JSON object that maps crate names to versions, the same
map that hydration injects. An empty object (`{}`) rehearses the full pipeline
without version changes.

The shared SBOM sanitizer parses JSON and XML with Python standard libraries.
It replaces absolute workspace and source-export paths with `/workspace`.
It replaces local `file://` download URLs with the repository URL, including
PURL download qualifiers. Package names and versions remain unchanged.

### Required tools

The rehearsal needs Python 3.11 or later, `git`, `rustc`, `cargo`,
`cargo-cyclonedx`, `objcopy`, `strip`, `tar`, `ldd`, and `nm`.
Install `cargo-cyclonedx` with
`cargo install cargo-cyclonedx --version 0.5.9 --locked`, which matches the SBOM step.
The `openssl` CLI is optional for provenance capture.

### Helper tests

Run the helper and workflow contract tests before a full rehearsal:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider .github/steps/release-manifest
```

The tests use fixture archives and mocked build tools. They cover provenance
binding, path sanitization, required formats, helper arguments, and stale output
rejection. The existing source-export test uses a temporary Git repository.
The fixture rehearsal also runs the registry, hydration, packaging, SBOM staging,
provenance, manifest, checksum, and rollback paths without publication.

### Scope

The rehearsal is Linux-only. It makes no Windows or container claim. It is not a
release. It never pushes a tag, writes the generated release branch, or
publishes an image.

## Rollback

A release is a source commit, a set of computed versions, and the tags and
generated release branch that point at a hydrated commit. To roll back, redeploy
a known good source commit and its recorded versions. Do not mutate a published
tag.

1. Find the known good commit. The release manifest `source.commit` and the
   release commit `Source-Commit` trailer both record it.
2. Redeploy the archives for that commit, or rebuild them from that commit with
   the recorded versions.
3. For the container, pull the image tag for the known good version and redeploy
   it.

The CI rehearsal does not perform a rollback. It records the evidence that a
rollback needs. The local `rehearse_linux.py` rehearses only the offline part:
it re-verifies the archives against the manifest and redeploys one archive into
a scratch directory. It never contacts a host and never changes a credential.
