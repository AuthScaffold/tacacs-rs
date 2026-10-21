# Developer Documentation

This document describes the development, CI, and release processes for tacacs-rs.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Session Wrapper Smoke Tests](#session-wrapper-smoke-tests)
- [Code Quality](#code-quality)
- [YANG Code Generation](#yang-code-generation)
- [CI/CD Overview](#cicd-overview)
- [Releasing](#releasing)

## Prerequisites

- Rust toolchain (install via [rustup](https://rustup.rs/))
- For formatting: `rustup component add rustfmt --toolchain nightly`
- For linting: `rustup component add clippy`

### Optional Tools

```bash
# Code coverage
cargo install cargo-llvm-cov

# Unused dependencies check
cargo install cargo-udeps

# Outdated dependencies check
cargo install cargo-outdated

# Security audit
cargo install cargo-audit

# SBOM generation (Software Bill of Materials)
cargo install cargo-cyclonedx
```

### Generate an SBOM locally

Run these commands to generate a Software Bill of Materials (SBOM):

```bash
# Generate SBOM in JSON format (CycloneDX standard)
cargo cyclonedx --format json --all --all-features

# Generate SBOM in XML format
cargo cyclonedx --format xml --all --all-features

# SBOM files are generated for each workspace member:
# - executables/tacon/tacon.cdx.json
# - libraries/tacacsrs_protocol/tacacsrs-protocol.cdx.json
# - libraries/tacacsrs_networking/tacacsrs-networking.cdx.json
```

SBOM generation is optional for local consumers.
The source-only release pipeline does not generate or distribute archive SBOMs.

## Development Setup

### Development container

The development container is the supported environment for complete workspace development.
Source, Git metadata, build artifacts, and remote editor state use persistent Linux-native volumes.
The original host checkout is a read-only seed for the first import, not the active source directory.

Before rebuilding, read the [container migration guide](docs/dev-container.md).
It explains how to preserve unpushed commits and untracked files.

On Windows, start a Podman 5 or later machine before opening the repository.
A Hyper-V or WSL2 machine is supported. Docker is an alternative runtime.

For Podman, configure VS Code:

```json
{
  "dev.containers.dockerPath": "podman"
}
```

After saving and committing the seed checkout, run **Dev Containers: Reopen in Container** or **Dev Containers: Rebuild Container**.
The bootstrap imports its current named branch once and preserves the native checkout on later rebuilds.

```bash
# Run inside the native-volume workspace after setup.
cd /workspaces/tacacs-rs
git branch --show-current

# Build all crates in Linux
cargo build --workspace

# Run all tests
cargo test --workspace
```

### Building with OpenSSL-backed TLS

The `tacacsrs_networking` library uses dynamically linked OpenSSL for certificate-based TLS. The `psk` feature adds TLS 1.3 pre-shared key support.

#### Linux

Install the OpenSSL development libraries with the package manager for your distribution:

```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev pkg-config

# Fedora/RHEL
sudo dnf install openssl-devel

# Build with OpenSSL-backed TLS and TLS 1.3 PSK support
cargo build --workspace
```

#### Windows `tacon`

A prebuilt OpenSSL installation is required. Use [vcpkg](https://vcpkg.io/) to install OpenSSL.

##### Installing OpenSSL with vcpkg (Recommended)

1. Use the [vcpkg getting started instructions](https://learn.microsoft.com/en-us/vcpkg/get_started/get-started) to install vcpkg.
2. Install OpenSSL:

   ```powershell
   vcpkg install openssl
   ```

3. Set the environment variable to the OpenSSL directory:

   ```powershell
   $env:OPENSSL_DIR = "X:\vcpkg\installed\x64-windows"
   ```

   Change the path for your vcpkg installation. Make sure that the directory contains the `include/openssl` and `lib` subdirectories.

4. Build the supported Windows packages:

   ```powershell
   cargo build --package tacon
   ```

Set `OPENSSL_DIR` through **System Properties → Environment Variables** to make the value available in new terminals.

##### Manual OpenSSL installation

To use a different prebuilt OpenSSL installation, set these environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `OPENSSL_DIR` | Root of the OpenSSL installation (must contain an `include/openssl` subdirectory) | `C:\development\tools\openssl` |
| `OPENSSL_LIB_DIR` | Directory containing `libssl.lib` and `libcrypto.lib` | `C:\development\tools\openssl\lib\VC\x64\MD` |

> **Note:** Use the **MD** (Multi-threaded DLL) variant of the OpenSSL libraries. The Rust MSVC toolchain links to the dynamic C runtime. The OpenSSL build must use the same runtime. Other variants cause linker errors or runtime errors.

```powershell
$env:OPENSSL_DIR     = "C:\development\tools\openssl"
$env:OPENSSL_LIB_DIR = "C:\development\tools\openssl\lib\VC\x64\MD"

cargo build --package tacon
```

## Running Tests

```bash
# Run all tests
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture

# Run a specific test
cargo test test_name

# Run tests for a specific crate
cargo test -p tacacsrs-protocol
```

### Session Wrapper Smoke Tests

The Linux `session-wrapper` has more smoke tests and integration tests. These tests cover seccomp notifications, child processes, and descendant processes.

For the test procedure, read [Session Wrapper Testing](docs/session-wrapper-testing.md).

### Parser fuzz smoke tests

The protocol parsers have libFuzzer targets in `fuzz/`. CI runs them as blocking smoke tests through the `.github/steps/run-fuzz-smoke` action. Each target runs for 30 seconds.

```bash
# Run one target (requires nightly + cargo-fuzz)
cargo +nightly fuzz run fuzz_authentication_parse -- -max_total_time=30

# List all targets
cargo +nightly fuzz list
```

The targets are `fuzz_header_parse`, `fuzz_accounting_request_parse`, `fuzz_accounting_reply_parse`, `fuzz_accounting_request_packet_parse`, `fuzz_authentication_parse`, `fuzz_authorization_parse`, and `fuzz_protocol_parse`. The dedicated `fuzz_authentication_parse` and `fuzz_authorization_parse` targets parse each message body with `from_bytes` and `from_packet`, then confirm that every parsed value re-serializes to identical bytes. The `fuzz_protocol_parse` target exercises every message family together.

### Code Coverage

```bash
# Generate coverage report (requires cargo-llvm-cov)
cargo llvm-cov --workspace --all-features

# Generate HTML report
cargo llvm-cov --workspace --all-features --html
```

## Code Quality

### Formatting

The project uses nightly rustfmt because `rustfmt.toml` enables unstable formatting options.

```bash
# Check formatting
cargo +nightly fmt --all -- --check

# Apply formatting
cargo +nightly fmt --all
```

### Linting

Blocking checks include default Clippy, checked numeric conversions, error and panic documentation, unsafe-block explanations, and internal API visibility.
Broad pedantic and nursery checks are advisory. Function length is not a design requirement.
Keep a cohesive state transition together when extraction would hide its sequencing or ownership.

The workspace allows `assert_is_empty` and `chunks_exact_to_as_chunks`.
Simple emptiness assertions avoid extra type annotations and do not print collection contents or secret bytes on failure.
Checked chunk iterators keep argument grouping and remainder validation together.
Keep correctness checks enabled. Add a specific global allowance when a style rule makes the code less clear.

Dependency freshness is a report, not a requirement to adopt unrelated major upgrades.
Security audits, unused-dependency checks, and tool execution failures remain blocking.

```bash
# Run clippy
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Inspect advisory style findings
cargo clippy --workspace --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery

# Match CI documentation coverage, including private implementation modules
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --document-private-items

# Verify the declared minimum supported compiler
cargo +1.88.0 check --workspace --all-targets --all-features --locked
```

Every package inherits `rust-version.workspace`. Parser fuzz failures are blocking, not advisory.

### Reading Stateful Code

Start with the owner and its transition, then read the adjacent tests:

| Behavior | Starting point |
| --- | --- |
| Canonical parsing and preparation | [Configuration facade](libraries/tacacsrs_config/src/lib.rs) |
| Source observation, refresh, and expiry | [Configuration supervisor](libraries/tacacsrs_agent/src/runtime/config_supervisor.rs) |
| Catalog and policy commits | [Publication](libraries/tacacsrs_agent/src/upstream/manager/publication.rs) |
| Client construction and closure | [Client facade](libraries/tacacsrs_networking/src/client/mod.rs) |
| First-reply negotiation and cache promotion | [Single-connect ownership](libraries/tacacsrs_networking/src/single_connect/mod.rs) |
| Logical operations and wire conversion | [Operation facade](libraries/tacacsrs_protocol/src/operations.rs) |
| CLI transport selection | [Backend](executables/tacon/src/backend.rs) |
| Unix listener lifetime | [Socket owner](libraries/tacacsrs_unix_socket/src/listener.rs) |

Module documentation names the owner, entry points, state transitions, and cancellation limits.
Function documentation explains contracts and failure conditions. Inline comments explain invariants rather than narrating assignments.
Client, catalog, connection, and session lifetimes are distinct even when their states use similar words.
Publication keeps runtime state, health, and coordinator bookkeeping in one non-awaiting commit. Retirement occurs afterward.

### Other Checks

```bash
# Check for unused dependencies (requires nightly + cargo-udeps)
cargo +nightly udeps --workspace --all-targets

# Check for outdated dependencies
cargo outdated --workspace

# Security audit
cargo audit
```

## YANG Code Generation

The `libraries/tacacsrs_config` crate contains generated Rust types that mirror the expanded `ietf-system-tacacs-plus` YANG tree.

### Prerequisites

Before you generate artifacts, install the generator requirements:

```bash
cd libraries/tacacsrs_config/yang
python -m pip install -r requirements.txt
```

### Regenerate the expanded tree reference

From the repository root:

```bash
cd libraries/tacacsrs_config/yang
python expand_yang_tree.py --features-ini feature-flags.ini > expanded-tree.txt
```

This command updates `expanded-tree.txt`. This checked-in file shows the expanded YANG data tree.

The tree includes all resolved `uses` statements and local YANG augmentations from `modules/`.

### Regenerate Rust types

From the same directory:

```bash
cd libraries/tacacsrs_config/yang
python expand_yang_tree.py \
  -f rust \
  --features-ini feature-flags.ini \
  -o generated_types.rs
cp generated_types.rs ../src/generated.rs
```

`expand_yang_tree.py` gets the upstream IETF YANG modules. It passes the local modules from `libraries/tacacsrs_config/yang/modules/` to `pyang`.

The `feature-flags.ini` file controls upstream and project features. Project features include `tacacsrs:psk-dhe-ke-hello-params`.

`expand_yang_tree.py` pins the upstream `YangModels/yang` commit. `generation-manifest.json` records this commit and the SHA-256 values for the source, input, and output.

The cache must use a detached HEAD at the specified commit. Use `--clean` to replace an old cache. The generator does not use a different revision.

Before you commit generated changes, run the generator unit tests and the full regeneration check:

```bash
cd libraries/tacacsrs_config/yang
python -m unittest discover -v -p 'test_*.py'
python verify_generated.py --clean
```

`verify_generated.py --clean` clones the pinned `YangModels/yang` commit, regenerates the tree and Rust types, and compares them against the checked-in artifacts. It needs network access for the clone. Run it when you change the pinned source, the feature flags, or the generator.

The verifier compares canonical LF content. Thus, Windows and Linux checkouts produce the same result.

### Offline consistency check

For a fast gate that needs no network access and does not regenerate anything, run:

```bash
cd libraries/tacacsrs_config/yang
python verify_generated.py --check
```

The offline check validates the recorded SHA-256 hashes of the pinned source identity, the pyang version, the reviewed feature flags, the secret-field manifest, the checked-in YANG module, and the generated outputs. It confirms that the checked-in tree still matches the manifest. It is a consistency gate, not a proof of deterministic regeneration.

CI runs the generator unit tests and the offline check through the `.github/steps/verify-yang` action. CI installs the pinned `pyang` version from `requirements.txt` and performs no branch writes. CI does not clone the upstream source or regenerate the artifacts; run `verify_generated.py --clean` locally when you change the source or generator.

`.gitattributes` keeps generation inputs and outputs at LF. Do not recreate `feature-flags.ini` with `--list-features` before you review each value.

That command enables all discovered features. It can remove intentional `false` selections.

The reviewed feature map enables RFC 9950 central keystore and truststore support. The generated model paths include:

- structured central asymmetric-key and certificate references for the client certificate identity
- a central symmetric-key reference for TLS 1.3 EPSK that preserves identity, hash, context, target, and group fields
- central CA and end-entity certificate-bag references for server authentication

Do not edit these shapes in `src/generated.rs`. `tacacsrs-config` validates inline and central choices. It preserves central values as opaque strings and expands only local bundles.

`tacacsrs-credential-resolution` owns provider-neutral request planning. It also owns secret-safe material and closed result matching.

The P3 provider and integration layer owns the SONiC-specific functions. These functions include reference grammar, file retrieval, watching, permissions, refresh policy, and runtime connection projection.

After you generate the code, run the workspace formatting, clippy, build, and test commands. Then commit the changes.

## CI/CD Overview

### Pull Request Workflow

When you open or update a pull request targeting `main`, these jobs run:

| Job | Description |
|-----|-------------|
| **Rustfmt** | Rust formatting validation |
| **Clippy** | Linting and static analysis |
| **Test** | Run the workspace on Linux and the `tacon` package group on Windows |
| **Build** | Builds all targets |
| **Build Validation** | Build each Linux selection and Windows `tacon` independently with default features in release mode |
| **ARMhf** | Build and execute tests with QEMU, then validate ABI and startup behavior |
| **Documentation** | Builds documentation without warnings |
| **Coverage** | Generate and upload code coverage |
| **Security Audit** | Finds known vulnerabilities after dependency changes |
| **YANG Verification** | Offline hash and version check plus generator unit tests for the pinned model (Linux) |
| **Fuzz Smoke** | Blocking libFuzzer smoke tests for the protocol parsers (Linux, nightly) |

All jobs must pass before you merge the pull request.

PRs validate source without publishing release assets.
CI reports are diagnostic outputs, not installation packages.
For validation before a PR exists, use the [manual CI rehearsal](docs/release-rehearsal.md#manual-signed-rehearsal).

### Main Branch CI

Main CI uses the reusable validation pipeline.
Eligible release pushes validate a signed hydrated source commit before publication.
AMD64, executed ARMhf, Windows direct mode, and the existing quality gates remain.
Current event-specific settings and advisory lint behavior remain unchanged.
There is no product-image publishing or release archive assembly.

For nonrelease changes, add a `norelease`, `no-release`, or `skip-release` label to the pull request. You can also add `[norelease]`, `[no-release]`, or `[skip-release]` to the head commit.

Main branch CI still computes versions and rehearses hydration in build-validation worktrees.
It does not create a remote candidate, advance `release`, create tags, or publish a GitHub Release.

### Release Workflow

Main branch CI is the release workflow. After a push to `main`, GitHub Actions:

1. Applies the release policy. `[norelease]`, `[no-release]`, `[skip-release]`, or matching pull request labels skip release outputs.
2. Computes versions from existing git tags with `.github/steps/compute-versions`.
3. Hydrates manifests and the lockfile in a temporary worktree.
4. Creates a GitHub-verified commit object without moving release refs.
5. Runs the validation pipeline against that exact SHA.
6. Atomically advances `release` and creates library SemVer and repository CalVer tags.
7. Creates the `TACACS-RS YYYY.MMDD.BUILD` GitHub Release with every workspace crate version and no uploaded assets.

Recovery reads an existing generated release for the same source before fresh version computation.
See [Source Release Validation](docs/release-rehearsal.md) for the complete contract.

## Releasing

### Version Management

Package manifests on `main` use `0.0.0-dev`. Do not add a version commit to `main` during normal development or release work.

Real release versions are derived from git tags:

- Libraries receive semver versions and tags of the form `<crate>-vX.Y.Z`.
- Repository releases use CalVer tags of the form `tacacs-rs-YYYY.MMDD.BUILD`.
- `tacon`, `tacacsrs-agentd`, and `tacacsrs-agent-health` share the executable CalVer version.

The pipeline injects the computed map before candidate validation.
It does not commit release versions to `main`.

### Release Branch

The generated `release` branch contains released Cargo package versions.
Pin a release tag or commit for a reproducible source selection.

Release automation retains append-only history.
Each generated commit has the previous release and current source as its parents.
The first release has only the source parent.
Release tags point to the validated hydrated commit.

Automation does not merge the generated commit into `main`.
Use `main` for development.

### Release Process

1. Merge the development changes into `main`.
2. Main CI computes release versions from the previous tags and the changed crate paths.
3. If release changes exist, CI prepares a signed hydrated candidate and validates its SHA.
4. After validation succeeds, CI publishes the release branch, tags, and source-only GitHub Release.

For CI, LDE, documentation, or other nonrelease changes, use the no-release labels or commit markers.

### Pre-release Versions

Pull request CI computes `dev` prerelease versions. It injects these versions into the CI checkout before the build.

These versions apply only to local build validation.
CI does not tag, commit, or push PR prerelease versions.

### Troubleshooting Releases

**Unexpected release tags**

Before you merge, add a `norelease`, `no-release`, or `skip-release` label to the pull request. You can also add `[norelease]`, `[no-release]`, or `[skip-release]` to the head commit.

**A tag or release page already exists**

Rerun the original workflow after a release-page error.
Recovery reuses the same candidate, versions, and tags.
Conflicting tags or a partial tag set stop publication.
Investigate the recorded source and candidate before any manual ref change.

**The verified commit or release branch update failed**

Review the API error, signature status, and branch rules.
The workflow requires `contents: write` for candidate creation and publication.
A signature error has no unsigned fallback.
A changed release head stops publication instead of replacing history.

## Project Structure

```
tacacs-rs/
├── Cargo.toml              # Workspace root and shared package metadata
├── rustfmt.toml            # Formatting configuration
├── .github/
│   ├── workflows/          # CI/CD workflows
│   │   ├── ci.yml          # Main branch CI
│   │   ├── pullrequest_workflow.yml
│   │   └── reusable-pipeline.yml
│   └── steps/              # Reusable composite actions
├── executables/
│   └── tacon/              # CLI application
└── libraries/
    ├── tacacsrs_protocol/  # Protocol message types
    └── tacacsrs_networking/# Network client implementation
```
