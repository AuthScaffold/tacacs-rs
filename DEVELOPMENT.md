# Developer Documentation

This document covers development workflows, CI/CD, and release processes for tacacs-rs.

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

# Release automation
cargo install cargo-release

# Unused dependencies check
cargo install cargo-udeps

# Outdated dependencies check
cargo install cargo-outdated

# Security audit
cargo install cargo-audit

# SBOM generation (Software Bill of Materials)
cargo install cargo-cyclonedx
```

### Generating SBOM Locally

To generate a Software Bill of Materials (SBOM) for compliance purposes:

```bash
# Generate SBOM in JSON format (CycloneDX standard)
cargo cyclonedx --format json --all --all-features

# Generate SBOM in XML format
cargo cyclonedx --format xml --all --all-features

# SBOM files are generated for each workspace member:
# - executables/tacon/tacon.cdx.json
# - libraries/tacacsrs_messages/tacacsrs-messages.cdx.json
# - libraries/tacacsrs_networking/tacacsrs-networking.cdx.json
```

SBOMs are automatically generated and included with all releases.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/AuthScaffold/tacacs-rs
cd tacacs-rs

# Build all crates
cargo build --workspace

# Run all tests
cargo test --workspace
```

### Building with OpenSSL-backed TLS

The `tacacsrs_networking` library uses dynamically linked OpenSSL for certificate-based TLS. Optional TLS 1.3 Pre-Shared Key support remains behind the `psk` feature flag and uses additional OpenSSL APIs.

#### Linux

Install the OpenSSL development libraries from your distribution's package manager:

```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev pkg-config

# Fedora/RHEL
sudo dnf install openssl-devel

# Build with OpenSSL-backed TLS and TLS 1.3 PSK support
cargo build --workspace
```

#### Windows

A pre-built OpenSSL installation is required. The recommended approach is to use [vcpkg](https://vcpkg.io/) to install OpenSSL.

##### Installing OpenSSL with vcpkg (Recommended)

1. Follow the [vcpkg getting started instructions](https://learn.microsoft.com/en-us/vcpkg/get_started/get-started) to install vcpkg.
2. Install OpenSSL:

   ```powershell
   vcpkg install openssl
   ```

3. Set your environment variables to point to the vcpkg-installed OpenSSL directory:

   ```powershell
   $env:OPENSSL_DIR = "X:\vcpkg\installed\x64-windows"
   ```

   Adjust the path to match your vcpkg installation location. The directory must contain `include/openssl` and `lib` subdirectories.

4. Build:

   ```powershell
   cargo build --workspace
   ```

Set `OPENSSL_DIR` permanently via **System Properties → Environment Variables** so it persists across terminals.

##### Manual OpenSSL installation

If you prefer not to use vcpkg, you can point to any pre-built OpenSSL installation by setting the following environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `OPENSSL_DIR` | Root of the OpenSSL installation (must contain an `include/openssl` subdirectory) | `C:\development\tools\openssl` |
| `OPENSSL_LIB_DIR` | Directory containing `libssl.lib` and `libcrypto.lib` | `C:\development\tools\openssl\lib\VC\x64\MD` |

> **Note:** Use the **MD** (Multi-threaded DLL) variant of the OpenSSL libraries. Rust's MSVC toolchain links against the dynamic C runtime, which must match the OpenSSL build. Using MT, MDd, or MTd variants will cause linker errors or runtime issues.

```powershell
$env:OPENSSL_DIR     = "C:\development\tools\openssl"
$env:OPENSSL_LIB_DIR = "C:\development\tools\openssl\lib\VC\x64\MD"

cargo build --workspace
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
cargo test -p tacacsrs-messages
```

### Session Wrapper Smoke Tests

The Linux `session-wrapper` has additional smoke and integration checks for seccomp notification handling, child lifecycle, and descendant process coverage. See [Session Wrapper Testing](docs/session-wrapper-testing.md).

### Code Coverage

```bash
# Generate coverage report (requires cargo-llvm-cov)
cargo llvm-cov --workspace --all-features

# Generate HTML report
cargo llvm-cov --workspace --all-features --html
```

## Code Quality

### Formatting

We use nightly rustfmt for additional formatting options (see `rustfmt.toml`).

```bash
# Check formatting
cargo +nightly fmt --all -- --check

# Apply formatting
cargo +nightly fmt --all
```

### Linting

```bash
# Run clippy
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

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

Install the checked-in generator requirements before regenerating artifacts:

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

This refreshes `expanded-tree.txt`, the checked-in reference used to inspect the fully expanded YANG data tree after all `uses` statements and repo-local YANG augmentations under `modules/` are resolved.

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

`expand_yang_tree.py` fetches the upstream IETF YANG modules and passes local project modules from `libraries/tacacsrs_config/yang/modules/` to `pyang`. The `feature-flags.ini` file controls both upstream features and project features such as `tacacsrs:psk-dhe-ke-hello-params`.

The upstream `YangModels/yang` commit is pinned in `expand_yang_tree.py` and recorded with source/input/output SHA-256 values in `generation-manifest.json`. The cache must be a detached HEAD at that exact commit. Use `--clean` to deliberately replace a stale cache; the generator never silently uses another revision.

Verify source identity, manifest hashes, two-run determinism, and checked-in output before committing generated changes:

```bash
cd libraries/tacacsrs_config/yang
python -m unittest -v test_expand_yang_tree.py
python verify_generated.py --clean
```

The verifier compares canonical LF content so Windows and Linux checkouts produce the same result. `.gitattributes` keeps generation inputs and outputs at LF. Do not recreate `feature-flags.ini` with `--list-features` without reviewing every value because that command emits all discovered features as enabled and can erase deliberate `false` selections.

The reviewed feature map enables RFC 9950 central keystore and central truststore support. Generated direct and bundled model paths include:

- structured central asymmetric-key and certificate references for client certificate identity;
- a central symmetric-key reference for TLS 1.3 EPSK while preserving identity, hash, context, target, and group fields;
- central CA and end-entity certificate-bag references for server authentication.

Do not hand-edit these shapes in `src/generated.rs`. `tacacsrs-config` validates generated inline-versus-central choices and preserves central values as opaque strings. It expands only config-local bundles. `tacacsrs-credential-resolution` owns provider-neutral request planning, secret-safe material, and closed result matching. SONiC reference grammar, filesystem retrieval, watching, permission checks, refresh policy, and runtime networking projection belong to the P3 provider/integration layer.

After regenerating, run the workspace formatting, clippy, build, and test commands before committing to ensure the emitted code still matches repository expectations.

## CI/CD Overview

### Pull Request Workflow

When you open a PR, the following checks run automatically:

| Job | Description |
|-----|-------------|
| **Rustfmt** | Code formatting check |
| **Clippy** | Linting and static analysis |
| **Test** | Run tests on Linux and Windows |
| **Build** | Verify compilation for all targets |
| **Build Artifacts** | Build release binaries for all platforms (same as release) |
| **SBOM** | Generate Software Bill of Materials (same as release) |
| **Checksums** | Generate SHA256 checksums for all artifacts |
| **Documentation** | Ensure docs build without warnings |
| **Coverage** | Generate and upload code coverage |
| **Security Audit** | Check for known vulnerabilities (when deps change) |

All jobs must pass before merging.

**Note:** The PR workflow now outputs all compiled assets identical to what the release build produces, including binaries for all platforms, SBOM files, and checksums. This ensures parity between CI and release environments.

### Main Branch CI

After merging to `main`, additional checks run:

- Test matrix (stable)
- Documentation link verification

The CI workflow also generates the same artifacts as the release workflow:

- **Release Binaries**: Built for all supported platforms (Linux GNU and Windows MSVC) plus GNU Debian packages for `tacon`, `tacacsrs-agentd`, and `tacacsrs-bash-plugin`
- **SBOM Files**: Software Bill of Materials in CycloneDX format (JSON and XML)
- **Checksums**: SHA256 checksums for all generated artifacts

These artifacts are uploaded and retained for 7 days, allowing for testing and validation before official releases.

For CI, LDE, documentation, or other non-release changes that should not create
new version tags, add a `norelease`, `no-release`, or `skip-release` label to
the merged PR. You can also include `[norelease]`, `[no-release]`, or
`[skip-release]` in the head commit message. Main branch CI still runs, but it
skips release version injection, tag creation, and GitHub release publication.
It also skips updates to the generated `release/versions` branch.

### Release Workflow

Main branch CI is the release workflow. On a push to `main`, GitHub Actions:

1. Checks the release policy. `[norelease]`, `[no-release]`, `[skip-release]`, or matching PR labels skip release outputs while still running CI.
2. Computes versions from existing git tags with `.github/steps/compute-versions`.
3. Injects the computed version map into `Cargo.toml` files in CI before official builds.
4. Builds release binaries, Debian packages, SBOMs, checksums, and release assets.
5. Creates and pushes any new library semver tags and executable CalVer tags.
6. Creates the GitHub Release for the primary executable release tag.
7. Updates the generated `release/versions` branch with final Cargo package metadata populated.

## Releasing

### Version Management

Committed package manifests on `main` use `0.0.0-dev`. Do not add a follow-up
version commit to `main` during normal development or release work.

Real release versions are derived from git tags:

- Libraries receive semver versions and tags of the form `<crate>-vX.Y.Z`.
- Executables receive CalVer versions of the form `YYYY.MMDD.BUILD` and tags of the form `<binary>-YYYY.MMDD.BUILD`.
- `tacacsrs-agentd` shares the primary `tacon` CalVer version in the current release workflow.

The official build pipeline injects the computed version map before compiling and packaging. This keeps Cargo metadata, CLI version output, Debian package versions, and release assets consistent without committing release versions back to `main`.

### Release Versions Branch

The `release/versions` branch is a generated source branch for consumers who want to clone and build with released Cargo package versions already populated.

Release automation creates or rewrites that branch after successful release tagging. The release tags remain on the original `main` commit; the generated version commit exists only on `release/versions` and is not merged back to `main`.

Use `release/versions` for clone-and-build release source checkouts. Use `main` for development.

### Release Process

1. Merge the development change to `main`.
2. Main CI computes release versions from the previous tags and the changed crate paths.
3. If there are release changes and CI succeeds, the release job creates the new tags and GitHub Release.
4. The same release job updates `release/versions` with the computed final versions injected into `Cargo.toml`.

For CI, LDE, documentation, or other non-release changes, use the no-release labels or commit markers described above.

### Pre-release Versions

Pull request CI computes `dev` pre-release versions and injects them into the CI checkout before building artifacts. These versions are for validation artifacts only. They are not tagged, committed, or pushed to `release/versions`.

### Troubleshooting Releases

**Unexpected release tags would be created?**

Add a `norelease`, `no-release`, or `skip-release` label to the PR before merging, or include `[norelease]`, `[no-release]`, or `[skip-release]` in the head commit message.

**Tag already exists?**

Delete the conflicting local and remote tag, then rerun the release workflow only after confirming the tag was created by mistake.

```bash
git tag -d <tag-name>
git push origin :refs/tags/<tag-name>
```

**`release/versions` failed to update?**

Check whether branch protection allows `github-actions[bot]` to update or force-update the generated branch. If protection is required, add an exception for the release workflow or update the branch through an approved automation token.

## Project Structure

```
tacacs-rs/
├── Cargo.toml              # Workspace root and shared package metadata
├── release-plz.toml        # git-only release-plz configuration
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
    ├── tacacsrs_messages/  # Protocol message types
    └── tacacsrs_networking/# Network client implementation
```
