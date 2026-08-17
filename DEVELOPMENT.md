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

### Generate an SBOM locally

Run these commands to generate a Software Bill of Materials (SBOM):

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

The release pipeline generates SBOMs and includes them with each release.

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

#### Windows

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

4. Build:

   ```powershell
   cargo build --workspace
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

The Linux `session-wrapper` has more smoke tests and integration tests. These tests cover seccomp notifications, child processes, and descendant processes.

For the test procedure, read [Session Wrapper Testing](docs/session-wrapper-testing.md).

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

Before you commit generated changes, run:

```bash
cd libraries/tacacsrs_config/yang
python -m unittest -v test_expand_yang_tree.py
python verify_generated.py --clean
```

The verifier compares canonical LF content. Thus, Windows and Linux checkouts produce the same result.

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

When you open a pull request, these jobs run:

| Job | Description |
|-----|-------------|
| **Rustfmt** | Rust formatting validation |
| **Clippy** | Linting and static analysis |
| **Test** | Run tests on Linux and Windows |
| **Build** | Builds all targets |
| **Build Artifacts** | Build release binaries for all platforms (same as release) |
| **SBOM** | Generate Software Bill of Materials (same as release) |
| **Checksums** | Generate SHA256 checksums for all artifacts |
| **Documentation** | Builds documentation without warnings |
| **Coverage** | Generate and upload code coverage |
| **Security Audit** | Finds known vulnerabilities after dependency changes |

All jobs must pass before you merge the pull request.

**Note:** The pull request workflow produces the same compiled assets as the release build. These assets include binaries, SBOM files, and checksums.

### Main Branch CI

After a merge to `main`, these additional checks run:

- Test matrix (stable)
- Documentation link verification

The CI workflow generates the same artifacts as the release workflow:

- **Release Binaries**: Linux GNU and Windows MSVC binaries, plus GNU Debian packages for `tacon`, `tacacsrs-agentd`, and `tacacsrs-bash-plugin`
- **SBOM Files**: Software Bill of Materials files in CycloneDX JSON and XML formats
- **Checksums**: SHA-256 checksums for all generated artifacts

GitHub stores these artifacts for seven days. You can use them for tests before an official release.

For nonrelease changes, add a `norelease`, `no-release`, or `skip-release` label to the pull request. You can also add `[norelease]`, `[no-release]`, or `[skip-release]` to the head commit.

Main branch CI still runs. It does not inject release versions, create tags, publish a GitHub release, or update `release/versions`.

### Release Workflow

Main branch CI is the release workflow. After a push to `main`, GitHub Actions:

1. Applies the release policy. `[norelease]`, `[no-release]`, `[skip-release]`, or matching pull request labels skip release outputs.
2. Computes versions from existing git tags with `.github/steps/compute-versions`.
3. Injects the computed version map into `Cargo.toml` files in CI before official builds.
4. Builds release binaries, Debian packages, SBOMs, checksums, and release assets.
5. Creates and pushes any new library semver tags and executable CalVer tags.
6. Creates the GitHub Release for the primary executable release tag.
7. Updates the generated `release/versions` branch with final Cargo package metadata populated.

## Releasing

### Version Management

Package manifests on `main` use `0.0.0-dev`. Do not add a version commit to `main` during normal development or release work.

Real release versions are derived from git tags:

- Libraries receive semver versions and tags of the form `<crate>-vX.Y.Z`.
- Executables receive CalVer versions of the form `YYYY.MMDD.BUILD` and tags of the form `<binary>-YYYY.MMDD.BUILD`.
- `tacacsrs-agentd` shares the primary `tacon` CalVer version in the current release workflow.

The official pipeline injects the computed version map before the build and packaging steps. It does not commit release versions to `main`.

### Release Versions Branch

The generated `release/versions` branch contains released Cargo package versions. Use this branch to build released source.

Release automation creates or rewrites this branch after successful release tagging. The release tags stay on the original `main` commit.

The generated version commit exists only on `release/versions`. Automation does not merge it into `main`.

Use `release/versions` for clone-and-build release source checkouts. Use `main` for development.

### Release Process

1. Merge the development changes into `main`.
2. Main CI computes release versions from the previous tags and the changed crate paths.
3. If release changes exist and CI succeeds, the release job creates the new tags and GitHub Release.
4. The same release job updates `release/versions` with the computed final versions injected into `Cargo.toml`.

For CI, LDE, documentation, or other nonrelease changes, use the no-release labels or commit markers.

### Pre-release Versions

Pull request CI computes `dev` prerelease versions. It injects these versions into the CI checkout before the build.

These versions apply only to validation artifacts. CI does not tag, commit, or push them to `release/versions`.

### Troubleshooting Releases

**Unexpected release tags**

Before you merge, add a `norelease`, `no-release`, or `skip-release` label to the pull request. You can also add `[norelease]`, `[no-release]`, or `[skip-release]` to the head commit.

**Tag already exists?**

First, make sure that the tag was created by mistake. Then remove the conflicting local and remote tag, and run the release workflow again.

```bash
git tag -d <tag-name>
git push origin :refs/tags/<tag-name>
```

**`release/versions` failed to update?**

Make sure that branch protection lets `github-actions[bot]` update the generated branch. If protection is required, add an exception for the release workflow.

You can instead update the branch with an approved automation token.

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
