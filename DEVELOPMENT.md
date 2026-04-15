# Developer Documentation

This document covers development workflows, CI/CD, and release processes for tacacs-rs.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Code Quality](#code-quality)
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
cargo install release-plz

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

### Building with TLS 1.3 PSK Support (Optional)

The `tacacsrs_networking` library includes optional TLS 1.3 Pre-Shared Key support behind the `psk` feature flag. This feature depends on OpenSSL and requires additional setup.

#### Linux

Install the OpenSSL development libraries from your distribution's package manager:

```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev pkg-config

# Fedora/RHEL
sudo dnf install openssl-devel

# Build with PSK support
cargo build --workspace --features tacacsrs-networking/psk
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

4. Build with PSK support:

   ```powershell
   cargo build --features tacacsrs-networking/psk
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

cargo build --features tacacsrs-networking/psk
```

> **Tip:** Without the `psk` feature, the default build uses rustls (pure Rust) and requires no external dependencies.

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

- Extended test matrix (stable, beta, MSRV)
- Nightly compatibility check
- Documentation link verification

The CI workflow also generates the same artifacts as the release workflow:

- **Release Binaries**: Built for all supported platforms (Linux GNU, Linux MUSL, Windows MSVC)
- **SBOM Files**: Software Bill of Materials in CycloneDX format (JSON and XML)
- **Checksums**: SHA256 checksums for all generated artifacts

These artifacts are uploaded and retained for 7 days, allowing for testing and validation before official releases.

### Release Workflow

Triggered automatically when release-plz publishes a GitHub release. Builds release binaries for:

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `x86_64-pc-windows-msvc`

Additionally, the release workflow generates:

- **Software Bill of Materials (SBOM)** in CycloneDX format (both JSON and XML)
  - Compliant with supply chain security requirements
  - Includes all dependencies and their licenses
  - Separate SBOM files for each workspace crate (tacon, tacacsrs-messages, tacacsrs-networking)

## Releasing

### Version Management

This project uses **workspace version inheritance**. The version is defined once in the root `Cargo.toml`:

```toml
[workspace.package]
version = "0.1.0"
```

All member crates inherit this version via `version.workspace = true`.

### Release Process (GitHub Actions)

We use [release-plz](https://github.com/release-plz/release-plz) in git-only mode to manage the repository version, open release PRs, create tags, and publish GitHub releases for `tacon`.

#### Prerequisites

Ensure your repository settings allow GitHub Actions to create PRs:
1. Go to **Settings** > **Actions** > **General**
2. Under "Workflow permissions", enable **"Allow GitHub Actions to create and approve pull requests"**

#### 1. Let release-plz open or update the Release PR

Every push to `main` runs the **Release-plz** workflow. When unreleased changes are detected for `tacon`, release-plz opens or updates a release PR that:

- Updates the workspace version in `Cargo.toml`
- Prepares the next `vX.Y.Z` git tag
- Applies the `release` label for visibility
- Defers the actual release until the release PR is merged

#### 2. Review the Release PR

- Review the version changes
- Edit the PR description to add release notes
- Request reviews from team members
- Ensure all CI checks pass

#### 3. Merge to Release

When the PR is merged:
1. release-plz creates and pushes the git tag (`vX.Y.Z`)
2. release-plz publishes the GitHub release
3. The release asset workflow automatically attaches binaries, SBOMs, Debian packages, and checksums
4. The final GitHub release notes are regenerated from merged PR titles instead of commit prefixes

Release artifacts include:
- Pre-built binaries for each platform
- Debian package (`.deb`) and optional debug symbols package
- SHA256 checksums file
- SBOM files in both JSON and XML formats (for supply chain compliance)

### Alternative: Local release-plz run

```bash
# Install (one-time)
cargo install release-plz

# Open or update the release PR
release-plz release-pr

# Publish after the release PR is merged
release-plz release
```

### Pre-release Versions

For alpha/beta/rc releases, set the version in the release PR to the full version string (for example `0.2.0-alpha.1`). The generated `v0.2.0-alpha.1` tag is automatically marked as a pre-release on GitHub.

### Troubleshooting Releases

**Release PR not opening or updating?**

Ensure GitHub Actions has permission to create pull requests and that the default branch is `main`.

**Tag already exists?**

```bash
# Delete local tag
git tag -d vX.Y.Z

# Delete remote tag (if pushed)
git push origin :refs/tags/vX.Y.Z
```

**Need to cancel a release PR?**

Simply close the PR without merging. No changes will be made to the repository.

## Project Structure

```
tacacs-rs/
├── Cargo.toml              # Workspace root with shared version
├── release-plz.toml        # release-plz configuration
├── rustfmt.toml            # Formatting configuration
├── .github/
│   ├── workflows/          # CI/CD workflows
│   │   ├── ci.yml          # Main branch CI
│   │   ├── pullrequest_workflow.yml
│   │   ├── release-plz.yml # Release PR and tag automation
│   │   ├── release.yml     # Release asset publishing
│   │   └── reusable-*.yml  # Shared workflow components
│   └── steps/              # Reusable composite actions
├── executables/
│   └── tacon/              # CLI application
└── libraries/
    ├── tacacsrs_messages/  # Protocol message types
    └── tacacsrs_networking/# Network client implementation
```
