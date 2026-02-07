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
- Minimal versions check
- Nightly compatibility check
- Documentation link verification

The CI workflow also generates the same artifacts as the release workflow:

- **Release Binaries**: Built for all supported platforms (Linux GNU, Linux MUSL, Windows MSVC)
- **SBOM Files**: Software Bill of Materials in CycloneDX format (JSON and XML)
- **Checksums**: SHA256 checksums for all generated artifacts

These artifacts are uploaded and retained for 7 days, allowing for testing and validation before official releases.

### Release Workflow

Triggered automatically when a version tag (`v*.*.*`) is pushed. Builds release binaries for:

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

We use [cargo-bins/release-pr](https://github.com/cargo-bins/release-pr) to create release PRs, which are then reviewed and merged to trigger the full release workflow.

#### Prerequisites

Ensure your repository settings allow GitHub Actions to create PRs:
1. Go to **Settings** > **Actions** > **General**
2. Under "Workflow permissions", enable **"Allow GitHub Actions to create and approve pull requests"**

#### 1. Open a Release PR

1. Go to **Actions** > **"Open Release PR"** workflow
2. Click **"Run workflow"**
3. Enter the version:
   - Exact version: `1.2.3`
   - Bump level: `patch`, `minor`, or `major`
4. Optionally select a specific crate (leave empty for all crates)
5. Click **"Run workflow"**

This creates a PR that:
- Updates version numbers in `Cargo.toml` files
- Runs `cargo publish --dry-run` to validate the release
- Includes a section for writing release notes
- Is labeled with `release` for automation

#### 2. Review the Release PR

- Review the version changes
- Edit the PR description to add release notes
- Request reviews from team members
- Ensure all CI checks pass

#### 3. Merge to Release

When the PR is merged:
1. The release workflow automatically triggers
2. Builds release binaries for all platforms
3. Generates Software Bill of Materials (SBOM) in CycloneDX format
4. Creates and pushes the git tag (`vX.Y.Z`)
5. Generates SHA256 checksums for all artifacts
6. Creates a GitHub Release with all artifacts (binaries, checksums, and SBOMs)

Release artifacts include:
- Pre-built binaries for each platform
- SHA256 checksums file
- SBOM files in both JSON and XML formats (for supply chain compliance)

### Alternative: Manual Tag Release

You can still trigger releases by pushing a tag directly:

```bash
# Create and push a tag
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
```

Or use `cargo-release` locally:

```bash
# Install (one-time)
cargo install cargo-release

# Dry run first
cargo release patch --dry-run

# Execute release
cargo release patch --execute
```

### Pre-release Versions

For alpha/beta/rc releases, use the full version string:

- Via GitHub Actions: Enter `0.2.0-alpha.1` as the version
- Via tag: `git tag -a v0.2.0-alpha.1 -m "Pre-release v0.2.0-alpha.1"`

Tags containing `-` are automatically marked as pre-releases on GitHub.

### Troubleshooting Releases

**Release PR not triggering the release workflow?**

Ensure the PR has the `release` label and the PR title contains the version (e.g., `release: v1.2.3`).

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
├── release.toml            # cargo-release configuration
├── rustfmt.toml            # Formatting configuration
├── .github/
│   ├── workflows/          # CI/CD workflows
│   │   ├── ci.yml          # Main branch CI
│   │   ├── pullrequest_workflow.yml
│   │   ├── release.yml     # Release automation
│   │   └── reusable-*.yml  # Shared workflow components
│   └── steps/              # Reusable composite actions
├── executables/
│   └── tacon/              # CLI application
└── libraries/
    ├── tacacsrs_messages/  # Protocol message types
    └── tacacsrs_networking/# Network client implementation
```
