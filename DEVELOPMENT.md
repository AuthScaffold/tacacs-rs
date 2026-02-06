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
```

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
| **Documentation** | Ensure docs build without warnings |
| **Coverage** | Generate and upload code coverage |
| **Security Audit** | Check for known vulnerabilities (when deps change) |

All jobs must pass before merging.

### Main Branch CI

After merging to `main`, additional checks run:

- Extended test matrix (stable, beta, MSRV)
- Minimal versions check
- Nightly compatibility check
- Documentation link verification

### Release Workflow

Triggered automatically when a version tag (`v*.*.*`) is pushed. Builds release binaries for:

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `x86_64-pc-windows-msvc`

## Releasing

### Version Management

This project uses **workspace version inheritance**. The version is defined once in the root `Cargo.toml`:

```toml
[workspace.package]
version = "0.1.0"
```

All member crates inherit this version via `version.workspace = true`.

### Release Process

We use [cargo-release](https://github.com/crate-ci/cargo-release) to automate releases.

#### 1. Install cargo-release (one-time)

```bash
cargo install cargo-release
```

#### 2. Prepare for Release

Ensure you're on `main` with a clean working directory:

```bash
git checkout main
git pull origin main
git status  # Should be clean
```

#### 3. Dry Run

Always do a dry run first to see what will happen:

```bash
# Patch release (0.1.0 → 0.1.1)
cargo release patch --dry-run

# Minor release (0.1.0 → 0.2.0)
cargo release minor --dry-run

# Major release (0.1.0 → 1.0.0)
cargo release major --dry-run

# Specific version
cargo release 1.2.3 --dry-run
```

#### 4. Execute Release

Once you're happy with the dry run:

```bash
cargo release patch --execute
```

This will:
1. Update the version in `Cargo.toml`
2. Create a commit: `chore: release X.Y.Z`
3. Create a git tag: `vX.Y.Z`
4. Push the commit and tag to origin

#### 5. Automated Release Build

Once the tag is pushed, GitHub Actions automatically:
1. Builds release binaries for all platforms
2. Generates SHA256 checksums
3. Creates a GitHub Release with:
   - Auto-generated release notes
   - All binary artifacts
   - Checksum file

### Pre-release Versions

For alpha/beta/rc releases:

```bash
cargo release 0.2.0-alpha.1 --execute
cargo release 0.2.0-beta.1 --execute
cargo release 0.2.0-rc.1 --execute
```

Tags containing `-` are automatically marked as pre-releases on GitHub.

### Troubleshooting Releases

**Release failed mid-way?**

If the release partially completed (e.g., committed but didn't push):

```bash
# Check current state
git log --oneline -3
git tag -l

# If you need to undo
git reset --hard HEAD~1
git tag -d vX.Y.Z
```

**Tag already exists?**

```bash
# Delete local tag
git tag -d vX.Y.Z

# Delete remote tag (if pushed)
git push origin :refs/tags/vX.Y.Z
```

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
