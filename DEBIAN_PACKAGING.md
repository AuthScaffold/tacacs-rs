# Debian Packaging for Tacon

This document describes how to build and publish Debian packages for the Tacon executable.

## Overview

Tacon uses [cargo-deb](https://github.com/kornelski/cargo-deb) to generate Debian-compliant `.deb` packages. The packaging configuration follows Debian's packaging standards and Rust Team guidelines.

## Package Details

- **Package Name**: `tacon`
- **Section**: `net`
- **Priority**: `optional`
- **Maintainer**: AuthScaffold <support@authscaffold.com>
- **Dependencies**: Automatically detected (libc6 >= 2.38)
- **Architecture**: amd64
- **Installation Path**: `/usr/bin/tacon`

## Prerequisites

### Installing cargo-deb

```bash
cargo install cargo-deb
```

### System Dependencies

For building on Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential
```

For linting the package (optional):

```bash
sudo apt-get install -y lintian
```

## Building the Package

### 1. Build the Release Binary

First, build the tacon binary in release mode:

```bash
cargo build --release --package tacon
```

### 2. Strip the Binary

Strip debug symbols to reduce package size:

```bash
strip target/release/tacon
```

### 3. Generate the .deb Package

Generate the Debian package without rebuilding:

```bash
cargo deb --package tacon --no-build --no-strip
```

The `.deb` file will be created in `target/debian/`:

```
target/debian/tacon_0.1.1-1_amd64.deb
```

### Single Command

You can also do all steps in one command (cargo-deb will build and strip automatically):

```bash
cargo deb --package tacon
```

## Verifying the Package

### Check Package Info

```bash
dpkg --info target/debian/tacon_*.deb
```

### Check Package Contents

```bash
dpkg --contents target/debian/tacon_*.deb
```

### Run Lintian Checks

```bash
lintian target/debian/tacon_*.deb
```

Expected output:
- No errors
- One warning about missing manual page (acceptable for now)

## Installing the Package

### Install Locally

```bash
sudo dpkg -i target/debian/tacon_*.deb
```

### Verify Installation

```bash
which tacon
tacon --help
```

### Uninstall

```bash
sudo dpkg -r tacon
```

## Package Structure

The Debian package includes:

```
/usr/bin/tacon                           # Main executable (stripped)
/usr/share/doc/tacon/README.md           # Documentation
/usr/share/doc/tacon/LICENSE             # License file
/usr/share/doc/tacon/copyright           # Debian copyright file
/usr/share/doc/tacon/changelog.Debian.gz # Debian changelog (compressed)
```

## Configuration Files

### Cargo.toml

Package metadata is defined in `executables/tacon/Cargo.toml` under `[package.metadata.deb]`:

```toml
[package.metadata.deb]
maintainer = "AuthScaffold <support@authscaffold.com>"
copyright = "2024, AuthScaffold <support@authscaffold.com>"
license-file = ["../../LICENSE", "0"]
extended-description = """..."""
depends = "$auto"
section = "net"
priority = "optional"
assets = [
    ["target/release/tacon", "usr/bin/", "755"],
    ["README.md", "usr/share/doc/tacon/", "644"],
    ["../../LICENSE", "usr/share/doc/tacon/", "644"],
    ["debian/changelog.gz", "usr/share/doc/tacon/changelog.Debian.gz", "644"],
]
```

### debian/changelog

The Debian changelog is located at `executables/tacon/debian/changelog.gz` (gzip compressed).

### debian/copyright

Machine-readable copyright file following the [DEP-5 format](https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/).

## CI/CD Integration

### Automated Builds

The `.deb` package is automatically built and published on GitHub releases via the release workflow (`.github/workflows/release.yml`).

### Triggering a Release

Releases are triggered by:

1. **Pushing a version tag**:
   ```bash
   git tag -a v0.1.1 -m "Release 0.1.1"
   git push origin v0.1.1
   ```

2. **Merging a release PR** with the `release` label

3. **Manual workflow dispatch** with a version tag

### Release Artifacts

Each release includes:
- Platform-specific binaries (Linux GNU, Linux MUSL, Windows)
- Debian package (`tacon_*.deb`)
- SHA256 checksums

## Publishing to a Repository

### Using a Private APT Repository

To distribute via APT, you can use tools like:

- [reprepro](https://salsa.debian.org/brlink/reprepro)
- [aptly](https://www.aptly.info/)
- [freight](https://github.com/rcrowley/freight)

### Example with aptly

```bash
# Initialize repository
aptly repo create tacon

# Add package
aptly repo add tacon target/debian/tacon_*.deb

# Create snapshot
aptly snapshot create tacon-0.1.1 from repo tacon

# Publish to local filesystem
aptly publish snapshot -distribution=stable tacon-0.1.1
```

### Using GitHub Releases

The simplest approach is to:

1. Download the `.deb` from GitHub releases
2. Install with `sudo dpkg -i tacon_*.deb`

## Updating the Package

### Version Updates

When the workspace version changes (in root `Cargo.toml`):

1. Update `executables/tacon/debian/changelog.gz`:
   - Uncompress: `gunzip executables/tacon/debian/changelog.gz`
   - Add new entry at the top following Debian changelog format
   - Recompress: `gzip -9 -n executables/tacon/debian/changelog`

2. Rebuild the package

### Debian Changelog Format

```
tacon (VERSION) DISTRIBUTION; urgency=URGENCY

  * Change description line 1
  * Change description line 2

 -- Maintainer Name <email@example.com>  DAY, DD MON YYYY HH:MM:SS +0000
```

Example:

```
tacon (0.1.2) stable; urgency=medium

  * Add new authentication features
  * Fix TLS connection issues
  * Update dependencies

 -- AuthScaffold <support@authscaffold.com>  Mon, 10 Feb 2026 10:00:00 +0000
```

## Debian Policy Compliance

### Lintian Checks

The package passes all critical lintian checks. Current status:
- ✅ No errors
- ⚠️ One warning: `no-manual-page` (acceptable, man page can be added in future)

### Standards Compliance

The package follows:
- [Debian Policy Manual](https://www.debian.org/doc/debian-policy/)
- [Debian Rust Team Guidelines](https://wiki.debian.org/Teams/RustPackaging)
- [DEP-5 Copyright Format](https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/)

## Troubleshooting

### Package Size Too Large

The package is automatically stripped. If size is still an issue:
- Verify strip ran: `file target/release/tacon` should show "stripped"
- Consider building with `--target x86_64-unknown-linux-musl` for static linking

### Dependency Issues

If automatic dependency detection fails:
- Manually specify in `Cargo.toml`: `depends = "libc6 (>= 2.38)"`
- Test on target system before publishing

### Lintian Errors

If lintian reports errors:
- Check `executables/tacon/debian/changelog.gz` format
- Verify `executables/tacon/debian/copyright` follows DEP-5
- Ensure all assets in `Cargo.toml` exist and have correct permissions

## References

- [cargo-deb Documentation](https://github.com/kornelski/cargo-deb)
- [Debian Rust Team Book](https://rust-team.pages.debian.net/book/)
- [Debian Policy Manual](https://www.debian.org/doc/debian-policy/)
- [Debian Packaging Tutorial](https://www.debian.org/doc/manuals/packaging-tutorial/)

## Support

For issues with Debian packaging:
- Open an issue on [GitHub](https://github.com/AuthScaffold/tacacs-rs/issues)
- Contact: support@authscaffold.com
