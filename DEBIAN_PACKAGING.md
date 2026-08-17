# Debian Packaging

This document describes the Debian packages for TACACS-rs. The packaging process uses a clean repository checkout.

## Overview

Official Linux packaging targets `x86_64-unknown-linux-gnu`.

The shared CI and release pipeline produces these packages:

| Package | Source crate | Install path | Notes |
| --- | --- | --- | --- |
| `tacon` | `executables/tacon` | `/usr/bin/tacon` | Includes OpenSSL-backed TLS and TLS 1.3 PSK support. |
| `tacacsrs-agentd` | `executables/tacacsrs_agentd` | `/usr/sbin/tacacsrs-agentd` | Includes OpenSSL-backed TLS and TLS 1.3 PSK support. |
| `tacacsrs-bash-plugin` | `libraries/tacacsrs_bash_plugin` | `/usr/lib/x86_64-linux-gnu/security/tacacsrs_bash_plugin.so` | SONiC bash execve plugin shared library package. |

The pipeline produces Windows archives separately. These archives include the required OpenSSL runtime DLLs.

## Prerequisites

Install the Debian packaging tools in the Linux packaging environment:

```bash
sudo apt-get update
sudo apt-get install -y build-essential lintian pkg-config libssl-dev
cargo install cargo-deb --locked
cargo install cargo-cyclonedx --locked
```

If you use Windows, run the build and packaging commands in WSL or another Linux environment. This process produces GNU/Linux artifacts.

## Build commands

Build the Linux release artifacts before you run `cargo deb --no-build`:

```bash
cargo build --release --target x86_64-unknown-linux-gnu -p tacon
cargo build --release --target x86_64-unknown-linux-gnu -p tacacsrs-agentd
cargo build --release --target x86_64-unknown-linux-gnu -p tacacsrs-bash-plugin
```

These commands produce the staged artifacts for Debian packaging:

```text
target/x86_64-unknown-linux-gnu/release/tacon
target/x86_64-unknown-linux-gnu/release/tacacsrs-agentd
target/x86_64-unknown-linux-gnu/release/libtacacsrs_bash_plugin.so
```

## Local helper script

The complete process generates the changelog and stages man pages for `tacon` and `tacacsrs-agentd`. It also generates the SBOM files.

The process runs `cargo deb --no-build --dbgsym` and `lintian`. To start it, run:

```bash
pwsh -File ./lde/run-debian-packages.ps1
```

To build one package, run:

```bash
pwsh -File ./lde/run-debian-packages.ps1 -Package tacacsrs-agentd
```

You can also run this process through the Linux GNU pretest helper:

```bash
pwsh -File ./lde/run-pre-tests.ps1 -Matrix LinuxGnu -Task DebianPackages
```

## Package reconfiguration

`tacacsrs-agentd` and `tacacsrs-bash-plugin` include `debconf` prompts. You can install each package before you configure it with `dpkg-reconfigure`.

To open the package configuration dialogs again, run:

```bash
sudo dpkg-reconfigure tacacsrs-agentd
sudo dpkg-reconfigure tacacsrs-bash-plugin
```

The packages manage these options:

- `tacacsrs-agentd` can enable or disable the SONiC `tacacsrs-agentd.service` unit. It records the package profile in `/etc/tacacsrs-agentd/config.ini`.
- `tacacsrs-bash-plugin` can add or remove its `plugin=` entry in `/etc/bash_plugins.conf`. It does not manage other file content.

## Generated packaging assets

The package metadata is in the manifest for each crate:

- `executables/tacon/Cargo.toml`
- `executables/tacacsrs_agentd/Cargo.toml`
- `libraries/tacacsrs_bash_plugin/Cargo.toml`

Before `cargo deb --no-build` runs, the packaging process generates assets in each local `debian/` directory:

- `changelog.gz`
- staged `sbom.json` and `sbom.xml`
- generated man pages for `tacon` and `tacacsrs-agentd`

CI or the local packaging process generates these build artifacts. Do not commit them as source files.

## Verification

Run the standard Debian tools on the packages:

```bash
dpkg --info target/debian/*.deb
dpkg --contents target/debian/tacacsrs-bash-plugin_*.deb
lintian target/debian/*.deb
```

Make sure that the Bash plugin package contains:

```text
/usr/lib/x86_64-linux-gnu/security/tacacsrs_bash_plugin.so
```

## Troubleshooting

### Missing OpenSSL headers while building Linux executable packages

Install `pkg-config` and `libssl-dev`. Then rebuild `tacon` and `tacacsrs-agentd`.

### Missing generated man page during packaging

Rebuild the applicable package in release mode for the Linux target. `clap_mangen` generates the man pages during the Cargo build.

### Missing plugin shared object during packaging

Before you run `cargo deb`, run `cargo build --release --target x86_64-unknown-linux-gnu -p tacacsrs-bash-plugin`. Make sure that the build produced this shared object:

`target/x86_64-unknown-linux-gnu/release/libtacacsrs_bash_plugin.so`
