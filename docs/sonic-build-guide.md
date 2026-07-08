# Building for SONiC

SONiC runs on a Debian/glibc userspace, so the supported TACACS-rs build flow is
based on GNU Linux binaries and Debian packages.

## Rust toolchain

Provision a current stable Rust toolchain inside WSL when the base image does
not already provide one:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
    --default-toolchain stable -y
```

## Build products

Build the SONiC-relevant artifacts from a Linux environment with GNU targets:

```bash
cargo build --release --target x86_64-unknown-linux-gnu -p tacon
cargo build --release --target x86_64-unknown-linux-gnu -p tacacsrs-agentd
cargo build --release --target x86_64-unknown-linux-gnu -p tacacsrs-bash-plugin
```

The resulting artifacts are:

```text
target/x86_64-unknown-linux-gnu/release/tacon
target/x86_64-unknown-linux-gnu/release/tacacsrs-agentd
target/x86_64-unknown-linux-gnu/release/libtacacsrs_bash_plugin.so
```

For package-oriented validation, prefer the GNU Debian packages produced by CI
or the local `cargo deb --no-build` flow described in `DEBIAN_PACKAGING.md`.

If you are starting from Windows, run these Linux-targeted Cargo commands from
WSL. Do not copy Windows-built binaries or libraries into SONiC.

## Publishing artifacts to the SONiC VM

Use the existing helper scripts instead of raw `scp` or `ssh` commands.

Publish GNU binaries:

```powershell
.\lde\sonic-vm\Publish-SonicBinary.ps1 -Package tacon -Profile release
.\lde\sonic-vm\Publish-SonicBinary.ps1 -Package tacacsrs-agentd -Bin tacacsrs-agentd -Profile release
```

Publish the bash plugin shared library:

```powershell
.\lde\sonic-vm\Publish-SonicSharedLibrary.ps1 -Package tacacsrs-bash-plugin -Profile release
```

The shared library publisher copies `libtacacsrs_bash_plugin.so` to the VM and
is the preferred path for SONiC bash plugin smoke testing.

## Component roles on a SONiC switch

- `tacacsrs-agentd`: long-running daemon that owns upstream TACACS+ connections
  and local IPC.
- `tacon`: operator CLI for ad-hoc requests and debugging.
- `tacacsrs-bash-plugin`: shared library loaded by patched bash for per-command
  authorization through `tacacsrs-agentd`.

## systemd interaction

Only `tacacsrs-agentd` needs a systemd unit on SONiC. A typical unit file looks
like this:

```ini
[Unit]
Description=TACACS+ client agent for local IPC consumers
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tacacsrs-agentd --config /etc/tacacsrs/tacacs.json
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
```

Enable it before testing any wrapper or plugin flow:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tacacsrs-agentd
```

## Bash plugin installation path

The standalone Debian package installs the plugin to:

```text
/usr/lib/x86_64-linux-gnu/security/tacacsrs_bash_plugin.so
```

Reference that path from `/etc/bash_plugins.conf`:

```text
plugin=/usr/lib/x86_64-linux-gnu/security/tacacsrs_bash_plugin.so
```

## Container image

For container-based delivery of the agent, this page covers building the image.
Runtime flags, host networking, Redis socket access, and exposure checks are
covered in [Running tacacsrs-agentd as a SONiC Docker container](sonic-agentd-container.md).

The multi-stage container build for `tacacsrs-agentd` lives under
`containers/tacacsrs-agentd/`. It compiles the daemon from source with the `psk`
feature and ships a minimal glibc runtime image, so it stays compatible with
SONiC's Debian userspace.

Build and test the image with the container Makefiles (run from a Linux
environment or WSL with Docker BuildKit available):

```bash
# Build just the agent image
make -C containers/tacacsrs-agentd build

# Run the agent daemon test suite inside the build container
make -C containers/tacacsrs-agentd test

# Build every container image in the repo
make -C containers build
```

The image name, tag, and registry are overridable:

```bash
make -C containers/tacacsrs-agentd build REGISTRY=<your-registry> BUILD_VERSION=<version>
```

The toolchain and runtime base images are `docker buildx` build arguments
(`BUILDER_IMAGE` and `RUNTIME_IMAGE`), so downstream builders can substitute
their own bases without editing the Dockerfile. The default `ENTRYPOINT`/`CMD`
mirrors the SONiC systemd unit and can be overridden at `docker run` time.

## Verification

Before enabling SONiC command authorization broadly, verify that:

1. `tacacsrs-agentd` is active and its IPC socket exists.
2. A manual `tacon` request against the configured endpoint succeeds.
3. The plugin shared library is present at the expected security path.
4. Any SONiC VM testing is performed with Linux artifacts built from WSL, not Windows binaries.
