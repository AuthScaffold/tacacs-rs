# Building for SONiC

SONiC runs on a glibc userspace. The supported TACACS-rs build flow produces
Linux GNU binaries and shared libraries.

## Rust toolchain

If the base image does not already provide a current stable Rust toolchain,
provision one inside WSL:

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

CI publishes each Linux artifact in a `.tar.gz` archive with its SBOM files.
The SONiC repository owns the installation scripts and target paths.

If you are starting from Windows, run these Linux-targeted Cargo commands from
WSL. Do not copy Windows-built binaries or libraries into SONiC.

## ARMhf build and executed tests

ARMhf is 32-bit ARM hard-float (`linux/arm/v7`), not ARM64. Its Rust target is
`armv7-unknown-linux-gnueabihf`. The required ARMhf CI job cross-compiles release
executables on AMD64 Debian Bookworm with Rust 1.90, the ARMhf linker and OpenSSL
libraries, and a host-native Protobuf compiler. It then executes Cargo tests
and all three release executables with QEMU, checking ELF32 and hard-float ABI.
Existing AMD64 build/test coverage remains separate.

Both protobuf build scripts honor an explicit `PROTOC` and use their vendored
compiler only when it is unset. An invalid explicit path is an error; it does
not silently select another compiler. Native ARMhf builds must install a
compatible host compiler and set `PROTOC`, for example `/usr/bin/protoc`.

From the repository root in WSL on an AMD64 Docker host:

```bash
# Only if ARM execution is not already configured on this Docker host:
docker run --rm --privileged \
  tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0 \
  --install arm

docker buildx build --platform linux/amd64 \
  --file .github/steps/armhf/Dockerfile --no-cache-filter verify \
  --output type=local,dest=target/armhf-evidence .
```

Installing the handler changes the Docker host. Do not reset unrelated handlers
on shared hosts. Cargo's QEMU runner alone is insufficient for integration tests
that start ARM child processes; those require working binfmt execution too.

The uncached verification stage runs the three executable packages plus
`tacacsrs-sonic`, `tacacsrs-ipc`, and `tacacsrs-agent-ipc-emulator`. Evidence
includes the verification log, release binaries, ELF headers, help output,
binary checksums, and a checksum manifest of the source inputs. Failures retain
their exit status in the build log; a timeout or
successful cross-compilation alone does not count as executed-test coverage.

PRs call the reusable pipeline, whose `CI Success` gate explicitly requires
ARMhf success, rejecting skipped or cancelled ARMhf jobs. Repository protection
must require the PR workflow's aggregate `CI Success` check. Adding a workflow
job does not itself configure GitHub branch protection.

For downstream SONiC validation, use the aaaagent service's `make test` on both
architectures. When advancing its source pin to this fix, retire its old ARMv7
patch atomically with the pin update. An unpublished local-source overlay is
useful for development but is not evidence for the final immutable source pin.

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

Install the plugin to:

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
(`BUILDER_IMAGE` and `RUNTIME_IMAGE`). Downstream builders can substitute
their own bases without editing the Dockerfile. The default `ENTRYPOINT`/`CMD`
mirrors the SONiC systemd unit and can be overridden at `docker run` time.

## Verification

Before enabling SONiC command authorization broadly, make sure that:

1. `tacacsrs-agentd` is active and its IPC socket exists.
2. A manual `tacon` request against the configured endpoint succeeds.
3. The plugin shared library is present at the expected security path.
4. Any SONiC VM testing is performed with Linux artifacts built from WSL, not Windows binaries.
