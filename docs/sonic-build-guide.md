# Building for SONiC

SONiC (Software for Open Networking in the Cloud) runs on Linux and requires statically-linked binaries for easy deployment across switch platforms. This guide covers producing fully static executables using [musl](https://musl.libc.org/).

## Rust Toolchain

For SONiC build environments that do not ship a Rust toolchain, or that ship an older version, the current stable Rust toolchain should be provisioned using `rustup`. This provides the greatest level of reproducibility across supported SONiC versions.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
    --default-toolchain stable -y
```

## Prerequisites

Install the musl toolchain and add the Rust target:

```bash
# Install musl tools (Debian/Ubuntu)
sudo apt install -y musl-tools

# Add the musl target to Rust
rustup target add x86_64-unknown-linux-musl
```

## Building

Build all workspace crates with the musl target:

```bash
cargo build --release --workspace --target x86_64-unknown-linux-musl
```

The binaries will be in `target/x86_64-unknown-linux-musl/release/`.

To output artifacts to a specific directory (requires nightly or `-Z unstable-options`):

```bash
cargo build --release --workspace --artifact-dir out -Z unstable-options --target x86_64-unknown-linux-musl
```

## Verifying Static Linkage

Confirm the binary is statically linked:

```bash
file target/x86_64-unknown-linux-musl/release/tacon
# Should show: "statically linked"

ldd target/x86_64-unknown-linux-musl/release/tacon
# Should show: "not a dynamic executable"
```

## Deploying to SONiC

Copy the static binary to the switch:

```bash
scp target/x86_64-unknown-linux-musl/release/tacon admin@switch:/usr/local/bin/
scp target/x86_64-unknown-linux-musl/release/tacacsrs-agentd admin@switch:/usr/local/bin/
```

No runtime dependencies are required — the binaries are self-contained.
