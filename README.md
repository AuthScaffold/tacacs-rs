# TACACS-rs

`tacacs-rs` is a reference implementation of the TACACS+ protocol, designed to provide a robust and efficient solution for authentication, authorization, and accounting (AAA) services.

## Demo

**Demo 1: Existing (Legacy) TACACS+ with Obfuscation**

```powershell
clear
cargo run -p tacon -- `
    --obfuscation-key tac_plus_key `
    -s tacacsserver.local:49 `
    --user test `
    --port 1 `
    --rem-addr 1.1.1.1 `
    -vvv `
    accounting test
```

**Demo 2: Upcoming TACACS+ with TLS 1.3**

```powershell
clear
$client_certificate = Join-Path -Path $(pwd) -ChildPath libraries tacacsrs_networking examples samples client.crt
$client_key = Join-Path -Path $(pwd) -ChildPath libraries tacacsrs_networking examples samples client.key
cargo run -p tacon -- `
    --use-tls `
    --client-certificate $client_certificate `
    --client-key $client_key `
    -s tacacsserver.local:449 `
    --user test `
    --port 1 `
    --rem-addr 1.1.1.1 `
    -vvv `
    accounting test
```


## TACACS+ server for Local Testing

Local testing uses Docker, and we have prepared a compose file in the `lde/containers` folder. You can simply run `docker compose up -d` and have a working TACACS+ server on port 49 for non-TLS and 449 for TLS (will change the default in the future when IANA assigns a well known port number to TACACS with TLS).

## Compiling for SONiC

SONiC (Software for Open Networking in the Cloud) runs on Linux and requires statically-linked binaries for easy deployment. We use [musl](https://musl.libc.org/) to produce fully static executables.

### Prerequisites

Install the musl toolchain and add the Rust target:

```bash
# Install musl tools (Debian/Ubuntu)
sudo apt install -y musl-tools

# Add the musl target to Rust
rustup target add x86_64-unknown-linux-musl
```

### Building

Build all workspace crates with the musl target:

```bash
cargo build --release --workspace --target x86_64-unknown-linux-musl
```

The binaries will be in `target/x86_64-unknown-linux-musl/release/`.

To output artifacts to a specific directory (requires nightly or `-Z unstable-options`):

```bash
cargo build --release --workspace --artifact-dir out -Z unstable-options --target x86_64-unknown-linux-musl
```

### Verifying Static Linkage

Confirm the binary is statically linked:

```bash
file target/x86_64-unknown-linux-musl/release/tacon
# Should show: "statically linked"

ldd target/x86_64-unknown-linux-musl/release/tacon
# Should show: "not a dynamic executable"
```
