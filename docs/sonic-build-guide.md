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

Copy the static binaries to the switch:

```bash
scp target/x86_64-unknown-linux-musl/release/tacon admin@switch:/usr/local/bin/
scp target/x86_64-unknown-linux-musl/release/tacacsrs-agentd admin@switch:/usr/local/bin/
scp target/x86_64-unknown-linux-musl/release/session-wrapper admin@switch:/usr/local/bin/
```

No runtime dependencies are required — the binaries are self-contained.

### Component roles on a SONiC switch

| Binary             | Role on the switch                                            | Lifetime                       |
|--------------------|---------------------------------------------------------------|--------------------------------|
| `tacacsrs-agentd`  | Long-running daemon. Maintains TACACS+ connections to upstream servers and exposes `/run/tacacs.sock` for local IPC. | systemd service (always on)    |
| `session-wrapper`  | **Not a daemon.** One process per SSH login, spawned by `sshd` via `ForceCommand` (or as the user's login shell). Forks the user's shell under a seccomp filter and proxies authorization through the agent. | Lives for the SSH session only |
| `tacon`            | Operator CLI for ad-hoc TACACS+ requests. Useful for accounting test traffic and debugging the agent.                                          | One-shot CLI invocation        |

### systemd interaction

Only `tacacsrs-agentd` needs a systemd unit on SONiC — `session-wrapper` is
launched on demand by `sshd` and exits with the user's session.

A typical unit file (`/etc/systemd/system/tacacsrs-agentd.service`) looks like:

```ini
[Unit]
Description=TACACS+ client agent for local IPC consumers
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tacacsrs-agentd --config /etc/tacacsrs/agentd.yaml
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
```

Enable and start it before any SSH session can require authorization:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tacacsrs-agentd
```

### Prerequisite: `tacacsrs-agentd` must be running

`session-wrapper` connects to the agent at `/run/tacacs.sock` (or whatever
path is passed via `--service-endpoint`). If the agent is not running, the
wrapper applies its `--fail-policy`:

- `closed` → the SSH session is denied. This is the production default.
- `open`   → the SSH session is allowed without authorization. Lab use only.

Before enabling `ForceCommand` system-wide, verify that:

1. `tacacsrs-agentd` is enabled in systemd and currently active.
2. The socket exists with the expected mode/owner: `ls -l /run/tacacs.sock`.
3. A manual `tacon` request against the same endpoint succeeds.

See [`docs/session-wrapper.md`](session-wrapper.md) for the full SSH
integration guide, configuration examples, and troubleshooting.

### Building only `session-wrapper`

The workspace musl build produces all three binaries in one pass. If you
want to verify the static `session-wrapper` binary in isolation:

```bash
cargo build --release --target x86_64-unknown-linux-musl -p session-wrapper

file target/x86_64-unknown-linux-musl/release/session-wrapper
# Should show: "statically linked"
```

The CI build matrix in `.github/workflows/reusable-build.yml` uses
`--workspace`, so `session-wrapper` is built and statically verified for the
`x86_64-unknown-linux-musl` target on every PR alongside `tacon` and
`tacacsrs-agentd`. The supporting `setup-rust` step builds and caches a
musl-targeted static `libseccomp` so the wrapper links cleanly.
