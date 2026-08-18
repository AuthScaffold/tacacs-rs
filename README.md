# TACACS-rs

`tacacs-rs` implements the TACACS+ protocol in Rust. It provides TACACS+ authentication, authorization, and accounting components for network infrastructure.

The `tacacsrs-agent` component provides a TACACS+ TCP proxy and a gRPC-based AAA service. The `tacon` application tests plain TCP and TLS transport modes. These modes include mTLS, TLS PSK, and TLS PSK-DHE.

The workspace also provides configuration parsing, daemon packaging, IPC emulation, and integration components.

## TACACS+ Proxy for `pam_tacplus`, `audisp-tacplus`, and Legacy TACACS+ Clients

`tacacsrs-agentd` can operate as a local compatibility proxy. It supports clients that cannot connect directly to a TACACS+ server through TLS.

These clients include [`pam_tacplus`](https://github.com/kravietz/pam_tacplus) and [`audisp-tacplus`](https://github.com/daveolson53/audisp-tacplus). The proxy also supports other TACACS+ TCP integrations.

The proxy accepts TACACS+ packets on a loopback TCP endpoint. It multiplexes concurrent downstream session IDs and preserves the packet order for each session.

The daemon connects to one or more upstream servers through TLS 1.3. It manages transport security, ordered failover, connection reuse, and TLS credentials.

The upstream modes include server-authenticated TLS, mTLS, TLS 1.3 PSK-DHE, and TLS 1.3 PSK-only interoperability.

```bash
tacacsrs-agentd \
  --server-addr tacacs1.example.com:449 \
  --service-mode tacacs-proxy \
  --proxy-endpoint 127.0.0.1:9049 \
  --shared-secret "$TACACS_SHARED_SECRET" \
  --use-tls
```

Use the proxy to move existing clients to the RFC 9887 TLS transport:

- For `pam_tacplus`, keep the PAM module. Set its `server=` value to the loopback TACACS+ proxy.
- For `audisp-tacplus`, keep the auditd plugin and the TACACS+ accounting fields. The daemon forwards accounting packets through TLS.

For the host cutover procedure, read the [Plain TACACS+ to TACACS+ over TLS Transition Guide](docs/tacacs-plus-tls-transition.md).

## Components

| Component | Description |
|-----------|-------------|
| **tacacsrs-agent** | TACACS+ TCP proxy and gRPC-based AAA service library |
| **tacon** | TACACS+ test application for AAA operations and transport modes |
| **tacacsrs-agentd** | Daemon that hosts `tacacsrs-agent`, maintains upstream connections, and manages failover |
| **tacacsrs-agent-ipc-emulatord** | OPA/Rego-based gRPC IPC emulator for `ServiceClient` integration tests |
| **tacacsrs-config** | YANG JSON parser, validator, and local credential-bundle enumerator for `ietf-system-tacacs-plus` |
| **tacacsrs-credential-resolution** | Provider-neutral credential plans, secret-safe material, and request-result matching |
| **session-wrapper** | Linux proof of concept for TACACS+ command authorization through seccomp user notifications |

## Workspace Architecture

```text
tacon (CLI)  ──────┬──► tacacsrs-agent-client
                   ├──► tacacsrs-config
                   ├──► tacacsrs-flows
                   ├──► tacacsrs-messages
                   └──► tacacsrs-networking

tacacsrs-agentd ───┬──► tacacsrs-agent
                   ├──► tacacsrs-agent-client
                   └──► tacacsrs-config

tacacsrs-agent ────┬──► tacacsrs-agent-client
                   ├──► tacacsrs-flows
                   ├──► tacacsrs-messages
                   └──► tacacsrs-networking

tacacsrs-agent-ipc-emulatord ───► tacacsrs-agent-ipc-emulator
                                  └──► tacacsrs-agent-client

tacacsrs-credential-resolution ──► tacacsrs-config
                              └──► tacacsrs-secrets
```

`tacacsrs-config` is the entry point for RFC 7951 YANG JSON parsing. It owns the generated `ietf-system-tacacs-plus` Rust types and validates YANG constraints.

The crate expands local credential bundles. It preserves external central references as opaque values.

`tacacsrs-credential-resolution` converts these references into typed, provider-neutral requests. It also validates resolved results. Other integration components retrieve credentials and create runtime connections.

## Documentation

- [Documentation site](https://authscaffold.github.io/tacacs-rs/) - Static mdBook site for the project guides
- [GitHub Discussions](https://github.com/AuthScaffold/tacacs-rs/discussions) is the preferred place for questions, support, design discussion, and migration help.
- [tacon Usage Guide](docs/tacon.md) — CLI client reference, connection modes, batch execution
- [tacacsrs-agentd Usage Guide](docs/tacacsrs-agentd.md) — Central service deployment, failover, IPC protocol
- [YANG Config Guide](docs/yang-config-guide.md) — RFC 7951 TACACS+ configuration shape, parsing APIs, and TLS credential formats
- [Plain TACACS+ to TACACS+ over TLS Transition Guide](docs/tacacs-plus-tls-transition.md) — Local proxy cutover plan for `pam_tacplus`, `audisp-tacplus`, and similar clients
- [tacacsrs-agent-ipc-emulator README](libraries/tacacsrs_agent_ipc_emulator/README.md) — Rego policy format and in-process/out-of-process IPC emulator usage
- [tacacsrs-config README](libraries/tacacsrs_config/README.md) — YANG JSON schema support, codegen workflow, parsing APIs
- [tacacsrs-credential-resolution README](libraries/tacacsrs_credential_resolution/README.md) — Central credential planning, resolver contracts, and secret-safe material
- [session-wrapper README](executables/session_wrapper/README.md) — Linux seccomp session wrapper architecture and current allow-all behavior
- [Session Wrapper Deployment Guide](docs/session-wrapper.md) — SSH `ForceCommand` integration, configuration examples, security notes, troubleshooting
- [Session Wrapper Testing](docs/session-wrapper-testing.md) — Linux smoke and integration checks for the session wrapper
- [Building for SONiC](docs/sonic-build-guide.md) — Static musl binaries for network switches
- [Debian Packaging](DEBIAN_PACKAGING.md) — Building `.deb` packages
- [Development Guide](DEVELOPMENT.md) — Building, testing, CI, project structure

## Rust Toolchain

This project has a minimum supported Rust version (MSRV) of **1.88**. The `rust-version` field in `Cargo.toml` defines this version.

The workspace crates are internal and are not published to crates.io.

## Quick Start

### Installation

**From GitHub Releases (Debian/Ubuntu):**

```bash
sudo dpkg -i tacon_*.deb
```

**From source:**

```bash
cargo build --release --package tacon
sudo cp target/release/tacon /usr/local/bin/
```

The `main` branch keeps Cargo package versions at `0.0.0-dev`. To build with released version metadata, clone the generated `release` branch:

```bash
git clone https://github.com/AuthScaffold/tacacs-rs.git --branch release
cd tacacs-rs
cargo build --release --package tacon
```

Release automation adds one generated commit to `release` for each release. Release tags and submodules can pin these commits. Use `main` for development work.

### Basic Usage

```bash
# Send an accounting record (direct connection)
tacon -s tacacs-server:49 --shared-secret shared_secret \
  accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
  "show running-config"

# Send via the central agent service
tacon --service-endpoint /run/tacacs/tacacs.sock \
  accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
  "show running-config"

# Load the direct connection from a YANG JSON config file
tacon --config ./tacacs.json \
  accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
  "show running-config"

# PAP authentication using a hidden prompt
tacon --config ./tacacs.json authentication \
  --user admin --port tty0 --rem-addr 10.0.0.1

# Retrieve shell-session attributes (`cmd=`) for a PAP-authenticated user
tacon --config ./tacacs.json authorization \
  --user admin --port tty0 --rem-addr 10.0.0.1 \
  --authentication-context pap session
```

### YANG JSON Configuration

Both `tacon` and `tacacsrs-agentd` can load server definitions from an RFC 7951 JSON document. The document must match the `ietf-system-tacacs-plus` YANG model.

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "server": [
      {
        "name": "primary",
        "server-type": "authentication authorization accounting",
        "address": "192.0.2.2",
        "port": 49,
        "shared-secret": "QaEfThUkO198010075460923+h3TbE8n",
        "timeout": 10
      }
    ]
  }
}
```

Use `--config <file>` with either executable to load this configuration. The `tacacsrs-config` crate owns the generated YANG types and validation.

The crate maps YANG JSON to the runtime `ServerConnectionConfig` values. The CLI and the agent daemon use these values.

## Local Testing

Local tests use Docker. A Compose file in `lde/containers` provides a server on port 49 for plain TCP. It uses port 449 for TLS.

```bash
cd lde/containers
docker compose up -d
```

## License

This project is licensed under the [MIT License](LICENSE).
