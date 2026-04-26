# TACACS-rs

`tacacs-rs` is a Rust implementation of the TACACS+ protocol, providing authentication, authorization, and accounting (AAA) services for network infrastructure. It supports both traditional TACACS+ with obfuscation and modern TACACS+ over TLS 1.3.

## Components

| Component | Description |
|-----------|-------------|
| **tacon** | CLI client for sending TACACS+ requests (accounting, authentication, authorization) |
| **tacacsrs-agentd** | Central service daemon that manages persistent TACACS+ connections with automatic failover |
| **tacacsrs-config** | YANG JSON configuration crate for `ietf-system-tacacs-plus` parsing, validation, and runtime mapping |

## Workspace Architecture

```text
tacon (CLI)  ──────┬──► tacacsrs-agent-client
                   ├──► tacacsrs-config
                   ├──► tacacsrs-messages
                   └──► tacacsrs-networking

tacacsrs-agentd ───┬──► tacacsrs-agent
                   ├──► tacacsrs-agent-client
                   └──► tacacsrs-config

tacacsrs-agent ────┬──► tacacsrs-agent-client
                   ├──► tacacsrs-messages
                   └──► tacacsrs-networking
```

`tacacsrs-config` is the entry point for RFC 7951 YANG JSON parsing. It owns the generated `ietf-system-tacacs-plus` Rust types, resolves credential references, validates YANG-specific choice constraints, and maps validated data into runtime connection settings shared by `tacon` and `tacacsrs-agentd`.

## Documentation

- [tacon Usage Guide](docs/tacon.md) — CLI client reference, connection modes, batch execution
- [tacacsrs-agentd Usage Guide](docs/tacacsrs-agentd.md) — Central service deployment, failover, IPC protocol
- [tacacsrs-config README](libraries/tacacsrs_config/README.md) — YANG JSON schema support, codegen workflow, parsing APIs
- [Building for SONiC](docs/sonic-build-guide.md) — Static musl binaries for network switches
- [Debian Packaging](DEBIAN_PACKAGING.md) — Building `.deb` packages
- [Development Guide](DEVELOPMENT.md) — Building, testing, CI, project structure

## Minimum Supported Rust Version (MSRV)

This project's Minimum Supported Rust Version (MSRV) is **Rust 1.85.0**.

The MSRV is defined as the minimum Rust toolchain required to build the project and its resolved runtime dependency graph. This floor reflects the requirements of core runtime dependencies, including cryptographic and serialization libraries, and is intentionally aligned with the modern Rust ecosystem to avoid maintaining fragile dependency pinning or forks.

The MSRV may be raised in the future as required by upstream dependencies or security considerations. Such changes will be documented explicitly.

<details>
<summary>If auditors ask "why not lower?"</summary>

Lower Rust versions are not supported because upstream runtime dependencies have adopted newer language editions and MSRV requirements; supporting older toolchains would require extensive and fragile dependency pinning with no security or operational benefit.
</details>

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

### Basic Usage

```bash
# Send an accounting record (direct connection)
tacon -s tacacs-server:49 --shared-secret shared_secret \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show running-config"

# Send via the central agent service
tacon --service-endpoint /run/tacacs.sock \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show running-config"

# Load the direct connection from a YANG JSON config file
tacon --config ./tacacs.json \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show running-config"
```

### YANG JSON Configuration

Both `tacon` and `tacacsrs-agentd` can load TACACS+ server definitions from an RFC 7951 JSON document matching the `ietf-system-tacacs-plus` YANG model.

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

Use `--config <file>` with either executable to load this configuration. The `tacacsrs-config` crate owns the generated YANG types, validation, and mapping from YANG JSON into runtime `ServerConnectionConfig` values consumed by the CLI and agent daemon.

## Local Testing

Local testing uses Docker. A compose file in `lde/containers` provides a TACACS+ server on port 49 (plain) and 449 (TLS):

```bash
cd lde/containers
docker compose up -d
```

## License

This project is licensed under the [MIT License](LICENSE).
