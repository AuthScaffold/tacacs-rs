# tacon

A command-line TACACS+ client for authentication, authorization, and accounting (AAA) operations.

## Overview

`tacon` is a CLI tool that enables interaction with TACACS+ servers. It supports both traditional TACACS+ with obfuscation and modern TACACS+ over TLS 1.3, making it suitable for both legacy and next-generation network infrastructure.

## Features

- **Authentication** - Verify user credentials against a TACACS+ server
- **Authorization** - Check if a user is permitted to execute specific commands
- **Accounting** - Record user activity and command execution
- **TLS Support** - Secure connections using TLS 1.3 with client certificates
- **Batch Mode** - Execute multiple requests from a JSON file (sequential or parallel)
- **Configurable Verbosity** - Multiple logging levels for debugging

## Installation

Build from source using Cargo:

```bash
cargo build --release -p tacon
```

The binary will be available at `target/release/tacon`.

## Usage

### Basic Syntax

```bash
tacon --server-addr <HOST:PORT> [OPTIONS] <COMMAND>
```

### Global Options

| Option | Description |
|--------|-------------|
| `-s, --server-addr <ADDR>` | TACACS+ server address and port (e.g., `192.168.1.1:49`) |
| `--config <FILE>` | Load direct connection settings from a YANG JSON config file |
| `-k, --shared-secret <KEY>` | Shared secret for TACACS+ packet obfuscation |
| `--use-tls` | Enable TLS 1.3 for the connection |
| `--client-certificate <FILE>` | Path to client certificate for TLS authentication |
| `--client-key <FILE>` | Path to client private key for TLS authentication |
| `-v, --verbose` | Increase verbosity (`-v` warn, `-vv` info, `-vvv` debug, `-vvvv` trace) |

### Commands

#### Accounting

Record command execution to the TACACS+ server:

```bash
tacon -s 192.168.1.1:49 -k "secret" accounting \
    --user admin \
    --port tty0 \
    --rem-addr 10.0.0.100 \
    "show running-config"
```

**Accounting Options:**

| Option | Description |
|--------|-------------|
| `-u, --user <USER>` | Username for the request |
| `-p, --port <PORT>` | Port identifier (e.g., `tty0`, `console`) |
| `-r, --rem-addr <ADDR>` | Remote address of the client |
| `--custom-flag-1` | Set TAC_PLUS_CUSTOM_FLAG_1 (0x40) on packet header |
| `--custom-flag-2` | Set TAC_PLUS_CUSTOM_FLAG_2 (0x80) on packet header |
| `--session-id <ID>` | Use a specific session ID instead of random |

#### Authentication

Authenticate a user (not yet implemented):

```bash
tacon -s 192.168.1.1:49 -k "secret" authentication \
    --user admin \
    --port tty0 \
    --rem-addr 10.0.0.100
```

#### Authorization

Check command authorization (not yet implemented):

```bash
tacon -s 192.168.1.1:49 -k "secret" authorization \
    --user admin \
    --port tty0 \
    --rem-addr 10.0.0.100
```

#### Batch Mode

Execute multiple requests from a JSON file:

```bash
tacon -s 192.168.1.1:49 -k "secret" batch requests.json
```

### Examples

#### Using Traditional TACACS+ with Obfuscation

```bash
tacon \
    --server-addr tacacsserver.local:49 \
    --shared-secret "tac_plus_key" \
    --user testuser \
    --port tty1 \
    --rem-addr 192.168.1.100 \
    -vvv \
    accounting "show version"
```

#### Loading a YANG JSON config

```bash
tacon \
    --config ./tacacs.json \
    --user testuser \
    --port tty1 \
    --rem-addr 192.168.1.100 \
    accounting "show version"
```

#### Using TACACS+ over TLS 1.3

```bash
tacon \
    --server-addr tacacsserver.local:449 \
    --use-tls \
    --client-certificate /path/to/client.crt.der \
    --client-key /path/to/client.key.der \
    --user testuser \
    --port tty1 \
    --rem-addr 192.168.1.100 \
    accounting "show interfaces"
```

## Batch File Format

Batch files use JSON format to define multiple TACACS+ requests:

```json
{
  "metadata": {
    "description": "Sample batch file",
    "parallel": false
  },
  "requests": [
    {
      "type": "accounting",
      "user": "user1",
      "port": "tty1",
      "rem_addr": "192.168.1.101",
      "cmd": "show version"
    },
    {
      "type": "accounting",
      "user": "user2",
      "port": "tty2",
      "rem_addr": "192.168.1.102",
      "cmd": "show interfaces"
    }
  ]
}
```

### Batch Metadata Options

| Field | Description |
|-------|-------------|
| `description` | Optional description of the batch |
| `parallel` | Execute requests in parallel (`true`) or sequentially (`false`) |

### Request Fields

| Field | Description |
|-------|-------------|
| `type` | Request type: `accounting`, `authentication`, or `authorization` |
| `user` | Username for the request |
| `port` | Port identifier |
| `rem_addr` | Remote address of the client |
| `cmd` | Command being executed (for accounting) |

See the [examples](examples/) directory for sample batch files.

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (connection failure, invalid arguments, request failure) |

## Related

- [tacacs-rs](../../README.md) - Parent project documentation
- [tacacsrs-messages](../../libraries/tacacsrs_messages/) - TACACS+ message library
- [tacacsrs-networking](../../libraries/tacacsrs_networking/) - TACACS+ networking library

## License

See the [LICENSE](../../LICENSE) file in the repository root.
