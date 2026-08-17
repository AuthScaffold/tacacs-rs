# tacon

A command-line TACACS+ client for authentication, authorization, and accounting (AAA) operations.

## Overview

`tacon` is a CLI tool for interaction with TACACS+ servers. It supports both traditional TACACS+ with obfuscation and modern TACACS+ over TLS 1.3. It works with legacy and next-generation network infrastructure.

## Features

- **Authentication** - Make sure that user credentials are valid for a TACACS+ server
- **Authorization** - Make sure that a user can run specific commands
- **Accounting** - Record user activity and command execution
- **TLS Support** - Secure connections using TLS 1.3 with optional client certificate and key files
- **Batch Mode** - Run multiple requests from a JSON file (sequential or parallel)
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
| --- | --- |
| `-s, --server-addr <ADDR>` | TACACS+ server address and port (for example, `192.168.1.1:49`) |
| `--config <FILE>` | Load direct connection configuration from a YANG JSON configuration file |
| `-k, --shared-secret <KEY>` | Shared secret for TACACS+ packet obfuscation |
| `--use-tls` | Enable TLS 1.3 for the connection |
| `--tls-server-name <NAME>` | Override the TLS server name used for SNI and certificate verification |
| `--client-certificate <FILE>` | Path to a PEM- or DER-encoded client certificate for TLS authentication |
| `--client-key <FILE>` | Path to a PEM- or DER-encoded client private key for TLS authentication |
| `--psk-identity <IDENTITY>` | TLS 1.3 PSK identity sent during the handshake (requires the `psk` feature) |
| `--psk-key <KEY>` | TLS 1.3 pre-shared key material (requires the `psk` feature) |
| `--psk-key-exchange <psk-dhe\|psk-only>` | Select PSK-DHE or explicit PSK-only interoperability mode |
| `--psk-key-exchange-groups <GROUPS>` | Comma-separated PSK-DHE supported groups in preferred order |
| `-v, --verbose` | Increase verbosity (`-v` warn, `-vv` info, `-vvv` debug, `-vvvv` trace) |

### TLS Client Certificates and Keys

When `--use-tls` is set, `--client-certificate` and `--client-key` let `tacon` present a TLS client identity to the upstream TACACS+ server.

- Provide both flags together. The certificate flag requires the key flag. The key flag requires the certificate flag.
- Both files can be PEM or DER. The client detects PEM input and converts it to DER before it builds the runtime connection configuration.
- If you connect to a TLS server by IP address, or by any socket address that does not match the certificate DNS name, use `--tls-server-name`. `tacon` uses the supplied value for both SNI and certificate name verification in direct mode.
- Windows "export with private key" workflows commonly produce PKCS#12 (`.pfx` / `.p12`) bundles. These flags do not accept that container format. Provide PEM or DER certificate and private-key material instead.
- This PEM-or-DER behavior applies only to the CLI flags. If you load TLS material through `--config`, the YANG-backed `tacacsrs-config` path remains DER-only.

### TLS 1.3 PSK

When built with the `psk` feature, `--psk-identity` and `--psk-key` select TLS
1.3 PSK authentication. The default key-exchange mode is PSK-DHE with the
preferred group order `secp384r1,secp256r1`.

Use `--psk-key-exchange-groups` to constrain the PSK-DHE groups offered in
ClientHello. Supplying groups implies PSK-DHE mode. If an interoperability peer
cannot negotiate PSK-DHE, use `--psk-key-exchange psk-only`. PSK-only mode
cannot be combined with `--psk-key-exchange-groups`.

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
| --- | --- |
| `-u, --user <USER>` | Username for the request |
| `-p, --port <PORT>` | Port identifier (for example, `tty0`, `console`) |
| `-r, --rem-addr <ADDR>` | Remote address of the client |

#### Authentication

Authenticate a user with PAP:

```bash
tacon -s 192.168.1.1:49 -k "secret" authentication \
    --user admin \
    --port tty0 \
    --rem-addr 10.0.0.100
```

#### Authorization

Request shell-session attributes:

```bash
tacon -s 192.168.1.1:49 -k "secret" authorization \
    --user admin \
    --port tty0 \
    --rem-addr 10.0.0.100 \
    --authentication-context pap session
```

Authorize one command:

```bash
tacon -s 192.168.1.1:49 -k "secret" authorization \
    --user admin \
    --port tty0 \
    --rem-addr 10.0.0.100 \
    --authentication-context pap command show users brief
```

#### Batch Mode

Run multiple requests from a JSON file:

```bash
tacon -s 192.168.1.1:49 -k "secret" batch requests.json
```

### Examples

#### Using Traditional TACACS+ with Obfuscation

```bash
tacon \
    --server-addr tacacsserver.local:49 \
    --shared-secret "tac_plus_key" \
    -vvv \
    accounting \
    --user testuser \
    --port tty1 \
    --rem-addr 192.168.1.100 \
    "show version"
```

#### Loading a YANG JSON configuration

```bash
tacon \
    --config ./tacacs.json \
    accounting \
    --user testuser \
    --port tty1 \
    --rem-addr 192.168.1.100 \
    "show version"
```

#### Using TACACS+ over TLS 1.3

```bash
tacon \
    --server-addr tacacsserver.local:449 \
    --use-tls \
    --client-certificate /path/to/client.crt.pem \
    --client-key /path/to/client.key.pem \
    accounting \
    --user testuser \
    --port tty1 \
    --rem-addr 192.168.1.100 \
    "show interfaces"
```

DER input works the same way:

```bash
tacon \
    --server-addr tacacsserver.local:449 \
    --use-tls \
    --client-certificate /path/to/client.crt.der \
    --client-key /path/to/client.key.der \
    accounting \
    --user testuser \
    --port tty1 \
    --rem-addr 192.168.1.100 \
    "show interfaces"
```

#### Using TLS 1.3 PSK-DHE

```bash
tacon \
    --server-addr tacacsserver.local:449 \
    --use-tls \
    --psk-identity client@example.com \
    --psk-key "$TACACS_TLS_PSK" \
    --psk-key-exchange-groups secp384r1,secp256r1 \
    accounting \
    --user testuser \
    --port tty1 \
    --rem-addr 192.168.1.100 \
    "show interfaces"
```

For PSK-only interoperability mode:

```bash
tacon \
    --server-addr legacy-tacacs.example.com:449 \
    --use-tls \
    --psk-identity client@example.com \
    --psk-key "$TACACS_TLS_PSK" \
    --psk-key-exchange psk-only \
    accounting \
    --user testuser \
    --port tty1 \
    --rem-addr 192.168.1.100 \
    "show interfaces"
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
| --- | --- |
| `description` | Optional description of the batch |
| `parallel` | Run requests in parallel (`true`) or sequentially (`false`) |

### Request Fields

All supported requests use these fields:

| Field      | Description                              |
| ---------- | ---------------------------------------- |
| `type`     | `accounting` or `authorization`          |
| `user`     | Username for the request                 |
| `port`     | Port identifier                          |
| `rem_addr` | Remote address of the client             |

Accounting requests require `cmd`. They can include `cmd_args`.

Authorization requests require `authentication_context`. Valid values are
`ascii`, `pap`, and `unauthenticated`. They can include `privilege_level`,
`cmd`, and `cmd_args`.

Batch files parse the `authentication` type, but both executors reject it.
Use the interactive `authentication` command instead.

See the [examples](examples/) directory for sample batch files.

## Exit Codes

| Code | Description                                                    |
| ---- | -------------------------------------------------------------- |
| 0    | Success                                                        |
| 1    | Error (connection failure, invalid arguments, request failure) |

## Related

- [tacacs-rs](../../README.md) - Parent project documentation
- [tacacsrs-messages](../../libraries/tacacsrs_messages/) - TACACS+ message library
- [tacacsrs-networking](../../libraries/tacacsrs_networking/) - TACACS+ networking library

## License

See the [LICENSE](../../LICENSE) file in the repository root.
