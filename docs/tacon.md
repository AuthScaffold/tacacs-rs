# tacon — TACACS+ Client CLI

`tacon` is a command-line TACACS+ client for sending authentication, authorization, and accounting (AAA) requests to TACACS+ servers.

## Connection Modes

`tacon` supports two connection modes, selected by which endpoint flag you provide:

### Direct Mode (`--server-addr`)

Connects directly to a TACACS+ server. You manage encryption, TLS, and connection configuration.

```bash
tacon -s tacacs-server:49 -k shared_secret \
  accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
  "show version"
```

**Best for:** testing, one-off requests, development, scripts.

### Service Mode (`--service-endpoint`)

Connects to the central [tacacsrs-agentd](tacacsrs-agentd.md) service. The service maintains upstream connections and manages automatic failover.

```bash
tacon --service-endpoint /run/tacacs/tacacs.sock \
  accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
  "show version"
```

**Best for:** production deployments where multiple clients share TACACS+ connections with automatic failover.

## Global Options

### Transport Target (one required)

| Flag | Description |
| --- | --- |
| `-s, --server-addr <ADDR>` | Direct connection to a TACACS+ server, for example `192.168.1.1:49` |
| `--config <FILE>` | Load the direct connection from a YANG JSON configuration file |
| `--service-endpoint <PATH>` | Connect through the agent service (Unix domain socket or TCP address) |

### Encryption (direct mode only)

| Flag | Description |
| --- | --- |
| `-k, --shared-secret <KEY>` | Shared secret for TACACS+ packet obfuscation |
| `--use-tls` | Enable TLS 1.3 |
| `--client-certificate <FILE>` | Client TLS certificate (requires `--client-key`) |
| `--client-key <FILE>` | Client TLS private key (requires `--client-certificate`) |
| `--insecure-disable-certificate-verification` | Skip server certificate verification |
| `--psk-identity <ID>` | TLS 1.3 pre-shared key identity *(requires `psk` feature)* |
| `--psk-key <KEY>` | TLS 1.3 pre-shared key *(requires `psk` feature)* |

### Connection Behavior (direct mode only)

| Flag | Description |
| --- | --- |
| `--dedicated` | Use a one-shot connection per request (no session multiplexing) |

### Debugging

| Flag | Description |
| --- | --- |
| `-v` | Warnings |
| `-vv` | Info |
| `-vvv` | Debug |
| `-vvvv` | Trace |

## Commands

### `accounting`

Record command execution to a TACACS+ server.

```bash
tacon -s server:49 \
  accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
  "show running-config" arg1 arg2
```

| Argument | Description |
| --- | --- |
| `<CMD>` | The command being recorded |
| `[ARGS...]` | Optional command arguments |

### `authentication`

Authenticate a username/password pair using the fixed RFC 8907 PAP exchange.
The password is never accepted as a command-line argument.

```bash
# Hidden terminal prompt
tacon -s server:49 authentication \
  --user admin --port tty0 --rem-addr 10.0.0.1

# Non-interactive input
printf '%s\n' "$PAP_PASSWORD" | tacon -s server:49 authentication \
  --user admin --port tty0 --rem-addr 10.0.0.1 \
  --password-stdin
```

PAP follows the configured direct or agent upstream connection. Classic TACACS+
obfuscation is not encryption. If you need password confidentiality, use
TACACS+ over TLS 1.3.

### `authorization`

Authorization requires the authentication context and an explicit shell mode.

```bash
# Session profile / shell provisioning (`service=shell`, `cmd=`)
tacon -s server:49 authorization \
  --user admin --port tty0 --rem-addr 10.0.0.1 \
  --authentication-context pap session

# Per-command authorization
tacon -s server:49 authorization \
  --user admin --port tty0 --rem-addr 10.0.0.1 \
  --authentication-context pap command show users brief
```

Authentication contexts are `ascii`, `pap`, and `unauthenticated`. Session
authorization is the TACACS+ mechanism for retrieving shell profile attributes.
It does not require ASCII authentication.

### `batch`

Run multiple requests from a JSON file.

```bash
tacon -s server:49 -k secret batch requests.json
```

## Batch File Format

Batch files are JSON documents containing metadata and a list of requests.

### Minimal Example

```json
{
  "requests": [
    {
      "type": "accounting",
      "user": "admin",
      "port": "tty0",
      "rem_addr": "10.0.0.1",
      "cmd": "show version"
    }
  ]
}
```

### Full Example

```json
{
  "metadata": {
    "description": "Nightly accounting audit",
    "parallel": true,
    "load_test": {
      "repetitions": 100,
      "max_parallel": 10
    }
  },
  "requests": [
    {
      "type": "accounting",
      "user": "admin",
      "port": "tty0",
      "rem_addr": "10.0.0.1",
      "cmd": "show running-config",
      "cmd_args": ["brief"]
    },
    {
      "type": "authorization",
      "user": "admin",
      "port": "tty0",
      "rem_addr": "10.0.0.1",
      "authentication_context": "pap",
      "privilege_level": 15
    }
  ]
}
```

### Metadata Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `description` | string | — | Optional description |
| `parallel` | bool | `false` | Run all requests concurrently |
| `load_test` | object | — | Enable load testing mode |
| `load_test.repetitions` | number | — | Number of times to repeat all requests |
| `load_test.max_parallel` | number | `10` | Maximum concurrent requests |

Batch authorization is shell-only. Omitting `cmd` performs session-profile
authorization. Providing `cmd` and `cmd_args` performs command authorization.
PAP authentication is intentionally unavailable in batch files because the
format has no credential-source abstraction, and plaintext JSON passwords
are rejected.

### Run Modes

| `parallel` | `load_test` | Behavior |
| --- | --- | --- |
| `false` | absent | Run requests sequentially |
| `true` | absent | Run all requests concurrently |
| any | present | All requests repeat N times with bounded parallelism |

### Batch with Different Connection Modes

```bash
# Direct — multiplexed sessions on one connection
tacon -s server:49 -k secret batch requests.json

# Dedicated — one TCP/TLS connection per request
tacon -s server:49 -k secret --dedicated batch requests.json

# Service — routed through the agent with failover
tacon --service-endpoint /run/tacacs/tacacs.sock batch requests.json
```

## Transport Options

### Legacy TACACS+ (obfuscation only)

```bash
tacon -s tacacs-server:49 -k tac_plus_key \
  accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
  "show version"
```

### YANG JSON configuration

```bash
tacon --config ./tacacs.json \
  accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
  "show version"
```

The configuration file must use RFC 7951 JSON encoding with the root key `ietf-system-tacacs-plus:tacacs-plus`.

### TLS 1.3 with Certificates

```bash
tacon -s tacacs-server:449 --use-tls \
    --client-certificate client.crt.der --client-key client.key.der \
  accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
  "show version"
```

### TLS 1.3 with Pre-Shared Keys

*(Requires the `psk` feature.)*

```bash
tacon -s tacacs-server:449 --use-tls \
    --psk-identity client1 --psk-key "shared_secret_at_least_16_bytes" \
  accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
  "show version"
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | All requests succeeded |
| `1` | One or more requests failed |
