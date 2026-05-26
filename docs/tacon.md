# tacon — TACACS+ Client CLI

`tacon` is a command-line TACACS+ client for sending authentication, authorization, and accounting (AAA) requests to TACACS+ servers.

## Connection Modes

`tacon` supports two connection modes, selected by which endpoint flag you provide:

### Direct Mode (`--server-addr`)

Connects directly to a TACACS+ server. You manage encryption, TLS, and connection settings yourself.

```bash
tacon -s tacacs-server:49 -k shared_secret \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show version"
```

**Best for:** testing, one-off requests, development, scripts.

### Service Mode (`--service-endpoint`)

Connects to the central [tacacsrs-agentd](tacacsrs-agentd.md) service, which maintains persistent upstream connections with automatic failover.

```bash
tacon --service-endpoint /run/tacacs.sock \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show version"
```

**Best for:** production deployments where multiple clients share TACACS+ connections with automatic failover.

**Restrictions in service mode:** explicit session IDs (`--session-id`) are not supported — the agent assigns these.

## Global Options

### Transport Target (one required)

| Flag | Description |
|------|-------------|
| `-s, --server-addr <ADDR>` | Direct connection to a TACACS+ server (e.g. `192.168.1.1:49`) |
| `--config <FILE>` | Load the direct connection from a YANG JSON config file |
| `--service-endpoint <PATH>` | Connect via the agent service (Unix socket or TCP address) |

### Encryption (direct mode only)

| Flag | Description |
|------|-------------|
| `-k, --shared-secret <KEY>` | Shared secret for TACACS+ packet obfuscation |
| `--use-tls` | Enable TLS 1.3 |
| `--client-certificate <FILE>` | Client TLS certificate (requires `--client-key`) |
| `--client-key <FILE>` | Client TLS private key (requires `--client-certificate`) |
| `--insecure-disable-certificate-verification` | Skip server certificate verification |
| `--psk-identity <ID>` | TLS 1.3 pre-shared key identity *(requires `psk` feature)* |
| `--psk-key <KEY>` | TLS 1.3 pre-shared key *(requires `psk` feature)* |

### Connection Behaviour (direct mode only)

| Flag | Description |
|------|-------------|
| `--dedicated` | Use a one-shot connection per request (no session multiplexing) |

### Debugging

| Flag | Description |
|------|-------------|
| `-v` | Warnings |
| `-vv` | Info |
| `-vvv` | Debug |
| `-vvvv` | Trace |

## Commands

### `accounting`

Record command execution to a TACACS+ server.

```bash
tacon -s server:49 \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show running-config" arg1 arg2
```

| Argument | Description |
|----------|-------------|
| `<CMD>` | The command being recorded |
| `[ARGS...]` | Optional command arguments |
| `--session-id <ID>` | Use a specific session ID (direct mode only) |

### `authentication`

Authenticate a user against the TACACS+ server. *(Not yet implemented.)*

### `authorization`

Check whether a user is authorized to execute a command. *(Not yet implemented.)*

### `batch`

Execute multiple requests from a JSON file.

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
      "cmd_args": ["brief"],
      "session_id": null
    }
  ]
}
```

### Metadata Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `description` | string | — | Optional description |
| `parallel` | bool | `false` | Execute all requests concurrently |
| `load_test` | object | — | Enable load testing mode |
| `load_test.repetitions` | number | — | Number of times to repeat all requests |
| `load_test.max_parallel` | number | `10` | Maximum concurrent requests |

### Execution Modes

| `parallel` | `load_test` | Behaviour |
|-----------|------------|-----------|
| `false` | absent | Requests execute sequentially |
| `true` | absent | All requests execute concurrently |
| any | present | All requests repeat N times with bounded parallelism |

### Batch with Different Connection Modes

```bash
# Direct — multiplexed sessions on one connection
tacon -s server:49 -k secret batch requests.json

# Dedicated — one TCP/TLS connection per request
tacon -s server:49 -k secret --dedicated batch requests.json

# Service — routed through the agent with failover
tacon --service-endpoint /run/tacacs.sock batch requests.json
```

## Transport Options

### Legacy TACACS+ (obfuscation only)

```bash
tacon -s tacacs-server:49 -k tac_plus_key \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show version"
```

### YANG JSON configuration

```bash
tacon --config ./tacacs.json \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show version"
```

The config file must use RFC 7951 JSON encoding with the root key `ietf-system-tacacs-plus:tacacs-plus`.

### TLS 1.3 with Certificates

```bash
tacon -s tacacs-server:449 --use-tls \
    --client-certificate client.crt.der --client-key client.key.der \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show version"
```

### TLS 1.3 with Pre-Shared Keys

*(Requires the `psk` feature.)*

```bash
tacon -s tacacs-server:449 --use-tls \
    --psk-identity client1 --psk-key "shared_secret_at_least_16_bytes" \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show version"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All requests succeeded |
| `1` | One or more requests failed |
