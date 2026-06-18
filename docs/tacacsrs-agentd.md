# tacacsrs-agentd — Central TACACS+ Service

`tacacsrs-agentd` is a long-running daemon that maintains persistent TACACS+ connections to one or more upstream servers and exposes a local IPC interface for clients like [tacon](tacon.md). It handles connection pooling, session multiplexing, and ordered failover automatically.

## Architecture

```
┌──────────┐  ┌──────────┐
│  tacon   │  │  auditd  │  ... other local consumers
│  client  │  │  plugin  │
└────┬─────┘  └────┬─────┘
     │  gRPC/Unix  │
     └──────┬──────┘
            ▼
   ┌─────────────────┐
   │ tacacsrs-agentd │
   │  (this daemon)  │
   └────────┬────────┘
            │  TACACS+ (TCP / TLS 1.3)
     ┌──────┴──────┐
     ▼             ▼
┌──────────┐ ┌──────────┐
│ TACACS+  │ │ TACACS+  │
│ server 1 │ │ server 2 │  (ordered preference)
└──────────┘ └──────────┘
```

## Quick Start

```bash
tacacsrs-agentd \
    --server-addr tacacs1.example.com:49 \
    --server-addr tacacs2.example.com:49 \
    --listen-endpoint /run/tacacs/tacacs.sock \
    --proxy-endpoint /run/tacacs/tacacs-proxy.sock \
    --shared-secret "shared_secret"
```

Then from any client on the same host:

```bash
tacon --service-endpoint /run/tacacs/tacacs.sock \
    --user admin --port tty0 --rem-addr 10.0.0.1 \
    accounting "show version"
```

## Command-Line Options

### Upstream Servers (required)

| Flag | Description |
|------|-------------|
| `--server-addr <ADDR>` | TACACS+ server address (repeatable, ordered by preference). First entry is the preferred server. |
| `--config <FILE>` | Load upstream server definitions from a YANG JSON config file |

### IPC Listener

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-endpoint <ENDPOINT>` | `/run/tacacs/tacacs.sock` | Unix socket path (Linux) or TCP address (other platforms) |
| `--proxy-endpoint <ENDPOINT>` | *(disabled)* | Optional TACACS+ proxy listener on a Unix socket path or loopback TCP address |
| `--socket-mode <MODE>` | `660` | File permission mode for the Unix socket (octal) |

### TACACS+ Proxy Mode

When `--proxy-endpoint` is set, `tacacsrs-agentd` also accepts local TACACS+ client connections and presents itself like a TACACS+ server. This is intended for clients that already speak TACACS+ directly and need a migration path onto the agent without using the gRPC IPC protocol.

Proxy mode is deliberately packet-transparent:

- Each accepted downstream connection is mapped to one upstream TACACS+ session.
- The downstream listener does not provide TACACS+ single-connection multiplexing.
- The proxy rejects a downstream connection if packets on that connection switch to a different TACACS+ session id.
- Packet bodies are forwarded unchanged. The proxy rewrites only the TACACS+ header session id so the downstream client's session id maps to the upstream session id selected by the networking layer.
- Accounting and authorization sessions close after one reply. Authentication sessions can continue across challenge replies and close when the reply status is terminal or unsupported.
- `FOLLOW` replies are forwarded to the downstream client, logged as unsupported in proxy mode, and then the connection is closed.

Proxy TCP endpoints must be loopback addresses. Unix domain socket endpoints use the same `--socket-mode` value as the IPC listener. The proxy endpoint must be different from `--listen-endpoint`.

The downstream TACACS+ shared-secret behavior follows the upstream server selected for that connection. If the selected upstream server has a `shared-secret`, the proxy uses that secret to deobfuscate downstream packets and obfuscate replies. If the selected upstream server has no shared secret, downstream packets must be sent with the unencrypted flag. When configured upstream servers use different shared secrets, a reconnect or failover can select a server with a different downstream secret; keep upstream shared secrets identical when using proxy mode.

### Upstream Encryption

| Flag | Description |
|------|-------------|
| `-k, --shared-secret <KEY>` | Shared secret for TACACS+ packet obfuscation |
| `--use-tls` | Enable TLS 1.3 for upstream connections |
| `--client-certificate <FILE>` | PEM- or DER-encoded client TLS certificate (requires `--client-key`) |
| `--client-key <FILE>` | PEM- or DER-encoded client TLS private key (requires `--client-certificate`) |
| `--insecure-disable-certificate-verification` | Skip TLS cert verification |
| `--psk-identity <ID>` | TLS 1.3 pre-shared key identity *(requires `psk` feature)* |
| `--psk-key <KEY>` | TLS 1.3 pre-shared key *(requires `psk` feature)* |

### TLS Client Certificates and Keys

When `--use-tls` is set, `--client-certificate` and `--client-key` let the daemon present a TLS client identity to upstream TACACS+ servers.

- Provide both flags together.
- Both files may be PEM or DER. PEM input is detected at runtime and normalized to DER internally before the daemon builds its runtime connection settings.
- Windows "export with private key" workflows commonly produce PKCS#12 (`.pfx` / `.p12`) bundles. Those container formats are not accepted by these flags; provide PEM or DER certificate/key material instead.
- This PEM-or-DER behavior applies only to the CLI flags. If upstream TLS material is loaded through `--config`, the YANG-backed `tacacsrs-config` path remains DER-only.

### Timeouts and Failover

| Flag | Default | Description |
|------|---------|-------------|
| `--connect-timeout-seconds <SECS>` | `5` | Timeout for upstream TACACS+ connections |
| `--preferred-probe-interval-seconds <SECS>` | `30` | How often to check if the preferred server has recovered |

### Debugging

| Flag | Description |
|------|-------------|
| `-v` | Warnings |
| `-vv` | Info |
| `-vvv` | Debug |
| `-vvvv` | Trace |

## Failover Behaviour

Servers are tried in the order they are specified. The first server (`--server-addr` index 0) is always the preferred server.

### State Transitions

```
              startup
                │
                ▼
        ┌────────────────┐
        │ PreferredActive│◄──── probe succeeds
        │   (server 0)   │
        └───────┬────────┘
                │ connection fails
                ▼
        ┌────────────────┐
        │  FailedOver    │──── try server 1, 2, ...
        │  (server N)    │
        └───────┬────────┘
                │ all servers fail
                ▼
        ┌───────────────────┐
        │ NoResponsiveServer│
        │ (returns error)   │──── requests get retriable error
        └───────────────────┘
```

### Preferred Server Recovery

While failed over to a backup server, the daemon periodically probes the preferred server (index 0) at the configured interval. When a probe succeeds, traffic is automatically routed back to the preferred server.

### Reconnect Behaviour

When multiple IPC requests arrive simultaneously during a reconnect, only one connection attempt runs per server. Other callers wait for the result rather than triggering duplicate TLS handshakes.

## Startup Warm-up

On startup the daemon attempts to connect to servers in order and stops at the first success. This prevents connection storms when many instances start simultaneously (e.g. during a fleet rollout). If no server is reachable at startup, the daemon still starts and requests will retry on demand.

## IPC Protocol

The daemon communicates with clients via gRPC over Unix domain sockets (Linux) or loopback TCP (other platforms). The protocol is defined in protobuf:

**Available RPCs:**

| RPC             | Description                          |
|-----------------|--------------------------------------|
| `Accounting`    | Record user activity (unary)         |
| `Authorization` | Check command authorization (unary)  |

**Error responses** include a `retriable` flag. When `true`, the client should retry the request — this typically means the daemon is reconnecting to a different upstream server.

The optional TACACS+ proxy endpoint is separate from IPC. It accepts raw TACACS+ packets and is configured with `--proxy-endpoint`.

## Deployment Examples

### Systemd Service

```ini
[Unit]
Description=TACACS+ Agent Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tacacsrs-agentd \
    --server-addr tacacs1.example.com:49 \
    --server-addr tacacs2.example.com:49 \
    --listen-endpoint /run/tacacs/tacacs.sock \
    --socket-mode 660 \
    --shared-secret "shared_secret" \
    --preferred-probe-interval-seconds 30
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### With TLS

```bash
tacacsrs-agentd \
    --server-addr tacacs1.example.com:449 \
    --server-addr tacacs2.example.com:449 \
    --use-tls \
    --client-certificate /etc/tacacs/client.crt.pem \
    --client-key /etc/tacacs/client.key.pem \
    --listen-endpoint /run/tacacs/tacacs.sock
```

DER input is also supported for the same flags:

```bash
tacacsrs-agentd \
    --server-addr tacacs1.example.com:449 \
    --server-addr tacacs2.example.com:449 \
    --use-tls \
    --client-certificate /etc/tacacs/client.crt.der \
    --client-key /etc/tacacs/client.key.der \
    --listen-endpoint /run/tacacs/tacacs.sock
```

### Multiple Servers with Fast Failover

```bash
tacacsrs-agentd \
    --server-addr primary.dc1.example.com:49 \
    --server-addr secondary.dc1.example.com:49 \
    --server-addr primary.dc2.example.com:49 \
    --connect-timeout-seconds 3 \
    --preferred-probe-interval-seconds 15 \
    --shared-secret "shared_secret" \
    --listen-endpoint /run/tacacs/tacacs.sock \
    -vv
```

### Local TACACS+ Proxy

```bash
tacacsrs-agentd \
    --server-addr tacacs1.example.com:49 \
    --server-addr tacacs2.example.com:49 \
    --listen-endpoint /run/tacacs/tacacs.sock \
    --proxy-endpoint /run/tacacs/tacacs-proxy.sock \
    --socket-mode 660 \
    --shared-secret "shared_secret"
```

On non-Linux development hosts, use a loopback TCP proxy endpoint:

```bash
tacacsrs-agentd \
    --server-addr 192.0.2.20:49 \
    --listen-endpoint 127.0.0.1:9049 \
    --proxy-endpoint 127.0.0.1:9050 \
    --shared-secret "shared_secret"
```

### Loading a YANG JSON config

```bash
tacacsrs-agentd \
    --config /etc/tacacs/tacacs.json \
    --listen-endpoint /run/tacacs/tacacs.sock
```

When `--config` is used, upstream server definitions are loaded from the `ietf-system-tacacs-plus` RFC 7951 JSON document instead of repeated `--server-addr` flags.

## Connection Reuse

The daemon maintains persistent upstream connections and multiplexes TACACS+ sessions over them. This avoids TCP/TLS handshake overhead for every request. When a connection can no longer accept new sessions (e.g. the server does not support single-connect mode), the daemon transparently reconnects.
