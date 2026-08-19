# tacacsrs-agentd — Central TACACS+ Service

`tacacsrs-agentd` is a long-running daemon. It maintains persistent TACACS+ connections to one or more upstream servers and exposes a local IPC interface for clients like [tacon](tacon.md). It handles connection pooling, session multiplexing, and ordered failover automatically.

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
    accounting --user admin --port tty0 --rem-addr 10.0.0.1 \
    "show version"
```

## Command-Line Options

### Upstream Servers (required)

| Flag | Description |
|------|-------------|
| `--server-addr <ADDR>` | TACACS+ server address (repeatable, ordered by preference). First entry is the preferred server. |
| `--config <FILE>` | Load upstream server definitions from a YANG JSON configuration file |

### IPC Listener

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-endpoint <ENDPOINT>` | `/run/tacacs/tacacs.sock` | Unix domain socket path (Linux) or TCP address (other platforms) |
| `--proxy-endpoint <ENDPOINT>` | *(disabled)* | Optional TACACS+ proxy listener on a Unix domain socket path or loopback TCP address |
| `--service-mode <MODE>` | `client-api`, or `both` when `--proxy-endpoint` is set | Runtime services to host: `client-api`, `tacacs-proxy`, or `both` |
| `--socket-mode <MODE>` | `660` | File permission mode for the Unix domain socket (octal) |
| `--host-integration <MODE>` | `auto` | Host adapter: `auto`, `none`, or strict `systemd` |

### Runtime Service Modes

`tacacsrs-agentd` can host the typed local client API, the raw TACACS+ proxy, or both services in one process:

| Mode | Services hosted | Required endpoint flags |
|------|-----------------|-------------------------|
| `client-api` | gRPC/protobuf client API only | `--listen-endpoint` optional, defaults to the platform local endpoint |
| `tacacs-proxy` | raw TACACS+ proxy only | `--proxy-endpoint` required |
| `both` | client API and raw TACACS+ proxy | `--proxy-endpoint` required, `--listen-endpoint` optional |

If `--service-mode` is omitted, the daemon preserves the old behavior: it runs `client-api` by default, and switches to `both` when `--proxy-endpoint` is supplied. Configurations with no hosted services are rejected.

### TACACS+ Proxy Mode

When the TACACS+ proxy service is enabled, `tacacsrs-agentd` accepts local TACACS+ client connections and presents itself like a TACACS+ server. This is intended for clients that already speak TACACS+ directly and need a migration path onto the agent without using the gRPC IPC protocol.

For a host-by-host cutover plan from plain TACACS+ clients such as `pam_tacplus` or `audisp-tacplus`, see the [Plain TACACS+ to TACACS+ over TLS Transition Guide](tacacs-plus-tls-transition.md).

Proxy mode preserves TACACS+ packet bodies while managing session routing:

- A downstream connection can carry multiple concurrent TACACS+ session IDs.
- Each downstream session owns one sequential upstream conversation with independent sequence validation.
- Different sessions can receive replies out of request order. One downstream writer serializes the resulting packets onto the TCP stream.
- Per-session input and connection reply queues are bounded to apply backpressure.
- Packet bodies are forwarded unchanged. The proxy rewrites only session IDs and the locally advertised single-connect flag.
- The proxy advertises single-connect support based on its own downstream multiplexer, not the selected upstream server's flag.
- Accounting and authorization conversations close after one reply. Authentication conversations continue across challenge replies and close when the reply status is terminal.
- `FOLLOW` replies are forwarded to the downstream client and complete that session. Per RFC 8907, authorization and accounting `FOLLOW` use the authentication `FOLLOW` behavior. Authentication `FOLLOW` is treated like `FAIL`.
- Authentication `RESTART` replies are forwarded and complete that session. A restarted sequence uses a new session ID and sequence number 1, as required by RFC 8907. The downstream TCP connection can remain open.

Proxy TCP endpoints must be loopback addresses. Unix domain socket endpoints use the same `--socket-mode` value as the IPC listener. When `client-api` and `tacacs-proxy` run together, the proxy endpoint must be different from `--listen-endpoint`.

Downstream TACACS+ obfuscation is independent of the selected upstream transport. In SONiC mode, the daemon filters rows that target its loopback proxy.

The daemon uses the highest-priority row's resolved `passkey` for the local hop. Outside SONiC mode, use `--proxy-shared-secret`.

If neither source provides a local-hop secret, downstream clients must send unobfuscated TACACS+ packets. Upstream failover never changes the downstream shared secret.

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
| `--psk-key-exchange <MODE>` | Select `psk-dhe` or explicit `psk-only` interoperability mode *(requires `psk` feature)* |
| `--psk-key-exchange-groups <GROUP[,GROUP...]>` | Comma-separated PSK-DHE supported groups in preferred order, for example `secp384r1,secp256r1` *(requires `psk` feature)* |

### TLS Client Certificates and Keys

When `--use-tls` is set, `--client-certificate` and `--client-key` let the daemon present a TLS client identity to upstream TACACS+ servers.

- Provide both flags together.
- Both files can be PEM or DER. The daemon detects PEM input and converts it to DER before it builds the runtime connection configuration.
- Windows "export with private key" workflows commonly produce PKCS#12 (`.pfx` / `.p12`) bundles. Those container formats are not accepted by these flags. Provide PEM or DER certificate and private-key material instead.
- This PEM-or-DER behavior applies only to the CLI flags. If upstream TLS material is loaded through `--config`, the YANG-backed `tacacsrs-config` path remains DER-only.

### Timeouts and Failover

| Flag | Default | Description |
|------|---------|-------------|
| `--connect-timeout-seconds <SECS>` | `5` | Timeout for upstream TACACS+ connections |
| `--runtime-policy <FILE>` | none | Optional live JSON policy for failover and request limits |

### Debugging

| Flag | Description |
|------|-------------|
| `-v` | Warnings |
| `-vv` | Info |
| `-vvv` | Debug |
| `-vvvv` | Trace |

## Failover Behavior

The server configuration order sets the preference order. Each operation uses
only servers that declare support for that operation.

Authentication, authorization, and accounting have independent routing
cursors. IPC and proxy requests share the cursor for a given operation.

Each server has a separate connection for each operation. Therefore, an
authorization connection failure does not close authentication or accounting
sessions.

### State Transitions

```
preferred route
      |
      | retryable operation failure
      v
open circuit and select the next eligible server
      |
      | recovery interval expires
      v
allow one real operation as a recovery trial
      |
      +-- success --> restore the higher-priority route
      |
      +-- failure --> reopen the circuit
```

### Failover Strategies

The default strategy is `deferred-failover`. The current request returns its
failure. The next request uses the next eligible server.

The `ordered-safe-retry` strategy can try the next eligible server during the
current request. These replay rules always apply:

- A denial is a valid response and does not cause failover.
- A server `ERROR` reply can use the next server.
- Authentication and authorization can use the next server after an uncertain transport failure.
- Accounting does not retry after an uncertain transport failure.
- A continuing authentication session stays on the server that sent its first valid reply.

### Preferred Server Recovery

The daemon does not use a cross-operation probe. After the recovery interval,
one real request tests a higher-priority server. Other requests continue to use
the active fallback during this trial.

### Reconnect Behavior

One connection attempt runs for each server and operation. Concurrent callers
share its result instead of starting duplicate TLS handshakes.

## Startup Warm-up

The daemon creates operation connections on first use. It does not send an
accounting watchdog to test authentication or authorization routes.

## Runtime Policy

The optional policy file contains no credentials. The daemon watches the file
and atomically applies each valid update. An invalid update leaves the
last-known-good policy active and marks runtime health as degraded.

An omitted field uses its safe default. This example enables same-request
failover for both local services:

```json
{
  "failover-recovery-interval-seconds": 30,
  "client-api-failover-strategy": "ordered-safe-retry",
  "tacacs-proxy-failover-strategy": "ordered-safe-retry",
  "authentication": {
    "max-body-length": 4096,
    "max-concurrent-requests": 64
  },
  "authorization": {
    "max-body-length": 16384,
    "max-concurrent-requests": 64
  },
  "accounting": {
    "max-body-length": 16384,
    "max-concurrent-requests": 64
  }
}
```

Each operation has one packet-size limit and one concurrency limit. IPC and
proxy clients share that capacity. A request waits for capacity for no longer
than the active server timeout.

SONiC ConfigDB is supervised differently from local CLI or file input. Before constructing the service, the daemon waits for a valid `TACPLUS_FORWARDER|global` row and uses its loopback address and port for the raw TACACS+ proxy listener. SONiC mode always hosts both the Client API and proxy. A conflicting `--proxy-endpoint` or non-`both` service mode is rejected. Ctrl-C or SIGTERM cancels this pre-bind retry.

After forwarder bootstrap, the daemon binds both listeners with an empty upstream configuration and reports startup and readiness as not serving. It then retries server and credential dependencies with capped jittered backoff. Each candidate is loaded, filtered, bundle-enumerated, completely resolved through the SONiC provider, materialized into generated inline server fields, and validated before one atomic apply. A missing provider root or object therefore cannot apply a partial server list.

When Redis and every referenced credential become available, the same process applies the first complete snapshot and becomes ready. Subscription failures and ended streams trigger a fresh load before resubscription. Invalid ConfigDB or credential candidates leave the previous known-good runtime configuration active and mark health degraded. The reload-safe provider reopens the root for each candidate. This lets a credential mount that appears after startup, or an explicitly replaced provider root, recover without a process restart.

The daemon validates forwarder changes against the same complete ConfigDB snapshot as live upstream changes. Server and credential updates continue to apply.

Changes to the forwarder configuration do not change active endpoints. Instead, the daemon reports a sanitized, restart-required degradation.

The daemon clears this degradation after the bound values return. It rejects malformed rows without reporting a listener change.

## Health and Probes

The Client API endpoint also serves the standard `grpc.health.v1.Health` protocol. No custom health protobuf or additional network listener is used.

| Service name | Meaning |
|---|---|
| `tacacsrs.agent.health.v1.Startup` | A validated snapshot is applied and every enabled listener is bound |
| `tacacsrs.agent.health.v1.Liveness` | The process is starting or serving and the Client API can answer |
| `tacacsrs.agent.health.v1.Readiness` | Startup is complete and at least one eligible upstream is configured |
| *(empty service name)* | Same as readiness |
| `tacacsrs.agent.v1.TacacsAgent` | Same as readiness for the business RPC service |

Current upstream reachability is diagnostic and does not gate readiness or liveness. During shutdown all names become `NOT_SERVING` before listeners stop accepting work.

Use the packaged probe for Kubernetes exec probes and local diagnostics:

```bash
tacacsrs-agent-health \
    --endpoint /run/tacacs/tacacs.sock \
    --check readiness \
    --timeout-seconds 2
```

| Exit code | Meaning |
|---|---|
| `0` | The selected health name is `SERVING` |
| `1` | The selected health name is not serving or unknown |
| `2` | Probe invocation or endpoint syntax is invalid |
| `3` | Endpoint, timeout, transport, or protocol failure |

The health endpoint exists only when `client-api` is enabled. A proxy-only process still publishes runtime state to logs and systemd but cannot use this gRPC probe.

## Host Integration

`--host-integration auto` selects systemd only when `NOTIFY_SOCKET` is present. `none` never invokes a host API and is the container setting. Explicit `systemd` requires both `NOTIFY_SOCKET` and `systemd-notify`. Missing prerequisites and runtime notification failures are fatal. Systemd receives a waiting status before readiness, `READY=1` exactly once, sanitized degraded status updates, and `STOPPING=1` before listener drain.

## IPC Protocol

The daemon communicates with clients through gRPC over Unix domain sockets (Linux) or loopback TCP (other platforms). The protobuf file defines the protocol:

**Available RPCs:**

| RPC             | Description                          |
|-----------------|--------------------------------------|
| `AuthenticatePap` | Authenticate one username/password pair with fixed PAP |
| `Accounting`    | Record user activity (unary)         |
| `Authorization` | Authorize a command (unary)  |

Typed authentication intentionally exposes PAP only. Interactive ASCII remains
available through the raw TACACS+ proxy. Authorization requests carry explicit
ASCII, PAP, or unauthenticated context. Shell-session profile retrieval uses
`service=shell` with an empty `cmd` value.

**Error responses** include a `retriable` flag. When this flag is set, the client can retry the request.

A `true` value usually means that the daemon is reconnecting to a different upstream server.

The optional TACACS+ proxy endpoint is separate from IPC. It accepts raw TACACS+ packets and is configured with `--proxy-endpoint`.

## Deployment Examples

### Systemd Service

```ini
[Unit]
Description=TACACS+ Agent Service
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=all
ExecStart=/usr/local/bin/tacacsrs-agentd \
    --server-addr tacacs1.example.com:49 \
    --server-addr tacacs2.example.com:49 \
    --listen-endpoint /run/tacacs/tacacs.sock \
    --socket-mode 660 \
    --host-integration systemd \
    --shared-secret "shared_secret" \
    --runtime-policy /etc/tacacs/runtime-policy.json
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
    --runtime-policy /etc/tacacs/runtime-policy.json \
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

For proxy-only deployments, select the proxy service explicitly:

```bash
tacacsrs-agentd \
    --server-addr tacacs1.example.com:49 \
    --server-addr tacacs2.example.com:49 \
    --service-mode tacacs-proxy \
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

### Loading a YANG JSON configuration

```bash
tacacsrs-agentd \
    --config /etc/tacacs/tacacs.json \
    --listen-endpoint /run/tacacs/tacacs.sock
```

When `--config` is used, upstream server definitions are loaded from the `ietf-system-tacacs-plus` RFC 7951 JSON document instead of repeated `--server-addr` flags.

## Connection Reuse

The daemon maintains persistent upstream connections and multiplexes TACACS+ sessions over them. This avoids TCP/TLS handshake overhead for every request. When a connection can no longer accept new sessions, for example because the server does not support single-connect mode, the daemon reconnects automatically.
