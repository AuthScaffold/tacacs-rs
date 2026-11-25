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

### Configuration Source (one required)

Exactly one configuration source selector (`--server-addr`, `--config`, `--sonic`, or `--kubesonic`) is required.

| Flag | Description |
|------|-------------|
| `--server-addr <ADDR>` | TACACS+ server address (repeatable, ordered by preference). The first entry is the preferred server. |
| `--config <FILE>` | Load upstream server definitions from a YANG JSON configuration file |
| `--sonic` | Load TACACS+ upstream servers and local forwarder configuration from SONiC ConfigDB |
| `--sonic-redis-url <URL>` | Override the SONiC ConfigDB Redis URL (requires `--sonic`; default `unix:///var/run/redis/redis.sock?db=4`) |
| `--sonic-redis-db <INDEX>` | Override the SONiC ConfigDB database index (requires `--sonic`; default `4`) |
| `--kubesonic` | Load KubeSONiC ConfigDB server rows and `TACACSD_` environment inputs (exclusive; cannot be combined with other CLI flags) |

### IPC Listener

| Flag | Default | Description |
|------|---------|-------------|
| `--local-services <FILE>` | none | Startup YANG listener resource, exclusive with listener flags and SONiC mode |
| `--listen-endpoint <ENDPOINT>` | `/run/tacacs/tacacs.sock` | Absolute Unix domain socket path |
| `--proxy-endpoint <ENDPOINT>` | *(disabled)* | Absolute Unix socket path or numeric IP socket address |
| `--service-mode <MODE>` | `client-api`, or `both` when `--proxy-endpoint` is set | Runtime services to host: `client-api`, `tacacs-proxy`, or `both` |
| `--socket-mode <MODE>` | `660` | File permission mode for the Unix domain socket (octal) |
| `--proxy-credential-source <SOURCE>` | `unobfuscated`, `inline` with a CLI secret, or `local-proxy-row` in SONiC mode | Canonical downstream credential source |
| `--proxy-shared-secret <SECRET>` | none | Nonempty inline downstream secret. Requires a proxy endpoint and conflicts with SONiC mode. |
| `--worker-threads <COUNT>` | `1` | Tokio worker threads. TACACS+ requests are small and I/O bound, so extra workers mainly add cross-thread task migration. |
| `--host-integration <MODE>` | `auto` | Host adapter: `auto`, `none`, or strict `systemd` |

### Runtime Service Modes

`tacacsrs-agentd` can host the typed local client API, the raw TACACS+ proxy, or both services in one process:

| Mode | Services hosted | Required endpoint flags |
|------|-----------------|-------------------------|
| `client-api` | gRPC/protobuf client API only | `--listen-endpoint` optional, defaults to the platform local endpoint |
| `tacacs-proxy` | raw TACACS+ proxy only | `--proxy-endpoint` required |
| `both` | client API and raw TACACS+ proxy | `--proxy-endpoint` required, `--listen-endpoint` optional |

If `--service-mode` is omitted, the daemon preserves the old behavior: it runs `client-api` by default, and switches to `both` when `--proxy-endpoint` is supplied. Configurations with no hosted services are rejected.

### Canonical Listener Resource

Service selection, listener endpoints, ingress limits, and Unix socket permissions belong to `tacacsrs:local-services` under `ietf-system:system`.
The daemon normalizes listener flags into this generated YANG resource. It derives omitted values from the YANG defaults.
The service validates the same source for library callers before binding sockets.
Worker threads, verbosity, and host integration remain process bootstrap inputs, not listener configuration.

Example resource for `--local-services`:

```json
{
    "tacacsrs:local-services": {
        "client-api-enabled": true,
        "client-api-endpoint": "/run/tacacs/tacacs.sock",
        "tacacs-proxy-enabled": true,
        "tacacs-proxy-endpoint": "127.0.0.1:49",
        "unix-socket-mode": 432,
        "max-connections": 512,
        "max-client-api-streams": 64,
        "connection-lifetime-seconds": 300
    }
}
```

The default document is `{"tacacsrs:local-services":{}}`. It enables only the client API with permissions `0660`.
YANG JSON encodes permission bits as a decimal number from 0 through 511. The CLI `--socket-mode` input remains octal.
The resource file loads once at startup. A change to the file has no effect until the daemon starts again. A source that supplies local services at runtime, such as SONiC ConfigDB, can change the listeners without a restart.
It cannot be combined with listener flags, `--proxy-credential-source`, or `--sonic`.
In SONiC mode, the forwarder row supplies the proxy endpoint after startup. The proxy listener reports `Pending` until the first valid row arrives.

Each listener serves at most `max-connections` connections, with a generated default of 512. Further connections wait in the operating system's bounded listen backlog. The client API permits at most `max-client-api-streams` concurrent HTTP/2 streams on each connection, with a generated default of 64. Both limits accept integers from 1 through 65535. Client API protobuf request and response envelopes are limited to 128 KiB, including framing overhead relative to the TACACS+ body limit.

Each served connection expires after `connection-lifetime-seconds`, including setup, idle time, requests, and reply delivery.
The generated default is 300 seconds; zero is invalid. Clients must reconnect after expiry.
The lifetime applies even to active requests. Increase it when the deployment requires longer local connections.

All endpoint paths must be absolute. Unix paths cannot contain NUL, parent traversal, or more than 107 bytes.
These rules apply even to a disabled client API endpoint. Relative paths previously accepted by the IPC parser are no longer valid listener inputs.
Preparation normalizes repeated separators and current-directory components to detect lexical Unix path collisions. It does not resolve filesystem symlinks.
Proxy TCP targets must use numeric addresses. IPv6 addresses require brackets. Port zero requests an ephemeral port.
Wildcard proxy addresses remain supported. Deployments must restrict access to trusted clients.

The resource also selects downstream credentials through `proxy-credential-source`:

| Value | Credential contract |
| --- | --- |
| `unobfuscated` | No secret is configured or inferred from upstream rows. This is the YANG default. |
| `inline` | `proxy-shared-secret` must contain a nonempty string. Matching upstream rows cannot override it. |
| `local-proxy-row` | A numeric TCP endpoint is required. The highest-priority matching upstream row must exist and contain a nonempty shared secret. |

An inline resource can contain these fields alongside its listener controls:

```json
{
    "tacacsrs:local-services": {
        "tacacs-proxy-enabled": true,
        "tacacs-proxy-endpoint": "127.0.0.1:49",
        "proxy-credential-source": "inline",
        "proxy-shared-secret": "replace-with-local-secret"
    }
}
```

CAUTION: Restrict access to files containing inline secrets. JSON serialization contains the configured secret, even though debug output is redacted.
CLI arguments can also appear in process listings. A protected resource file avoids placing the secret in the command line.
Changes to this startup resource, including inline secret rotation, require a restart.
With `local-proxy-row`, accepted upstream source updates can rotate the derived secret without changing the credential-source selection.
Existing downstream connections retain their captured credentials until they close. This change does not force credential revocation on established connections.

### TACACS+ Proxy Mode

When the TACACS+ proxy service is enabled, `tacacsrs-agentd` accepts local TACACS+ client connections and presents itself like a TACACS+ server. This is intended for clients that already speak TACACS+ directly and need a migration path onto the agent without using the gRPC IPC protocol.

For a host-by-host cutover plan from plain TACACS+ clients such as `pam_tacplus` or `audisp-tacplus`, see the [Plain TACACS+ to TACACS+ over TLS Transition Guide](tacacs-plus-tls-transition.md).

Proxy mode preserves TACACS+ packet bodies while managing session routing:

- A single-connect downstream connection can carry up to `max-proxy-sessions-per-connection` (default: 64) concurrent active TACACS+ session IDs; excess new sessions on that connection receive a local `ERROR` reply.
- Each downstream session owns one sequential upstream conversation with independent sequence validation.
- Different sessions can receive replies out of request order. One downstream writer serializes the resulting packets onto the TCP stream.
- Per-session input and connection reply queues are bounded to apply backpressure.
- The downstream read timeout equals the largest configured server timeout. The proxy closes an idle downstream connection when no packet arrives within this timeout. While any session on the connection waits for an upstream reply, the idle timeout does not apply, so a slow upstream server does not cause the proxy to drop the client. A packet that has started to arrive must always complete within the timeout.
- Packet bodies are forwarded unchanged. The proxy rewrites only session IDs and the locally advertised single-connect flag.
- The proxy advertises single-connect support based on its own downstream multiplexer.
- The downstream client and proxy negotiate single-connect mode in the first request and reply. Later packets on a negotiated single-connect stream can omit the flag without ending connection reuse.
- When the first packet on a downstream connection omits `TAC_PLUS_SINGLE_CONNECT_FLAG`, the proxy accepts only that session ID on the connection and closes the socket immediately after delivering the session's terminal reply.
- Accounting and authorization conversations close after one reply. Authentication conversations continue across challenge replies, release upstream concurrency capacity while waiting for the client's next `CONTINUE` packet, and close when the reply status is terminal.
- `FOLLOW` replies are forwarded to the downstream client and complete that session. Per RFC 8907, authorization and accounting `FOLLOW` use the authentication `FOLLOW` behavior. Authentication `FOLLOW` is treated like `FAIL`.
- Authentication `RESTART` replies are forwarded and complete that session. A restarted sequence uses a new session ID and sequence number 1, as required by RFC 8907. Single-connect downstream connections remain open for the restarted session, while non-single-connect connections close so the client opens a new connection.

Proxy TCP endpoints bind the configured address. On a host, use a loopback address to limit access to local clients.

In a bridge-network container, bind a wildcard address and publish the port only on the host loopback interface:

```yaml
command: ["--proxy-endpoint", "0.0.0.0:49"]
ports:
    - "127.0.0.1:49:49"
```

Other containers on the same Docker network can reach the wildcard listener. Use an isolated Docker network if other containers are untrusted.

Unix domain socket endpoints use the same `--socket-mode` value as the IPC listener. When both services run, their endpoints must be different.

Before publication, the shared loop filter checks upstreams on the proxy's configured TCP port.
It removes matching classic rows after downstream credential preparation and rejects matching TLS rows.
Wildcard listeners include current interface addresses and loopback destinations. IPv6 wildcard checks conservatively include dual-stack binding.
DNS failures, empty answers, unspecified destinations, and lookup timeouts reject the candidate instead of retaining an unchecked upstream.
The agent also guards each upstream connection after DNS resolution and before TCP connect.
It checks the connected socket again before any TLS handshake or TACACS+ bytes.
The TCP proxy registers its actual bound address before accepting clients, including the port selected by an ephemeral bind.
Wildcard checks refresh interface addresses and inspect the connected socket's local address.
While the TCP proxy is unbound or closed, new upstream connections fail closed. Disabled and Unix-only proxies do not restrict upstream TCP targets.
Cached clients retain the same live guard across reconnects and configuration reloads. These checks do not rewrite canonical configuration.

Downstream TACACS+ obfuscation is independent of the selected upstream transport. In SONiC mode, the daemon filters rows that target its loopback proxy.

SONiC mode always uses `local-proxy-row` from ConfigDB and rejects `--proxy-credential-source` and `--proxy-shared-secret` on the command line; the matching loopback row's mapped `passkey` supplies downstream material. Outside SONiC mode, downstream proxy traffic defaults to `unobfuscated`, `--proxy-shared-secret` selects `inline` policy unless an explicit `--proxy-credential-source` conflicts with it, and `--proxy-credential-source unobfuscated` keeps plaintext downstream traffic explicit.

This replaces the previous implicit local-row override and missing-secret fallback.
A missing row, missing secret, or empty secret rejects the candidate generation in row-derived mode.
Rejected updates retain the previous upstream set and downstream credentials, even if the candidate removed the local row.
Before the first valid generation, the proxy rejects connections without reading packets. It never substitutes unobfuscated traffic for unresolved credentials.
Upstream failover does not change downstream credentials. Source preparation publishes valid credential and upstream changes together.

If the proxy returns an `ERROR`, only the affected downstream session ends. Other sessions can continue on the same downstream connection. The [failover strategies](#failover-strategies) determine whether the proxy retries the request or returns an `ERROR` to the client.

TACACS+ has no general in-band request to drain a single-connect connection. Clearing the single-connect flag after negotiation has no effect. A server can reject new sessions with `ERROR` until active sessions finish, then close the TCP connection. A downstream client can also close its connection. If it closes at a packet boundary, the daemon logs a normal disconnect at the info level.

### Upstream Encryption

Inline upstream flags (`-k`/`--shared-secret`, `--use-tls`, `--client-certificate`, `--client-key`, `--insecure-disable-certificate-verification`, `--connect-timeout-seconds`, `--dedicated`, `--psk-identity`, `--psk-key`, `--psk-key-exchange`, and `--psk-key-exchange-groups`) apply only with `--server-addr` and are rejected with `--config`, `--sonic`, and `--kubesonic`. `--use-tls` conflicts with `-k`/`--shared-secret`, `--client-certificate` and `--client-key` require `--use-tls` and each other, and `--insecure-disable-certificate-verification` requires `--use-tls` and conflicts with `--psk-*`.

| Flag | Description |
|------|-------------|
| `-k, --shared-secret <KEY>` | Shared secret for TACACS+ packet obfuscation (requires `--server-addr`; conflicts with `--use-tls`) |
| `--use-tls` | Enable TLS 1.3 for upstream connections (requires `--server-addr`; conflicts with `--shared-secret`) |
| `--client-certificate <FILE>` | PEM client certificate chain or single DER certificate (requires `--server-addr`, `--use-tls`, and `--client-key`) |
| `--client-key <FILE>` | PEM- or DER-encoded client TLS private key (requires `--server-addr`, `--use-tls`, and `--client-certificate`) |
| `--insecure-disable-certificate-verification` | Skip upstream TLS certificate verification (requires `--server-addr` and `--use-tls`; conflicts with `--psk-*`) |
| `--psk-identity <ID>` | TLS 1.3 pre-shared key identity (requires `--server-addr`, `--use-tls`, and `--psk-key`) |
| `--psk-key <KEY>` | Standard base64-encoded TLS 1.3 pre-shared key (requires `--server-addr`, `--use-tls`, and `--psk-identity`) |
| `--psk-key-exchange <MODE>` | Select `psk-dhe` or explicit `psk-only` interoperability mode |
| `--psk-key-exchange-groups <GROUP[,GROUP...]>` | Comma-separated PSK-DHE supported groups in preferred order, for example `secp384r1,secp256r1` |
| `--dedicated` | Open a dedicated upstream connection per request instead of negotiating TACACS+ single-connection mode (requires `--server-addr`) |

### TLS Client Certificates and Keys

Without an explicit server port, TLS inputs now select port 300 instead of the previous CLI default of 49.
Legacy TCP still defaults to 49. Explicit configured ports are preserved.

When `--use-tls` is set, `--client-certificate` and `--client-key` let the daemon present a TLS client identity to upstream TACACS+ servers.

- Provide both flags together.
- Both files can be PEM or DER. The daemon detects PEM input and converts it to DER before it builds the runtime connection configuration.
- Windows "export with private key" workflows commonly produce PKCS#12 (`.pfx` / `.p12`) bundles. Those container formats are not accepted by these flags. Provide PEM or DER certificate and private-key material instead.
- This PEM-or-DER behavior applies only to the CLI flags. If upstream TLS material is loaded through `--config`, the YANG-backed `tacacsrs-config` path remains DER-only.

Certificate verification now checks the peer's DNS/IP SAN as well as certificate trust.
The expected identity is `domain-name` when configured, otherwise `address`. SNI selection is independent of that check.
Previously accepted CN-only or mismatched certificates now fail before TACACS+ traffic.
See [certificate peer identity](yang-config-guide.md#certificate-peer-identity) for the full identity-selection contract.

Configured CA trust and exact end-entity trust are now separate. Empty explicit trust bags fail before publication instead of selecting platform roots.
A rejected replacement leaves the previous prepared generation active.
See [certificate trust](yang-config-guide.md#certificate-trust) for exact-match renewal behavior and additive trust rules.

### Certificate Revocation

The daemon checks upstream server certificates against certificate revocation lists (CRLs). The global `tacacsrs:certificate-revocation` YANG container configures the policy. The daemon has no command-line flags for revocation. In KubeSONiC mode, the `TACACSD_REVOCATION_` environment variables set the same container. See [certificate revocation](yang-config-guide.md#certificate-revocation) for the leaves and an example.

Both the static or SONiC profile and the KubeSONiC profile select `RevocationComponent`. The component creates the `CrlVerifier` of [`tacacsrs-revocation`](../libraries/tacacsrs_revocation/README.md) and gives it to the agent. It also runs the "CRL revocation refresh" hosted service, which prefetches and refreshes allowed CRLs until shutdown. While `enforcement` is `disabled`, the component does no work.

The `enforcement` leaf selects one of these policies:

- `disabled` is the default. The daemon does not check revocation.
- `hard-fail` rejects the server when no valid current CRL is available.
- `soft-fail` accepts a validated CRL for `soft-fail-grace-seconds` after its `nextUpdate`. After that time, the daemon rejects the server. The grace never excuses a listed certificate or an invalid CRL.
- `warn-only` accepts the server and logs a warning when CRL evidence is unavailable. It still rejects a certificate that a valid CRL lists.

The daemon checks revocation only when it establishes a new certificate TLS connection. When the verifier needs a CRL, the handshake pauses and the verifier fetches the CRL within the connection timeout. The handshake then continues on the same socket. The daemon never closes an established connection because a CRL expires, a refresh fails, or a refreshed CRL lists the server. A policy-only change applies to future handshakes and retires no connection and no server.

The check applies only to CA-authenticated certificate TLS servers. Exact pinned end-entity trust and disabled `certificate-verification` skip the check. TCP and TLS-PSK servers are not affected.

`tacacsrs-agent-health statistics` reports these per-server counters next to `tls-revoked-certificates`:

| Counter | Recorded event |
| --- | --- |
| `revocation-evidence-waits` | A TLS handshake paused while the verifier obtained CRL evidence |
| `revocation-unverified-accepts` | A connection accepted without fresh CRL evidence under `soft-fail` or `warn-only` |
| `revocation-pinned-skips` | A connection to an exactly pinned peer that skipped the CRL check |

### Timeouts and Failover

| Flag | Default | Description |
|------|---------|-------------|
| `--connect-timeout-seconds <SECS>` | `5` | Timeout for upstream TACACS+ connections when `--server-addr` is used. It bounds the TCP connect and the TLS or PSK handshake together. |
| `--runtime-policy <FILE>` | none | Optional live JSON policy for failover and request limits |
| `--upstream-watchdog-interval-seconds <SECS>` | none (disabled) | Interval between upstream watchdog probes. See [Host Integration](#host-integration). |

### Operational Statistics

`--statistics-file FILE` publishes a read-only RFC 7951 JSON snapshot once per second.
The parent directory must already exist. Each write uses a private temporary file and atomic replacement, with mode `0600`.
The destination cannot be a configuration input, discovery certificate, or local listener socket. Symlink destinations are rejected.
No exporter runs when the flag is absent. An export error is a supervised failure and stops the daemon after normal cleanup.
The last complete report remains after shutdown; consumers must check process health or file age before treating it as current.

```json
{
    "ietf-system-tacacs-plus:tacacs-plus": {
        "tacacsrs:runtime-generation": "4",
        "server": [{
            "name": "primary",
            "tacacsrs:counter-epoch": "2",
            "statistics": {
                "discontinuity-time": "2026-10-14T12:00:00Z",
                "connection-opens": "1",
                "messages-sent": "2",
                "messages-received": "2",
                "sessions": "2"
            }
        }]
    }
}
```

The example omits other zero-valued counters. The actual report includes every supported counter.
All 64-bit counters and identities are JSON strings. RPK counters are omitted because raw-public-key authentication is disabled.
The file contains server names and statistics, not addresses, credential references, secrets, or command data.
It is operational data, not a configuration file. Configuration parsing rejects it.

Counters belong to prepared endpoint identities. Unchanged endpoints retain their epoch across configuration and policy reloads.
Replacements receive a new epoch and discontinuity time. Removed endpoints leave the current report.
Late events from an old endpoint update only its old counter owner, never the replacement.
The report captures one routing generation. Each server snapshot is coherent, but different servers are not sampled at one global instant.

| Counter | Recorded event |
| --- | --- |
| `connection-opens` | A logical establishment request for the configured server, including DNS and address selection |
| `connection-failures` | An unsuccessful or cancelled establishment request |
| `connection-timeouts` | A native configured connection-timeout failure; caller cancellation is a failure without a timeout classification |
| `connection-closes` | Clean EOF or successful transport shutdown, recorded once when the transport closes |
| `connection-aborts` | Forced closure, transport error, or failed/cancelled setup after TCP connects |
| `messages-sent` | One fully written TACACS+ packet; queued or partial writes do not count |
| `messages-received` | One complete, decoded packet frame; truncated or invalid frames do not count |
| `errors-received` | A valid protocol `ERROR` reply, not an ordinary denial |
| `sessions` | A validated terminal response, once per client session; abandoned or incomplete conversations do not count |
| `cert-errors` | Establishment failures identified by local certificate or revocation verification |

Single-connect negotiation and configured preflight traffic are included. IPC and proxy operations share the same per-endpoint counters.
Counters wrap at 64 bits and are never reset in place. A new epoch marks a counter-lifetime discontinuity, not an ordinary counter wrap.
Atomic replacement prevents partial reports but does not make filesystem I/O hard-cancellable. Temporary cleanup is best effort if underlying I/O outlives cancellation.

### Debugging

| Flag | Description |
|------|-------------|
| `-v` | Warnings |
| `-vv` | Info |
| `-vvv` | Debug |
| `-vvvv` | Trace |

## Failover behavior

Each operation (authentication, authorization, or accounting) has its own active route and its own circuit on each server. The route contains only servers that support the operation, in configuration order. IPC and proxy requests share that route. Each server has one cached upstream connection, and all three operations use it. With single-connect, sessions of every operation share that connection.

### State transitions

A closed circuit lets a server receive new sessions. A failed connection attempt, an upstream `ERROR`, or a timeout during an upstream exchange opens the circuit for that operation only. If the failed server was active, the operation's route advances one position. After an `ERROR` or a timeout, the shared connection stays open, because the other operations can still be healthy on that server. A downstream disconnect alone leaves the circuit unchanged.

A lost connection or a truncated reply is a transport fault. The routed client discards the shared connection for all operations. If the connection already completed a valid exchange for any operation, the circuit stays closed. The next session of each operation reconnects to the same server, and the operations share the new connection. The session that was in progress on the lost connection fails. The circuit opens only if the reconnect fails, the server times out, or the server returns `ERROR`. A transport fault on a connection that has not completed a valid exchange opens the circuit, so a server that accepts connections and then drops them cannot keep traffic. This rule also applies when another session has already replaced the failed connection. The late report does not close the replacement connection. It opens the circuit for its operation unless the failed connection or a newer connection to the same server has completed a valid exchange.

For each new binding, the routed client tries each eligible server at most once across three passes:

1. **Recovery trial.** In configuration order, the client tries open circuits whose `failover-recovery-interval-seconds` has elapsed (default: 30 seconds). Each circuit allows one recovery trial at a time.
2. **Healthy servers.** The client tries closed circuits from the active position and wraps to the start of the route. The first server that connects becomes active.
3. **Last resort.** If neither pass found a connection, the client tries the remaining open circuits from the active position, without waiting for recovery.

A connection failure in any pass opens that server's circuit or keeps it open, and selection continues within the same call. If another server connects and answers in time, the downstream client receives its reply. Concurrent callers share a connection attempt for the same server, whatever their operations. After a successful exchange on a recovery trial or last-resort binding, the circuit closes. That server becomes active if it comes before the active server in configuration order, or if the active server's circuit is open.

Each operation attempt makes a new binding. A later binding can revisit an endpoint, including a due recovery trial. The attempt budget does not guarantee one attempt per endpoint. With one upstream, later requests can use that upstream through the last-resort pass without a recovery delay.

### Connection sharing and retirement

An operation that moves to a server with an open connection uses that connection. It does not open a second one. The routed client retires a server's connection when no operation's route has that server active and no session holds the connection. A retired connection refuses new sessions and closes after its active sessions finish.

For example, the configuration lists A, then B:

- **Authorization receives `ERROR` on A.** Authorization moves to B and opens one connection to B. Authentication and accounting keep using the connection to A.
- **Accounting then receives `ERROR` on A.** Accounting moves to B and uses the existing connection to B.
- **A recovers.** A recovery trial for authorization succeeds on A's existing connection, and authorization returns to A. Accounting returns after its own trial. When no operation uses B and its last session ends, the connection to B closes.
- **A shuts down.** Each operation finds out separately, when its next session fails to reach A. Each one then moves to B, and all three share one connection to B. B receives one connection from each proxy.

### Failover strategies

Under [RFC 8907 section 4.4](https://www.rfc-editor.org/rfc/rfc8907#section-4.4), an `ERROR` status means the server did not finish the request. The client must treat the server as unreachable and can try a backup. A denial is a completed decision and leaves the route unchanged.

The `tacacs-proxy-failover-strategy` policy controls how the proxy handles the first packet of a session:

- `deferred-failover` (default) allows one first-packet attempt. The proxy forwards an upstream `ERROR`. The next session uses the updated route.
- `ordered-safe-retry` retries on the next eligible server after a first-packet `ERROR` or proven non-delivery. The attempt budget equals the number of eligible servers. If the last attempt returns `ERROR`, the proxy forwards it. A timeout after transmission or a lost reply leaves the outcome unknown. The proxy stops because replay can duplicate accounting records or affect audit or lockout state.

After an authentication challenge, the session stays on the server that sent the challenge. Under either strategy, the proxy forwards a later `ERROR`. If the proxy has no upstream reply to forward, it sends a local `ERROR`. An upstream failure ends only the affected session. Other sessions can continue on the same downstream connection.

For a connection-related `ERROR` in single-connect mode, section 4.4 says that the client must not start new sessions on that connection, and must close it after its active sessions finish. The proxy applies this rule per operation. It stops new sessions of the failed operation on that server, and keeps the shared connection open for the other operations. This is a deliberate trade-off. An `ERROR` often comes from one request type or one request's content, and closing the connection would move every operation to the backup at once. If the server is down for every operation, each operation fails over when its own sessions fail. When a retired connection closes and the connector takes more than one second to initiate retirement, the routed client forces closure. Sessions that have already started to drain have no separate one-second cutoff.

[RFC 8907 section 3.6](https://www.rfc-editor.org/rfc/rfc8907#section-3.6) also calls for `ERROR` for an unsupported or unrecognized option. The status alone cannot distinguish this case from a server fault. One such request can therefore move its operation to a backup.

### Preferred server recovery

A recovery trial uses a real request and takes priority over a healthy server. While the trial runs, other requests can use the active server. If the trial server refuses the connection, the same request continues to the next candidate. If the trial server accepts the connection but returns `ERROR`, drops the reply, or times out, the recovery interval starts again.

While a healthy server remains available, each persistently unhealthy server can cost about one failed trial request per operation per recovery interval. With deferred failover, the client receives `ERROR` for that exchange. With ordered safe retry, a backup can answer a first-packet `ERROR`. Neither strategy replays a request after a lost reply or a timeout after transmission.

### Server selection scenarios

The examples describe new proxy sessions. If a slow server answers before both the server timeout and the request deadline, it still counts as healthy. The proxy does not compare response times. In the [runtime policy](#runtime-policy), `request-timeout-seconds` sets the total budget for each operation (default: 30 seconds). Admission, connection setup, retries, and authentication continuations share that budget. A shorter server timeout can end an exchange earlier.

| Eligible servers | Where requests go | What the client sees |
| --- | --- | --- |
| One healthy or slow server | Every request uses that server. | The client waits for its reply. |
| One unhealthy server | The next request tries the same server immediately. Before the recovery interval expires, it uses the last-resort pass. | A refusal produces a local `ERROR`. If the server accepts but never replies, each exchange waits until its timeout or deadline. |
| Two responsive servers (fast or slow) | The first server stays active while it answers in time. A faster backup does not attract traffic. | The active server determines the response time. |
| One healthy server and one unhealthy server | If the healthy server is active, it keeps new sessions. If the other server fails first, the healthy server takes over. | A refusal can be invisible to the client. A failure after connection follows the [failover strategy](#failover-strategies). |
| One slow server and one unhealthy server | The slow server keeps new sessions between recovery trials as long as it answers in time. | The client waits for the slow reply. If that server also times out, both servers now have open circuits. |
| Three or more servers, some responsive | Selection skips failed servers between recovery trials. The first responsive server on the active route keeps traffic. | The client receives that server’s reply. Only recovery trials revisit failed servers while a healthy route remains available. |
| Two or more servers, all unhealthy | Each new session tries due recovery trials, then any remaining servers as a last resort. Selection stops at the first connection. | The proxy forwards the final upstream `ERROR`. Without a reply, it sends a local `ERROR`. A session can fail before every server receives a packet. |

For example, the configuration lists A, B, then C. A returns `ERROR`, B accepts the request but times out, and C is healthy. Assume that no recovery trial is due yet. With deferred failover, the first session receives A’s `ERROR`, the second receives a local `ERROR` after B’s timeout, and the third uses C. With ordered safe retry, the first session retries on B after A’s `ERROR` and stops at B’s timeout. The next session uses C.

In both cases, new sessions stay on C between recovery trials. If A’s recovery interval expires during B’s timeout, A can receive a trial before C serves its first request.

## Startup Warm-up

The daemon creates server connections on first use by default. When a server enables `single-connection`, concurrent sessions wait for the first reply on the new connection before multiplexing onto that connection or falling back to dedicated connections. Set `connect-preflight` to `accounting-watchdog` in the [runtime policy](#runtime-policy) to send an accounting `WATCHDOG` probe when opening an accounting-capable upstream client; any valid accounting reply proves transport reachability and discovers single-connection support ahead of user traffic.

The optional periodic upstream watchdog acts as an in-process client and submits accounting `WATCHDOG` records. It uses normal client API admission, request deadlines, retry policy, and networking recovery. The watchdog does not select endpoints or change circuits itself. It does not test authentication or authorization routes.

## Runtime Policy

The optional policy file contains a `tacacsrs:runtime-policy` YANG resource with no credentials. The daemon watches the file
and atomically applies each valid update. An invalid update leaves the
last-known-good policy active and marks runtime health as degraded.

An omitted field uses its generated YANG default. This example enables same-request
failover for both local services:

```json
{
    "tacacsrs:runtime-policy": {
        "shutdown-timeout-seconds": 30,
        "source-stale-timeout-seconds": 300,
        "credential-stale-timeout-seconds": 300,
        "failover-recovery-interval-seconds": 30,
        "max-upstream-packets-per-second": 512,
        "max-packet-body-length": 65536,
        "max-proxy-sessions-per-connection": 64,
        "client-api-failover-strategy": "ordered-safe-retry",
        "tacacs-proxy-failover-strategy": "ordered-safe-retry",
        "connect-preflight": "disabled",
        "authentication": {
            "max-body-length": 4096,
            "max-concurrent-requests": 64,
            "max-packets-per-second": 128,
            "request-timeout-seconds": 30
        },
        "authorization": {
            "max-body-length": 16384,
            "max-concurrent-requests": 64,
            "max-packets-per-second": 256,
            "request-timeout-seconds": 30
        },
        "accounting": {
            "max-body-length": 16384,
            "max-concurrent-requests": 64,
            "max-packets-per-second": 512,
            "request-timeout-seconds": 30
        }
  }
}
```

This replaces the old flat policy JSON format. Wrap existing fields in `tacacsrs:runtime-policy` before upgrading.
The default document is `{"tacacsrs:runtime-policy":{}}`; a bare `{}` is no longer accepted.
Unknown fields, trailing JSON, zero intervals, zero packet rates, zero body or session limits, and operation body limits that exceed `max-packet-body-length` are rejected.
Recovery seconds, packet rates, body lengths, and concurrent-request limits are unsigned 32-bit values; `max-proxy-sessions-per-connection` is an unsigned 16-bit value.
An omitted operation or field uses the corresponding YANG default, including authentication's smaller body and packet-rate limits. `max-packet-body-length` (default: 65536) bounds raw frame allocations on downstream proxy connections and upstream server replies, and updates apply at runtime.

The resource is defined by the [project YANG augmentation](../libraries/tacacsrs_config/yang/modules/tacacsrs@2026-11-25.yang) under `ietf-system:system`.
It is a sibling of the upstream `tacacs-plus` resource, not a field inside the server list.
The policy file remains an independently watched resource. Policy and server changes use the shared runtime-generation publication boundary.

`shutdown-timeout-seconds` bounds graceful teardown and defaults to 30 seconds. Its minimum is one second.
The daemon captures the applied value when cleanup begins. Service drain and both peer tasks share that absolute deadline.
Sequential cleanup steps do not receive new budgets, and policy changes cannot extend cleanup already in progress.

`source-stale-timeout-seconds` limits continued use of stale source configuration. Its default is 300 seconds and its minimum is one second.
After the first observed stale-source condition, retries, credential refresh, and policy updates do not renew the captured grace interval.
At expiry the agent withdraws the upstream catalog, retires the old endpoints, and reports `SourceExpired`.
Readiness becomes `NOT_SERVING`; liveness and configuration observation remain active.
A valid source publication restores service without a process restart. Credential refresh alone cannot revive an expired unavailable source.
The source budget is independent of provider validity.

`credential-stale-timeout-seconds` defaults to 300 seconds and rejects zero.
Relevant credential invalidation, failed refresh, or notification loss starts a grace period for referenced material.
Pending resolution counts as stale; a resolver that does not return cannot avoid expiry.
Inline-only catalogs are not expired by loss of an unused credential notification source.
Repeated failures and policy changes cannot renew the current grace period.
Expiry withdraws the whole upstream catalog and reports `CredentialsExpired`, even if the source remains current.
Fresh complete revalidation restores service. Pre-expiry work cannot revive withdrawn credentials, and credential recovery cannot bypass an expired source.
These staleness budgets do not implement provider validity or CRL retrieval.

The daemon validates client-certificate dates during preparation and before each new connection.
It validates peer certificates in the native TLS handshake.
An established connection continues after an authentication certificate expires.
Certificate dates do not withdraw a catalog or shorten a request deadline.
Provider validity, source staleness, and administrative revocation remain independent limits. CRL freshness affects only new connections. See [certificate revocation](#certificate-revocation).

IPC and proxy clients share each operation's active capacity, bounded FIFO admission queue, and token-bucket packet rate limiters. The pending queue limit equals `max-concurrent-requests`. When both active slots and the pending queue are full, the service returns an immediate overload error without upstream I/O. Reducing `max-concurrent-requests` retains existing work and waiters while preventing new admissions above the updated active limit.

After acquiring a concurrency slot, each upstream request packet acquires one token from its operation's `max-packets-per-second` limiter (defaults: 128 for authentication, 256 for authorization, 512 for accounting) and one token from `max-upstream-packets-per-second` (default: 512). Each limiter provides a one-second burst capacity and paces sustained traffic in FIFO order within the request's admission wait budget. Evaluating the operation limiter before the aggregate upstream limiter prevents a sustained flood in one operation from exhausting the aggregate budget needed by other operations. Interactive proxy sessions acquire and release admission per round trip, so connections waiting on downstream `CONTINUE` input hold no upstream concurrency permits and still apply admission and rate limits to every `CONTINUE` packet.

Each operation also has a total `request-timeout-seconds` budget, with a generated default of 30 seconds and a minimum of one second.
The request captures its deadline before admission. Admission, connection setup, retries, and proxy continuations consume that same budget.
The active server timeout can shorten the admission wait. The selected server timeout can shorten an exchange attempt.
Neither a retry nor a policy reload extends an existing request's deadline.
Set a longer authentication budget when an interactive conversation needs more than 30 seconds.

Expiry before transmission is classified as not sent. An expired exchange with an unknown outcome does not retry automatically.
Proxy expiry terminates the conversation and releases admission capacity.
The proxy reserves active or pending capacity before creating each session task. Overload replies use a bounded connection-level queue and create no session task.
The request deadline covers upstream execution, reply queueing, and physical proxy socket writes.
A final reply retains admission capacity until the writer acknowledges delivery. A partial write that expires closes the connection; it is not resumed or replayed.
Full continuation queues also close the connection so one session cannot block dispatch to all other sessions.
Client API physical delivery is bounded by the connection lifetime; its operation deadline still bounds upstream execution.

SONiC ConfigDB is supervised differently from local CLI or file input. The daemon does not read ConfigDB at startup. The Client API and the health service bind at once. The raw TACACS+ proxy listener reports `pending` until the daemon reads a valid `TACPLUS_FORWARDER|global` row. The proxy then binds to the loopback address and port of that row. While the row is missing, the server configuration applies and the proxy waits. An invalid row rejects the ConfigDB candidate, and the active configuration and listeners stay. SONiC mode always hosts both the Client API and proxy. A conflicting `--proxy-endpoint` or non-`both` service mode is rejected.

After forwarder bootstrap, the daemon binds both listeners with an empty upstream configuration and reports startup and readiness as not serving. It then retries server and credential dependencies with capped jittered backoff. Each candidate is loaded, filtered, bundle-enumerated, completely resolved through the SONiC provider, materialized into generated inline server fields, and validated before one atomic apply. A missing provider root or object therefore cannot apply a partial server list.

When Redis and every referenced credential become available, the same process applies the first complete snapshot and becomes ready. Subscription failures and ended streams trigger a fresh load before resubscription. Invalid ConfigDB or credential candidates leave the previous known-good runtime configuration active and mark health degraded. The reload-safe provider reopens the root for each candidate. This lets a credential mount that appears after startup, or an explicitly replaced provider root, recover without a process restart.

The daemon validates forwarder changes against the same complete ConfigDB snapshot as live upstream changes. Server and credential updates continue to apply.

A change to the forwarder row moves the proxy at runtime. The proxy binds the new endpoint first, and then stops the old endpoint and drains its connections. If the two endpoints use the same port, the proxy stops the old endpoint first. If the new endpoint cannot bind, the old endpoint continues to serve, and the proxy tries again after 1 s, with a delay that doubles up to 30 s. A removed row stops the proxy, and the proxy reports `pending`.

## Health and Probes

### Retirement and Shutdown

When a reload removes an endpoint, existing requests retain it only until a fixed retirement cutoff.
The cutoff uses the maximum current `request-timeout-seconds` value when preparation starts; its default is 30 seconds.
All endpoints removed by that update share the same cutoff. Later reloads do not extend it.
At expiry, retained endpoints reject new bindings, cancel setup, close active sockets, and join their owned tasks.
Unchanged endpoints retain their connections.

Shutdown closes admission and stops new upstream work before draining listeners.
Library drain uses the smaller of the maximum current operation budget and `shutdown-timeout-seconds`.
The daemon also applies one absolute cleanup deadline across service drain, configuration supervision, and host integration.
At expiry, outstanding work is cancelled and remaining transports close. Unknown outcomes are not replayed automatically.
The service removes its owned socket paths and reports stopped only after explicit cleanup completes.
If daemon cleanup exceeds its budget, remaining service and peer futures are cancelled and shutdown reports failure.
Pending systemd helper processes are terminated when their owner is dropped.
Future cancellation cannot preempt arbitrary blocking code; deployments still need an external process supervisor for that case.
An embedded host can use `TacacsClientService::serve_until` to request this sequence without process signals or process exit.

Alongside standard `grpc.health.v1.Health`, the Client API Unix domain socket serves the read-only `AgentHealth.Details` RPC (from `tacacsrs_agent_health.proto`) and `Diagnostics.Statistics` RPC (from `tacacsrs_agent.proto`) with no additional network listener.

| Service name | Meaning |
|---|---|
| `tacacsrs.agent.health.v1.Startup` | A validated snapshot is applied and every enabled listener is bound |
| `tacacsrs.agent.health.v1.Liveness` | The process is starting or serving and the Client API can answer |
| `tacacsrs.agent.health.v1.Readiness` | Startup is complete, at least one eligible upstream is configured, and the enabled upstream watchdog has a successful probe for the current server set |
| *(empty service name)* | Same as readiness |
| `tacacsrs.agent.v1.TacacsAgent` | Same as readiness for the business RPC service |

Without the upstream watchdog, upstream reachability is diagnostic and does not gate readiness. Upstream reachability never gates liveness. During shutdown all names become `NOT_SERVING` before listeners stop accepting work.

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

`--host-integration auto` selects systemd only when `NOTIFY_SOCKET` is present. `none` never invokes a host API and is the container setting. Explicit `systemd` requires both `NOTIFY_SOCKET` and `systemd-notify`. Missing prerequisites and runtime notification failures are fatal. Systemd receives `READY=1` exactly once, after the enabled listeners bind. `READY=1` does not wait for configuration or upstream health, so a start timeout cannot stop the daemon while its source is unavailable. Status updates report the wait for configuration, a failed upstream watchdog probe, and other degraded states. Systemd receives `STOPPING=1` before listener drain.

The daemon does not exit because the initial configuration is unavailable. It binds its listeners, reports that it is not ready, and retries. One exception applies. If the runtime rejects the configuration of a static source, the configuration cannot change. The runtime then adds the `SourceConfigurationInvalid` degradation reason, and the daemon exits with a failure status. A credential resolver failure does not cause this exit. Use the readiness health name to find this state.

The optional upstream watchdog (`--upstream-watchdog-interval-seconds`) also gates readiness. Readiness waits for the first successful probe after each new server set. A policy reload does not start a new server set. Each tick submits one logical accounting operation through the normal client API path. The operation shares admission capacity, its total request deadline, and the configured client API failover strategy with other accounting requests. Unknown delivery stops the request without special watchdog replay.

A final valid accounting reply counts as connectivity success, regardless of its status. Normal retry can discard an intermediate `ERROR` and then fail on another attempt. The watchdog reports that final failure. No eligible accounting upstream also produces a failed probe. A failed probe withdraws readiness until a later probe succeeds. Capacity pressure or cancellation produces an inconclusive result and leaves watchdog health unchanged. A result from an old server set has no effect. Frequent server changes can briefly withdraw readiness while the watchdog waits for a new result.

## IPC Protocol

The daemon runs on Linux and communicates with local clients through gRPC over an absolute Unix domain socket path (`client-api-endpoint`). The protobuf schema defines these client RPCs:

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

### Multiple servers with fast failover

See [server selection scenarios](#server-selection-scenarios) for how the proxy uses these three servers.

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

### Loading a YANG JSON configuration

```bash
tacacsrs-agentd \
    --config /etc/tacacs/tacacs.json \
    --listen-endpoint /run/tacacs/tacacs.sock
```

When `--config` is used, upstream server definitions are loaded from the `ietf-system-tacacs-plus` RFC 7951 JSON document instead of repeated `--server-addr` flags.

## Connection Reuse

When an upstream server confirms single-connect support, the daemon maintains the connection and multiplexes TACACS+ sessions over it. This avoids TCP/TLS handshake overhead for every request. If the transport closes, active sessions fail and a later request negotiates a new connection. If the server denies single-connect during initial negotiation, the daemon uses dedicated connections instead.
