# tacacsrs-agent

Reusable building blocks for the central TACACS+ client service introduced for
local IPC consumers such as TACON.

The crate keeps the local listener, upstream failover logic, and persistent
connection management together in one library while the runnable process lives
in `executables/tacacsrs_agentd`. Transport-independent domain types and
the checked-in protobuf IPC contract live in the companion
[`tacacsrs-agent-client`](../tacacsrs_agent_client/) crate so
that both the server and local consumers share the same protocol definitions.

## Design goals

- Expose a higher-level RPC contract instead of raw TACACS+ packet headers.
- Keep upstream TACACS+ connections persistent and reusable across IPC requests.
- Support ordered failover with automatic preferred-server recovery.
- Keep the IPC contract visible and versioned through a checked-in `.proto`
  schema.
- Make the same architecture documentation visible in both rustdoc and GitHub.

## Module hierarchy

```text
tacacsrs_agent
├── config           - public runtime configuration
├── runtime          - TacacsClientService lifecycle, hot reload, and drains
├── services         - internal service boundaries
│   ├── client_api   - local client-facing gRPC service and IPC transports
│   │   ├── service  - ClientApiService runtime dependency owner
│   │   ├── grpc     - Tonic TacacsAgent adapter
│   │   ├── listener - endpoint dispatch and shutdown drain
│   │   │   ├── tcp  - loopback TCP binding for non-Unix builds
│   │   │   └── unix - Unix socket binding and cleanup
│   │   └── upstream_bridge
│   │                - client API operation/protocol mapping and failover bridge
│   └── tacacs_proxy - raw TACACS+ proxy service
│       ├── service   - TacacsProxyService runtime dependency owner
│       ├── listener  - endpoint dispatch, accept loop, and shutdown drain
│       │   ├── tcp   - loopback TCP binding
│       │   └── unix  - Unix socket binding and cleanup
│       └── upstream_bridge
│           ├── packet_io
│           │          - downstream/upstream TACACS+ packet read/write helpers
│           ├── reply_action
│           │          - reply status classification for session completion
│           ├── session_mapping
│           │          - TACACS+ session-id rewriting
│           └── error - downstream/upstream connection error boundary
├── upstream         - TACACS+ upstream service boundary
│   ├── manager      - server snapshots, failover, cache, and probes
│   ├── connection   - upstream connection and connector traits
│   └── network      - production TCP/TLS upstream connector
└── test_support     - fake upstream fixtures for tests
```

## Architecture overview

```text
┌──────────────────┐
│ Local Consumer   │
│ (e.g. TACON)     │
└──────┬───────────┘
       │ protobuf request / response
       v
┌──────────────────┐
│ ServiceClient    │
│ (client crate)   │
└──────┬───────────┘
       │ gRPC over Unix socket / loopback TCP
       v
┌──────────────────────────────┐
│ TacacsClientService          │
│ - service orchestration      │
│ - hot reload                 │
│ - graceful shutdown tracking │
└──────┬───────────────────────┘
  │ starts client API service
       v
┌──────────────────────────────┐
│ services::client_api         │
│ - gRPC transport             │
│ - typed operation execution  │
│ - ServiceError mapping       │
└──────┬───────────────────────┘
  │ binds requests
  v
┌──────────────────────────────┐
│ UpstreamManager              │
│ - active server selection    │
│ - preferred server probing   │
│ - connection cache           │
└──────┬───────────────────────┘
       │ creates / reuses sessions
       v
┌──────────────────────────────┐
│ UpstreamConnection           │
│ - persistent TACACS+ socket  │
│ - accounting transaction API │
└──────┬───────────────────────┘
       │ TACACS+ protocol (RFC 8907)
       v
┌──────────────────────────────┐
│ TACACS+ Server(s)            │
└──────────────────────────────┘
```

On Unix, the client API gRPC service accepts only Unix socket endpoints. The raw
TACACS+ proxy is a sibling runtime service with its own endpoint policy: when
`EnabledServices` includes the proxy service, `TacacsClientService` starts
`services::tacacs_proxy`; when it includes both services, the proxy runs
alongside `services::client_api`. The proxy may bind either a Unix socket or
loopback TCP endpoint on Unix. The proxy uses its own `upstream_bridge` because
it forwards packet sessions rather than typed RPC operations.

## Request activity diagram

The runtime uses unary accounting and authorization RPCs over the local IPC
endpoint.

```text
Client
  |
  v
connect to IPC endpoint
  |
  v
send Accounting RPC
  |
  v
local IPC listener accepts client
  |
  v
GrpcService decodes the request
  |
  v
client_api::upstream_bridge maps the typed operation
  |
  v
UpstreamManager chooses the active server
  |
  +--> no responsive server
  |      |
  |      v
  |   return ServiceError { retriable: true }
  |
  v
reuse or establish upstream connection
  |
  v
create upstream session
  |
  v
send TACACS+ accounting request
  |
  +--> upstream error
  |      |
  |      v
  |   clear cached connection
  |   advance active index
  |   return ServiceError { server, retriable: true }
  |
  v
map reply to the operation-specific response
  |
  v
return protobuf response envelope
```

## Failover state chart

The preferred server is always server index `0`. New sessions use that server
whenever it is healthy. A failed request or failed connection attempt marks the
current server unusable for new sessions and advances selection through the
ordered list.

```text
                       preferred probe succeeds
                 +----------------------------------+
                 |                                  |
                 v                                  |
        +---------------------+                     |
        | PreferredActive(0)  |                     |
        +----------+----------+                     |
                   |                                |
                   | connection/session failure     |
                   v                                |
        +---------------------+                     |
        | FailedOver(n > 0)   |---------------------+
        +----------+----------+
                   |
                   | current server fails
                   v
        +---------------------+
        | FailedOver(next n)  |
        +----------+----------+
                   |
                   | all servers unavailable
                   v
        +---------------------+
        | NoResponsiveServer  |
        +----------+----------+
                   |
                   | a server connects successfully
                   v
        +---------------------+
        | PreferredActive(0)  |  if server 0 is back
        +---------------------+
```

## Listener lifecycle and shutdown

On Unix systems the listener follows this startup sequence:

```text
1. create the parent directory if it does not exist
2. inspect the socket path if it already exists
3. if the path accepts connections → fail (another instance is running)
4. if the path is stale → remove and bind a new socket
5. apply the configured socket mode
6. begin serving IPC clients
```

Shutdown stops accepting new IPC connections first, waits for active RPCs to
finish, and then removes the Unix socket path.

## Configuration details

### IPC endpoint format

`ServiceConfig::endpoint` is explicit rather than permissive:

- On Unix, values containing `/` are treated as Unix socket paths, for example
  `/run/tacacs/tacacs.sock`.
- On all platforms, values that parse as `SocketAddr` are treated as TCP
  endpoints, for example `127.0.0.1:9049`.
- An empty string is rejected as invalid configuration; it does **not** fall
  back to the platform default endpoint.

The only way to opt into the built-in default endpoint is to call
`IpcEndpoint::default_local()`.

### Upstream warm-up behavior

At startup the service performs a best-effort warm-up pass across the configured
TACACS+ servers until it finds the first responsive server. Once one usable
upstream connection has been cached, the warm-up stops immediately; it does
**not** establish full TACACS+ connections to every configured server.

This keeps startup load bounded in large deployments where many clients may
start at once against a relatively small TACACS+ server pool. If no server is
reachable during startup, the service still starts and later IPC requests retry
failover on demand.

Per-server reconnect attempts are serialized inside the upstream manager. When
many IPC requests arrive at once, they share one in-flight reconnect attempt for
a given TACACS+ server instead of generating a burst of duplicate TLS handshakes.
After that reconnect attempt finishes, queued callers reuse the cached
connection if it succeeded, or fail over without immediately retrying the same
server again for that same burst of IPC work if it failed.

### Per-client request handling

Each accepted IPC connection currently carries a single unary RPC exchange:

1. Decode one protobuf accounting or authorization request.
2. Map the typed operation through `services::client_api::upstream_bridge`.
3. Select the upstream server for that request through `UpstreamManager`.
4. Encode one protobuf reply envelope.

## Protocol source of truth

The maintainable split between this crate and
[`tacacsrs-agent-client`](../tacacsrs_agent_client/) is:

- Define the wire contract in the client crate's
  [`proto/tacacsrs_agent.proto`](../tacacsrs_agent_client/proto/tacacsrs_agent.proto).
- Generate the Rust gRPC/protobuf bindings at build time in the client crate.
- Keep the operation-centric domain types in the client crate's
  [`protocol`](../tacacsrs_agent_client/src/protocol.rs) module.
- Keep focused conversion tests between the domain types and protobuf messages.

This keeps the on-the-wire IPC schema explicit and type-safe while still
letting the rest of the crate work with small hand-written domain types. The
checked-in `.proto` is the compatibility surface for local IPC, and the build
step ensures the generated Rust transport bindings stay aligned with it.

There is also no compatibility promise for this IPC protocol today. When the
contract changes, the `.proto`, generated transport bindings, and domain-type
conversions should change together in the same patch.
