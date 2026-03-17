# tacacsrs-client-service

Reusable building blocks for the central TACACS+ client service introduced for
local IPC consumers such as TACON.

The crate keeps the transport-independent protocol, IPC framing, local listener,
and upstream failover logic together in one library while the runnable process
lives in `executables/tacacs_client_service`.

## Design goals

- expose a higher-level RPC contract instead of raw TACACS+ packet headers
- keep upstream TACACS+ connections persistent and reusable
- support ordered failover with preferred-server recovery
- keep the protocol visible to non-Rust consumers through a checked-in JSON
  schema
- make the same architecture documentation visible in both rustdoc and GitHub

## Module hierarchy

```text
tacacsrs_client_service
├── client      - short-lived IPC client wrapper
├── codec       - framed JSON read/write helpers
├── protocol    - operation-centric IPC request/response contract
├── service
│   ├── config       - public listener and failover configuration
│   ├── coordinator  - long-lived service runtime and listener lifecycle
│   ├── state        - internal failover state and request execution logic
│   └── tests        - service integration and failover coverage
└── upstream    - persistent TACACS+ connection adapters
```

## Architecture overview

```text
┌─────────────────┐
│ Local consumer  │
│ (for example    │
│ TACON)          │
└──────┬──────────┘
       │ ServiceRequest / ServiceResponse
       v
┌─────────────────┐
│ ServiceClient   │
│ + codec         │
└──────┬──────────┘
       │ framed JSON over Unix socket / loopback TCP
       v
┌──────────────────────────────┐
│ TacacsClientService          │
│ - listener lifecycle         │
│ - graceful shutdown          │
│ - stale socket handling      │
└──────┬───────────────────────┘
       │ delegates request binding + failover
       v
┌──────────────────────────────┐
│ ServiceState                 │
│ - active server selection    │
│ - preferred server probing   │
│ - request execution          │
│ - active client tracking     │
└──────┬───────────────────────┘
       │ creates / reuses sessions
       v
┌──────────────────────────────┐
│ UpstreamConnection           │
│ - persistent TACACS+ socket  │
│ - accounting transaction API │
└──────────────────────────────┘
```

## Request activity diagram

The runtime uses one framed request/response exchange per local IPC session in
the current accounting-focused scope.

```text
Client
  |
  v
connect to IPC endpoint
  |
  v
send ServiceRequest::Accounting
  |
  v
TacacsClientService accepts client
  |
  v
ServiceState chooses the active server
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
map reply to AccountingOperationResponse
  |
  v
write ServiceResponse::Accounting
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

1. create the parent directory if it does not exist
2. inspect the socket path if it already exists
3. if the path accepts connections, fail startup because another instance is
   likely active
4. if the path is stale, remove the filesystem entry and bind a new socket
5. apply the configured socket mode

Shutdown stops accepting new IPC connections first, waits for active clients to
finish, and then removes the Unix socket path.

## Configuration details

### IPC endpoint format

`ServiceConfig::endpoint` is explicit rather than permissive:

- on Unix, values containing `/` are treated as Unix socket paths, for example
  `/run/tacacs.sock`
- on all platforms, values that parse as `SocketAddr` are treated as TCP
  endpoints, for example `127.0.0.1:9049`
- an empty string is rejected as invalid configuration; it does **not** fall
  back to the platform default endpoint

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

Per-server reconnect attempts are also serialized inside the service. When many
IPC requests arrive at once, they share one in-flight reconnect attempt for a
given TACACS+ server instead of generating a burst of duplicate TLS handshakes.
After a failed connect attempt, that server enters a short retry cooldown so
concurrent callers fail over quickly instead of hammering the same down server.

### Per-client request handling

Each accepted IPC connection currently carries a single request/response
exchange:

1. decode one `ServiceRequest`
2. select the upstream server for that IPC session
3. execute the request against that bound server
4. encode one `ServiceResponse`

Unsupported request kinds do not enter the dispatch path because they fail
during JSON decoding of the tagged `ServiceRequest` enum.

## Protocol source of truth

The maintainable choice for this crate is:

- define the IPC contract directly in Rust in `src/protocol.rs`
- derive `serde` for runtime serialization
- derive `schemars::JsonSchema` for schema generation
- check the generated schema into `ipc-protocol.schema.json`
- keep a test that ensures the checked-in schema matches the Rust types

This keeps the runtime types, the schema visible in GitHub, and the validation
logic aligned without introducing a separate code generation pipeline. The
protocol is intentionally small and internal to the repository, so adding a
schema-first build step would increase moving parts without reducing day-to-day
maintenance cost.

There is also no compatibility promise for this IPC protocol today. When the
contract changes, the Rust types and checked-in schema should change together in
the same patch.
