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
- Support ordered failover independently for each TACACS+ operation.
- Keep the IPC contract visible and versioned through a checked-in `.proto`
  schema.
- Make the same architecture documentation visible in both rustdoc and GitHub.

## Module hierarchy

```text
tacacsrs_agent
├── config           - public runtime configuration
│   └── policy       - failover strategies and operation limits
├── runtime          - TacacsClientService lifecycle, hot reload, and drains
├── services         - internal service boundaries
│   ├── client_api   - local client-facing gRPC service and IPC transports
│   │   ├── service  - ClientApiService runtime dependency owner
│   │   ├── grpc     - Tonic TacacsAgent adapter
│   │   ├── listener - endpoint dispatch and shutdown drain
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
│           ├── session
│           │          - initial packet execution and conversation pinning
│           ├── session_mapping
│           │          - TACACS+ session-id rewriting
│           └── error - downstream/upstream connection error boundary
├── upstream         - TACACS+ upstream service boundary
│   ├── router       - per-service facade over the upstream manager
│   ├── executor     - the one retry loop that applies a failover plan
│   ├── failover     - shared strategy and replay-safety decisions
│   ├── admission    - shared operation-size and concurrency admission
│   ├── operation    - authentication, authorization, and accounting identity
│   ├── attempt      - transmission-aware request failures
│   ├── proxy_transport
│   │                - downstream settings published with the server set
│   ├── manager      - server snapshots and operation routing
│   │   ├── circuit  - server-operation recovery state
│   │   ├── routing  - route selection and connection invalidation
│   │   ├── server_set
│   │   │            - immutable catalogs and operation cursors
│   │   └── server_slot
│   │                - operation-scoped connection ownership
│   ├── connection   - upstream connection and connector traits
│   └── network      - production TCP/TLS upstream connector
└── test_support     - fake upstream fixtures for tests
```

## Failover ownership

Only two modules read the failover configuration:

- `upstream::failover` turns a `RuntimePolicy` into a `FailoverPlan`. The plan
  holds the attempt budget and the replay-safety rule for one operation.
- `upstream::executor` applies that plan. It is the only retry loop.

A service does not read the plan. It implements `FailoverAttempt` and returns
one `Attempt` value for each try. This keeps strategy interpretation out of the
client API bridge and out of the raw proxy bridge.

Services reach routing and admission through `upstream::OperationRouter`. The
router binds one `PolicyService` identity at construction. A service therefore
cannot read another service's state, cannot change the runtime configuration,
and does not pass a service identity on each call.

## Tower boundary

The upstream failover plan is domain code. It interprets TACACS+ `ERROR`
responses, uncertain accounting outcomes, and authentication session pinning.
Tower retry and balancing layers do not model these rules directly.

Tower can wrap the local gRPC transport, but it does not own upstream routing.
The runtime uses one shared failover plan for typed IPC operations and proxy
initial packets. It uses Tokio semaphores for operation-wide admission.

## Architecture overview

```text
┌──────────────────┐
│ Local Consumer   │
│ such as TACON    │
└──────┬───────────┘
       │ protobuf request / response
       v
┌──────────────────┐
│ ServiceClient    │
│ (client crate)   │
└──────┬───────────┘
       │ gRPC over Unix socket
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
│ - operation server catalogs  │
│ - shared operation cursors   │
│ - recovery circuits          │
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

The client API gRPC service accepts only Unix domain socket endpoints.
The raw TACACS+ proxy is a sibling runtime service with its own endpoint policy.
When `EnabledServices` includes the proxy service, `TacacsClientService` starts
`services::tacacs_proxy`. When it includes both services, the proxy runs
alongside `services::client_api`. The proxy can bind either a Unix domain
socket or loopback TCP endpoint. The proxy uses its own
`upstream_bridge` because it forwards packet sessions rather than typed RPC
operations.

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
  |   advance the operation cursor
  |   return ServiceError { server, retriable: true }
  |
  v
map reply to the operation-specific response
  |
  v
return protobuf response envelope
```

## Failover state chart

Each operation has an independent ordered server catalog. IPC and proxy requests
share one cursor for each operation. A retryable failure opens the applicable
server-operation circuit and advances only that operation cursor.

```text
active operation route
        |
        | retryable failure
        v
open server-operation circuit
        |
        v
select next eligible server
        |
        | recovery interval expires
        v
one real recovery trial
        |
        +-- success --> restore higher-priority route
        |
        +-- failure --> reopen circuit
```

## Listener lifecycle and shutdown

The listener follows this startup sequence:

```text
1. create the parent directory if it does not exist
2. inspect the socket path if it already exists
3. if the path accepts connections → fail (another instance is running)
4. if the path is stale → remove and bind a new socket
5. apply the configured socket mode
6. begin serving IPC clients
```

One coordinator receives SIGTERM or Ctrl-C, changes the shared lifecycle to `Draining`, and then broadcasts shutdown to every listener. Registration guards publish `Binding`, `Bound`, and `Stopped` on every return path. Shutdown stops accepting new local work, waits for active gRPC and raw proxy requests to finish, removes Unix domain socket paths, and finally publishes `Stopped`. A listener bind or accept-loop failure marks fatal health, cancels siblings, and waits for their guards and cleanup before returning.

The same typed watch-backed snapshot drives startup, liveness, readiness, datastore freshness, upstream availability, standard gRPC health, host integration, and operator status. It contains only typed flags and counts. Configuration values, server identities, credential references, and raw errors stay outside the shared state.

## Configuration details

### IPC endpoint format

`ServiceConfig::endpoint` is explicit rather than permissive:

- Values containing `/` are treated as Unix domain socket paths, for
  example `/run/tacacs/tacacs.sock`.
- Values that parse as `SocketAddr` identify TCP endpoints for the TACACS+
  proxy or IPC emulator. The client API rejects TCP endpoints.
- An empty string is rejected as invalid configuration. It does **not** fall
  back to the default endpoint.

The only way to opt into the built-in default endpoint is to call
`IpcEndpoint::default_local()`.

### Upstream warm-up behavior

At startup the service performs a best-effort warm-up pass across the configured
TACACS+ servers until it finds the first responsive server. Once the warm-up
caches one usable upstream connection, it stops immediately. It does **not**
establish full TACACS+ connections to every configured server.

This keeps startup load bounded in large deployments where many clients can
start at once against a relatively small TACACS+ server pool. If no server is
reachable during startup, the service still starts and later IPC requests retry
failover on demand.

Per-server reconnect attempts are serialized inside the upstream manager. When
many IPC requests arrive at once, they share one in-flight reconnect attempt for
a given TACACS+ server instead of generating a burst of duplicate TLS handshakes.
After that reconnect attempt finishes, queued callers reuse the cached
connection if it succeeded. If it failed, they fail over without an immediate
retry against the same server for that burst of IPC work.

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
step keeps the generated Rust transport bindings aligned with it.

There is also no compatibility promise for this IPC protocol today. When the
contract changes, the `.proto`, generated transport bindings, and domain-type
conversions must change together in the same patch.
