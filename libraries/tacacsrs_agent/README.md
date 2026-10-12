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
│   ├── admission    - shared operation-size and concurrency admission
│   ├── attempt      - transmission-aware request failures
│   ├── proxy_transport
│   │                - downstream settings published with the server set
│   ├── manager      - source snapshots, policy publication, and health
│   │   ├── availability - generation-aware upstream observations
│   │   ├── binding  - networking bindings paired with source metadata
│   │   ├── server_set
│   │   │            - generic request snapshots and networking catalog handles
│   │   └── prepared_server
│   │                - source metadata and prepared endpoint identity
│   ├── connection   - agent exchange interface
│   └── network      - production TCP/TLS upstream connector
└── test_support     - fake upstream fixtures for tests
```

## Failover ownership

`config::RuntimePolicy` projects canonical service policy into a `FailoverPlan` attempt budget.
`tacacsrs_networking::retry` applies the conservative replay rules and owns the retry loop.
The networking `routed` module owns endpoint catalogs, operation identities, circuits, reconnect serialization, and lifecycle state.
The agent does not keep duplicate routing or retry state.

Each ingress path implements `FailoverAttempt` and returns one `Attempt` value for each try.
The networking executor decides whether another attempt is permitted. Unknown outcomes are never replayed automatically.

Services reach routing and admission through `upstream::OperationRouter`. The
router binds one `PolicyService` identity at construction. A service therefore
cannot read another service's state, cannot change the runtime configuration,
and does not pass a service identity on each call.

## Connector Composition

`TacacsClientService` is the public, nongeneric service facade.
It contains `ServiceRuntime<NetworkUpstreamConnector>`, whose connector returns the concrete `TacacsUpstreamConnection` type.
Snapshots, request routers, both ingress services, listeners, and exchange adapters remain generic over the connector internally.
This keeps the async `Send` proof in generic implementations and avoids the specialized erased shape described in the architecture investigation.

Production and fake factories implement networking's `EndpointConnector` contract.
The former agent `UpstreamConnector` trait is removed; that name now identifies a test-only trait-object alias.
The erased `ServiceConnector` adapter also compiles only in tests. No dynamic connector or dynamic connection is stored on the production routing path.
The agent exchange interface remains because it owns protocol-to-service error conversion and operation-specific diagnostics.

## Generation Readiness

`RuntimeHealthSnapshot::runtime_generation()` identifies the currently published routing and policy snapshot.
`RuntimeGeneration` values are scoped to one runtime instance. They are not source or credential revisions.
Catalog replacement, applied-configuration status, eligible-server count, and availability reset now commit under the same publication lock.
Health readers cannot observe a partially updated publication. Policy-only updates advance the runtime generation without resetting availability or replacing global admission.
An unchanged catalog reload preserves observed upstream availability. A rejected replacement leaves the published generation and applied-health metadata unchanged.

Materialized updates also commit the coordinator's active-server set and active source generation inside the runtime publication boundary.
Cancellation before publication leaves the prior runtime and active material unchanged.
Cancellation during later connection retirement retains matching runtime, health, and coordinator state.
The coordinator releases its state lock at commit, before asynchronous retirement. Canonical source snapshots and credential references remain unchanged.

`RuntimeHealthSnapshot::materialization_revision()` reports the applied `SourceRevision` and `CredentialRevision` for coordinated materialization.
The source counter advances when the coordinator accepts a canonical candidate, including repeated observations.
The credential counter advances independently when an invalidation schedules materialization.
These counters belong to one controller instance. They are not content hashes, provider versions, or globally comparable identifiers.
Policy-only updates preserve the applied pair. Direct server reloads clear it because they bypass coordinated materialization.

Successful materialization clears credential-resolution failure in the publication commit.
Failure reporting checks the attempt revision under the coordinator lock, so an old result cannot change health for newer work.
If a newer credential invalidation supersedes incomplete work, it refreshes all dependencies before targeted selection resumes.

`runtime::ConfigSupervisor` owns source recovery, credential notifications, and materialization coordination.
The host supplies a `ConfigDatastore`, service, health publisher, and `TacacsPlusFilter`.
`NoopTacacsPlusFilter` preserves every upstream. Host-specific filters can derive a working candidate without changing the retained authoritative snapshot.

Use `with_credential_resolver` and `with_credential_changes` to configure credential providers.
Notifications require a resolver. Provider configuration is checked before source I/O.
`initialize_until(stop)` optionally prepares the initial configuration before listeners start.
`run_until(stop)` consumes the supervisor and runs both source and credential supervision, without repeating successful initialization.
The stop future belongs to the host. The supervisor installs no process signal handlers.

Cancellation drops pending load, filter, resolution, and publication futures. It preserves the last successfully published configuration.
The runtime uses `ConfigDatastore::observe()` for both initial configuration and later changes.
Successful initialization retains the same session. Interrupted initialization starts a fresh session before retry or serving.
File observations own their watcher and coalesce invalidations without a detached reload worker.
All retained configuration sources implement owned observation. The transitional adapter and datastore subscription method are removed.
Coordinated generation and health publication remain Stage 4 work.

`ServiceConfig::validation_options` carries the schema policy selected by the configuration source.
Construction and both reload APIs apply the shared configuration checks with that policy.
The daemon obtains the policy from `ConfigDatastore::validation_options`, including explicit migration relaxations.

The service prepares native transport contexts before publishing changed server slots.
Invalid DER material or a short PSK rejects the candidate before it can replace the active routing snapshot.
Failure preserves the old routes, proxy policy, cached connections, and applied health state.
An empty replacement remains valid for a runtime that waits for new configuration.

Each server slot retains one prepared endpoint for its lifetime.
Connectors receive clones of that endpoint for operation-specific clients and reconnects. They do not interpret YANG or parse credentials.
An unchanged server reuses its existing slot and native contexts.
Changed credential material creates a new slot while bound requests retain the previous generation.

## Tower Boundary

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
│ - local shutdown tracking    │
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

`serve()` waits for SIGTERM or Ctrl-C in its owned serving future.
Embedded hosts use `serve_until(stop_future)` without installing signal handlers.
Shutdown changes health to `Draining`, closes admission and upstream connection creation, and stops listeners from accepting new work.
The maximum current operation request budget supplies one absolute deadline for listener drain and all current and historical upstream cleanup.
At expiry, remaining listener tasks are cancelled and joined, and upstream sockets are forced closed.
Owned Unix socket paths are removed before successful shutdown publishes `Stopped`.
A listener failure cancels its siblings and uses the same cleanup path.

Reload schedules removed endpoints for terminal retirement under one cutoff derived from the maximum operation budget at preparation start.
Captured requests can still use their old endpoints before that cutoff; the retirement owner then cancels setup, closes sockets, and joins drivers.
Unchanged endpoint identities retain their caches. A later reload cannot extend an earlier retirement cutoff.
Terminal shutdown also reaches retired endpoints retained by old requests. A stopped service rejects reload and cannot be served again.

Cancelling the serving future schedules immediate upstream cleanup and drops listener-owned transport guards.
Use `close_and_join(deadline)` to confirm upstream cleanup after cancellation or when the service has not started listeners.
For an active listener run, request shutdown through the future passed to `serve_until` and await that run's result.

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
