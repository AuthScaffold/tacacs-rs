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
