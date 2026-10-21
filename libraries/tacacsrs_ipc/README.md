# tacacsrs-ipc

Reusable local IPC transport for the central TACACS+ client service.

This crate owns the protobuf schema, generated gRPC bindings, conversions,
the reusable `ServiceClient` channel, and the bounded IPC server adapter.
Local consumers such as [TACON](../../executables/tacon/) use the client SDK.
The daemon composes the server adapter with an agent operation handler.
The agent runtime does not depend on this crate or generated IPC bindings.

The `tacacsrs-protocol` package owns logical requests, responses, and authorization interpretation.
Direct callers and IPC callers use those same types.

## Read-only diagnostics

`DiagnosticsClient` queries the separate `Diagnostics.Statistics` RPC over the
same local endpoint. It accepts an optional exact server name and returns an
RFC 7951 operational JSON document. The maximum JSON payload is 120 KiB.

A host supplies `DiagnosticsProvider` through `serve_unix_with_diagnostics`.
The provider must bound snapshot copying and serialization and must not perform
upstream I/O. The daemon adapts its read-only runtime handle to this interface.
Provider errors use fixed public status messages. Hosts without a provider return
`UNIMPLEMENTED`; the existing AAA handler and standard health service are unchanged.

## Design goals

- Provide a self-contained client that can make IPC calls without depending on
  the full service crate.
- Keep the protobuf schema checked in as the single source of truth for the
  on-the-wire IPC contract.
- Expose operation-centric Rust types so callers never deal with generated
  protobuf structs directly.
- Support Unix domain socket IPC on Linux and loopback TCP for the IPC emulator.
- Keep server adaptation independent of agent routing, canonical configuration,
  and networking connector types.

## Module hierarchy

```text
tacacsrs_ipc
├── client      - ServiceClient wrapper
├── endpoint    - IpcEndpoint parsing and reusable channel setup
├── convert     - private conversions to shared protocol operations
├── health      - standard health client
├── server      - domain handler, bounded Unix listener, and health publication
└── proto       - generated protobuf/gRPC bindings
```

## Architecture overview

```text
┌──────────────────┐
│ Local Consumer   │
│ such as TACON    │
└──────┬───────────┘
       │ constructs / provides
       v
┌──────────────────┐     ┌───────────────────┐
│ ServiceClient    │────>│ IpcEndpoint       │
└──────┬───────────┘     └───────────────────┘
       │ converts to proto types
       │ gRPC call
       v
┌──────────────────────────────┐
│ Central TACACS+ Client       │
│ Service                      │
│ (IPC adapter + agent handler)│
└──────┬───────────────────────┘
       │ gRPC reply
       v
┌──────────────────┐
│ protocol types   │
│ (domain results) │
└──────────────────┘
```

## IPC endpoint resolution

`IpcEndpoint::connect_channel()` owns Unix and TCP connection setup.
Service, emulator controller, health, and diagnostics clients use this method.
Each client retains its channel for later RPCs. Channel clones share the connection.
Connection errors include the socket path or address.

```text
Endpoint string
  |
  v
empty? ──yes──> Error: cannot be empty
  |
  no
  |
  v
contains '/'?
  |           |
 yes          no
  |           |
  v           v
Unix(path)  parse as SocketAddr
               |         |
             valid    invalid
               |         |
               v         v
           Tcp(addr)   Error
```

## Protocol mapping

The protobuf schema
([`proto/tacacsrs_agent.proto`](proto/tacacsrs_agent.proto))
defines the on-the-wire contract. `tacacsrs_protocol::operations` defines the shared request and
response domain types, and `tacacsrs_protocol::failure` defines the shared `ServiceError`:

| Protobuf message      | Rust domain type                | Direction      |
|-----------------------|---------------------------------|----------------|
| `AccountingRequest`   | `AccountingOperation`           | Client → Service |
| `AccountingResponse`  | `AccountingOperationResponse`   | Service → Client |
| `AuthorizationRequest` | `AuthorizationOperation`       | Client → Service |
| `AuthorizationResponse` | `AuthorizationOperationResponse` | Service → Client |
| `ServiceError`        | `ServiceError`                  | Service → Client |
| `AccountingReply`     | *(oneof envelope)*              | Service → Client |
| `AuthorizationReply`  | *(oneof envelope)*              | Service → Client |
| `AccountingStatus`    | `AccountingResponseStatus`      | Service → Client |
| `AuthorizationStatus` | `AuthorizationResponseStatus`   | Service → Client |

The crate implements conversions between protobuf and domain types with
`From` and `TryFrom`. Unit tests cover round-trip fidelity, invalid privileges,
and identical TACACS+ request bodies through direct and IPC paths.

## Usage example

```rust,no_run
use tacacsrs_ipc::{IpcEndpoint, ServiceClient};
use tacacsrs_protocol::operations::AccountingOperation;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = ServiceClient::connect(IpcEndpoint::default_local()).await?;

    let response = client
        .send_accounting(AccountingOperation {
            user: "admin".into(),
            port: "tty0".into(),
            remote_address: "10.0.0.1".into(),
            command: "show".into(),
            command_arguments: vec!["users".into()],
        })
        .await?;

    println!("Server: {} Status: {:?}", response.server, response.status);
    Ok(())
}
```
