# tacacsrs-agent-client

Reusable local IPC transport for the central TACACS+ client service.

This crate is the **client-facing half** of the service architecture. It owns
the protobuf schema, generated gRPC bindings, conversions, and the `ServiceClient` wrapper that local
consumers (such as [TACON](../../executables/tacon/)) use to talk to the
long-lived TACACS+ client service.

The `tacacsrs-protocol` package owns logical requests, responses, and authorization interpretation.
Direct callers and IPC callers use those same types.

## Design goals

- Provide a self-contained client that can make IPC calls without depending on
  the full service crate.
- Keep the protobuf schema checked in as the single source of truth for the
  on-the-wire IPC contract.
- Expose operation-centric Rust types so callers never deal with generated
  protobuf structs directly.
- Support Unix domain socket IPC on Linux and loopback TCP for the IPC emulator.

## Module hierarchy

```text
tacacsrs_agent_client
├── client      - ServiceClient wrapper
├── endpoint    - IpcEndpoint parsing
├── convert     - private conversions to shared protocol operations
├── health      - standard health client
└── ipc         - generated protobuf/gRPC bindings
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
       │ converts to ipc types
       │ gRPC call
       v
┌──────────────────────────────┐
│ Central TACACS+ Client       │
│ Service                      │
│ (tacacsrs-agent)             │
└──────┬───────────────────────┘
       │ gRPC reply
       v
┌──────────────────┐
│ protocol types   │
│ (domain results) │
└──────────────────┘
```

## IPC endpoint resolution

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
defines the on-the-wire contract. `tacacsrs_protocol::operations` defines the shared domain types:

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
use tacacsrs_agent_client::{IpcEndpoint, ServiceClient};
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
