# tacacsrs-protocol

Pure TACACS+ wire types, logical operations, exchange descriptions, and conversation validation.
This package does not open sockets or depend on Tokio, OpenSSL, YANG, protobuf, or an agent process.

## Layering

The crate stacks three transport-independent layers:

1. **Wire bodies** — the `accounting`, `authentication`, and `authorization`
   message families encode and decode RFC 8907 request and reply octets through
   the `body::TacacsBodyTrait` seam.
2. **Exchanges** — `exchange` pairs one request body with its single reply and
   describes the transfer without performing I/O.
3. **Logical operations** — `operations` expresses caller intent in
   transport-independent types. An operation converts to an exchange, and a
   response type decodes a validated reply with `from_reply`.

A successful operation yields a response type. A failed operation yields a
`failure::ServiceError` that carries structured failure facts, not response
fields. A reply *status* is not a failure: callers interpret the status enums
directly, and `AuthorizationResponseStatus::unchanged_execution` turns an
authorization reply into an execute-or-deny decision for hosts that cannot apply
response attributes.

## Ownership

| Module | Contract |
| --- | --- |
| `header`, `packet`, message families | Wire encoding and complete-buffer parsing |
| `body` | The `TacacsBodyTrait` wire-serialization seam for message bodies |
| `exchange` | Fixed accounting, PAP, and authorization exchanges without I/O |
| `conversation` | Session identity, request/reply sequencing, and exhaustion |
| `operations` | Shared logical requests, responses, wire conversion, and unchanged-command authorization decisions |
| `failure` | Failure facts and the structured `ServiceError` for failed operations |
| `privilege` | Privilege levels limited to 0 through 15 |

The networking package executes exchanges and owns connection lifetimes.
The local IPC package owns protobuf conversion through `From` and `TryFrom`.
Neither adapter defines a second logical operation model.

## Build an operation

```rust
use tacacsrs_protocol::exchange::FixedExchange;
use tacacsrs_protocol::operations::{AuthorizationAuthenticationContext, AuthorizationOperation};

let operation = AuthorizationOperation::builder(
    "admin", 15, AuthorizationAuthenticationContext::TacacsPap,
)
.port("tty0")
.remote_address("192.0.2.1")
.service("shell")
.command("show")
.command_args(["interfaces", "brief"])
.build()?;

let encoded_body = operation.exchange()?.encode_request()?;
assert!(!encoded_body.is_empty());
# Ok::<(), anyhow::Error>(())
```

The same operation can be sent through the direct client or the local IPC client.
`PrivilegeLevel` rejects values outside the protocol range before an operation reaches either transport.
Authorization arguments retain order, duplicate names, and mandatory/optional separators.

## Host authorization

`AuthorizationResponseStatus::unchanged_execution` interprets replies for hosts that cannot apply response attributes.
It rejects malformed arguments, mandatory changes, and non-pass statuses.
It never turns a server denial into an unavailable-service outcome.
This is not an attribute-application engine for hosts that can rewrite commands.

## Validation

```bash
cargo test -p tacacsrs-protocol
cargo tree -p tacacsrs-protocol --edges normal
```

The tests cover pure protocol behavior without a running agent or an asynchronous runtime.
Configuration remains authoritative in the YANG configuration package and is outside this crate's responsibilities.