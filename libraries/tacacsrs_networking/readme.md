# tacacsrs-networking

`tacacsrs-networking` owns TACACS+ transport establishment, adaptive
single-connection reuse, packet framing, multiplexing, sequencing, response
routing, and connection recovery.

## Two Client Lanes

Most TACACS+ operations are one request followed by one reply. Accounting,
authorization, and PAP authentication use the fixed exchange lane:

```rust,ignore
let reply = client.execute(exchange).await?;
```

An exchange descriptor serializes its operation body and parses its typed
reply. Networking owns the random session ID, request/reply sequence numbers
`1/2`, header validation, transport selection, and cleanup.

Transparent proxying and genuinely interactive authentication use a mutable
conversation:

```rust,ignore
let mut conversation = client.open_conversation().await?;
let reply = conversation.round_trip(request).await?;
```

`round_trip` enforces one outstanding packet, one session ID and packet type,
and odd/even sequence progression. RFC 8907 sequence numbers never wrap. A
conversation must restart with a new session ID after exhaustion.

ASCII authentication is intentionally absent from the typed fixed API. The raw
conversation and agent proxy retain wire-compatible GETUSER, GETPASS, GETDATA,
RESTART, and terminal reply handling.

## Shared Connection Runtime

One reader task and one writer task own each confirmed single-connect stream.
The writer consumes a bounded outbound queue because bytes on one TCP/TLS stream
must be serialized. The reader can receive server replies in any cross-session
order and routes each packet by its TACACS+ session ID.

Fixed exchanges register a direct one-shot route:

```text
execute(exchange)
  -> reserve random nonzero session ID
  -> registry[session ID] = expected header + one-shot sender
  -> bounded outbound queue
  -> server reply arrives in any session order
  -> reader validates type/version/sequence
  -> one-shot receiver wakes the matching operation
  -> completion removes the route and releases the ID
```

Conversations register a bounded per-session inbox instead. Only interactive
and proxy traffic pays that channel cost.

The reader ignores unknown or late replies after cancellation. A metadata
mismatch on an active route is a protocol violation and closes the shared
connection. Reader or writer failure stops admission and closes all routes so
every waiter observes connection failure. Networking serializes shared
connection recovery to avoid simultaneous reconnect probes.

Cancellation after outbound enqueue has an indeterminate distributed outcome:
the server can process the request before the cancellation reaches it.
Networking does not automatically replay an in-flight accounting,
authorization, or authentication operation.

## Dedicated Fallback

When single-connect is disabled, denied by the server, or already claimed by
another in-flight negotiation, a fixed exchange uses a dedicated TCP/TLS
stream. The same exchange descriptor and response validation apply. A
successful capability probe can promote its completed dedicated stream into
the shared runtime.

## Packet Ownership

Networking exposes packet bodies as byte slices, formats them as redacted
metadata, and zeroizes them on drop. Obfuscation and deobfuscation mutate
owned bodies in place. The writer emits the 12-byte header and body
separately rather than allocating a second combined packet buffer.

TACACS+ shared-secret obfuscation is not confidentiality. PAP is allowed over
the operator-configured transport for interoperability. Prefer TACACS+ over TLS
1.3 for production deployments.

## Baseline

The ignored `routing_burst_baseline` tests compare registry mechanics without
network latency. On the Windows debug build used during this redesign, 512
reverse-order exchanges measured approximately:

| Route | Exchanges/s |
|---|---:|
| Conversation channel | 56,173 |
| Direct fixed one-shot | 89,899 |

This is about a 60% routing-throughput increase in that non-CI diagnostic run.
The values are informational rather than stable performance thresholds.

Run both baselines with:

```bash
cargo test -p tacacsrs-networking routing_burst_baseline --lib -- --ignored --nocapture
```