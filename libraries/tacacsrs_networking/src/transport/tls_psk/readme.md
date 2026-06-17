# TLS-PSK Transport

This module implements TLS 1.3 External Pre-Shared Key (EPSK) transport for
TACACS+ connections, gated behind the `psk` feature flag. It uses OpenSSL (via
`openssl` and `tokio-openssl` crates) because the default `rustls` backend does
not yet support TLS 1.3 external PSKs.

## Background: What is TLS-PSK?

Standard TLS authenticates peers using X.509 certificates (or raw public keys).
**Pre-Shared Key (PSK)** mode is an alternative where both client and server
already share a secret key, provisioned out-of-band. During the TLS handshake
the client proves it holds the key, and the server proves it holds the same key
— no certificate authority or PKI is needed.

TLS 1.3 (RFC 8446) defines two flavours of PSK:

| Flavour | Source | Use case |
|---------|--------|----------|
| **Resumption PSK** | Derived from a previous TLS session via `NewSessionTicket` | Session resumption / 0-RTT |
| **External PSK (EPSK)** | Provisioned out-of-band (manual config, key management system, etc.) | Lightweight mutual auth without PKI |

This module implements **External PSK only** — the key material comes from the
YANG configuration model, not from a prior TLS session.

## How TLS 1.3 EPSK Authentication Works

RFC 8446 §2.2 describes the PSK handshake flow:

```text
Client                                           Server

ClientHello
  + key_share*
  + pre_shared_key        -------->
                                                ServerHello
                                           + pre_shared_key
                                               + key_share*
                                      {EncryptedExtensions}
                                                 {Finished}
                          <--------   [Application Data*]
{Finished}                -------->
[Application Data]        <------->   [Application Data]
```

Key points:

1. **No Certificate or CertificateVerify messages are exchanged.** Authentication
   is implicit: only a party holding the correct PSK can produce valid binder
   HMACs (client → server) and a valid Finished MAC (server → client).

2. The client sends a `pre_shared_key` extension containing the PSK identity
   (a label) and a cryptographic binder proving knowledge of the key.

3. The server selects the PSK (by index) in its `pre_shared_key` extension.

4. Optionally, `key_share` can be included alongside the PSK for **(EC)DHE +
   PSK** mode, adding forward secrecy. Without it, the PSK alone determines
   all traffic keys (PSK-only mode, no forward secrecy).

5. For external PSKs, `obfuscated_ticket_age` is always 0 and the hash
   algorithm must be explicitly specified (defaults to SHA-256 per RFC 8446
   §4.2.11).

### Server Authentication via PSK

> "As the server is authenticating via a PSK, it does not send a Certificate
> or a CertificateVerify message." — RFC 8446 §2.2

The server proves its identity by producing a valid `Finished` message. The
Finished MAC is derived from `server_handshake_traffic_secret`, which is itself
derived from the PSK via the key schedule. Only a server possessing the correct
PSK can produce this MAC. This is what the YANG `server-auth-tls13-epsk` feature
flag enables.

## YANG Configuration Model

The EPSK material is sourced from the `ietf-system-tacacs-plus` YANG module
(RFC 9950, revision 2026-03-31). Two nodes control PSK behaviour:

### `client-identity/tls13-epsk` — The Key Material

```
container tls13-epsk {
  uses ks:inline-or-keystore-symmetric-key-grouping;  // the base key
  leaf external-identity { type string; mandatory true; }
  leaf hash { type tlscmn:epsk-supported-hash; default "sha-256"; }
  leaf context { type string; }
  leaf target-protocol { type uint16; }
  leaf target-kdf { type uint16; }
  leaf-list tacacsrs:psk-dhe-ke-groups { type tacacsrs:psk-dhe-ke-supported-group; }
}
```

This configures the actual EPSK tuple `(Base Key, External Identity, Hash)` that
the client offers in the TLS handshake. The `external-identity` is the label
sent in the `pre_shared_key` ClientHello extension; the base key is the shared
secret. The repository's `tacacsrs` augmentation adds
`tacacsrs:psk-dhe-ke-groups`; when this leaf-list is present, the ordered values
are translated into OpenSSL supported-group names and used to send TLS 1.3
`psk_dhe_ke` key shares. When the leaf-list is empty, the transport leaves the
OpenSSL group list unchanged and preserves the existing PSK-only behaviour.

### `server-authentication/tls13-epsks` — The Trust Policy

```
leaf tls13-epsks {
  if-feature "tlsc:server-auth-tls13-epsk";
  type empty;
}
```

This is a **policy flag** (presence = enabled). It declares that successful
completion of a PSK handshake is sufficient to authenticate the server — no
CA certificates or certificate pinning needed. No additional configuration is
required because the key is inherently the same one in `client-identity`.

### Why Both Nodes Exist

The YANG model separates `client-identity` and `server-authentication` into
independent containers because other auth types (certificate, raw-public-key)
genuinely support asymmetric combinations (e.g., client authenticates with a
certificate while verifying the server via CA trust chain).

For the PSK case specifically, this separation is **structural only** — it does
not enable mixed PSK + certificate authentication. RFC 8446 §4.1.1 is explicit:

> "When authenticating via a certificate, the server will send the Certificate
> (Section 4.4.2) and CertificateVerify (Section 4.4.3) messages. In TLS 1.3
> as defined by this document, either a PSK or a certificate is always used,
> **but not both**. Future documents may define how to use them together."

When the server accepts a PSK, it MUST NOT send Certificate or CertificateVerify
messages (RFC 8446 §2.2). The only scenario where configuring `ca-certs`
alongside a PSK client-identity would activate is if the server *rejects* the
offered PSK and falls back to a full (EC)DHE + certificate handshake — at which
point the client is no longer authenticating via PSK either.

### PSK with (EC)DHE vs PSK-only

RFC 8446 §2.2 notes:

> "PSKs can be used with (EC)DHE key exchange in order to provide forward
> secrecy in combination with shared keys, or can be used alone, at the cost
> of losing forward secrecy for the application data."

This is about **key derivation**, not authentication. The two PSK sub-modes are:

| Mode | Traffic keys derived from | Forward secrecy | Server auth mechanism |
|------|---------------------------|-----------------|----------------------|
| PSK-only | PSK alone | **No** | PSK (Finished MAC) |
| PSK + (EC)DHE | PSK + ephemeral DH secret | **Yes** | PSK (Finished MAC) |

In both cases the server authenticates via the PSK — no certificate is sent.
Adding `key_share` alongside `pre_shared_key` means traffic keys incorporate an
ephemeral Diffie-Hellman exchange, so if the PSK later leaks, past sessions with
unique DH keys remain protected. But the authentication mechanism is unchanged.

By default, the implementation preserves PSK-only mode for existing
configurations. To request forward secrecy, configure one or more
`tacacsrs:psk-dhe-ke-groups` values under `client-identity/tls13-epsk`; the
client passes those groups to OpenSSL in the same order. Supported mappings are:

| YANG value | OpenSSL group name |
|------------|--------------------|
| `x25519` | `X25519` |
| `secp256r1` | `P-256` |
| `secp384r1` | `P-384` |
| `secp521r1` | `P-521` |
| `ffdhe2048` | `ffdhe2048` |
| `ffdhe3072` | `ffdhe3072` |
| `ffdhe4096` | `ffdhe4096` |
| `ffdhe6144` | `ffdhe6144` |
| `ffdhe8192` | `ffdhe8192` |

If the linked OpenSSL library rejects the configured list, connection setup fails
with an error that includes the OpenSSL group list and points at
`psk-dhe-ke-groups`.

### Practical Guidance

In practice, when configuring EPSK for TACACS+, the `tls13-epsks` leaf in
`server-authentication` should always be present: it declares that PSK-based
server auth is acceptable, which is the only kind possible when the PSK is
accepted.

## Implementation Architecture

```
tls_psk/
├── mod.rs              — crate-internal API surface + Transport impl
├── context.rs          — OpenSSL SslContext construction + hash/group projections
├── config.rs           — PskClientConfig: validated SslContext → SslStream
├── from_server.rs      — TacacsPlusServer PSK selection + connection establishment
├── tls13_epsk.rs       — validation/accessors for the YANG TLS 1.3 EPSK node
├── ffi/ — OpenSSL TLS 1.3 PSK callback + SSL_SESSION FFI bridge
└── readme.md           — this file
```

### Data Flow

```
TacacsPlusServer (YANG config)
        │
        ▼
from_server::establish_from_server()
        │  selects client-identity.tls13-epsk
        ▼
PskClientConfig::prepare(epsk)
        │  validates EPSK fields and builds the OpenSSL context before async handshake work
        │
        ▼
      context::create_psk_ssl_context()
        │  SslContext: TLS 1.3 only, VERIFY_NONE, PSK use-session callback,
        │  hash-matched ciphersuite, optional psk-dhe-ke groups
        ▼
PskClientConfig::connect(address, tcp_stream)
        │  OpenSSL performs TLS 1.3 PSK handshake
        ▼
SslStream<TcpStream> implements Transport
        │
        ▼
tokio::io::split() → (ReadHalf, WriteHalf)
```

### OpenSSL PSK Callback

The `openssl` crate's safe callback API only covers the legacy TLS 1.2-style PSK
callback and cannot attach the digest required by a TLS 1.3 external PSK. This
module therefore registers OpenSSL's TLS 1.3 `SSL_CTX_set_psk_use_session_callback`
directly and stores callback state in `SSL_CTX` ex-data.

When OpenSSL asks for the client PSK session, the callback:

1. Verifies the requested digest matches the configured EPSK hash.
2. Looks up the configured TLS 1.3 ciphersuite using OpenSSL standard names.
2. Looks up the configured TLS 1.3 ciphersuite using OpenSSL standard names.
3. Builds a synthetic `SSL_SESSION` with TLS 1.3, the selected cipher, and the
  PSK bytes copied as the session master key.
4. Returns the PSK identity bytes and transfers the new `SSL_SESSION` to OpenSSL.

This is the client-side counterpart to server implementations that use
`SSL_CTX_set_psk_find_session_callback`, such as the .NET OpenSSL proof of
concept in `Networking-AAA/src/OpenSsl`.

### Transport Trait

`tokio_openssl::SslStream<TcpStream>` implements the crate's `Transport` trait
by splitting via `tokio::io::split()` for concurrent read/write processing.
Unlike `tokio::net::TcpStream::into_split()` (which yields owned halves),
`tokio::io::split()` yields borrowed halves behind a lock — this is necessary
because `SslStream` does not support owned splitting.

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Key length | EPSK validation rejects keys shorter than 16 bytes (128 bits) per RFC 9257 §6 |
| Identity injection | NUL bytes in identity are rejected before OpenSSL callback registration |
| Forward secrecy | An empty `tacacsrs:psk-dhe-ke-groups` list configures OpenSSL to allow and prefer PSK-only key exchange. Configure one or more groups to negotiate `psk_dhe_ke` and add ephemeral (EC)DHE key material. |
| Unsupported groups | OpenSSL group-list setup errors are surfaced before the handshake with the configured group list in the message. |
| Certificate verification | Explicitly set to `SslVerifyMode::NONE` — intentional for PSK, where authentication comes from the shared secret, not certificates |
| Key logging | The PSK transport does not log key material. The generated `Tls13Epsk` model contains inline key bytes, so do not debug-log the full model. |
| Ciphersuites | Restricted to the configured EPSK hash: SHA-256 uses `TLS_AES_128_GCM_SHA256`; SHA-384 uses `TLS_AES_256_GCM_SHA384` |

## Feature Flag

This entire module is gated behind `#[cfg(feature = "psk")]`. Without it, the
build uses rustls (pure Rust) and requires no OpenSSL dependency. The feature
propagates: `tacon` → `tacacsrs-networking` → OpenSSL.

## References

- **RFC 8446** — The Transport Layer Security (TLS) Protocol Version 1.3
  - §2.2: Resumption and Pre-Shared Key (PSK) — handshake flow
  - §4.2.11: Pre-Shared Key Extension — wire format, binders, hash requirements
  - §7.1: Key Schedule — how PSK feeds into traffic key derivation
- **RFC 9257** — Guidance for External Pre-Shared Key (PSK) Usage in TLS
  - §6: Key provisioning requirements (≥128-bit entropy)
- **RFC 9258** — Importing External Pre-Shared Keys (PSKs) for TLS 1.3
  - §3: target-protocol, target-kdf fields
  - §5.1: context field for anti-reflection
- **RFC 9887** — TACACS+ over TLS 1.3
  - §5.1: TLS version and cipher requirements for TACACS+
- **RFC 9950** — YANG Data Model for TACACS+ (revision 2026-03-31)
  - Defines the `tls13-epsk` grouping and `server-auth-tls13-epsk` feature
- **ietf-tls-client@2024-10-10.yang** (RFC 9645)
  - `client-ident-tls13-epsk` feature: client presents EPSK identity
  - `server-auth-tls13-epsk` feature: client trusts server via PSK
- **ietf-system-tacacs-plus@2026-03-31.yang** (RFC 9950)
  - `grouping tls13-epsk`: the EPSK tuple configuration
  - `leaf tls13-epsks` in `server-authentication`: the trust policy flag
