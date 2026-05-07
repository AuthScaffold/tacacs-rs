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
}
```

This configures the actual EPSK tuple `(Base Key, External Identity, Hash)` that
the client offers in the TLS handshake. The `external-identity` is the label
sent in the `pre_shared_key` ClientHello extension; the base key is the shared
secret.

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

Our implementation currently uses PSK-only mode (no `key_share`), so there is no
forward secrecy. This is noted in the Security Considerations table below.

The YANG configuration model (RFC 9645 / RFC 9950) provides **no knob** to
control this. The `hello-params-grouping` from `ietf-tls-common` contains only
`tls-versions` (min/max) and `cipher-suites` (ordered list) — there is no
`psk_key_exchange_modes`, `supported_groups`, or `key_share` configuration. The
`psk-key-exchange-mode` typedef exists in `iana-tls-profile@2025-04-18.yang` but
is only consumed by the MUD/ACL traffic-matching model, not by the TLS client
configuration model. Therefore, the choice between `psk_ke` (PSK-only) and
`psk_dhe_ke` (PSK + (EC)DHE) is entirely an implementation decision, invisible
to the YANG configuration layer. If forward secrecy is desired in the future, it
can be hardcoded in the OpenSSL context setup without any YANG model changes.

### Practical Guidance

In practice, when configuring EPSK for TACACS+, the `tls13-epsks` leaf in
`server-authentication` should always be present: it declares that PSK-based
server auth is acceptable, which is the only kind possible when the PSK is
accepted.

## Implementation Architecture

```
tls_psk/
├── mod.rs              — crate-internal API surface + create_psk_ssl_context()
├── config_builder.rs   — PskConfigurationBuilder: SslContext → SslStream
├── from_server.rs      — YANG config → PskIdentity + handshake orchestration
├── psk_identity.rs     — PskIdentity type (identity label + key bytes)
├── tls_psk.rs          — Transport trait impl for SslStream<TcpStream>
└── readme.md           — this file
```

### Data Flow

```
TacacsPlusServer (YANG config)
        │
        ▼
from_server::establish_from_server()
        │  extracts external-identity + cleartext-symmetric-key
        ▼
PskIdentity::new(identity, key)
        │  validates: non-empty, no NUL, key ≥ 16 bytes
        ▼
PskConfigurationBuilder::new(psk)
        │
        ▼
create_psk_ssl_context()
        │  SslContext: TLS 1.3 only, VERIFY_NONE, PSK callback
        ▼
SslStream::connect(tcp_stream)
        │  OpenSSL performs TLS 1.3 PSK handshake
        ▼
SslStream<TcpStream> implements Transport
        │
        ▼
tokio::io::split() → (ReadHalf, WriteHalf)
```

### OpenSSL PSK Callback

The `set_psk_client_callback` closure is invoked by OpenSSL during the handshake
when it needs PSK material. It writes:

1. The identity string (null-terminated) into the identity buffer — this becomes
   the `PskIdentity.identity` field in the `pre_shared_key` extension.
2. The raw key bytes into the PSK buffer — OpenSSL uses this to compute the
   binder HMAC and derive traffic keys.

### Transport Trait

`tokio_openssl::SslStream<TcpStream>` implements the crate's `Transport` trait
by splitting via `tokio::io::split()` for concurrent read/write processing.
Unlike `tokio::net::TcpStream::into_split()` (which yields owned halves),
`tokio::io::split()` yields borrowed halves behind a lock — this is necessary
because `SslStream` does not support owned splitting.

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Key length | `PskIdentity::new()` rejects keys shorter than 16 bytes (128 bits) per RFC 9257 §6 |
| Identity injection | NUL bytes in identity are rejected (OpenSSL uses C strings) |
| Forward secrecy | Current implementation uses PSK-only mode (no `key_share`). Traffic keys are only as secure as the PSK. If the PSK is compromised, all past sessions using it can be decrypted. |
| Certificate verification | Explicitly set to `SslVerifyMode::NONE` — intentional for PSK-only, where authentication comes from the shared secret, not certificates |
| Key logging | `PskIdentity` implements a custom `Debug` that redacts the key bytes |
| Ciphersuites | Restricted to `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256` (AEAD-only, no CBC) |

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
