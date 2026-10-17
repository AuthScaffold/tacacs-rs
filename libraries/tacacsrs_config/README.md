# tacacsrs-config

`tacacsrs-config` provides TACACS+ configuration support using the RFC 7951 JSON encoding of the `ietf-system-tacacs-plus` YANG module.

## What this crate contains

- Generated Rust types in `src/generated.rs` that mirror the expanded YANG tree
- Generated enums for YANG enumerations and `identityref` leaves (key format types)
- Validation logic for YANG-specific constraints and semantic checks on inline key material
- Configuration-local credential bundle validation
- Per-server bundle enumeration helpers for `client-credentials` and `server-credentials`
- Secret-free inspection of central keystore and truststore references on enumerated servers
- Provider request planning and transactional materialization under `prepare`
- Canonical local-service policy parsing and validation under `policy`
- YANG-to-endpoint projection with native TLS credential validation
- Source contracts, snapshot deltas, and static configuration under `source`
- CLI input normalization, credential-file loading, and file watching under `input`
- A reusable `TacacsPlusServerBuilder` for constructing `TacacsPlusServer` values in code
- A project-owned YANG augmentation for TLS 1.3 PSK DHE key exchange group selection

`tacacsrs-credential-resolution` defines provider-neutral requests, material, and resolver contracts.
This crate owns their conversion to and from canonical YANG fields. Provider implementations remain outside configuration.

## Parsing API

```rust
use tacacsrs_config::{enumerate_servers, parse_yang_json};

let config = parse_yang_json(json_str)?;
let servers = enumerate_servers(&config)?;
# anyhow::Ok::<()>(())
```

The primary entry points are:

- `parse_yang_json(&str)` — parse and structurally validate a JSON string without mutating credential references
- `parse_yang_json_file(&Path)` — file-based wrapper around `parse_yang_json`
- `validate_credential_references(&TacacsPlus)` — validate configuration-local `credentials-reference` links into shared bundles
- `enumerate_servers(&TacacsPlus)` — inline shared credential bundles onto each `TacacsPlusServer`
- `enumerate_server(&TacacsPlus, &str)` — inline shared credential bundles for one named server
- `inspect_central_references(&TacacsPlusServer)` — inspect opaque central references without retrieving secret material

Enumerate servers before calling `prepare::resolution_plan`.
Planning rejects unresolved configuration-local bundle references with an enumerate-first error.

## Multi-layer design

This crate implements a three-layer design to support both round-tripping (for configuration reporting) and safe credential access:

### 1) Raw YANG (non-destructive)

```rust
use tacacsrs_config::pipeline;

let raw_config = pipeline::parse_root_json(json_str)?;
// raw_config is unchanged; credential references are still present as-is
// Safe for round-tripping, logging, and reporting
```

If you need the submitted root YANG model, use this API for round trips, reports, or custom processing.

### 2) Configuration-local bundle enumeration

Credential references in YANG can point to shared bundles inside the same configuration:
- **Bundles** (`client-credentials`, `server-credentials`) in the same configuration

Use this crate to validate and inline only those local references:

```rust
use tacacsrs_config::{enumerate_server, parse_yang_json, validate_credential_references};

let config = parse_yang_json(json_str)?;
validate_credential_references(&config)?;

let server = enumerate_server(&config, "primary")?;
```

### 3) Central credential resolution

Pass each enumerated server to `prepare::resolution_plan`.
The planner maps central references to deterministic provider requests without changing their values.
A `CredentialResolver` returns typed material, and `resolve_plan` validates the complete slot/variant-matched result set.

For complete materialization, call `prepare::enumerate_materialized_servers` with a source snapshot, resolver, and validation options.
This function enumerates local bundles, resolves central requests, installs provider results, and validates the complete candidate set.
It leaves the source snapshot and its references unchanged.
`prepare::materialize_server` and `prepare::materialize_servers` accept servers whose local bundles are already expanded.

Central references are opaque in both generic crates. They can contain spaces, slashes, traversal-like text, or provider-defined syntax.

`tacacsrs-config` enforces the generated YANG structure and inline-versus-central choices. It does not apply SONiC identifier grammar or map references to paths.

Materialization does not inspect provider paths or permissions. It delegates secret retrieval to the supplied resolver.
The separate `input` module loads CLI credential files and observes file-backed configuration.

The SONiC integration layer supplies a resolver. It does not interpret generated fields during provider lookup.

### 4) Native Endpoint Preparation

Call `prepare::prepare_endpoint` with a materialized server and `prepare::PrepareOptions`.
The source snapshot must first pass schema validation with its selected validation options.
Configuration maps the YANG transport choice, certificate encodings, PSK hash, ordered groups, expected peer identity, and optional SNI into networking inputs.
Networking validates borrowed DER and PSK material and constructs private reusable TLS contexts.
The resulting `PreparedEndpoint` contains no generated model or source reference.

Preparation derives the TCP connection timeout from the canonical server's `timeout` leaf, in seconds.
`PrepareOptions` has no timeout override. It selects preflight and an explicit development-only certificate-verification override.
These controls are not serialized configuration and do not change the source snapshot.
The timeout bounds TCP connection establishment, not TLS handshakes or complete requests.
`PreparedEndpoint::connection_timeout` exposes the prepared value for inspection.

Callers must replace networking `ConnectOptions` with `prepare::PrepareOptions` at this API boundary.
Set a different timeout in the canonical YANG source or with `TacacsPlusServerBuilder::with_timeout` before preparation.
Schema-free native callers can still use networking `ConnectOptions` with `PreparedEndpoint::tcp`.

Certificate TLS verifies the configured `domain-name`, or `address` when no domain is configured, against the peer's DNS or IP subject alternative name.
Verification remains active when SNI is disabled. CN fallback and partial-label wildcard matches are disabled.
The `sni-enabled` field controls only the optional DNS name sent in the TLS `ClientHello`.
An omitted or false value sends no SNI. A true value requires `domain-name`.
Native callers pass the expected peer identity and optional SNI name separately to `PreparedEndpoint::with_certificate_tls`.
This replaces the earlier chain-only check and can reject previously accepted certificates that lack a matching SAN.
The explicit development verification override still disables certificate verification. It does not change SNI selection.

Certificate trust roles remain distinct during preparation:

- `ca-certs` permits a valid certificate path to a configured authority.
- `ee-certs` permits an exact DER certificate match, not another certificate with the same key or issuer.
- Both sets are additive. An exact peer entry cannot authorize certificates that it issued, but an independent CA path can still succeed.
- Explicit bags must contain materialized certificates. Empty bags fail even when the development verification override is selected.
- If neither bag is selected, the existing server-authentication-only API uses platform trust. Selecting either bag excludes platform roots.

Native callers now pass `CertificateTrust::Platform` or `CertificateTrust::Certificates` to `PreparedEndpoint::with_certificate_tls` instead of an undifferentiated root iterator.
The explicit variant separates authority DER from exact peer DER. Its collections cannot both be empty.
OpenSSL still enforces peer identity, validity, purpose, and path checks. The trust-role callback never changes failed native verification into success.
Direct trust accepts a CA-signed leaf without requiring its issuer. A renewed certificate with the same key needs a new exact entry or CA trust.
These changes do not add revocation retrieval or client certificate-chain provisioning.

Each certificate field contains exactly one DER certificate. Native preparation rejects concatenated certificates and trailing bytes, including with verification disabled.
CLI PEM input likewise requires exactly one certificate. DER input is normalized without modification, then checked during native preparation.
The generic certificate-with-key provider result contains one end-entity certificate. Trust bags can contain multiple individually encoded certificates with distinct names.
Provisioning a client chain needs a separate canonical/provider contract. It is not supported by concatenating certificates into `cert-data`.

Separate client public-key metadata must include both its bytes and format.
Preparation supports one DER SPKI value matching the certificate key and rejects SSH encoding, missing metadata, mismatches, and trailing data.
The certificate and private key must also agree. The development verification override does not bypass material validation.
Native `CertificateIdentity` now includes optional `public_key_info` for this validated metadata path.

The optional server `tls13-epsks` selector uses `Option<YangEmpty>` and RFC 7951 `[null]` encoding, not `Option<bool>`.
Presence requires a client EPSK identity after enumeration. Certificate trust bags alongside client EPSK are explicitly rejected by runtime readiness.
The canonical root parser consumes the complete JSON document and rejects trailing input.

Pass this endpoint to `TacacsClient::connect_prepared`.
With preflight disabled, construction does not open a connection. Native material errors still fail during preparation.
The old networking `connect` and `connect_shared` constructors are removed.

Before publishing a complete materialized server set, call `prepare::validate_materialized_servers` with the source's validation options.
This shared check rejects invalid choices, duplicate names or endpoints, unresolved credentials, and unsupported runtime fields.
An empty runtime set is permitted so a service can wait for configuration. Parsed YANG documents still require a nonempty server list.
Each changed endpoint must also finish native context construction before the generation becomes active.

Runtime preparation rejects `source-ip`, `source-interface`, and `vrf-instance` because the transport does not implement binding through those fields.
It also rejects PSK derivation fields and `one-symmetric-key-format`, which the native PSK path does not implement.
Schema-valid source values remain available for reports and round trips. Validation relaxations do not enable these unsupported transport capabilities.

### Module-oriented API (recommended for most users)

This crate also exposes grouped modules so callers can choose APIs by intent:

- `builders` — programmatic construction helpers for `TacacsPlusServer`
- `model` — YANG-generated types and namespaces
- `extensions` — helper traits layered over generated model types
- `pipeline` — step-by-step processing
- `runtime` — bundle enumeration (`enumerate_server`, `enumerate_servers`)
- `prepare` — provider request planning, materialization, candidate validation, and native endpoint projection
- `source` — configuration source contract, snapshot deltas, runtime policy, and change streams
- `input` — parsed CLI inputs, PEM/DER normalization, YANG file loading, and file-backed sources
- `stats` — runtime stats types

For simple end-to-end usage with credential bundles defined directly in the configuration:

```rust
use tacacsrs_config::{parse_yang_json, runtime};

let config = parse_yang_json(json_str)?;
let servers = runtime::enumerate_servers(&config)?;
```

The existing flat root exports remain available for compatibility.

## Runtime Policy Resource

The project module defines `tacacsrs:runtime-policy` as a system-level YANG augmentation.
It specifies local-service failover strategies, recovery seconds, and per-operation body and concurrency limits.
It is separate from the ordered upstream server resource.

`policy::parse_runtime_policy` parses the module-qualified RFC 7951 resource and rejects unknown fields and invalid ranges.
The generated `tacacsrs::RuntimePolicy` retains absent operation containers as `None`.
Consumers use their generated defaults when preparing runtime behavior without changing the source value.
`policy::validate_runtime_policy` also validates programmatically constructed generated values.

The YANG defaults are 30 recovery seconds, deferred failover, and 64 concurrent requests per operation.
Authentication defaults to a 4096-byte body limit. Authorization and accounting default to 16384 bytes.
The runtime derives these defaults from generated types rather than independent constants.

## Local Service Resource

`tacacsrs:local-services` defines startup service selection, listener endpoints, and Unix socket permissions under `ietf-system:system`.
`local_services::parse_local_services` parses its module-qualified RFC 7951 resource and rejects unknown fields and invalid values.
`local_services::prepare_local_services` borrows the generated source and returns immutable `PreparedLocalServices` bind targets.
It performs no network or filesystem I/O. The source remains unchanged.

The default enables the client API at `/run/tacacs/tacacs.sock` with mode `0660` and disables the raw proxy.
Permissions use decimal numbers in JSON. Unix listener paths use absolute Linux syntax and at most 107 bytes.
Preparation rejects inconsistent service selection, invalid permissions, and lexical endpoint collisions before binding.
It does not resolve symlink aliases. TCP proxy targets accept numeric addresses, including wildcard and ephemeral-port bindings.
Runtime listeners still report filesystem permissions, occupied addresses, and other bind-time failures.

Agent callers now supply `ServiceConfig::local_services`, not independent service flags, IPC endpoints, or socket modes.
The agent prepares this source before startup and stores the resulting targets privately.
Process runtime settings remain separate from this resource.

### Downstream Credentials

`LocalServices::proxy_credential_source` selects `unobfuscated`, `inline`, or `local-proxy-row` behavior.
Inline mode requires `proxy_shared_secret`. Generated code uses a redacted, zeroizing `SecretString` for that leaf.
Other modes reject the inline field. Credential-bearing modes require an enabled proxy.

`proxy_policy::prepare_proxy_policy` derives immutable `PreparedProxyPolicy` material without changing the source.
For row-derived mode, the adapter supplies the first matching row in canonical server order before removing self-looping upstreams.
Preparation rejects missing or empty credentials. Inline and unobfuscated modes ignore row credentials, so filtering cannot override explicit policy.
The runtime type has private state and no serialization. Its unavailable state rejects access rather than returning a plaintext policy.

The agent no longer accepts an independent `ServiceConfig::proxy_downstream_obfuscation` field or the old mutable credential enum.
Startup derives inline or unobfuscated policy directly from the canonical source.
Row-derived startup uses `waiting_for_configuration`, followed by publication of the adapter's prepared policy and upstream set.
Publication rejects unavailable policy and retains the previous generation on failure.
This contract uses existing inline and source-row material. It does not add a new central credential provider or change upstream EPSK resolution.

## Configuration Sources

`source::ConfigDatastore` supplies canonical YANG snapshots through `load` and change events through `subscribe`.
Every accepted change contains the complete snapshot. Consumers can use its delta, but the delta does not replace authoritative configuration.
`source::StaticDatastore` holds one caller-validated snapshot and returns an empty subscription stream.
The source contract also carries validation options and initial-load and subscription policies.

`input::CliDatastoreInput` accepts parsed executable inputs without depending on clap.
`input::tacacs_plus_from_cli_input` converts those inputs into a validated YANG snapshot through the canonical builders and validation rules.
These input values are adapters, not a second desired-configuration schema.

For an omitted input port, shared configuration defaults select 49 for legacy TCP and 300 for certificate or PSK TLS.
Explicit ports remain unchanged. Malformed explicit ports fail instead of selecting a default.
The pinned YANG model requires a port, so canonical snapshots and programmatic server builders retain explicit port values.

`input::CliFileDatastore` implements the same source contract for CLI and file inputs.
It watches a YANG file or referenced CLI certificate and key files when applicable.
Subscriptions install observation before loading and publishing their baseline snapshot.
Rejected reloads emit `CandidateRejected` without replacing the previous accepted snapshot.
On Linux, native notifications keep idle file observations passive without timer wakes or periodic filesystem checks.
On Windows, each file observation checks the captured directory identity every 100 ms.
Directory removal, rename, or replacement ends the observation with an error.
Dropping the observation stops its native watcher and any Windows identity checks. No detached monitor remains.
Inputs with no watched paths have an empty subscription stream.

```rust
use tacacsrs_config::input::{CliConfigSource, CliDatastoreInput, CliFileDatastore};
use tacacsrs_config::source::ConfigDatastore;

# async fn load() -> anyhow::Result<()> {
let source = CliFileDatastore::new(CliDatastoreInput::new(
  CliConfigSource::YangFile { path: "tacacs.json".into() },
  "file",
));
let snapshot = source.load().await?;
# Ok(())
# }
```

The separate `tacacsrs-datastore` and `tacacsrs-cli-datastore` packages are removed.
Consumers import `tacacsrs_config::source` and `tacacsrs_config::input` directly.
This consolidation preserves the load and observation contracts. File sources use owned observation sessions.

## Programmatic builder API

When callers need to construct TACACS+ server definitions in Rust instead of parsing RFC 7951 JSON, use `TacacsPlusServerBuilder`.

CLI callers previously duplicated these defaulting and security-shape choices. The builder now centralizes them:

- `TacacsPlusServerBuilder::new(...)` — create a server with standard defaults
- `with_timeout(...)` — override the default timeout
- `with_shared_secret(...)` — select obfuscation mode
- `with_tls_client_certificate(...)` — select TLS with an inline client certificate and private key
- `with_tls13_epsk(...)` — select TLS 1.3 PSK mode
- `with_tls_server_authentication()` — select TLS without a client identity by enabling the server-authentication container

Example:

```rust
use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerExt, TacacsPlusServerType};

let server = TacacsPlusServerBuilder::new(
  "primary",
  TacacsPlusServerType::ACCOUNTING,
  "192.0.2.10",
  49,
)
.with_timeout(10)
.with_shared_secret("super-secret")
.build();

assert_eq!(server.socket_address(), "192.0.2.10:49");
assert!(server.is_obfuscation());
# anyhow::Ok::<(), anyhow::Error>(())
```

The builder is intentionally small. Use it for runtime construction of valid server shapes. It does not replace schema validation or full YANG parsing.

### Central crypto integration boundary

The intended long-term split is:

- `tacacsrs-config` stays as the open configuration model. It owns RFC 7951 parsing, schema validation, bundle enumeration, and generated YANG types.
- Small derived helpers that are valid before and after secret resolution belong here, in `extensions`, on top of `TacacsPlusServer` and other generated types.
- `tacacsrs-credential-resolution` consumes typed request plans and returns closed provider-neutral result sets. It does not depend on configuration.
- `prepare` maps YANG references and provider metadata, then validates materialized candidates without changing authoritative snapshots.
- `prepare_endpoint` projects the materialized YANG server into explicit networking inputs.
- Networking owns native context construction and execution. It has no dependency on configuration or credential providers.

This separation keeps the generated configuration model suitable for round trips and reports. Runtime code receives only the normalized fields that it needs for connections.

## Examples

The crate includes runnable examples under `examples/`:

- `quick_start.rs` — parse + validate + enumerate using the root exports plus `runtime`
- `quick_start_credential_refs.rs` — minimal end-to-end example showing bundle validation and enumeration
- `pipeline_flow.rs` — explicit step-by-step parse/enumerate/external-resolution pipeline
- `model_access.rs` — direct access to generated model types and flags
- `central_resolution.rs` — YANG planning and provider-neutral resolution with a fake resolver
- `single_transaction.rs` and `multiple_transactions.rs` — configured accounting clients
- `tls_client.rs` and `tls_psk_client.rs` — certificate TLS and PSK clients

Run examples from the workspace root:

```bash
cargo run -p tacacsrs-config --example quick_start
cargo run -p tacacsrs-config --example quick_start_credential_refs
cargo run -p tacacsrs-config --example pipeline_flow
cargo run -p tacacsrs-config --example model_access
cargo run -p tacacsrs-config --example central_resolution
```

## Public API surface

This crate intentionally exposes both:

- a high-level, opinionated parsing pipeline for most callers
- the full generated YANG model and lower-level helpers for advanced integrations

### 1) High-level parse + validate + enumerate workflow

These are the recommended entry points for application code:

- `parse_yang_json(&str) -> anyhow::Result<TacacsPlus>`
- `parse_yang_json_file(&Path) -> anyhow::Result<TacacsPlus>`
- `validate_credential_references(&TacacsPlus) -> anyhow::Result<()>`
- `enumerate_servers(&TacacsPlus) -> anyhow::Result<Vec<TacacsPlusServer>>`
- `enumerate_server(&TacacsPlus, &str) -> anyhow::Result<TacacsPlusServer>`

`parse_yang_json()` deserializes the JSON and validates YANG constraints. These constraints include server presence, unique addresses, SNI requirements, and key formats.

The function returns the configuration **without mutations**. Credential references remain intact for round trips.

Validation checks include:

- At least one server is present
- Server addresses and ports are unique
- SNI-enabled servers have domain names
- Security choice constraint: choose TLS or obfuscation, not both. Strict mode requires one of them.
- YANG choice constraints across all credential subtrees
- Key format identity values (`private-key-format`, `public-key-format`, `key-format`) are valid RFC 7951 identityref strings
- Inline key material (`cleartext-private-key`, `public-key`, `cert-data`, `cleartext-symmetric-key`) is valid base64-encoded binary data. The crate carries certificates and private keys internally as DER bytes.
- Credential references have matching definitions in the same configuration
- Configuration-local credential references have matching definitions

To resolve central credentials, create a `ResolutionPlan` after enumeration. Submit the plan to a `CredentialResolver`.

Then materialize the results into generated inline fields. Provider I/O remains outside both generic crates.

This design separates parsing/validation from credential retrieval and enables round-trip safety.

### 1b) Programmatic server construction

For code paths that do not start from RFC 7951 JSON, use:

- `TacacsPlusServerBuilder::new(...) -> TacacsPlusServerBuilder`
- `TacacsPlusServerBuilder::with_timeout(...) -> TacacsPlusServerBuilder`
- `TacacsPlusServerBuilder::with_shared_secret(...) -> TacacsPlusServerBuilder`
- `TacacsPlusServerBuilder::with_tls_client_certificate(...) -> TacacsPlusServerBuilder`
- `TacacsPlusServerBuilder::with_tls13_epsk(...) -> TacacsPlusServerBuilder`
- `TacacsPlusServerBuilder::with_tls13_epsk_with_psk_dhe_groups(...) -> TacacsPlusServerBuilder`
- `TacacsPlusServerBuilder::with_tls13_epsk_psk_only(...) -> TacacsPlusServerBuilder`
- `TacacsPlusServerBuilder::with_tls_server_authentication() -> TacacsPlusServerBuilder`
- `TacacsPlusServerBuilder::build() -> TacacsPlusServer`

This is the supported way to create `TacacsPlusServer` values in application code without manually repeating the crate's default field setup.
`with_tls13_epsk(...)` uses PSK-DHE by default with preferred groups
`secp384r1,secp256r1`. Use `with_tls13_epsk_psk_only(...)` only for
interoperability with peers that cannot negotiate PSK-DHE.

### 2) Advanced: Generated YANG model and pipeline API

For advanced use cases, these lower-level functions are available:

- `pipeline::parse_root_json()` - Parse JSON into raw generated types without validation
- `pipeline::parse_root_json_file()` - File-based raw parse into the generated root type without validation
- `generated` module - Full generated type graph for schema-aware integrations

### 3) Runtime types

Secret-bearing result types live in `tacacsrs-credential-resolution`. Connection-ready server types remain outside `tacacsrs-config`.
Shared derived helpers for the generated server model live in `TacacsPlusServerExt`.
Programmatic construction helpers for the generated server model live in `TacacsPlusServerBuilder`.

Runtime statistics are exposed separately via:

- `ServerStatistics`
- `stats` module

### 4) Generated YANG model (advanced use)

The generated model is intentionally public for schema-aware or tooling-heavy integrations:

- `generated` module (full generated type graph)
- Re-exported submodules: `keystore`, `truststore`, `crypto_types`
- Re-exported root: `YangConfigRoot`
- Re-exported common TACACS+ model types, including:
  - `TacacsPlus`
  - `TacacsPlusServer`
  - `TacacsPlusServerType`
  - `ClientCredentials`
  - `ServerCredentials`
  - `TlsClientClientIdentity`
  - `TlsClientServerAuthentication`
  - `ClientIdentityCertificate`
  - `Tls13Epsk`
  - `ServerAuthenticationCaCerts`
  - `EpskSupportedHash`
  - `TacacsPlusServerExt`
  - `TacacsPlusServerBuilder`

### 5) Generated enum helper types

Generated YANG enumeration and `identityref` enums provide:

- `ALL` — list of all valid identities
- `ALLOWED_VALUES` — RFC 7951 JSON string values
- `as_rfc7951_str()` — convert enum to the canonical JSON string
- `from_rfc7951_str(&str)` — parse an RFC 7951 string into the enum
- `is_valid(&str)` — report whether a string is valid

Available identity sets:

- `crypto_types::PrivateKeyFormat` — `rsa-private-key-format`, `ec-private-key-format`, `one-asymmetric-key-format`
- `crypto_types::PublicKeyFormat` — `ssh-public-key-format`, `subject-public-key-info-format`
- `crypto_types::SymmetricKeyFormat` — `octet-string-key-format`, `one-symmetric-key-format`

`plugins/yang2rust.py` generates these values from the YANG identity hierarchy. Fixed-set `identityref` fields use these enums in the generated structure.

Unknown RFC 7951 strings fail during deserialization instead of later validation.

## Inline key format identities

When configuring TLS with inline key material, several fields indicate the encoding format of the key data. These are YANG `identityref` leaves whose values come from the `ietf-crypto-types` module (RFC 9640). Values in RFC 7951 JSON are module-qualified strings.

### `private-key-format`

Used in `EndEntityCertWithKeyInlineDefinition` (the inline definition for certificate client identities). Indicates how the private key binary is encoded.

| JSON value | Meaning |
|---|---|
| `ietf-crypto-types:rsa-private-key-format` | RSAPrivateKey (RFC 8017), DER-encoded |
| `ietf-crypto-types:ec-private-key-format` | ECPrivateKey (RFC 5915), DER-encoded |
| `ietf-crypto-types:one-asymmetric-key-format` | CMS OneAsymmetricKey (RFC 5958), DER-encoded *(feature-gated)* |

### `public-key-format`

Used alongside `private-key-format` in `EndEntityCertWithKeyInlineDefinition`. Indicates how the public key binary is encoded.

| JSON value | Meaning |
|---|---|
| `ietf-crypto-types:subject-public-key-info-format` | SubjectPublicKeyInfo (RFC 5280), DER-encoded |
| `ietf-crypto-types:ssh-public-key-format` | SSH public key (RFC 4253 §6.6) |

The TACACS+ YANG model constrains `public-key-format` to `subject-public-key-info-format` for TLS client identity and server authentication paths.

### `key-format`

Used in `SymmetricKeyInlineDefinition` (the inline definition for TLS 1.3 external PSKs). Indicates how the symmetric key binary is encoded.

| JSON value | Meaning |
|---|---|
| `ietf-crypto-types:octet-string-key-format` | Raw octet string, length must match the algorithm's block size |
| `ietf-crypto-types:one-symmetric-key-format` | CMS OneSymmetricKey (RFC 6031), DER-encoded *(feature-gated)* |

### Example: TLS with inline certificate

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "server": [
      {
        "name": "tls-inline",
        "server-type": "authentication",
        "address": "192.0.2.1",
        "port": 49,
        "domain-name": "tacacs.example.com",
        "sni-enabled": true,
        "client-identity": {
          "certificate": {
            "inline-definition": {
              "public-key-format": "ietf-crypto-types:subject-public-key-info-format",
              "public-key": "BASE64VALUE=",
              "private-key-format": "ietf-crypto-types:rsa-private-key-format",
              "cleartext-private-key": "BASE64VALUE=",
              "cert-data": "BASE64VALUE="
            }
          }
        },
        "server-authentication": {
          "ca-certs": {
            "inline-definition": {
              "certificate": [
                {"name": "CA-1", "cert-data": "BASE64VALUE="}
              ]
            }
          }
        }
      }
    ]
  }
}
```

## Project TACACS+/TLS augmentation

The repository includes a local YANG module, `tacacsrs`, that augments
the TACACS+ TLS 1.3 EPSK configuration with `psk-dhe-ke-groups`. The
`psk-dhe-ke-hello-params` YANG feature in
`yang/feature-flags.ini` controls the augmentation. To exclude the
extension from generated artifacts, set that entry to `false` before regenerating.

This leaf-list belongs to a different YANG module than its parent, so RFC 7951
JSON uses the module-qualified key
`tacacsrs:psk-dhe-ke-groups`. The value is an ordered array. The TLS client
prefers earlier entries when it builds its ClientHello key shares:

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "server": [
      {
        "name": "tls-psk-dhe",
        "server-type": "accounting",
        "address": "192.0.2.10",
        "port": 49,
        "client-identity": {
          "tls13-epsk": {
            "inline-definition": {
              "cleartext-symmetric-key": "BASE64VALUE="
            },
            "external-identity": "client@example.com",
            "tacacsrs:psk-dhe-ke-groups": [
              "x25519",
              "secp256r1",
              "ffdhe3072"
            ]
          }
        }
      }
    ]
  }
}
```

Supported group values are `x25519`, `secp256r1`, `secp384r1`, `secp521r1`,
`ffdhe2048`, `ffdhe3072`, `ffdhe4096`, `ffdhe6144`, and `ffdhe8192`. Unknown
values fail during JSON deserialization.

## Example configuration

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "server": [
      {
        "name": "primary",
        "server-type": "authentication authorization accounting",
        "address": "192.0.2.2",
        "port": 49,
        "shared-secret": "QaEfThUkO198010075460923+h3TbE8n",
        "timeout": 10
      }
    ]
  }
}
```

## Code generation workflow

The generated Rust types come from the checked-in YANG tooling under `yang/`:

- `yang/plugins/yang2rust.py` — custom `pyang` plugin that emits Rust structs/enums/bitflags, plus helper methods for YANG enumerations and identity set enums from `identityref` leaves
- `yang/expand_yang_tree.py` — helper used to refresh the fully expanded tree reference
- `yang/modules/` — project-owned YANG modules passed to `pyang` alongside the upstream TACACS+ model
- `yang/generated_types.rs` — generator output, produced on demand and copied into `src/generated.rs`

The generator emits Rust enums with `ALL`, `ALLOWED_VALUES`, `as_rfc7951_str()`, `from_rfc7951_str()`, and `is_valid()` helpers. It also resolves `identityref` base identities.

The generator collects derived identities from the loaded modules. Fixed-set `identityref` fields use these enums directly.

YANG `binary` leaves deserialize from RFC 7951 base64 into in-memory `Vec<u8>` values. When the crate writes JSON, it serializes these values to base64.

The higher-level validation logic in `src/validation.rs` is still maintained manually, but enum membership and base64 decoding now happen during deserialization. The handwritten validation layer is therefore focused on semantic checks such as choice rules, non-empty inline material, and TLS-specific policy.

To regenerate after YANG module updates:

```bash
# Install pyang and any other generator requirements.
python -m pip install -r requirements.txt

# Example with a repo-local venv instead of a global install:
# python -m venv .venv
# source .venv/bin/activate
# python -m pip install pyang

cd libraries/tacacsrs_config/yang
python expand_yang_tree.py --list-features
python expand_yang_tree.py --list-features --list-features-format ini > feature-flags.ini
python expand_yang_tree.py --features-ini feature-flags.ini > expanded-tree.txt
python expand_yang_tree.py \
  -f rust \
  --features-ini feature-flags.ini \
  -o generated_types.rs
cp generated_types.rs ../src/generated.rs
```

Run the normal workspace formatting, clippy, build, and test commands after regeneration.
