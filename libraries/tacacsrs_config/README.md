# tacacsrs-config

`tacacsrs-config` provides TACACS+ configuration support using the RFC 7951 JSON encoding of the `ietf-system-tacacs-plus` YANG module.

## What this crate contains

- Generated Rust types in `src/generated.rs` that mirror the expanded YANG tree
- Generated enums for YANG enumerations and `identityref` leaves (key format types)
- Validation logic for YANG-specific constraints and semantic checks on inline key material
- Config-local credential bundle validation
- Per-server bundle enumeration helpers for `client-credentials` and `server-credentials`
- Secret-free inspection of central keystore and truststore references on enumerated servers
- A reusable `TacacsPlusServerBuilder` for constructing `TacacsPlusServer` values in code
- A project-owned YANG augmentation for TLS 1.3 PSK DHE key exchange group selection

External secret resolution is defined by `tacacsrs-credential-resolution`. Provider implementations and runtime materialization remain outside `tacacsrs-config`.

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
- `validate_credential_references(&TacacsPlus)` — validate config-local `credentials-reference` links into shared bundles
- `enumerate_servers(&TacacsPlus)` — inline shared credential bundles onto each `TacacsPlusServer`
- `enumerate_server(&TacacsPlus, &str)` — inline shared credential bundles for one named server
- `inspect_central_references(&TacacsPlusServer)` — inspect opaque central references without retrieving secret material

Enumerate servers before passing them to `tacacsrs-credential-resolution`. Planning rejects unresolved config-local bundle references with an enumerate-first error.

## Multi-layer design

This crate implements a three-layer design to support both round-tripping (for config reporting) and safe credential access:

### 1) Raw YANG (non-destructive)

```rust
use tacacsrs_config::pipeline;

let raw_config = pipeline::parse_root_json(json_str)?;
// raw_config is unchanged; credential references are still present as-is
// Safe for round-tripping, logging, and reporting
```

Use this when you need the root YANG model exactly as submitted for round-tripping, reporting, or further custom processing.

### 2) Config-local bundle enumeration

Credential references in YANG can point to shared bundles inside the same config:
- **Bundles** (`client-credentials`, `server-credentials`) in the same config

Use the config crate to validate and inline only those local references:

```rust
use tacacsrs_config::{enumerate_server, parse_yang_json, validate_credential_references};

let config = parse_yang_json(json_str)?;
validate_credential_references(&config)?;

let server = enumerate_server(&config, "primary")?;
```

### 3) Central credential resolution

Pass each enumerated server to `tacacsrs_credential_resolution::ResolutionPlan::from_server`. The resolution crate extracts deterministic typed requests for central certificate-with-key, TLS 1.3 symmetric key, CA bag, and end-entity bag references. A `CredentialResolver` returns typed material, and `resolve_plan` validates the complete slot/variant-matched result set.

Central references are opaque in both generic crates. They may contain spaces, slashes, traversal-like text, or provider-defined syntax. `tacacsrs-config` enforces generated YANG structure and inline-versus-central choices, but it does not apply SONiC identifier grammar, map references to paths, test existence or permissions, watch files, or retrieve secrets.

P3 provides the SONiC-specific resolver and projects the closed result set into networking inputs.

### Module-oriented API (recommended for most users)

This crate also exposes grouped modules so callers can choose APIs by intent:

- `builders` — programmatic construction helpers for `TacacsPlusServer`
- `model` — YANG-generated types and namespaces
- `extensions` — helper traits layered over generated model types
- `pipeline` — step-by-step processing
- `runtime` — bundle enumeration (`enumerate_server`, `enumerate_servers`)
- `stats` — runtime stats types

For simple end-to-end usage with in-config credential bundles:

```rust
use tacacsrs_config::{parse_yang_json, runtime};

let config = parse_yang_json(json_str)?;
let servers = runtime::enumerate_servers(&config)?;
```

The existing flat root exports remain available for compatibility.

## Programmatic builder API

When callers need to construct TACACS+ server definitions in Rust instead of parsing RFC 7951 JSON, use `TacacsPlusServerBuilder`.

The builder centralizes the same defaulting and security-shape choices that were previously duplicated in CLI callers:

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

The builder is intentionally small. It is meant for runtime construction of valid server shapes, not as a replacement for schema validation or full YANG parsing.

### Central crypto integration boundary

The intended long-term split is:

- `tacacsrs-config` stays as the open configuration model. It owns RFC 7951 parsing, schema validation, bundle enumeration, and generated YANG types.
- Small derived helpers that are valid before and after secret resolution belong here, in `extensions`, on top of `TacacsPlusServer` and other generated types.
- `tacacsrs-credential-resolution` consumes enumerated `TacacsPlusServer` values and returns a closed provider-neutral result set with concrete material.
- Provider implementations and projection into connection-ready networking types remain integration-layer responsibilities.

That keeps the generated config model optimized for round-tripping and reporting, while runtime code gets a provider-agnostic handoff with only the normalized fields needed to connect.

## Examples

The crate includes runnable examples under `examples/`:

- `quick_start.rs` — parse + validate + enumerate using the root exports plus `runtime`
- `quick_start_credential_refs.rs` — minimal end-to-end example showing bundle validation and enumeration
- `pipeline_flow.rs` — explicit step-by-step parse/enumerate/external-resolution pipeline
- `model_access.rs` — direct access to generated model types and flags
- The provider-neutral central-resolution example lives in `tacacsrs-credential-resolution`.

Run examples from the workspace root:

```bash
cargo run -p tacacsrs-config --example quick_start
cargo run -p tacacsrs-config --example quick_start_credential_refs
cargo run -p tacacsrs-config --example pipeline_flow
cargo run -p tacacsrs-config --example model_access
cargo run -p tacacsrs-credential-resolution --example central_resolution
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

`parse_yang_json()` performs deserialization and validation of YANG-derived JSON constraints (server presence, unique addresses, SNI requirements, choice constraints, key format identities, inline key material encoding, etc.). The config is returned **without mutations**—credential references remain intact for round-tripping.

Validation checks include:

- At least one server is configured
- Server addresses and ports are unique
- SNI-enabled servers have domain names
- Security choice constraints (TLS vs obfuscation, not both; strict mode also requires one of them)
- YANG choice constraints across all credential subtrees
- Key format identity values (`private-key-format`, `public-key-format`, `key-format`) are valid RFC 7951 identityref strings
- Inline key material (`cleartext-private-key`, `public-key`, `cert-data`, `cleartext-symmetric-key`) is valid base64-encoded binary data; certificates and private keys are carried internally as DER bytes
- Credential references have matching definitions in the same config
- Config-local credential references have matching definitions

To resolve central credentials, create a `ResolutionPlan` after enumeration, execute it through a `CredentialResolver`, and materialize the results into generated inline fields. Provider I/O remains outside both generic crates.

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
`secp384r1,secp256r1`; use `with_tls13_epsk_psk_only(...)` only for
interoperability with peers that cannot negotiate PSK-DHE.

### 2) Advanced: Generated YANG model and pipeline API

For advanced use cases, these lower-level functions are available:

- `pipeline::parse_root_json()` - Parse JSON into raw generated types without validation
- `pipeline::parse_root_json_file()` - File-based raw parse into the generated root type without validation
- `generated` module - Full generated type graph for schema-aware integrations

### 3) Runtime types

Secret-bearing result types live in `tacacsrs-credential-resolution`; connection-ready server types remain outside `tacacsrs-config`.
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
- `is_valid(&str)` — check if a string is a valid value

Available identity sets:

- `crypto_types::PrivateKeyFormat` — `rsa-private-key-format`, `ec-private-key-format`, `one-asymmetric-key-format`
- `crypto_types::PublicKeyFormat` — `ssh-public-key-format`, `subject-public-key-info-format`
- `crypto_types::SymmetricKeyFormat` — `octet-string-key-format`, `one-symmetric-key-format`

These are generated automatically from the YANG identity hierarchy by `plugins/yang2rust.py`. Fixed-set `identityref` fields now use these enums directly in the generated struct graph, so unknown RFC 7951 strings fail during deserialization instead of being validated later as plain strings.

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
the TACACS+ TLS 1.3 EPSK configuration with `psk-dhe-ke-groups`. The augmentation
is controlled by the `psk-dhe-ke-hello-params` YANG feature in
`yang/feature-flags.ini`; set that entry to `false` before regenerating if the
extension should be excluded from generated artifacts.

Because this leaf-list is added by a different YANG module than its parent, RFC 7951
JSON uses the module-qualified key
`tacacsrs:psk-dhe-ke-groups`. The value is an ordered array; earlier
entries are preferred when the TLS client builds its ClientHello key shares:

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

## Example config

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

The generator emits Rust enums with `ALL`, `ALLOWED_VALUES`, `as_rfc7951_str()`, `from_rfc7951_str()`, and `is_valid()` helpers for YANG enumerations. It also resolves `identityref` base identities and walks loaded modules to collect derived identities with the same helper shape. Fixed-set `identityref` fields use these enums directly, while YANG `binary` leaves deserialize from RFC 7951 base64 into in-memory `Vec<u8>` values and serialize back to base64 when writing JSON.

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
