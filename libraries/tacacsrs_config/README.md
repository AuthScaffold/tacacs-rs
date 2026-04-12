# tacacsrs-config

`tacacsrs-config` provides TACACS+ configuration support using the RFC 7951 JSON encoding of the `ietf-system-tacacs-plus` YANG module.

## What this crate contains

- Generated Rust types in `src/generated.rs` that mirror the expanded YANG tree
- Generated identity set enums for YANG `identityref` leaves (key format types)
- Validation logic for YANG-specific constraints, key format identities, and inline key material
- Config-local credential bundle validation
- Per-server bundle enumeration helpers for `client-credentials` and `server-credentials`

External keystore/truststore validation and secret materialization now live in the separate `tacacsrs-credentials` crate.

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

For external keystore or truststore references, enumerate the servers first and then pass the resulting `TacacsPlusServer` values to `tacacsrs-credentials`.

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

### 3) External secret resolution (separate crate)

External keystore/truststore references are intentionally handled outside this crate.
After enumeration, pass the resulting `TacacsPlusServer` values to `tacacsrs-credentials` for optional external validation and runtime secret materialization.

### Module-oriented API (recommended for most users)

This crate also exposes grouped modules so callers can choose APIs by intent:

- `model` — YANG-generated types and namespaces
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

## Examples

The crate includes runnable examples under `examples/`:

- `quick_start.rs` — parse + validate + enumerate using the root exports plus `runtime`
- `quick_start_credential_refs.rs` — minimal end-to-end example showing bundle validation and enumeration
- `pipeline_flow.rs` — explicit step-by-step parse/enumerate/external-resolution pipeline
- `model_access.rs` — direct access to generated model types and flags
- External secret-resolution example now lives in `tacacsrs-credentials/examples/credential_references.rs`

Run examples from the workspace root:

```bash
cargo run -p tacacsrs-config --example quick_start
cargo run -p tacacsrs-config --example quick_start_credential_refs
cargo run -p tacacsrs-config --example pipeline_flow
cargo run -p tacacsrs-config --example model_access
cargo run -p tacacsrs-config --example credential_references
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
- Security choice constraints (TLS vs obfuscation, not both)
- YANG choice constraints across all credential subtrees
- Key format identity values (`private-key-format`, `public-key-format`, `key-format`) are valid RFC 7951 identityref strings
- Inline key material (`cleartext-private-key`, `public-key`, `cert-data`, `cleartext-symmetric-key`) is valid base64 or PEM
- Credential references have matching definitions in the same config
- Config-local credential references have matching definitions

To resolve external credentials and materialize them for runtime use, use `tacacsrs-credentials` after enumeration.

This design separates parsing/validation from credential retrieval and enables round-trip safety.

### 2) Advanced: Generated YANG model and pipeline API

For advanced use cases, these lower-level functions are available:

- `pipeline::parse_root_json()` - Parse JSON into raw generated types without validation
- `pipeline::parse_root_json_file()` - File-based raw parse into the generated root type without validation
- `generated` module - Full generated type graph for schema-aware integrations

### 3) Runtime types

Runtime secret-materialized server types now live in `tacacsrs-credentials`.

Runtime statistics are exposed separately via:

- `ServerStatistics`
- `stats` module

### 4) Generated YANG model (advanced use)

The generated model is intentionally public for schema-aware or tooling-heavy integrations:

- `generated` module (full generated type graph)
- Re-exported submodules: `keystore`, `truststore`, `crypto_types`, `tls_common`
- Re-exported root: `YangConfigRoot`
- Re-exported common TACACS+ model types, including:
  - `TacacsPlus`
  - `TacacsPlusServer`
  - `TacacsPlusServerType`
  - `ClientCredentials`
  - `ServerCredentials`
  - `TlsClientClientIdentity`
  - `TlsClientServerAuthentication`
  - `TlsClientHelloParams`
  - `ClientIdentityCertificate`
  - `RawPrivateKey`
  - `Tls13Epsk`
  - `ServerAuthenticationCaCerts`
  - `ServerAuthenticationRawPublicKeys`
  - `EpskSupportedHash`

### 5) Generated identity set types

The `crypto_types` module includes generated enums for YANG `identityref` leaves. Each enum provides:

- `ALL` — list of all valid identities
- `ALLOWED_VALUES` — RFC 7951 JSON string values
- `as_rfc7951_str()` — convert enum to the canonical JSON string
- `from_rfc7951_str(&str)` — parse an RFC 7951 string into the enum
- `is_valid(&str)` — check if a string is a valid identity value

Available identity sets:

- `crypto_types::PrivateKeyFormat` — `rsa-private-key-format`, `ec-private-key-format`, `one-asymmetric-key-format`
- `crypto_types::PublicKeyFormat` — `ssh-public-key-format`, `subject-public-key-info-format`
- `crypto_types::SymmetricKeyFormat` — `octet-string-key-format`, `one-symmetric-key-format`
- `crypto_types::EncryptedValueFormat` — `cms-encrypted-data-format`, `cms-enveloped-data-format`

These are generated automatically from the YANG identity hierarchy by `yang2rust.py`. The existing struct fields remain `String`/`Option<String>` for serde compatibility; the enums are additive companion types for validation and programmatic use.

## Inline key format identities

When configuring TLS with inline key material, several fields indicate the encoding format of the key data. These are YANG `identityref` leaves whose values come from the `ietf-crypto-types` module (RFC 9640). Values in RFC 7951 JSON are module-qualified strings.

### `private-key-format`

Used in `EndEntityCertWithKeyInlineDefinition` and `AsymmetricKeyInlineDefinition` (the inline definitions for certificate and raw-private-key client identities). Indicates how the private key binary is encoded.

| JSON value | Meaning |
|---|---|
| `ietf-crypto-types:rsa-private-key-format` | RSAPrivateKey (RFC 8017), DER-encoded |
| `ietf-crypto-types:ec-private-key-format` | ECPrivateKey (RFC 5915), DER-encoded |
| `ietf-crypto-types:one-asymmetric-key-format` | CMS OneAsymmetricKey (RFC 5958), DER-encoded *(feature-gated)* |

### `public-key-format`

Used alongside `private-key-format` in the same inline definitions and in `PublicKeysPublicKey` (raw public keys for server authentication). Indicates how the public key binary is encoded.

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

- `yang/yang2rust.py` — custom `pyang` plugin that emits Rust structs/enums/bitflags and identity set enums from YANG `identityref` leaves
- `yang/expand_yang_tree.py` — helper used to refresh the fully expanded tree reference
- `yang/generated_types.rs` — generator output, produced on demand and copied into `src/generated.rs`
- `yang/plugins/yang2rust.py` — copy of the plugin used by `--plugindir` (avoids loading `expand_yang_tree.py` from the same directory)

The generator automatically resolves `identityref` base identities and walks loaded modules to collect derived identities, emitting companion Rust enums with `ALL`, `ALLOWED_VALUES`, `as_rfc7951_str()`, `from_rfc7951_str()`, and `is_valid()` helpers. Existing `String` field types are preserved for serde compatibility (hybrid approach).

Today, the Rust type graph and identity set enums are generated, but the higher-level validation logic in `src/validation.rs` is still maintained manually. The validation code uses the generated `ALLOWED_VALUES` constants for key format checking. That split is intentional for now: the YANG-derived constraints are manageable in handwritten Rust, and keeping them explicit has made it easier to refine behavior during development.

To regenerate after YANG module updates:

```bash
python -m pip install pyang
cd libraries/tacacsrs_config/yang
python expand_yang_tree.py > expanded-tree.txt
cp yang2rust.py plugins/yang2rust.py
pyang \
  -f rust \
  --plugindir plugins \
  -p .yang-cache/yang-models/standard/ietf/RFC \
  -p .yang-cache/secure-tacacs-yang/yang \
  .yang-cache/secure-tacacs-yang/yang/ietf-system-tacacs-plus.yang \
  .yang-cache/yang-models/standard/ietf/RFC/ietf-keystore@2024-10-10.yang \
  .yang-cache/yang-models/standard/ietf/RFC/ietf-truststore@2024-10-10.yang \
  .yang-cache/yang-models/standard/ietf/RFC/ietf-crypto-types@2024-10-10.yang \
  .yang-cache/yang-models/standard/ietf/RFC/ietf-tls-common@2024-10-10.yang \
  -o generated_types.rs
cp generated_types.rs ../src/generated.rs
```

The `default_tls13_epsk_hash()` function in `generated.rs` requires a manual fixup after regeneration — the generator emits a placeholder comment for enum defaults. Replace the generated body with `EpskSupportedHash::Sha256`.

Run the normal workspace formatting, clippy, build, and test commands after regeneration.
