# tacacsrs-config

`tacacsrs-config` provides TACACS+ configuration support using the RFC 7951 JSON encoding of the `ietf-system-tacacs-plus` YANG module.

## What this crate contains

- Generated Rust types in `src/generated.rs` that mirror the expanded YANG tree
- Validation logic for YANG-specific constraints that must hold after deserialization
- Credential-reference resolution helpers
- Mapping from parsed YANG config into runtime `ServerConnectionConfig` values

## Parsing API

```rust
use tacacsrs_config::{parse_yang_json, parse_yang_json_file, to_connection_configs};

let config = parse_yang_json_file(std::path::Path::new("tacacs.json"))?;
let servers = to_connection_configs(&config)?;
# anyhow::Ok::<(), anyhow::Error>(())
```

The primary entry points are:

- `parse_yang_json(&str)` — parse and validate a JSON string without mutating credential references
- `parse_yang_json_file(&Path)` — file-based wrapper around `parse_yang_json`
- `to_connection_configs(&TacacsPlus)` — map validated YANG data into runtime connection configs

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

### 2) Credential resolvers (pluggable)

Credential references in YANG can point to:
- **Bundles** (`client-credentials`, `server-credentials`) in the same config
- **Central keystores/truststores** managed by the operating system
- **Filesystem** certificates
- **Environment** variables, etc.

Define custom resolvers to handle your credential sources:

```rust
pub enum CredentialRefType {
    ClientCredential,
    ServerCredential,
    Keystore,
    Truststore,
}

pub trait CredentialResolver: Send + Sync {
    /// Resolve a credential reference to inline material
    /// Implementations specialize by CredentialRefType to know which refs to handle
    fn resolve(&self, key: &str, ref_type: CredentialRefType) -> anyhow::Result<Option<String>>;

    /// Validate that a credential reference is resolvable (optional)
    fn validate(&self, key: &str, ref_type: CredentialRefType) -> anyhow::Result<()>;
}
```

### 3) On-demand resolved servers (secret-safe)

Resolve credentials **only when accessing a specific server**, not for the entire config.
This avoids materializing all secrets at once, reducing the risk of accidental leaks:

```rust
use tacacsrs_config::{get_resolved_server, parse_yang_json, validate_credential_references};

let config = parse_yang_json(json_str)?;
let resolvers: Vec<Box<dyn CredentialResolver>> = vec![
    // Add your resolvers here
];

// Validate all credential references upfront (optional but recommended)
validate_credential_references(&config, &resolvers)?;

// Resolve credentials only for the server being used
let resolved_server = get_resolved_server(&config, "primary", &resolvers)?;
```

The parsed config remains unmodified and safe for round-tripping. Secrets are materialized only on demand. Structural validation happens during parsing; resolver-based validation can be run separately to catch missing external credentials early rather than at runtime.

### Module-oriented API (recommended for most users)

This crate also exposes grouped modules so callers can choose APIs by intent:

- `model` — YANG-generated types and namespaces
- `pipeline` — step-by-step processing
- `runtime` — runtime projection
- `stats` — runtime stats types

For simple end-to-end usage with in-config credential bundles:

```rust
use tacacsrs_config::{parse_yang_json_file, runtime};

let config = parse_yang_json_file(std::path::Path::new("tacacs.json"))?;
let servers = runtime::to_connection_configs(&config)?;
```

The existing flat root exports remain available for compatibility.

## Examples

The crate includes runnable examples under `examples/`:

- `quick_start.rs` — parse + validate + map to runtime using the root exports plus `runtime`
- `quick_start_credential_refs.rs` — minimal end-to-end example showing separate resolver validation and on-demand server resolution
- `pipeline_flow.rs` — explicit step-by-step parse/resolve/validate pipeline
- `model_access.rs` — direct access to generated model types and flags
- `credential_references.rs` — resolve credential references into inline material

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

### 1) High-level parse + validate workflow

These are the recommended entry points for application code:

- `parse_yang_json(&str) -> anyhow::Result<TacacsPlus>`
- `parse_yang_json_file(&Path) -> anyhow::Result<TacacsPlus>`
- `to_connection_configs(&TacacsPlus) -> anyhow::Result<Vec<ServerConnectionConfig>>`

`parse_yang_json()` performs deserialization and validation of YANG-derived JSON constraints (server presence, unique addresses, SNI requirements, choice constraints, etc.). The config is returned **without mutations**—credential references remain intact for round-tripping.

To resolve credentials and materialize them for runtime use, use the pluggable resolver API:
1. Create resolvers implementing [`CredentialResolver`]
2. Call [`validate_credential_references()`] to validate all references can be resolved
3. Call [`get_resolved_server()`] for on-demand per-server resolution

This design separates parsing/validation from credential retrieval and enables round-trip safety.

### 2) Advanced: Generated YANG model and pipeline API

For advanced use cases, these lower-level functions are available:

- `pipeline::parse_root_json()` - Parse JSON into raw generated types without validation
- `pipeline::parse_root_json_file()` - File-based raw parse into the generated root type without validation
- `generated` module - Full generated type graph for schema-aware integrations

### 3) Runtime mapping types

The runtime-facing mapping layer is public:

- `ServerConnectionConfig`
- `ResolvedSecurity`

`ServerConnectionConfig` represents normalized per-server connection settings consumed by runtime networking/client code.

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

This split lets simple consumers use the high-level API, while advanced consumers can work directly with generated YANG-aligned types.

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

- `yang/yang2rust.py` — custom `pyang` plugin that emits Rust structs/enums/bitflags
- `yang/expand_yang_tree.py` — helper used to refresh the fully expanded tree reference
- `yang/generated_types.rs` — checked-in generator output copied into `src/generated.rs`

Today, the Rust type graph is generated, but the higher-level validation logic in `src/validation.rs` is still maintained manually. That split is intentional for now: the current YANG-derived constraints are manageable in handwritten Rust, and keeping them explicit has made it easier to refine behavior during development. If the YANG model evolves substantially or the amount of schema-derived validation grows, generating some or all of that validation code from the same YANG metadata would be a reasonable next step.

To regenerate after YANG module updates:

```bash
python -m pip install pyang
cd libraries/tacacsrs_config/yang
python expand_yang_tree.py > expanded-tree.txt
pyang \
  -f rust \
  --plugindir . \
  ietf-system-tacacs-plus.yang \
  ietf-keystore.yang \
  ietf-truststore.yang \
  ietf-crypto-types.yang \
  ietf-tls-common.yang \
  > generated_types.rs
cp generated_types.rs ../src/generated.rs
```

Run the normal workspace formatting, clippy, build, and test commands after regeneration.
