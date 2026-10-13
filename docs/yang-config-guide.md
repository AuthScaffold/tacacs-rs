# YANG Configuration Guide

`tacacsrs-config` provides TACACS+ configuration support using the RFC 7951 JSON encoding of the `ietf-system-tacacs-plus` YANG module. The crate owns parsing, generated model types, validation, local credential bundle enumeration, and helper APIs used by `tacon` and `tacacsrs-agentd`.

If you need to author, validate, or consume TACACS+ server configuration from JSON, use this guide.

## What the configuration crate provides

- Generated Rust types that mirror the expanded TACACS+ YANG tree.
- RFC 7951 JSON parsing into the generated TACACS+ model.
- Validation for required server data, unique addresses, TLS choice constraints, SNI requirements, key format identities, base64-encoded key material, and configuration-local credential references.
- Bundle enumeration helpers that inline local `client-credentials` and `server-credentials` references onto server entries.
- Secret-free inspection of central keystore and truststore references.
- A `TacacsPlusServerBuilder` for constructing valid server definitions in Rust.
- A project-owned TACACS+/TLS augmentation for TLS 1.3 PSK-DHE key exchange group selection.

Central references remain opaque in this crate. Parse and enumerate configuration first, then use `tacacsrs-credential-resolution` to build provider-neutral requests, validate resolved results, and materialize generated inline fields. Provider-specific retrieval remains a separate integration concern.

## Basic JSON shape

Both `tacon` and `tacacsrs-agentd` can load TACACS+ server definitions from an RFC 7951 JSON document:

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "server": [
      {
        "name": "primary",
        "server-type": "authentication authorization accounting",
        "address": "192.0.2.2",
        "port": 49,
        "shared-secret": "example-shared-secret",
        "timeout": 10
      }
    ]
  }
}
```

Use `--config <file>` with `tacon` or `tacacsrs-agentd` to load the configuration.

## Parsing API

For simple application code, parse the JSON and enumerate per-server entries:

```rust
use tacacsrs_config::{enumerate_servers, parse_yang_json};

let config = parse_yang_json(json_str)?;
let servers = enumerate_servers(&config)?;
# anyhow::Ok::<()>(())
```

The primary entry points are:

| Function | Purpose |
| --- | --- |
| `parse_yang_json(&str)` | Parse and structurally validate a JSON string without mutating credential references. |
| `parse_yang_json_file(&Path)` | Parse a JSON file from disk. |
| `validate_credential_references(&TacacsPlus)` | Validate configuration-local credential bundle references. |
| `enumerate_servers(&TacacsPlus)` | Inline shared credential bundles onto every server. |
| `enumerate_server(&TacacsPlus, &str)` | Inline shared credential bundles for one named server. |
| `inspect_central_references(&TacacsPlusServer)` | Inspect typed central usages without retrieving material. |

The module-oriented API is also available for callers that want grouped imports:

- `builders` - programmatic construction helpers.
- `model` - generated YANG model types and namespaces.
- `extensions` - helper traits layered over generated model types.
- `pipeline` - step-by-step parsing and processing.
- `runtime` - bundle enumeration helpers.
- `stats` - runtime statistics types.

## Certificate Peer Identity

For certificate TLS, `domain-name` selects the expected peer identity when configured. Otherwise, verification uses `address`.
DNS names match certificate DNS SANs, and numeric addresses match IP SANs.
The client also performs its existing certificate trust verification. Setting SNI alone is not identity verification.

`sni-enabled` controls the DNS name sent in the TLS `ClientHello`, not whether the peer identity is verified.
When it is true, `domain-name` is required and sent as SNI. An omitted or false value sends no SNI.
A configured domain remains the verification identity even when SNI is disabled.
IP addresses are not sent as certificate-TLS SNI names.

The implementation disables CN fallback and partial-label wildcards. A complete leftmost-label wildcard can match one label, not multiple nested labels.
This follows the DNS/IP identity rules referenced by RFC 9887 Section 3.4.2 and RFC 9525.
It does not establish full RFC 9887 conformance, including revocation, certificate-chain provisioning, or other profile requirements.

Migration can require certificates with matching SAN entries. Chain trust alone no longer permits a certificate for a different identity.
The explicit development-only verification override still bypasses certificate verification and permits server impersonation.

## Certificate Trust

The pinned TLS YANG model gives CA and end-entity bags different meanings:

| Selection | Accepted certificate |
| --- | --- |
| `server-authentication/ca-certs` | A peer with a valid path to a configured authority |
| `server-authentication/ee-certs` | A peer whose DER certificate exactly matches a configured entry |
| Both | A peer accepted by either trust rule |

An end-entity entry is not a CA grant. It cannot authorize another leaf, including a renewed certificate with the same public key.
A CA-signed exact entry works without its issuer in the authority bag. Identity, time validity, and server-purpose checks still apply.
When both bags are configured, a separate valid authority path remains sufficient even if an exact entry shortens OpenSSL's initial path.

Explicitly selected bags must contain materialized certificates. Empty selections fail during preparation and cannot silently enable platform trust.
With neither bag selected, the existing server-authentication-only API retains its platform-trust behavior.
Configured trust excludes platform roots. Preparation does not modify the authoritative bags or their references.

This replaces the old combined-root behavior. Certificate renewal can require updating an exact `ee-certs` entry.
Use CA trust only when authorizing other valid certificates issued by that authority is intended.
Certificate revocation retrieval is not implemented. Full RFC 9887 conformance remains unclaimed.

## Certificate Input Boundary

Each `cert-data` value must contain exactly one DER certificate. Concatenated certificates and trailing bytes fail before runtime publication.
This rule also applies to each CA or end-entity trust-bag entry. Multiple entries remain supported.
CLI client certificate files accept a PEM chain or one DER certificate. Each individual DER value must still contain exactly one certificate.
The development verification override does not relax certificate framing.

If separate `public-key` metadata is supplied, `public-key-format` must also be present, and vice versa.
TLS preparation supports `ietf-crypto-types:subject-public-key-info-format` with exactly one DER SPKI value that matches the certificate's public key.
The private key must still match the certificate. SSH public-key encoding is explicitly unsupported for TLS certificate metadata.
Malformed, incomplete, mismatched, and trailing public-key data fail before publication, including when certificate verification is disabled for development.

### Client Certificate Chains

Inline client identities use the following fields under `certificate/inline-definition`:

| Field | Content |
| --- | --- |
| `cert-data` | One base64-encoded DER leaf certificate |
| `tacacsrs:intermediate-certificate` | An ordered JSON array of base64-encoded DER intermediate certificates |
| `cleartext-private-key` | The private key that matches the leaf, using the declared key format |

The intermediate list starts with the leaf's issuer and proceeds toward the root. Do not include the leaf again or a self-signed root.
The same fields work in per-server identities and reusable `client-credentials` bundles. Omit the list when no intermediates are needed.
Each list entry must be nonempty and unique. Native preparation checks framing, issuer order, signatures, client purpose, and certificate validity.
Malformed, duplicate, out-of-order, or unrelated intermediates fail before publication. The development peer-verification override does not bypass these local checks.

For CLI PEM files, put the leaf first and append intermediates in issuer order. Do not append the root or concatenate DER certificates.
The file loader preserves this order in canonical configuration. Native preparation sends the leaf and supplied intermediates to the peer.
The peer still decides whether the supplied path reaches one of its trust anchors; a missing intermediate can cause handshake rejection.

Credential providers return ordered intermediate bytes with the leaf and key. Materialization installs them only in a derived server value.
Authoritative snapshots and provider references remain unchanged. The earliest supplied certificate expiry bounds the prepared identity's lifetime.
Revocation retrieval remains a separate Stage 4 requirement, not a current capability.

## EPSK Presence

`server-authentication/tls13-epsks` is a YANG `empty` leaf, not a boolean.
A present leaf uses RFC 7951 JSON `[null]`. Omit the field when it is absent.
Boolean values, bare `null`, and arrays with the wrong shape are rejected for direct fields and server-credential bundles.
Rust callers use `Some(YangEmpty::default())` for presence.

```json
{
  "server-authentication": {
    "tls13-epsks": [null]
  }
}
```

This selector requires a client EPSK identity after credential-bundle expansion. It cannot select certificate TLS implicitly.
Client EPSK configuration still works without the optional server selector.
The current PSK transport cannot apply CA or end-entity trust bags alongside a client EPSK identity, so preparation rejects that combination.
Root configuration parsing also rejects trailing JSON after the first complete document.

## Three-layer processing model

The crate separates parsing and runtime preparation into three layers.

### Raw YANG model

If you need the submitted YANG model preserved exactly for round-tripping or reporting, use the raw pipeline:

```rust
use tacacsrs_config::pipeline;

let raw_config = pipeline::parse_root_json(json_str)?;
# anyhow::Ok::<()>(())
```

### Configuration-local bundle enumeration

Credential references can point to bundles in the same configuration. Validate those references, then enumerate the selected server:

```rust
use tacacsrs_config::{enumerate_server, parse_yang_json, validate_credential_references};

let config = parse_yang_json(json_str)?;
validate_credential_references(&config)?;

let server = enumerate_server(&config, "primary")?;
# anyhow::Ok::<()>(())
```

### Central credential resolution

Build `tacacsrs_credential_resolution::ResolutionPlan` values after enumeration. The resolution crate emits deterministic requests for central certificate-with-key, TLS 1.3 symmetric key, CA bag, and end-entity bag usages. Its async resolver contract returns secret-safe typed material, and `resolve_plan` rejects incomplete or mismatched result sets.

Neither generic crate interprets a central string as a SONiC identifier or filesystem path. P3 supplies provider retrieval, refresh behavior, and projection into networking inputs.

## Programmatic server construction

When code needs to construct server definitions directly instead of parsing RFC 7951 JSON, use `TacacsPlusServerBuilder`:

```rust
use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerExt, TacacsPlusServerType};

let server = TacacsPlusServerBuilder::new(
    "primary",
    TacacsPlusServerType::ACCOUNTING,
    "192.0.2.10",
    49,
)
.with_timeout(10)
.with_shared_secret("example-shared-secret")
.build();

assert_eq!(server.socket_address(), "192.0.2.10:49");
assert!(server.is_obfuscation());
# anyhow::Ok::<(), anyhow::Error>(())
```

The builder is for runtime construction of valid server shapes. It is not a replacement for schema validation of submitted YANG JSON.

## Inline key format identities

TLS inline key material uses YANG `identityref` fields from `ietf-crypto-types`. RFC 7951 JSON represents those values as module-qualified strings.

### Private key format

| JSON value | Meaning |
| --- | --- |
| `ietf-crypto-types:rsa-private-key-format` | DER-encoded RSAPrivateKey. |
| `ietf-crypto-types:ec-private-key-format` | DER-encoded ECPrivateKey. |
| `ietf-crypto-types:one-asymmetric-key-format` | DER-encoded CMS OneAsymmetricKey. |

### Public key format

| JSON value | Meaning |
| --- | --- |
| `ietf-crypto-types:subject-public-key-info-format` | DER-encoded SubjectPublicKeyInfo. |
| `ietf-crypto-types:ssh-public-key-format` | SSH public key format. |

The TACACS+ YANG model constrains TLS client identity and server authentication paths to `subject-public-key-info-format`.

### Symmetric key format

| JSON value | Meaning |
| --- | --- |
| `ietf-crypto-types:octet-string-key-format` | Raw octet string. |
| `ietf-crypto-types:one-symmetric-key-format` | DER-encoded CMS OneSymmetricKey. |

## TLS with inline certificate material

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
                {
                  "name": "CA-1",
                  "cert-data": "BASE64VALUE="
                }
              ]
            }
          }
        }
      }
    ]
  }
}
```

## TACACS+/TLS PSK-DHE augmentation

The repository includes a local `tacacsrs` YANG module that augments TACACS+ TLS 1.3 EPSK configuration with `psk-dhe-ke-groups`. RFC 7951 JSON uses the module-qualified key `tacacsrs:psk-dhe-ke-groups`:

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

Supported group values are `x25519`, `secp256r1`, `secp384r1`, `secp521r1`, `ffdhe2048`, `ffdhe3072`, `ffdhe4096`, `ffdhe6144`, and `ffdhe8192`. Unknown values fail during JSON deserialization.

## Code generation workflow

The generated Rust types come from the checked-in YANG tooling under `libraries/tacacsrs_config/yang/`:

- `plugins/yang2rust.py` emits Rust structs, enums, bitflags, and helper methods.
- `expand_yang_tree.py` refreshes the expanded tree reference and generated Rust output.
- `modules/` contains project-owned YANG modules passed to `pyang` alongside the upstream TACACS+ model.
- `generated_types.rs` is copied into `src/generated.rs` after regeneration.

Regenerate after YANG module updates:

```bash
python -m pip install -r requirements.txt

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

Run formatting, clippy, build, and tests after regeneration.
