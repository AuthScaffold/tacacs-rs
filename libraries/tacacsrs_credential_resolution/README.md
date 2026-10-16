# tacacsrs-credential-resolution

`tacacsrs-credential-resolution` defines provider-neutral credential requests, results, and change events.
It has no dependency on configuration, generated YANG types, native TLS, or an async runtime.

The crate owns:

- deterministic typed request plans
- an asynchronous resolver trait
- typed certificate, private-key, symmetric-key, trust-bag, and CRL material
- a closed result set that validates request/response slots and variants
- provider-neutral credential change events and subscriptions
- sanitized typed failures
- a deterministic fake resolver for tests

It performs no filesystem, `SONiC`, `ConfigDB`, watcher, permission, retry, or runtime connection work. Providers inspect opaque references only through explicit request accessors. Debug and public error output omit opaque references and secret bytes.

```text
typed references and diagnostic context
       |
       v
ResolutionPlan -> CredentialResolver -> ResolvedCredentialSet
       |                                      |
       +-- stable server/field context         +-- validated slots and variants
```

`ResolutionPlan::new` accepts typed references and diagnostic context.
It assigns deterministic slots in input order and rejects references that do not match the requested material kind.
Provider key-format types describe byte encodings. They contain no YANG serialization or configuration defaults.

The [configuration preparation module](../tacacsrs_config/src/prepare/mod.rs) owns YANG inspection and materialization.
It maps provider metadata to generated YANG identities and validates complete candidates before returning them.
The source configuration remains unchanged.

## Workflow

1. Construct typed references and diagnostic context.
2. Build a closed plan with `ResolutionPlan::new`.
3. Submit the plan to a `CredentialResolver`.
4. Consume the validated result set in the calling adapter.

Requests support certificate-with-key, TLS 1.3 symmetric key, CA certificate bag, end-entity certificate bag, and certificate revocation list usages.
Result-set construction rejects missing, duplicate, unexpected, and wrong-variant responses.
For YANG servers, use `tacacsrs_config::prepare::resolution_plan` or its materialization functions instead of constructing requests manually.

Central reference strings stay opaque. The generic API does not impose provider grammar or convert a reference into a path.

`CertificateRevocationListsMaterial` carries complete DER CRLs in `PublicBytes` wrappers and retains the provider's absolute validity limits.
Configuration materialization installs those values only in derived server data. Native TLS separately validates signed freshness, path coverage, and revocation status.
Providers report updates through the existing credential change contract. This crate does not fetch CRL distribution points or implement an HTTP client.

It does not inspect path existence, inspect permissions, watch for changes, or retry retrieval. Only sanitized `ProviderErrorKind` values cross this boundary.

## Secret Material

`SecretBytes` directly owns a `zeroize::Zeroizing<Vec<u8>>` and exposes a value only through the explicitly named borrowed `expose_secret` method. Clones own independent zeroizing allocations, equality compares the real value, and `Display` and hashing remain unavailable. Secret-bearing credentials, responses, generated fields, and result sets preserve redacted formatting. Public certificate bytes report length only.

The P2 test suite enforces these properties with compile-time negative trait assertions and public-behavior redaction tests. It does not inspect freed memory or use unsafe code.

## Example

The configuration package contains a runnable example with `FakeCredentialResolver`:

```bash
cargo run -p tacacsrs-config --example central_resolution
```

A production resolver implements `CredentialResolver`, reads references through explicit accessors, and returns the material variant requested by each slot.
The coordinator owns provider notifications and publication. Configuration owns YANG materialization.
