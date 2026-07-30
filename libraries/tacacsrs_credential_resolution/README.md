# tacacsrs-credential-resolution

`tacacsrs-credential-resolution` defines provider-neutral contracts for planning and resolving central credential references found in an enumerated `tacacsrs-config` server.

The crate owns:

- deterministic typed request plans;
- an asynchronous resolver trait;
- typed certificate, private-key, symmetric-key, and trust-bag material;
- a closed result set that validates request/response slots and variants;
- sanitized typed failures;
- a deterministic fake resolver for tests.

It performs no filesystem, `SONiC`, `ConfigDB`, watcher, permission, retry, or runtime connection work. Providers inspect opaque references only through explicit request accessors. Debug and public error output omit opaque references and secret bytes.

```text
enumerated server
       |
       v
ResolutionPlan -> CredentialResolver -> ResolvedCredentialSet
       |                                      |
       +-- stable server/field context         +-- validated slots and variants
```

P3 supplies the `SONiC` provider and projects the closed result set into runtime networking inputs.

## Workflow

1. Parse and validate RFC 7951 JSON with `tacacsrs-config`.
2. Enumerate config-local client and server credential bundles.
3. Build a `ResolutionPlan` for each enumerated server.
4. Execute the plan with a `CredentialResolver`.
5. Consume the validated `ResolvedCredentialSet` by request slot.

Planning emits deterministic requests for certificate-with-key, TLS 1.3 symmetric key, CA certificate bag, and end-entity certificate bag usages. It rejects unexpanded local bundle references and structurally incomplete central certificate requests. Result-set construction rejects missing, duplicate, unexpected, and wrong-variant responses.

Central reference strings stay opaque. The generic API does not impose a provider grammar, convert a reference into a path, check existence or permissions, watch for changes, or retry retrieval. Provider-specific errors cross this boundary only as sanitized `ProviderErrorKind` values.

## Secret Material

`SecretBytes` directly owns a `zeroize::Zeroizing<Vec<u8>>` and exposes a value only through the explicitly named borrowed `expose_secret` method. It does not implement `Clone`, serde, `Display`, equality, or hashing. Secret-bearing credentials, responses, and result sets preserve those restrictions. Custom `Debug` implementations redact private keys, symmetric keys, opaque references, and provider details; public certificate bytes report length only.

The P2 test suite enforces these properties with compile-time negative trait assertions and public-behavior redaction tests. It does not inspect freed memory or use unsafe code.

## Example

The runnable example uses `FakeCredentialResolver` to demonstrate the generic handoff without choosing a provider:

```bash
cargo run -p tacacsrs-credential-resolution --example central_resolution
```

A production resolver implements `CredentialResolver`, reads references only through explicit request accessors, and returns the material variant requested by each slot. P3 supplies the platform provider and the projection from `ResolvedCredentialSet` to networking connection inputs.
