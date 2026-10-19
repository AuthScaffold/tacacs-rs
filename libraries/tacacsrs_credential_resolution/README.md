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

## Registered Work

`CredentialResolver::resolve` and `resolve_plan` require a `WorkScope` from the caller.
`WorkScope::new(owner)` returns a root lease and separate `WorkScopeControl` sealing authority.
The last lease releases the opaque owner exactly once. The control does not keep that owner alive.
Owner destructors must not block, panic, reenter coordinator state, or require a live async runtime.
The API contains no Tokio, YANG, or concrete scheduler types.

A provider must call `register` before it queues owned work that can outlive the resolver future.
The actual worker and its queued result must retain that lease until transfer or disposal.
A lease does not implement `Clone`. Move a lease to transfer it. After sealing, `register` returns `None`, so no new lease is possible.
Sealing prevents new registrations. It cannot force quiet while a root, worker, or result lease remains.
Dropping a resolver future or join handle does not prove quiet.

Direct tests and unmanaged callers can use `WorkScope::unowned()` explicitly.
That scope has no scheduler owner and proves no global admission bound.
Generic unregistered background work and unobservable OS or SDK internals are outside the ownership guarantee.
Provider-owned blocking jobs are not excluded. Providers must register them.
`ResolvedCredential::payload_bytes` returns the checked decoded length without exposing credential content.

## Notification Ownership

Each `CredentialChangeStream` owns its subscription and backend notification workers.
Dropping the stream stops event delivery and cancels those workers. Worker cleanup can finish asynchronously.
The generic stream type cannot cancel arbitrary I/O. Providers must document work that can outlive cancellation and prevent further event publication.

Subscription failure returns `CredentialChangeError`. Observation failure emits `Unavailable` or ends the stream.
A provider can emit `Recovered` on the same stream or require a new subscription after the stream ends.
Recovery means that notifications are available. It does not validate credentials or authorize publication without resolution.
