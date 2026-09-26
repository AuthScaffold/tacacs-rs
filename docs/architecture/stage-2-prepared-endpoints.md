# Stage 2: Prepared Endpoints

## Status

Stage 2 is in progress. This checkpoint covers native transport preparation, single-endpoint execution, and configuration-owned credential materialization.
Configuration now depends on the provider-neutral credential package. Networking still depends on configuration until native projection moves.
The canonical YANG model, feature manifest, and defaults remain authoritative and unchanged.

## Implemented Boundary

`prepare_endpoint` borrows a materialized YANG server and returns an immutable `PreparedEndpoint`.
Preparation opens no sockets and does not resolve DNS.
It derives the host and port, single-connection setting, protected obfuscation key, TLS context, and connection options.
It does not mutate the source server or retain that server in the live client.

The endpoint is a derived artifact, not another desired-configuration schema.
Its fields are private. Callers cannot construct unchecked native transport state through this API.
Its debug output excludes credentials and native context internals.

`TacacsClient::connect_prepared` consumes the endpoint and runs the configured preflight.
With preflight disabled, client construction remains network-free.
Dedicated connections and reconnects reuse prepared native contexts.
Endpoint clones share those contexts, but each client owns its connection and session state.

The temporary YANG constructors, `connect` and `connect_shared`, forward through this same path.
Their implementation lives in the preparation adapter, outside client execution.
They no longer retain the generated server value.

## Readiness Changes

The lazy client previously accepted invalid PSK material and discovered the error only when an operation opened a connection.
It now rejects invalid native material before returning the client, even when preflight is disabled.
Preparation rejects unresolved credential references and conflicting certificate and PSK client identities.
A selected certificate identity requires both certificate and private-key material.
It can no longer silently become a client without a certificate when either field is absent.

Server-authentication-only TLS remains supported. This checkpoint does not impose a new mutual-TLS requirement.
Packet obfuscation alongside TLS remains available for callers that explicitly permit that existing configuration relaxation.

## PSK Callback Ownership

OpenSSL ex-data now stores owned identity bytes, a zeroizing secret, a native digest, and a cipher name.
The callback does not store a generated YANG server or inspect configuration fields.
It verifies the requested digest, finds the cipher, and constructs an OpenSSL session from prepared bytes.

The callback borrows ex-data through the live `SslRef` instead of returning an artificial static reference.
The identity remains owned by the context after the callback returns.
Successful callbacks transfer each new session to OpenSSL. Failure paths retain their existing session cleanup.

## Configuration-Owned Credentials

`tacacsrs_config::prepare` now owns YANG request planning, provider metadata conversion, and transactional credential materialization.
`resolution_plan` replaces `ResolutionPlan::from_server`.
The materialization functions and their sanitized error types moved from the credential package into this module without compatibility re-exports.
The daemon coordinator and SONiC provider tests use the new API.

`tacacsrs-credential-resolution` no longer depends on configuration, directly or transitively.
It retains typed references, deterministic request slots, resolver contracts, protected material, closed result sets, and credential change events.
`ResolutionPlan::new` constructs checked plans from typed references and diagnostic context without interpreting YANG.
Provider key-format types describe standard byte encodings without configuration defaults or serialization.
Configuration explicitly maps every provider format to a generated YANG identity.

Materialization preserves its existing all-or-nothing behavior and source immutability contract.
Local bundle expansion, request field order, provider reference values, certificate order, and final validation remain unchanged.
The existing materialization and YANG planning tests moved with their implementation.
Provider safety tests now construct neutral request plans directly.
The central-resolution example moved into the configuration package.

CI now rejects configuration, networking, IPC, SONiC, native TLS, and runtime dependencies in the credential package's normal dependency tree.

## Verification

Focused regressions cover early credential rejection, unresolved references, source immutability, runtime redaction, and release of source configuration.
Native callback tests cover SHA-256, SHA-384, repeated calls, digest mismatch, and null output guards.
Bounded OpenSSL loopback tests cover repeated TLS, mTLS, PSK-only, and PSK-DHE connections.
The TLS loopback tests disable client certificate verification to isolate context reuse. They do not prove hostname-verification behavior.
SHA-384 has native callback/session coverage, not a separate peer handshake test in this checkpoint.

Package Clippy passes with `--features tokio/fs`.
Without that flag, the existing TLS example fails because its package does not enable the filesystem feature it uses.
This checkpoint does not change that unrelated example dependency.

Workspace tests pass, including 137 active networking tests and all doctests.
Two existing manual networking baselines remain ignored.
The workspace build, formatting check, warnings-as-errors rustdoc build, and architecture book build pass.
`cargo +nightly udeps --workspace --all-targets --locked` reports no unused dependencies.
Workspace Clippy passes with only the existing `clippy::comparison_chain` warning allowed in the validation command.
The strict workspace command still fails on that warning in the agent admission module.
No permanent lint allowance was added.

`cargo audit` found no vulnerabilities in the resolved lockfile.
The advisory database updated successfully, but the crates.io index refresh could not acquire the concurrent Cargo cache lock.
External dependency versions are unchanged.
The lockfile records the reversed configuration-to-credentials dependency and the relocation of test dependencies.

The configuration-owned credential increment passes workspace tests, build, formatting, rustdoc, and dependency-usage checks.
Workspace Clippy passes with the same admission-warning exception.
The new dependency guard and the relocated central-resolution example also pass.
No SONiC VM or Windows build ran for this increment. Linux provider and generation-coordination tests pass.

Miri did not run. It required the nightly `rust-src` component, whose installation failed because the shared toolchain directory was not writable.
Native OpenSSL callback and handshake tests provide the FFI validation for this checkpoint.
They are not a substitute for Miri coverage or independent server interoperability tests.

## Remaining Stage 2 Work

1. Move native endpoint projection under the configuration preparation owner.
2. Remove the networking crate's configuration dependency and the temporary YANG client constructors after consumer conversion.
3. Consolidate datastore contracts and CLI/file adapters into configuration modules.
4. Apply common schema and feature validation before generation publication, including explicit unsupported-feature rejection.
5. Extend CLI, SONiC, and YANG equivalence fixtures through prepared behavior and credential rotation.
6. Move remaining product controls into documented namespaced YANG augmentations where required.

The existing source-equivalence and credential-generation tests remain required gates.
Routing, request leases, deadlines, and runtime retirement remain Stage 3 work.