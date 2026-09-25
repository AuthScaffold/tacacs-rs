# Stage 2: Prepared Endpoints

## Status

Stage 2 is in progress. This checkpoint covers native transport preparation and single-endpoint execution.
It does not complete configuration consolidation or reverse the crate dependency direction.
The canonical YANG model, feature manifest, defaults, and credential materialization APIs remain authoritative and unchanged.

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
No external dependency versions or lockfiles changed.

Miri did not run. It required the nightly `rust-src` component, whose installation failed because the shared toolchain directory was not writable.
Native OpenSSL callback and handshake tests provide the FFI validation for this checkpoint.
They are not a substitute for Miri coverage or independent server interoperability tests.

## Remaining Stage 2 Work

1. Move YANG projection and native-material preparation under the configuration preparation owner.
2. Separate schema-independent credential providers from generated-model materialization to avoid dependency cycles.
3. Remove the networking crate's configuration dependency and the temporary YANG client constructors after consumer conversion.
4. Consolidate datastore contracts and CLI/file adapters into configuration modules.
5. Apply common schema and feature validation before generation publication, including explicit unsupported-feature rejection.
6. Extend CLI, SONiC, and YANG equivalence fixtures through prepared behavior and credential rotation.
7. Move remaining product controls into documented namespaced YANG augmentations where required.

The existing source-equivalence and credential-generation tests remain required gates.
Routing, request leases, deadlines, and runtime retirement remain Stage 3 work.