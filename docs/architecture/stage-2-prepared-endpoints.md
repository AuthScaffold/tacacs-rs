# Stage 2: Prepared Endpoints

## Status

Stage 2 is in progress. This checkpoint covers native transport preparation, single-endpoint execution, credential materialization, source consolidation, and publication readiness.
Configuration now depends on the provider-neutral credential package and networking. Neither depends on configuration.
The canonical YANG model, feature manifest, and defaults remain authoritative and unchanged.

## Implemented Boundary

`tacacsrs_config::prepare::prepare_endpoint` borrows a materialized YANG server and returns an immutable `PreparedEndpoint`.
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

The temporary YANG constructors, `connect` and `connect_shared`, are removed.
The agent, CLI, and examples explicitly prepare endpoints through configuration before creating clients.

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

## Native Projection

Configuration owns transport selection, source field interpretation, and mappings from generated key formats, hashes, and ordered groups.
Networking accepts borrowed DER material and explicit `PrivateKeyEncoding`, `PskHash`, and `PskDheGroup` values.
These types describe transport inputs, not desired configuration. They have no configuration defaults or serialization.
OpenSSL objects remain private to networking, which owns DER validation, native context construction, and handshakes.

`PreparedEndpoint::tcp` takes explicit address, single-connection, obfuscation, and connection-option values.
`with_certificate_tls` and `with_psk` validate material before replacing the endpoint's transport.
They return an error instead of falling back to plaintext when preparation fails.

Networking no longer imports generated configuration in production code, tests, or examples.
The YANG examples moved to configuration, where their dependencies are declared explicitly.
The configuration projection uses the canonical address directly for certificate server names, without parsing its formatted socket address.
Tests cover IPv4, IPv6, domain overrides, disabled SNI, and the existing protocol-specific missing-domain behavior.
The PSK mapping covers every generated hash and group and preserves group order.
CI now guards networking against configuration, credential-provider, IPC, and integration dependencies.

## Sources and Inputs

`tacacsrs_config::source` owns `ConfigDatastore`, snapshot deltas, change events, runtime policy, static sources, and watch-channel conversion.
`tacacsrs_config::input` owns parsed CLI inputs, YANG file loading, PEM/DER normalization, and `CliFileDatastore`.
The separate datastore and CLI/file packages are removed without forwarding APIs.
The workspace now contains 15 packages. The CLI, daemon, and SONiC consumers import the configuration modules directly.
Windows CI selections and the local check matrix no longer name the removed packages.

Sources still return complete canonical YANG snapshots with their original references.
The delta remains advisory. Structural equality detects secret-only changes without serializing protected material.
Input normalization still uses the canonical builders and validation options. It introduces no alternative configuration model or clap dependency.

File subscriptions still register observation before loading and publishing the baseline.
Rejected reloads leave the previous accepted snapshot intact, and subscriber cancellation stops the idle watcher task.
The existing source and file-watcher tests moved with their owners.
A new regression passes TCP and PSK inputs through file and static source contracts into endpoint preparation without network I/O.
It checks snapshot equality, server order, timeout values, and single-connection behavior.

This increment does not redesign source sessions, supervisor lifetimes, or generation publication.
Those existing contracts remain in place for the later validation and lifecycle work.
CI now rejects clap, IPC, Redis, agent, and SONiC dependencies in configuration's normal dependency tree.

## Publication Readiness

Configuration owns `validate_materialized_servers`, the shared schema and capability check for a complete runtime server set.
Source parsing and runtime validation share server-set validation, including duplicate endpoint and duplicate server-name rejection.
The runtime check also rejects unresolved references and unsupported transport fields.
An empty runtime set remains valid. This does not relax the nonempty server-list requirement for parsed YANG documents.

`ServiceConfig::validation_options` carries the source's explicit validation policy into construction and reloads.
The daemon obtains this policy from the datastore. Migration relaxations remain explicit and cannot enable unsupported transport features.
The daemon coordinator no longer has a separate publication validator or builds an extra generated snapshot for that check.

The service now stages native endpoints before replacing the active routing snapshot.
Each server slot owns a prepared endpoint, and connectors accept that endpoint instead of a generated server.
Operation-specific clients and reconnects share its prepared native contexts.
Unchanged materialized servers reuse their slots. Changed material creates new slots without changing bound requests or authoritative source references.

A failed staged endpoint leaves the entire previous generation active, including routes, proxy policy, cached connections, and applied health state.
Preparation opens no sockets. Socket and handshake failures remain execution-time errors.
The new malformed-certificate reload regression failed before this change and now passes.
Existing coordinator fixtures with short placeholder PSKs now use valid-length material so they exercise generation behavior rather than invalid transport inputs.

Direct endpoint preparation and service publication reject `source-ip`, `source-interface`, and `vrf-instance` instead of silently ignoring them.
They also reject PSK derivation fields and `one-symmetric-key-format`.
These checks report unsupported field names without displaying their values or secret material.
Canonical YANG snapshots still preserve schema-valid values for reporting. The change affects whether the client can apply them.

The coordinator still owns source tickets and the known-good credential transaction.
This increment does not extract routing or redesign cancellation and publication-lock lifetimes.

## Prepared Source Equivalence

The existing CLI, SONiC, and YANG fixture now checks the shared readiness gate and prepared endpoint order and connection mode.
The [prepared-source integration tests](../../executables/tacacsrs_agentd/tests/prepared_sources.rs) extend that comparison through native connections and TACACS+ packet exchange.

The TCP fixture uses each source with and without obfuscation and with single-connection mode enabled and disabled.
The peer checks request sequence and flags, deobfuscates bodies, and compares accounting body bytes across sources.
The client checks the corresponding reply. All source snapshots remain unchanged.

The PSK fixture compares inline CLI credentials with SONiC and YANG central references after provider resolution.
It checks equal materialized server values, TLS 1.3, the SHA-256 cipher, SNI, and successful accounting exchange.
Its no-DHE peer selects a disjoint group list and verifies that no ephemeral key was negotiated.
Its PSK-DHE peer requires P-384 and checks the negotiated key. A DHE-configured client rejects the no-DHE peer.

Re-preparation with a new key retains the same authoritative SONiC and YANG references.
Old and new prepared endpoints authenticate only with their respective keys, and the old endpoint still works after the replacement is prepared.
Failed provider resolution and invalid replacement key material do not change the source or prevent use of the existing endpoint.
These tests complement the coordinator's separate stale-publication and known-good-generation regressions. They do not run a live daemon reload.

The stronger peer check exposed an OpenSSL-version limitation without requiring production changes.
OpenSSL 3.0 supports the no-DHE allowance but not the no-DHE preference option.
At that checkpoint, PSK-only permitted no-DHE exchange but accepted a peer-selected DHE connection too.
The fixture forced a genuine no-DHE path instead of assuming that the setting guaranteed exclusive mode selection.
The negotiated-acceptance rule below closes that gap without relying on the missing preference option.

## Negotiated PSK Contract

An empty PSK group list now requires an accepted connection to use no-DHE exchange.
A nonempty list requires PSK-DHE. After the native TLS handshake, the client checks the negotiated mode before returning the stream to packet I/O.
Mismatch closes the connection before any TACACS+ bytes are written.
The three-source fixtures exercise both mismatches alongside successful exchanges and credential rotation.

This contract governs accepted connections, not exclusive ClientHello offers.
OpenSSL can offer both modes for an empty group list. A peer that selects DHE is now rejected, even if the native handshake completes.
No unsupported preference bit is set. The no-DHE allowance uses the safe OpenSSL wrapper, and the old raw option-setting helper is removed.
One read-only FFI helper queries OpenSSL's negotiated group directly. A failed query is not treated as absence of DHE.
PSK preparation requires OpenSSL 3.0 or newer so the query cannot silently become an unsupported control operation.
The configured YANG model and its generated types are unchanged.

The client also rejects certificate-authenticated fallback from the PSK path.
OpenSSL's TLS 1.3 session-reuse result identifies the successful PSK authentication.
Tests complete a native certificate handshake and verify that the client rejects it without sending an accounting byte.
The earlier PSK-only mismatch regression observed an application byte before the fix and observes none afterward.

Operators must pair PSK-only configuration with a peer that negotiates no-DHE exchange.
Peers that previously selected DHE with an empty group list now need matching PSK-DHE configuration or a compatible server mode.

## Verification

Focused regressions cover early credential rejection, unresolved references, source immutability, runtime redaction, and release of source configuration.
Native callback tests cover SHA-256, SHA-384, repeated calls, digest mismatch, and null output guards.
Bounded OpenSSL loopback tests cover repeated TLS, mTLS, PSK-only, and PSK-DHE connections.
The TLS loopback tests enable certificate verification with YANG-projected CA and end-entity trust stores.
They cover certificate trust and context reuse, but do not prove hostname-verification behavior.
SHA-384 has native callback/session coverage, not a separate peer handshake test in this checkpoint.

Package Clippy passes without a feature override.
The TLS example now belongs to configuration, which explicitly enables its filesystem dependency.

The focused suites include 104 active networking tests, 47 configuration unit tests, 100 agent tests, and 75 daemon tests, plus integration suites.
Four prepared-source integration tests cover wire behavior, PSK generation isolation, mode rejection, and certificate fallback with bounded local peers.
Projection tests moved to configuration. Native tests consolidate equivalent schema-based fixtures into transport-input tables.
Two existing manual networking baselines remain ignored.
The workspace build, formatting check, warnings-as-errors rustdoc build, and architecture book build pass.
`cargo +nightly udeps --workspace --all-targets --locked` reports no unused dependencies.
Workspace Clippy passes with only the existing `clippy::comparison_chain` warning allowed in the validation command.
The strict workspace command still fails on that warning in the agent admission module.
No permanent lint allowance was added.

`cargo audit` found no vulnerabilities in the resolved lockfile.
The advisory database updated successfully, but the crates.io index refresh could not acquire the concurrent Cargo cache lock.
External dependency versions are unchanged.
The lockfile records the reversed configuration-to-credentials and configuration-to-networking dependencies and the relocation of test dependencies.

The configuration-owned credential increment passes workspace tests, build, formatting, rustdoc, and dependency-usage checks.
Workspace Clippy passes with the same admission-warning exception.
The new dependency guard and the relocated central-resolution example also pass.
No SONiC VM or Windows build ran for this increment. Linux provider and generation-coordination tests pass.

The native projection increment also passes workspace tests, build, formatting, rustdoc, and dependency-usage checks.
Networking passes its standalone package tests without configuration feature unification.
The schema-free networking dependency guard passes. Workspace Clippy uses only the same existing admission-warning exception.
No external dependency version changed. Native PSK callback code is unchanged, and its existing tests still pass.

The source/input consolidation passes workspace tests, build, formatting, rustdoc, and dependency-usage checks.
All 51 release-version computation and hydration fixtures pass.
The configuration dependency guard passes, and Cargo metadata contains neither removed package.
Workspace Clippy uses only the same existing admission-warning exception.
The audit found no vulnerabilities in the 300 remaining lockfile packages. External dependency versions are unchanged.
No Windows build, PowerShell execution, or SONiC VM validation ran for this increment. PowerShell is not installed in this Linux container.
The updated package selections resolve through Cargo, and Linux source, watcher, CLI, and daemon tests pass.

The publication-readiness increment passes workspace tests, build, formatting, and warnings-as-errors rustdoc.
Workspace Clippy uses only the same existing admission-warning exception.
Focused tests verify native failure before publication, complete rollback, prepared-slot reuse, explicit validation policy, and sanitized unsupported-field errors.
The authoritative-source and credential-rotation regressions still pass with valid transport fixtures.
No dependencies, lockfiles, or native FFI code changed. No Windows or SONiC VM validation ran for this increment.

The prepared-equivalence increment passes workspace tests, build, formatting, rustdoc, and unused-dependency checks.
Workspace Clippy uses only the existing admission-warning exception. The dependency audit found no vulnerabilities.
The daemon declares existing protocol and OpenSSL packages as dev-dependencies for the native peer fixtures. No external package versions changed.
All peer connections use bounded local listeners. No live SONiC VM, external server, Windows test, or Miri run was part of this increment.
Production transport and publication code is unchanged.

The negotiated-PSK increment passes workspace tests, build, formatting, and warnings-as-errors rustdoc.
Workspace Clippy uses only the existing admission-warning exception.
Native tests exercise successful no-DHE and DHE handshakes, both mode mismatches, and certificate fallback before application data.
They also retain the source-equivalence, wrong-key, and prepared-key rotation coverage.
No dependency or lockfile changed. Only OpenSSL 3.0 was exercised locally; Windows and live SONiC validation remain unrun.
Miri's nightly `rust-src` prerequisite is still absent. The native callback and negotiated-group checks ran against real OpenSSL instead.

Miri did not run. It required the nightly `rust-src` component, whose installation failed because the shared toolchain directory was not writable.
Native OpenSSL callback and handshake tests provide the FFI validation for this checkpoint.
They are not a substitute for Miri coverage or independent server interoperability tests.

## Remaining Stage 2 Work

1. Move remaining product controls into documented namespaced YANG augmentations where required.
2. Close the remaining interoperability gaps, including a SHA-384 peer handshake and independent-server evidence.

The existing source-equivalence and credential-generation tests remain required gates.
Routing, request leases, deadlines, and runtime retirement remain Stage 3 work.