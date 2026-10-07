# Stage 2: Prepared Endpoints

## Status

Stage 2 is in progress. This checkpoint covers native transport preparation, single-endpoint execution, credential materialization, source consolidation, and publication readiness.
Configuration now depends on the provider-neutral credential package and networking. Neither depends on configuration.
The canonical YANG model, feature manifest, and defaults remain authoritative.

## Completion Checklist

On 2026-10-06, the user confirmed that Stage 2 can incorporate newly discovered issues.
Backward compatibility does not constrain the complete refactor. Existing APIs, configuration formats, and behavior can change when the design requires it.
Canonical YANG, protocol correctness, and security requirements still apply.

Add each discovered issue as a separate unchecked item with an owner, a completion condition, and a focused validation check.
Check off an item only after its implementation and validation finish. Record the commit and evidence in this checkpoint.
If work moves between stages, record its new owner and update both stage descriptions. Do not silently defer defects to close the stage.

### Completed Scope

- [x] S2-01: Preserve canonical YANG snapshots and credential references. Source equality and rotation tests cover immutability. See [prepared source equivalence](#prepared-source-equivalence).
- [x] S2-02: Introduce immutable prepared endpoints and remove generated-model interpretation from client execution and callbacks. Commits `b0f3eff` and `eac8b92` establish the [prepared boundary](#implemented-boundary).
- [x] S2-03: Consolidate credential planning, materialization, and native projection under configuration. Commits `58caa4a` and `eac8b92` establish [configuration-owned credentials](#configuration-owned-credentials).
- [x] S2-04: Merge datastore and CLI/file source plumbing into configuration. Commit `8329688` removes the old packages and updates consumers and dependency guards. See [sources and inputs](#sources-and-inputs).
- [x] S2-05: Verify equivalent CLI, SONiC, and YANG inputs through preparation and packet exchange. Commits `acec6ef` and `8b8e686` cover [source equivalence](#prepared-source-equivalence) and credential rotation.
- [x] S2-06: Reject unsupported runtime fields explicitly. Commit `6f2c9a7` adds capability checks and source-preservation tests. See [publication readiness](#publication-readiness).
- [x] S2-12: Make service selection, listener endpoints, and Unix socket permissions canonical YANG controls. Commit `594b5be` removes independent runtime fields and duplicate validation. See [canonical local services](#canonical-local-services) for pre-bind rejection, input equivalence, and permission tests.
- [x] S2-13: Derive downstream credentials from explicit canonical source policy. Commit `66c59d6` removes mutable runtime credentials and implicit row overrides. See [canonical downstream credentials](#canonical-downstream-credentials) for redaction, rotation, startup rejection, and publication rollback evidence.
- [x] S2-14: Normalize the SONiC forwarder profile into canonical local services and consolidate publication-time loop validation. Commit `64b2e4e` preserves source rows and adds cross-source, wildcard, interface, and DNS regressions. See [SONiC mapping and loop checks](#sonic-mapping-and-loop-checks). Connection-time enforcement is recorded under completed item S2-17.
- [x] S2-17: Enforce loop exclusion at connection time using actual bound listener addresses. Commit `031eb3a` adds a schema-free guard and agent-owned listener state. See [connection-time loop exclusion](#connection-time-loop-exclusion) for changed-resolution, zero-byte, ephemeral-port, and shutdown regressions.

### Completed Discoveries

- [x] S2-07: Prepare complete generations before publication and retain the previous generation after failure. Commit `6f2c9a7` adds the native-material rejection and rollback regressions.
- [x] S2-08: Reject PSK mode mismatches and certificate fallback before application traffic. Commits `b7f1610` and `8b8e686` verify the [negotiated PSK contract](#negotiated-psk-contract) for both hashes.
- [x] S2-09: Validate retained transport modes against an independent server. Commit `4dc051f` adds the native runner. All nine cases also pass after `31dedd9`. See [independent server evidence](#independent-server-evidence).
- [x] S2-10: Replace the parallel policy schema and duplicate defaults with generated YANG policy. Commit `3400393` includes generator corrections, parser tests, and deterministic regeneration. See [canonical runtime policy](#canonical-runtime-policy).
- [x] S2-11: Derive connection timeout from YANG for every consumer and remove caller overrides. Commit `31dedd9` verifies [preparation controls](#preparation-controls), source equivalence, and the restricted API.
- [x] S2-18: Verify certificate peer identity independently of SNI. Commit `8e6243e` rejects mismatched SANs before application data, disables CN fallback and partial wildcards, and separates native identity/SNI inputs. See [peer identity and standard ports](#peer-identity-and-standard-ports).
- [x] S2-19: Use TLS port 300 for omitted CLI and SONiC ports while preserving explicit ports. Commit `8e6243e` also rejects malformed explicit port syntax instead of selecting a default. See [peer identity and standard ports](#peer-identity-and-standard-ports).
- [x] S2-20: Preserve CA, exact peer, and platform trust roles during preparation. Commit `bdbec25` rejects empty explicit bags and verifies exact signed leaves and additive CA paths without weakening native checks. See [certificate trust roles](#certificate-trust-roles).

Open items and their completion conditions appear under [remaining Stage 2 work](#remaining-stage-2-work).
The implementation sections below preserve the evidence and limits for completed items.

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

The [hash-bound test peer](../../executables/tacacsrs_agentd/tests/prepared_sources/psk_peer.rs) uses OpenSSL's TLS 1.3 server PSK session callback.
Unlike the legacy server callback, this interface binds each external PSK to the cipher's SHA-256 or SHA-384 hash.
The peer accepts both cipher suites, so hash-mismatch tests do not fail merely because there is no common cipher suite.
The production callback and transport implementation are unchanged.

The native peer owns protected key bytes in context ex-data and creates a fresh session for each recognized identity.
It transfers successful sessions to OpenSSL and frees sessions when a native setter fails.
Tests cover null arguments, unknown identities, repeated handshakes, wrong hashes, wrong keys, and retained old endpoints after key rotation.

SONiC and YANG sources now pass materialization and accounting exchange with SHA-256 and SHA-384 in both no-DHE and PSK-DHE modes.
The peer checks TLS version, cipher, PSK authentication, SNI, negotiated group, and accounting body bytes.
The source snapshots and central references remain unchanged across re-preparation.
Direct CLI PSK flags still select SHA-256; the SHA-384 fixtures do not claim support for a CLI flag that does not exist.
This is native OpenSSL peer evidence, not evidence from a separate TLS implementation or deployed TACACS+ server.

Focused regressions cover early credential rejection, unresolved references, source immutability, runtime redaction, and release of source configuration.
Native callback tests cover SHA-256, SHA-384, repeated calls, digest mismatch, and null output guards.
Bounded OpenSSL loopback tests cover repeated TLS, mTLS, PSK-only, and PSK-DHE connections.
The TLS loopback tests enable certificate verification with YANG-projected CA and end-entity trust stores.
They cover certificate trust and context reuse, but do not prove hostname-verification behavior.
Both supported PSK hashes now have native peer handshake and accounting coverage.

Package Clippy passes without a feature override.
The TLS example now belongs to configuration, which explicitly enables its filesystem dependency.

The focused suites include 104 active networking tests, 47 configuration unit tests, 100 agent tests, and 75 daemon tests, plus integration suites.
Five prepared-source integration tests and two peer-callback guard tests cover wire behavior, both hashes, key rotation, mode rejection, and certificate fallback.
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

The hash-bound peer increment passes all seven prepared-source tests and the full workspace test suite.
Workspace build, formatting, warnings-as-errors rustdoc, and unused-dependency checks pass.
Workspace Clippy uses only the existing admission-warning exception. The dependency audit found no vulnerabilities, with the same index-refresh lock warning.
The new callback uses test-only declarations of existing native dependencies. No external dependency versions or production transport files changed.
Miri remains unavailable without nightly `rust-src`. No Windows, live SONiC, or independent-server tests ran in this increment.

Miri did not run. It required the nightly `rust-src` component, whose installation failed because the shared toolchain directory was not writable.
Native OpenSSL callback and handshake tests provide the FFI validation for this checkpoint.
They are not a substitute for Miri coverage or independent server interoperability tests.

## Independent Server Evidence

The [native interoperability runbook](../tacplus-interop.md) records tests against unmodified `tac_plus-ng` revision `70bf938b542d63bca00d50be0874a38a290319e0`.
This is the independent server implementation used by the repository's Compose image recipe.
It was built in a temporary directory with OpenSSL 3.0.20, without Docker or privileged installation.

PAP, authorization, and repeated accounting pass over TCP with and without obfuscation, verified certificate TLS, client-certificate TLS, and both PSK exchange modes.
SHA-256 and SHA-384 PSK-DHE pass against hash-specific server settings.
A strict mutual-TLS variant accepts the fixture client certificate and rejects a client without a certificate.
The client keeps certificate verification enabled. Hostname-mismatch behavior is not covered by this matrix.

The fixture needed realm-level `tls psk = yes` in addition to its PSK listener setting.
Without it, the server used certificate fallback and the client's PSK authentication check rejected the connection.
That fixture fix is now checked in. Production Rust transport behavior is unchanged.
The opt-in tests and runner retain the server setup and cleanup procedure for future checks.

All nine runner cases passed on 2026-10-06. The ordinary workspace suite passes with the eight external tests ignored by default.
Workspace build, formatting, warnings-as-errors rustdoc, Python syntax, and the architecture book build pass.
Workspace Clippy uses only the existing admission-warning exception.
No dependency, lockfile, production Rust transport, or dev-container configuration changed. All test peer processes were stopped.
The native tests do not validate Docker/Compose execution, Windows, or SONiC deployment.

## Canonical Runtime Policy

The project module revision `2026-10-06` defines `tacacsrs:runtime-policy` under `ietf-system:system`.
It covers local client API and proxy failover strategies, recovery seconds, and per-operation body and concurrency limits.
The IETF upstream module, feature selection, server model, and credential references are unchanged.
The project module and regenerated artifacts are recorded in the generation manifest.

The daemon's `--runtime-policy` file now contains a module-qualified YANG resource.
Its independent document structs and duplicate defaults are removed.
Configuration parses and validates the generated policy, and the agent derives runtime values without changing that source.
Default runtime policy and default queue sizing use generated YANG defaults.

The old flat JSON format is not retained. Existing files must wrap their fields in `tacacsrs:runtime-policy`.
The default resource is `{"tacacsrs:runtime-policy":{}}`.
Partial operation containers use the operation's own defaults. Unknown fields and invalid ranges fail before policy publication.
The existing watcher still retains the previous valid policy on rejected updates.
Policy observation remains separate from server observation until the planned controller work.

The generator now distinguishes structures whose leaf defaults or mandatory constraints differ.
It emits `Default` only when every field has a YANG default or an optional/empty representation.
Mandatory leaves do not receive invented defaults. Authentication and accounting retain their different default body limits.
The original canonical-policy regression failed against the old parser and now passes.

The policy increment passes workspace tests, build, formatting, warnings-as-errors rustdoc, and unused-dependency checks.
All twelve YANG generator tests pass. Deterministic regeneration matches the pinned source, manifest hashes, and checked-in artifacts.
The documentation book builds. Workspace Clippy uses only the existing admission-warning exception.
The dependency audit found no vulnerabilities, with the same index-refresh lock warning.
Configuration now uses its existing protocol dependency for the body-length limit. No external dependency versions or lockfile changed.
No native transport, unsafe code, or protobuf contract changed. No Windows, live SONiC, or independent-server test ran for this increment.

## Preparation Controls

Endpoint preparation now derives the TCP connection timeout from the canonical server's `timeout` leaf.
Previously, the agent projected this value while direct preparation could leave TCP establishment unbounded or accept a competing caller timeout.
The regression observed no prepared timeout for a server whose YANG timeout was five seconds.
The shared preparation function now owns this mapping. The duplicate agent projection is removed.

`prepare_endpoint` now accepts configuration-owned `PrepareOptions`, not networking `ConnectOptions`.
The new type selects only preflight and the explicit development-only certificate-verification override.
It cannot override the canonical timeout. A compile-fail example checks that API restriction.
Preflight is an execution action, not desired configuration. The verification override remains an explicit unsafe deployment choice, not a persisted default.
Source validation options still govern schema admission and cannot enable unsupported transport features.

The agent, direct CLI, batch executor, examples, and integration tests use the new API.
The independent server fixture sets its three-second timeout in its YANG builder.
Networking still accepts explicit native `ConnectOptions` without importing configuration.
`PreparedEndpoint::connection_timeout` exposes the derived value without allowing mutation.

Focused tests cover multiple canonical timeout values, unchanged source snapshots, and the default unbounded native constructor.
Existing CLI, static-source, SONiC, YANG, and credential-rotation fixtures now check the prepared timeout.
Workspace tests, build, formatting, warnings-as-errors rustdoc, and the documentation book pass.
Clippy uses only the existing admission-warning exception. All nine native `tac_plus-ng` runner cases pass after the fixture migration.
No dependencies, generated YANG artifacts, protobuf contract, or unsafe code changed. Windows and live SONiC validation did not run.
This timeout bounds TCP establishment. Absolute request deadlines and TLS-handshake deadline coverage remain Stage 3 work.

## Canonical Local Services

Commit `594b5be` completes S2-12 with the system-level `tacacsrs:local-services` resource.
Enabled services, IPC/proxy listener endpoints, and Unix socket permissions are product configuration, not independent host defaults.
Worker threads, verbosity, and systemd integration remain process bootstrap inputs.
The existing project module revision contains the new resource. The pinned IETF module and feature selection are unchanged.

Configuration owns `parse_local_services` and `prepare_local_services`.
Preparation produces private, immutable bind targets without filesystem or network I/O and leaves the generated source unchanged.
It rejects disabled service sets, inconsistent proxy selection, invalid endpoints, invalid permission bits, and lexical Unix path collisions.
The new collision regression failed against the previous service constructor before the shared validation fix.
The daemon previously rejected that conflict, but library callers could reach listener startup with it.

`ServiceConfig::local_services` replaces its independent service flags, IPC endpoints, and socket mode.
The service prepares this source before runtime construction and retains the resulting targets privately.
Both production and test constructors use the shared validation path. Obsolete validation wrappers are removed.
Existing listener tests verify the configured socket permissions, startup health, and shutdown cleanup.

The daemon normalizes listener flags into generated YANG values and obtains omitted defaults from those types.
`--local-services` loads a module-qualified resource once at startup. Listener changes require a restart.
The file is exclusive with parallel listener flags and SONiC mode, so it cannot silently override another listener source.
SONiC's existing forwarder result enters the canonical resource in the daemon adapter.
Its full mapping, default ownership, and loop-prevention review remain S2-14.

Unix listener paths must be absolute, contain no NUL or parent traversal, and fit the Linux 107-byte pathname limit.
Preparation normalizes repeated separators and current-directory components without resolving symlinks.
Invalid client API endpoint values fail even when that service is disabled.
Proxy TCP targets remain numeric and can use wildcard addresses or port zero. Deployment access controls remain necessary.
At this checkpoint, downstream credentials retained their existing paths until S2-13. The following increment adds their canonical source contract.

Workspace tests, build, formatting, warnings-as-errors rustdoc, and the documentation book pass.
Workspace Clippy uses only the existing admission-warning exception.
All twelve generator tests pass, and deterministic regeneration matches the updated artifact hashes.
Four configuration tests and five daemon adapter tests cover defaults, immutability, invalid values, file loading, and CLI/YANG equivalence.
All fifteen agent runtime tests pass, including the collision regression and bound-socket permission assertion.
No dependency, lockfile, protobuf contract, unsafe code, or native transport changed.
Windows, live SONiC, and independent-server validation did not run for this listener-only increment.

## Canonical Downstream Credentials

Commit `66c59d6` completes S2-13.
The generated `LocalServices` source now includes `proxy-credential-source` and the protected `proxy-shared-secret` leaf.
Its modes are `unobfuscated`, `inline`, and `local-proxy-row`. The YANG default is explicit unobfuscated behavior.
The CLI normalizes its secret into inline policy. SONiC selects row-derived policy unless the operator explicitly selects another mode.
The resource file can configure inline credentials. File changes still require a restart.

The loop filter previously let a matching upstream row override an explicit downstream secret.
The new precedence regression failed against that behavior and now passes.
Filtering now identifies the first matching row in canonical order, while configuration owns credential preparation.
Only row-derived mode uses that row's material. Filtering cannot override inline or unobfuscated policy.
Missing rows, missing secrets, and empty secrets reject row-derived candidates rather than select plaintext or lower-priority credentials.

`proxy_policy::prepare_proxy_policy` returns immutable `PreparedProxyPolicy` with private state.
The old `ProxyDownstreamObfuscation` enum and independent `ServiceConfig` credential field are removed.
Preparation borrows canonical values and leaves the source and selected row unchanged.
Generated fields, runtime material, and the CLI secret use redacted, zeroizing `SecretString` values.
The secret-field manifest and deterministic-generation hashes include the new leaf.
Serialization still contains configured inline material. Resource files require appropriate access controls and must not be logged as reports.

A waiting row-derived service starts with unavailable credentials, not an unobfuscated fallback.
The proxy rejects those connections before packet I/O. Publication also rejects unavailable policy before changing routes or health.
Valid credential and upstream changes publish together. Rejected candidates retain the previous complete generation.
Tests preserve the old prepared key across replacement and verify that invalid preparation and unavailable publication leave active state unchanged.
Established downstream connections retain their captured keys until closure. Forced revocation remains later lifecycle work.

This increment uses inline material and mapped source-row secrets. It does not add a central provider or change upstream EPSK resolution.
Removing the required local row now rejects the candidate, including its upstream changes.
SONiC deployments that require plaintext downstream traffic must select `--proxy-credential-source unobfuscated` explicitly.
The full SONiC default and loop-prevention review remains S2-14.

Workspace tests, build, formatting, warnings-as-errors rustdoc, and the documentation book pass.
Workspace Clippy uses only the existing admission-warning exception.
All twelve generator tests and deterministic artifact verification pass.
Unused-dependency checks pass. The dependency audit found no vulnerabilities, with the existing index-refresh lock warning.
The CLI build target now declares the existing secrets crate. No external dependency version, lockfile, protobuf contract, or unsafe code changed.
Windows, live SONiC, and independent-server validation did not run for this increment.

## SONiC Mapping and Loop Checks

Commit `64b2e4e` completes S2-14's source normalization and publication-time loop checks.
`SonicForwarderSettings::local_services` now owns the SONiC profile: both services, the mapped proxy endpoint, and row-derived credentials.
Generated YANG defaults supply the IPC path and socket permissions. The daemon no longer repeats these profile choices.
The ConfigDB listener port's default of 49 remains an explicit SONiC input rule. The canonical endpoint contains that resolved port.
CLI, SONiC, and YANG fixtures produce equal source and prepared listener values for IPv4, IPv6, and IPv4-mapped inputs.

The mapper no longer removes classic local rows or rejects TLS self-targets before producing the authoritative snapshot.
It preserves row material and credential references for the shared runtime filter.
An end-to-end regression failed because the earlier mapper deleted the local row required by S2-13's credential preparation.
That regression now passes through SONiC normalization, downstream credential preparation, and removal from the applied upstream set.
Distinct loopback addresses remain distinct hosts. Only actual IPv4-mapped aliases normalize to the same address.

`ListenerEndpoint::covers_tcp_destination` owns deterministic matching against resolved destinations and supplied interface addresses.
The daemon uses `if-addrs` to refresh local addresses for each wildcard-listener candidate check.
Wildcard checks cover loopback and non-loopback interfaces. IPv6 wildcard matching conservatively includes dual-stack bindings.
A regression that previously retained a loopback target under `0.0.0.0` now passes without removing a remote server on the same port.
The shared runtime filter rejects TLS self-targets, including those supplied outside SONiC.

When ports match, hostname resolution uses the canonical server timeout and checks every returned address.
Lookup failures, empty answers, unspecified destinations, and timeouts reject the candidate instead of retaining an unchecked row.
Deterministic tests inject resolution results and use paused time for timeout coverage.
Interface enumeration failure also rejects the candidate. Literal addresses and different-port candidates require no DNS lookup.
The existing supervisor retains the previous accepted generation when filtering fails.

Publication checks cannot guard address changes before a later connection attempt.
Networking resolves names again during execution, and an ephemeral listener's actual port differs from its configured zero value.
S2-17 records the required execution guard and its no-traffic regression criteria. This increment does not claim complete runtime loop protection.

Workspace tests, build, formatting, warnings-as-errors rustdoc, and the documentation book pass.
Workspace Clippy uses only the existing admission-warning exception. Unused-dependency checks pass.
The dependency audit found no vulnerabilities in 301 locked packages, with the existing index-refresh lock warning.
The daemon adds `if-addrs` 0.15.0. No existing external package version, generated YANG artifact, protobuf contract, or project unsafe code changed.
Windows, live SONiC, and independent-server validation did not run for this increment.

## Connection-Time Loop Exclusion

Commit `031eb3a` completes S2-17 on 2026-10-07.
Networking exposes `ConnectionGuard` through `PreparedEndpoint::with_connection_guard` without importing generated YANG types or agent configuration.
TCP establishment checks each freshly resolved destination before connecting and checks the connected socket before TLS or TACACS+ I/O.
A rejected destination stops the attempt. The new pre-connect rejection test failed before enforcement and now passes.

The agent owns `ProxyLoopGuard` and attaches it through the production upstream connector.
The TCP listener registers its actual bound address before publishing bound health or accepting clients.
This includes the kernel-selected port when configuration requests port zero. Canonical listener configuration remains unchanged.
Endpoint clones and cached clients share live guard state across reloads and reconnects.

Pending and closed TCP listener states reject new upstream connections.
A listener-owned registration closes the guard on normal return, failure after binding, or task cancellation.
Disabled and Unix-only proxy services do not apply TCP listener exclusions.
Wildcard checks refresh local interfaces and inspect the connected socket's local address in addition to its peer address.
No lock remains held across network awaits. These checks supplement publication-time validation rather than replacing it.

Deterministic resolution tests change the returned destination and verify that the excluded listener receives no connection.
Native post-connect rejection tests observe zero bytes for plain TCP, certificate TLS, and PSK endpoints.
Guard tests cover pending/bound/closed states, mapped addresses, and changed interface snapshots.
A real ephemeral listener test reloads an upstream self-target, exercises the production cached client, and verifies rejection before and after shutdown.
The test also verifies that runtime binding does not rewrite the canonical endpoint.

Workspace tests, build, formatting, warnings-as-errors rustdoc, and the documentation book pass.
Workspace Clippy uses only the existing admission-warning exception. Unused-dependency checks pass.
All nine independent `tac_plus-ng` runner cases pass after the shared establishment change.
The audit found no vulnerabilities in 301 locked packages, with the existing index-refresh lock warning.
The agent declares the existing `if-addrs` dependency. No external version, generated YANG artifact, protobuf contract, or project unsafe code changed.
Windows and live SONiC validation did not run for this increment.

## Peer Identity and Standard Ports

The S2-15 inventory review found two defects, recorded and corrected as S2-18 and S2-19 in commit `8e6243e`.
The original certificate path verified trust but only set SNI. It did not configure DNS/IP identity verification.
A native regression observed TACACS+ application data at a trusted peer with the wrong identity before the fix.
That regression now rejects the peer before application data.

Certificate preparation now derives the expected identity from `domain-name`, or from `address` when no domain is configured.
This identity is independent of `sni-enabled`. Only a true value sends the configured DNS name in the TLS `ClientHello`.
The native endpoint API accepts expected identity and optional SNI separately.
OpenSSL verifies DNS or IP SANs, with CN fallback and partial-label wildcard matching disabled.
The explicit development verification override still bypasses certificate checks without changing SNI selection.

The native matrix covers correct and mismatched DNS/IP identities, address-based identity, SNI on/off, CN-only certificates, and wildcard boundaries.
It observes actual SNI and application bytes, and verifies unchanged source values.
Repeated TLS/mTLS preparation tests and all nine independent `tac_plus-ng` cases pass with identity verification enabled.
This evidence does not establish certificate revocation, full chain provisioning, end-entity pinning, or complete RFC 9887 conformance.

The pinned YANG module requires explicit ports and documents port 300 for TLS, consistent with RFC 9887 Sections 3.1 and 5.2.
Shared CLI normalization previously selected 49 for TLS, while SONiC selected 449. Both omitted-port regressions failed before the correction.
Configuration now owns the common input constants: 49 for legacy TCP and 300 for certificate or PSK TLS.
SONiC reuses those constants. Explicit ports, including 449 and nonstandard fixture ports, remain unchanged.
Canonical YANG port requirements and generated artifacts are unchanged.

Address parsing now returns `Result` and uses a default only when the port is absent.
A regression demonstrated that `[::1]:bad` previously selected a default silently.
Malformed brackets, malformed explicit ports, and out-of-range explicit ports now fail before normalization succeeds.
Tests cover hostnames, IPv4, bracketed IPv6, bare IPv6, every CLI TLS mode, and explicit-port preservation.

Workspace tests, build, formatting, warnings-as-errors rustdoc, and the documentation book pass.
Networking and configuration pass strict package Clippy. Workspace Clippy uses only the existing admission-warning exception.
No dependency, lockfile, generated YANG, protobuf, or unsafe-code change was required.
Windows and live SONiC validation did not run for this increment.

## Certificate Trust Roles

Commit `bdbec25` completes S2-20 on 2026-10-07.
The pinned `ietf-tls-client` module defines CA trust as a valid path to a configured authority and end-entity trust as an exact certificate match.
Their contributions are additive. The previous projection combined both bags into one root list and lost those roles.
It also selected platform trust when a configured bag was empty.

The empty-bag preparation regression failed before the fix and now passes.
Explicit CA and end-entity bags must each contain materialized certificates. Preparation does not change the source.
When neither bag is selected, the existing server-authentication-only API retains platform trust.
Explicit trust never adds platform roots, and empty explicit trust remains an error even with the development verification override enabled.

Networking now accepts `CertificateTrust::Platform` or `CertificateTrust::Certificates` with separate borrowed authority and exact-peer DER collections.
The native endpoint API no longer accepts an undifferentiated root iterator.
OpenSSL partial-chain validation allows an exact configured CA-signed leaf without requiring its issuer as a trust anchor.
A native regression demonstrated that the previous root-list path rejected this legitimate exact match.

The verification callback never converts a failed native check into success.
After normal verification succeeds, it requires an exact peer match or a path to a configured authority.
A peer-only entry cannot authorize another certificate issued by that entry.
When an exact entry shortens the initial native path, a separate CA-only verification preserves any independent valid authority path.
The alternate path uses server-purpose validation and only runs after the initial identity, validity, purpose, and native path checks succeed.

The native matrix covers signed exact pins, CA anchors, renewed certificates with the same key, and additive authority/pin policies.
It also covers a peer entry that is not authorized as a CA and a shortened path with an independent configured CA.
Mismatched identity, expired, not-yet-valid, and client-only peer certificates receive no TACACS+ application data.
Tests verify unchanged canonical sources. Existing repeated TLS/mTLS and SNI tests still pass.
Revocation retrieval and client-chain provisioning are not added by this increment and remain explicit inventory questions.

Workspace tests, build, formatting, warnings-as-errors rustdoc, and the documentation book pass.
Networking and configuration pass strict package Clippy. Workspace Clippy uses only the existing admission-warning exception.
All nine independent `tac_plus-ng` runner cases pass with the updated verifier.
No dependency, lockfile, generated YANG, protobuf contract, or project unsafe code changed.
Windows and live SONiC validation did not run. These checks do not establish full RFC 9887 conformance.

## Remaining Stage 2 Work

- [ ] S2-15: Finish reconciliation of the [field-to-behavior inventory](stage-0-contract-gates.md#field-to-behavior-inventory). Identity/SNI, port defaults, CA versus exact-peer trust, and empty selections are resolved under S2-18 through S2-20. Review remaining client-chain/provider constraints. Complete the field cross-references and explicit operational-statistics and revocation dispositions. Resolve each remaining gap as supported and tested, explicitly rejected, or assigned to a named later-stage contract.
- [ ] S2-16: Complete the final Stage 2 validation and status update after the open implementation items finish. Run relevant workspace, generation, source-equivalence, rotation, and native interoperability checks. Record unavailable checks and known exceptions separately. Update the migration plan and this checkpoint together.

The existing source-equivalence and credential-generation tests remain required gates.
Upstream `source-ip`, `source-interface`, and `vrf-instance` already fail explicitly under S2-06. Their implementation is not an implicit local-listener requirement.
Routing, request leases, deadlines, and runtime retirement remain assigned to Stage 3.
Unified source observation and policy/server publication remain assigned to Stage 4. Policy schema normalization is already complete under S2-10.
Necessary corrections can move into Stage 2 through explicit new checklist items. The stage is not closed merely to preserve its original size.