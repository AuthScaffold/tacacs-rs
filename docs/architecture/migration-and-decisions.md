# Migration and Architecture Decisions

## Recommendation

Use a staged replacement inside the existing repository.
Each stage produces a deployable set of applications and removes the superseded ownership for its completed behavior.
Old Rust APIs and old IPC schemas do not require compatibility.
Temporary internal adapters are acceptable only with a named removal stage.

The target remains one coordinated toolkit and its adapters.
It does not become a collection of independently deployed services.

YANG remains the authoritative configuration model at every migration stage.
CLI and SONiC inputs normalize into that model, and the preparation pipeline derives immutable runtime generations from it.
The refactor does not introduce a competing desired-configuration schema or independent runtime defaults.

The [target architecture](target-architecture.md) defines destinations.
The [runtime contracts](runtime-contracts.md) define acceptance criteria.
The [current-state assessment](current-state.md) supplies evidence and finding identifiers.

## Decision Record

These decisions are recommendations for implementation, not approvals to modify product code during this review.

### D1. Organize around toolkit consumers

**Decision:** make protocol operations, single-endpoint execution, and routed execution usable without the agent.

The user selected a reusable toolkit as the primary product.
The existing client already owns transport and session behavior.
The agent's routing and retry machinery can become client capabilities without retaining its listener and health dependencies.

**Rejected alternative:** keep the agent as the only reliable multi-server API.
That forces direct consumers to host unnecessary infrastructure or duplicate routing policy.

**Cost:** extraction needs a neutral failure model and tests that do not depend on gRPC handlers.
**Success measure:** a direct routed-client example uses the canonical YANG preparation API without an agent, Redis, or tonic dependency.
The client execution code consumes prepared values without interpreting generated YANG types.

### D2. Consolidate small layers while protecting external boundaries

**Decision:** merge messages and pure flow descriptions into one protocol package.
Merge datastore contracts and CLI/file source plumbing into the configuration package.
Keep secrets, credentials, native client, IPC, and SONiC as separate dependency boundaries.

**Rejected alternative:** create a crate for every trait, state machine, and conversion module.
That increases package navigation and release work for a small maintainer group.

**Rejected alternative:** one large crate containing all integrations behind many flags.
That hides dependency direction and creates a large feature-combination burden.

**Cost:** several imports and tests move together.
**Success measure:** protocol-only builds need no native libraries or generated IPC code.
Source/provider changes remain outside the client implementation.

### D3. Preserve canonical YANG and derive prepared runtime state

**Decision:** preserve YANG as the authoritative configuration model and use one preparation pipeline for every configuration consumer.
This decision incorporates the user's clarification on 2026-09-24 and replaces the earlier independent desired-model proposal.
The [canonical YANG contract](target-architecture.md#canonical-yang-contract) records the RFC 9887 and RFC 9950 basis.

CLI, SONiC, and file adapters normalize into the generated model with its supported features and reviewed augmentations.
Preparation validates snapshots, resolves credentials, and constructs connection-ready artifacts without mutating authoritative configuration or references.
Generated types remain legitimate configuration APIs, while client execution and native callbacks consume narrow prepared values.

**Rejected alternative:** replace YANG with an independent desired model or let SONiC bypass it.
That duplicates configuration authority and risks different defaults, validation rules, and security behavior.

**Rejected alternative:** label an unchecked generated server as resolved through a wrapper alone.
A stage-specific wrapper is useful only when its construction proves validation or preparation guarantees.
It does not require a new configuration schema.

**Cost:** explicit conversion code and provenance mapping remain necessary.
**Success measure:** every supported YANG field maps to prepared behavior with acceptance tests.
Equivalent inputs share one normalization and preparation contract, and unsupported configured features fail explicitly.
Prepared generations cannot be independently edited, persisted as configuration, or assigned competing defaults.
The client execution package has no production dependency on generated YANG types.

### D4. Retain Tokio, gRPC, and OpenSSL at explicit boundaries

**Decision:** keep the current asynchronous runtime, local RPC stack, and native TLS backend initially.
Move their types out of pure domain APIs where they do not belong.

The existing EPSK bridge needs capabilities beyond a basic certificate-only TLS client.
A replacement must demonstrate certificate, mTLS, EPSK, hash, importer, and key-exchange parity for retained modes.

**Rejected alternative:** change runtime, RPC, and TLS libraries during the ownership refactor.
That combines independent risks and obscures whether the new boundaries improved maintenance.

**Cost:** native OpenSSL packaging and the narrow unsafe callback remain.
**Success measure:** those dependencies remain isolated and their interoperability tests pass.
No technology receives permanent exemption from later evidence-based replacement.

### D5. Use one typed operation and failure model

**Decision:** direct clients, IPC clients, and host adapters share logical operation values and response interpretation.
The wire representation remains distinct from logical operations where semantics differ.
Errors preserve delivery facts separately from retry advice.

**Rejected alternative:** flatten every reply into success/failure and one retriable flag.
That cannot represent server denial, unsupported mandatory changes, and unknown accounting outcomes accurately.

**Cost:** the IPC schema and all callers change together.
**Success measure:** conformance fixtures give equivalent logical results through direct and IPC execution.
Host enforcement fixtures also cover adapter capability differences explicitly.

### D6. Make task lifetime and request generation explicit

**Decision:** owned runtime handles provide close and join behavior.
Each request captures one routing lease. Global admission remains shared across generations.

**Rejected alternative:** one actor for every server, session, credential, and policy object.
Actors can clarify an owner, but they are not a default replacement for short locks and ordinary functions.

**Rejected alternative:** rely on process exit to clean up detached tasks.
That is not sufficient for an embedded toolkit or repeated live reload.

**Cost:** cancellation and retirement require explicit states and bounded cleanup tests.
**Success measure:** resource counts return to baseline after repeated reload, cancellation, and embedded shutdown scenarios.

### D7. Treat experiments and test machinery as optional

**Decision:** keep session-wrapper outside the supported release path until its security model is approved.
Retain the Bash integration only after its response interpretation, timeout, and ABI gates pass.
Use deterministic test scenarios as the baseline. Preserve Rego only for scenarios that require its expressiveness.

**Rejected alternative:** preserve every current executable as a permanent product.
The user explicitly allowed retirement of low-value capabilities.
Each additional host integration has a maintenance and security obligation.

**Cost:** users of an experimental component need a clear status notice and migration decision.
**Success measure:** shipping products have named acceptance tests and support scope.
Experimental components do not force native dependencies into core builds.

### D8. Coordinate releases across the workspace

**Decision:** use one release version and source tag for the shipped toolkit/application set.
Prefer a normal version-update commit on the development line followed by immutable artifact builds.
Retire independent internal-library version propagation and the generated release-source branch after a successful rehearsal.

**Rejected alternative:** maintain independent library compatibility analysis without independently supported consumers.
The current packages are internal and unpublished.

**Cost:** release consumers must adopt the new artifact/version contract.
**Success measure:** one source commit reproduces one release set, including manifests, binaries, symbols, SBOMs, and checksums.
Historical tags and artifacts remain intact.

## Staged Implementation

The stages are ordered by dependency and behavioral risk, not by directory name.
Every stage includes code, tests, documentation, and deletion of completed temporary scaffolding.

### Stage 0. Establish contract gates

**Scope:** current implementation only. No package reorganization yet.

Implementation checkpoint: [Stage 0 contract gates](stage-0-contract-gates.md).
The checkpoint records implemented regressions, corrections, the YANG baseline, and validation exceptions.

1. Add regression tests for F1 through F5 at their existing owners.
2. Correct any demonstrated defects before extracting the affected code.
3. Add forced-interleaving tests for publication, source setup, connection retirement, and cancellation.
4. Define the supported product/platform matrix and experimental component status.
5. Capture representative direct, IPC, proxy, and credential-rotation scenarios.
6. Record the pinned YANG module, enabled features, augmentations, and supported field-to-behavior mappings.

Primary starting points:

- [Packet constructors](../../libraries/tacacsrs_protocol/src/packet.rs)
- [Client retirement](../../libraries/tacacsrs_networking/src/client/mod.rs)
- [Source subscription](../../libraries/tacacsrs_cli_datastore/src/datastore.rs)
- [IPC failure conversion](../../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/routed.rs)
- [Bash authorization](../../libraries/tacacsrs_bash_plugin/src/authorization.rs)

**Exit gate:** the chosen behavior is explicit and covered by tests that fail against the prior faulty path.
The existing applications remain deployable.
Security-relevant behavior corrections do not wait for the final package design.
Equivalent CLI, SONiC, and YANG fixtures establish the canonical configuration baseline before model or preparation changes.

### Stage 1. Extract protocol and operation ownership

**Scope:** messages, flow descriptors, logical operations, and conversion boundaries.

1. Establish `tacacsrs-protocol` from existing wire code and pure flow descriptors.
2. Move `FixedExchange` and conversation validation into the pure layer.
3. Move logical operation values and authorization interpretation out of the IPC client.
4. Add strong types only for demonstrated invariants such as privilege and ordered authorization attributes.
5. Keep protobuf conversion in the IPC adapter and update every consumer.

Primary starting points:

- [Exchange description](../../libraries/tacacsrs_protocol/src/exchange.rs)
- [Flow modules](../../libraries/tacacsrs_protocol/src/exchange.rs)
- [Current logical operations](../../libraries/tacacsrs_protocol/src/operations.rs)
- [CLI dual construction](../../executables/tacon/src/commands/authorization.rs)

**Temporary adapter:** old crate re-exports can bridge one integration commit.
**Removal:** remove them before this stage ends. They are not public compatibility commitments.
**Exit gate:** protocol-only builds have no I/O dependencies, and direct/IPC fixtures use one logical request model.

### Stage 2. Introduce prepared endpoints and consolidate configuration

**Scope:** canonical YANG snapshots, credential materialization, and derived client connection inputs.

1. Preserve generated YANG types and builders as the authoritative configuration APIs.
2. Normalize CLI and SONiC inputs into YANG snapshots through the same schema and feature validation contract.
3. Consolidate bundle expansion, credential resolution, and runtime projection under one preparation owner.
4. Derive connection-ready endpoints and native contexts without mutating the source snapshot or its credential references.
5. Merge datastore and CLI/file packages into configuration modules.
6. Replace generated-model interpretation in client execution and native callbacks with narrow prepared values.
7. Model product controls absent from the standard through documented namespaced YANG augmentations.

Primary starting points:

- [Credential materialization](../../libraries/tacacsrs_credential_resolution/src/materialization.rs)
- [Certificate conversion](../../libraries/tacacsrs_networking/src/transport/tls/from_server.rs)
- [EPSK callback state](../../libraries/tacacsrs_networking/src/transport/tls_psk/ffi/mod.rs)
- [SONiC mapping](../../libraries/tacacsrs_sonic/src/mapping.rs)

**Temporary adapter:** forward existing configuration entry points through the canonical YANG preparation pipeline during consumer conversion.
**Removal:** remove duplicated interpretation paths, not the canonical YANG model or its builders.
**Exit gate:** equivalent CLI, SONiC, and YANG inputs produce equivalent prepared behavior.
Field mappings preserve supported choices, defaults, units, ordering, identities, references, and constraints.
Unsupported configured features fail explicitly before publication.
Preparation and credential rotation leave authoritative snapshots unchanged.
Client execution has no generated-model dependency, and all retained transport modes pass interoperability tests.

### Stage 3. Extract the routed client and owned connection runtime

**Scope:** endpoint routing, failover, sessions, and resource lifetime.

1. Move operation routing, circuits, and reconnect serialization from the agent to the client.
2. Retain the shared retry executor and adapt it to neutral operation/failure types.
3. Add request leases, absolute deadlines, bounded queues, and explicit client close/join behavior.
4. Make proxy and typed-operation callers consume the same routing owner.
5. Adopt the conservative default retry policy and document the intentional behavior change.
6. Preserve configured YANG server ordering, operation eligibility, timeout semantics, and security choices during routing extraction.

Primary starting points:

- [Upstream manager](../../libraries/tacacsrs_agent/src/upstream/manager/mod.rs)
- [Shared executor](../../libraries/tacacsrs_agent/src/upstream/executor.rs)
- [Connection driver](../../libraries/tacacsrs_networking/src/runtime/multiplexed/mod.rs)
- [Session routes](../../libraries/tacacsrs_networking/src/session/manager.rs)

**Temporary adapter:** agent connection interfaces can forward to the new client during consumer conversion.
**Removal:** remove duplicate routing and retry state from the agent before the stage ends.
**Exit gate:** a routed direct client works without the agent.
Retirement, cancellation, backpressure, and reload tests pass.
Routing observations cannot silently override canonical policy or cause TLS-to-plaintext fallback.

### Stage 4. Create one configuration controller and lifecycle API

**Scope:** source observation, materialization coordination, health, and process ownership.

1. Replace separate load/subscribe startup with owned observation sessions that supply canonical YANG snapshots.
2. Move generic source and policy supervision into the agent runtime.
3. Commit generation state and applied-health metadata through one controller.
4. Keep global admission independent of generation replacement.
5. Accept explicit cancellation from the host and remove process signal handling from libraries.
6. Add stale-material, expiry, revocation, and bounded drain policies.
7. Normalize existing policy-file inputs into documented YANG augmentations instead of a parallel policy schema.

Primary starting points:

- [Configuration supervisor](../../executables/tacacsrs_agentd/src/config_supervisor.rs)
- [Materialization coordinator](../../executables/tacacsrs_agentd/src/materialization_coordinator.rs)
- [Policy supervisor](../../executables/tacacsrs_agentd/src/policy_supervisor.rs)
- [Agent shutdown](../../libraries/tacacsrs_agent/src/runtime/shutdown.rs)
- [Health model](../../libraries/tacacsrs_agent/src/runtime/health.rs)

**Temporary adapter:** old source implementations can enter through a reconciliation wrapper with explicit limitations.
**Removal:** replace that wrapper for every retained source before the stage ends.
**Exit gate:** source-race tests converge, stale completions cannot publish, embedded shutdown completes, and process health behavior matches deployment tests.
Credential-only changes derive new generations from unchanged YANG snapshots with separate credential revisions.
No controller or provider rewrites authoritative credential references during preparation or publication.

### Stage 5. Simplify adapters and supported products

**Scope:** daemon, CLI, IPC, proxy, health probe, host integration, and test scenarios.

1. Finish the IPC package split and update the schema to preserve failure facts.
2. Make the daemon a composition root with no independent routing or materialization algorithm.
3. Make CLI batch and direct modes use the shared client implementation.
4. Apply shared authorization interpretation to every retained enforcement adapter.
5. Move experimental wrapper and optional Rego scenarios outside the supported core release profile.
6. Replace duplicated test fixtures with shared conformance cases where the semantics are identical.
7. Keep direct CLI and daemon configuration on the same canonical YANG preparation path.

**Deployment unit:** if the IPC contract changes, ship the daemon, clients, health probe, and host adapters as one matched set.
There is no dual-schema support requirement.
**Exit gate:** matched-set process tests pass, direct/IPC results agree, and experimental status is visible in documentation and packaging.

### Stage 6. Simplify delivery and enforce architecture

**Scope:** release versions, CI, generation, packaging, and documentation.

1. Generate package inventories from Cargo metadata, including dependency kind and target conditions.
2. Enforce the production dependency allowlist from the target architecture.
3. Run protocol-only, direct-client, IPC, and full Linux profiles in CI.
4. Add authentication and authorization parser fuzz targets for implemented bodies.
5. Replace independent internal-library version propagation with one coordinated release version.
6. Rehearse source-to-artifact reproduction, SBOM generation, native dependencies, and rollback.
7. Remove obsolete crates, scripts, generated release-branch machinery, and architecture guidance only after their replacement gates pass.
8. Verify pinned YANG generation, supported features, augmentations, and field-to-behavior tests in the relevant configuration gates.

Primary starting points:

- [CI matrix](../../.github/workflows/reusable-pipeline.yml)
- [Version computation](../../.github/steps/compute-versions/action.yml)
- [Version hydration](../../.github/steps/inject-versions/hydrate_versions.py)
- [Container recipe](../../containers/tacacsrs-agentd/Dockerfile)
- [Schema generation guidance](../../DEVELOPMENT.md#L225)

**Exit gate:** one release rehearsal produces the complete artifact set from an identified source commit.
No completed temporary adapter remains.
The documentation names actual owners and matches the package graph.
Dependency rules isolate generated-model interpretation from client execution without prohibiting its use in configuration APIs.

## Rollback and Deployment Safety

Deployability does not require source-level backward compatibility.
It requires that each stage has a complete artifact set and an explicit operational contract.

The rollback unit is the matched release set, not an arbitrary mixture of old and new libraries or IPC clients.
The release manifest records source revision, configuration schema revision, IPC revision, and artifact hashes.
Rollback documentation identifies any changed defaults, especially retry, health, and credential-retention policy.

Configuration conversion is separate from runtime deployment.
The migration must not rewrite operator files or credential stores without an explicit conversion step and rollback copy.
No stage assumes that a renamed Rust type implies a persistent-data migration.
The refactor alone does not require a replacement YANG schema or conversion to a custom configuration format.
Configuration export and rollback use authoritative YANG snapshots, not reconstructed native runtime state.

Rollback copies preserve credential references rather than create unprotected copies of credential material.
Rollback must not restore expired or revoked credentials.
Shadow comparisons use pure transformations or non-authoritative test traffic.
They must not duplicate real accounting records or authentication attempts merely to compare implementations.

Existing active sessions cannot survive a process restart unless the product explicitly implements that feature.
The deployment procedure therefore uses drain and a bounded interruption window.
The architecture does not claim zero-downtime upgrades by default.

## Verification Strategy

### Fast local loop

Each changed owner runs its focused tests first.
Pure state-machine tests use controlled time and explicit barriers rather than timing guesses.
Cross-package extraction also runs all affected consumers before a stage merges.

### Contract suites

| Suite | Required coverage |
| --- | --- |
| Protocol | Exact framing, round trips, malformed fields, sequence rules, and secret-safe diagnostics |
| Client | Dedicated/shared negotiation, concurrent recovery, cancellation, late replies, drain, and backpressure |
| Routing | Captured generations, stale failure reports, per-operation eligibility, and replay matrix |
| Sources | Canonical YANG normalization, initial observation, reconnect, dropped events, rejected candidates, and disposal |
| Configuration preparation | Supported YANG field semantics, immutable snapshots, unsupported-feature rejection, and RFC 9887 behavior |
| Credentials | Result matching, protected material, expiry, revocation, supersession, and provider confinement |
| Adapters | Direct/IPC equivalence, raw proxy pinning, host mandatory attributes, and error preservation |
| Processes | Startup, signals, socket ownership, matched IPC deployment, health exits, and bounded shutdown |
| Delivery | Reproducible generation, package profiles, native dependencies, archives, SBOMs, and source provenance |

### Required gates

Implementation stages follow the repository's format, Clippy, documentation, build, and workspace-test requirements.
Dependency changes also run audit and unused-dependency checks.
Protobuf changes run the protobuf compatibility tool against the selected migration baseline and record intentional breaks.
The old baseline is not an obligation to preserve obsolete behavior.

YANG changes run pinned generation verification and the supported field-to-behavior suite.
Tests cover equivalent source normalization, preserved references during rotation, and explicit rejection of unsupported configured features.
Schema-valid inputs also need RFC 9887 runtime tests for TLS versions, mutual authentication, obfuscation prohibition, and downgrade prevention.

Pure protocol and safe state code use Miri where applicable.
Native OpenSSL, Bash ABI, seccomp, and process behavior need native integration tests and appropriate sanitizer/ABI checks.
Miri is not a substitute for executing native FFI behavior.

Fuzzing covers every implemented parser family and packet framing boundary.
Benchmarks cover connection reuse, concurrent operations, reconnect contention, and memory after repeated reloads.
Performance changes are evaluated against measured workload limits, not an unmeasured speed claim.

## Maintenance Acceptance

The redesign is successful when these observable conditions hold:

- A maintainer can find one owner for each contract in the runtime document.
- A new configuration source does not change protocol or client code.
- A new credential provider does not change native TLS callbacks.
- A direct routed-client program uses canonical YANG preparation without hosting the agent.
- YANG remains the only authoritative configuration model across CLI, SONiC, and library entry points.
- Prepared runtime generations add no independent configuration defaults or editable configuration interface.
- Every supported YANG field has a documented preparation mapping and an observable behavior test.
- Credential resolution and rotation preserve authoritative snapshots and their references.
- The same logical request construction serves direct and IPC paths.
- Every long-lived task has a stop path and a tested completion obligation.
- Repeated reloads and canceled operations return resource counts to a bounded baseline.
- Each retained host adapter applies the same authorization interpretation rules.
- Every shipping product has a defined support scope and process-level acceptance tests.
- The release set has one source identity and no unnecessary internal compatibility cascade.

File count and line count are not acceptance metrics.
Neither is a smaller number of tests.
The relevant result is less duplicated policy and fewer hidden lifecycle obligations.

## Decisions Still Needed

These decisions do not block the architecture recommendation, but they block specific production stages:

| Decision | Needed before | Recommended approach |
| --- | --- | --- |
| Required operation set and expected concurrency | Stage 3 tuning | Record real CLI, agent, and proxy workloads. Keep finite limits. |
| Credential stale budget and revocation behavior | Stage 4 deployment | Set explicit deployment policy and test expiry/revocation |
| Bash plugin support owner and fork contract | Stage 5 product retention | Retain only with native ABI and host tests |
| Wrapper threat model and support owner | Any return to supported status | Keep experimental until those requirements exist |
| Rego scenarios that cannot use deterministic fixtures | Stage 5 test migration | Retain only demonstrated policy needs |
| Public crates.io distribution intent | Stage 6 release policy | Keep one coordinated version until independent distribution is required |

## Deliverable Boundary

This review proposes changes and specifies their acceptance criteria.
It does not implement the target packages, change runtime behavior, or approve capability removal on the user's behalf.
The source-based findings identify where implementation work begins.
Focused regressions and deployment evidence remain required before those changes ship.