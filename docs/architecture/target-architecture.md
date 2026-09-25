# Target Architecture

## Recommendation

Build a reusable toolkit with a pure protocol layer, an asynchronous client, and optional integration packages.
Keep the agent as an application runtime over that toolkit.
Keep process integration in executable adapters.

YANG remains the authoritative configuration model throughout the refactor.
CLI and SONiC inputs normalize into that model before preparation.
Prepared runtime generations are derived execution artifacts, not a second configurable model.

Prefer extraction and consolidation of proven code over replacement of working algorithms.
The design removes misplaced ownership, not all existing abstractions.
It introduces no distributed control service, general plugin framework, dependency-injection container, or custom asynchronous runtime.

Status: proposed architecture, not implemented APIs.
The [current-state assessment](current-state.md) supplies the evidence.
The [runtime contracts](runtime-contracts.md) define behavioral requirements.
The [migration plan](migration-and-decisions.md) defines deployable stages and decision rationale.

## Goals and non-goals

The primary users are Rust consumers of TACACS+ capabilities and maintainers of the supplied applications.
The expected maintainer group is small.

The design must make these changes local:

- A new message or operation changes protocol code and its conformance tests.
- A transport change does not require edits to YANG generation or gRPC conversion.
- A credential provider does not require edits to TLS callbacks.
- A configuration source does not require edits to routing or retry policy.
- An application can use ordered failover without hosting a daemon.
- A host adapter does not implement its own interpretation of mandatory authorization arguments.

The design does not promise new authentication mechanisms, operating systems, or TLS backends.
It establishes extension points for demonstrated responsibilities, not speculative future products.
Maintaining wire correctness is necessary even when Rust and IPC APIs change freely.

## Logical dependency direction

Dependencies point from integration code toward domain code.
The protocol and client runtimes do not import applications, generated YANG types, or generated RPC contracts.
Configuration components intentionally use the canonical YANG model.

| Layer | Owns | Must not own |
| --- | --- | --- |
| Secret values | Protected ownership and explicit exposure | Configuration formats, providers, logging setup |
| Protocol | Wire values, operation semantics, exchange descriptions, failure facts | Sockets, timers, TLS, protobuf, files |
| Client | Endpoint preparation, connections, sessions, routing, execution | YANG, ConfigDB, gRPC, signals, systemd |
| Credentials | Provider requests, material, revisions, resolution contracts | Generated YANG fields, TLS connections, publication |
| Configuration | Source normalization, canonical YANG snapshots, preparation | Request routing, listener tasks, native callbacks |
| Agent runtime | Source supervision, generation publication, health, coordinated shutdown | Process signals, CLI parsing, platform credential grammar |
| Integration adapters | IPC, raw proxy ingress, SONiC, shell ABI | Duplicate protocol or retry policy |
| Executables | Composition, host integration, exit status | Independent implementations of toolkit behavior |

Each representation has its own authority.
YANG defines operator intent and configuration semantics. Protobuf describes local IPC.
TACACS+ packets describe the upstream wire protocol.
Prepared runtime values derive from YANG without replacing that configuration authority.

## End-to-end paths

These diagrams show execution order, not Cargo dependencies.

```text
Direct operation:
	application -> protocol operation -> client request lease
							-> endpoint selection -> connection/session -> TACACS+ peer

Local API operation:
	IPC client -> protobuf -> IPC handler -> agent handle
						 -> protocol operation -> the same client execution path

Raw proxy conversation:
	downstream packet -> proxy session mapping -> routed conversation
										-> pinned upstream session after an accepted reply
```

Logical requests and failure facts are shared by direct and IPC paths.
The proxy shares routing and connection owners without converting every packet into a unary operation.

```text
Configuration update:
	source observation -> canonical YANG snapshot -> credential resolution
										 -> endpoint preparation -> current-ticket check
										 -> generation publication -> retirement of old endpoints

Credential change:
	provider invalidation -> reprepare the affected YANG configuration
												-> the same preparation and publication path
```

No source or provider publishes directly into active connection state.
The publication controller rejects stale work before the routed client accepts a new generation.

## Proposed package layout

Package names below identify the proposed destinations.
They are not claims that these packages already exist.
Modules remain the default unit of internal decomposition.

| Package | Main modules and types | Production workspace dependencies |
| --- | --- | --- |
| `tacacsrs-secrets` | `SecretBytes`, `SecretString`, protected ownership | None |
| `tacacsrs-protocol` | `wire`, `operations`, `exchange`, `conversation`, `authorization`, `failure` | `secrets` |
| `tacacsrs-client` | `endpoint`, `transport`, `connection`, `session`, `routing`, `execution` | `protocol`, `secrets` |
| `tacacsrs-credentials` | `reference`, `request`, `material`, `resolver`, `change` | `secrets` |
| `tacacsrs-config` | `yang`, `snapshot`, `source`, `prepare`, `files` | `client`, `credentials`, `protocol`, `secrets` |
| `tacacsrs-agent` | `controller`, `runtime`, `health`, `proxy` | `client`, `config`, `credentials`, `protocol` |
| `tacacsrs-ipc` | `generated`, `convert`, `client`, `server`, `health`, `endpoint` | `protocol`, `secrets` |
| `tacacsrs-sonic` | `configdb`, `mapping`, `credentials`, `binding` | `config`, `credentials`, `secrets` |
| `tacacsrs-test-support` | Wire peer, operation fixtures, source/provider doubles, scenario runner | Selected toolkit and adapter packages, development use only |

Dependency names in the final column omit the `tacacsrs-` prefix for readability.
The dependency table is an allowlist, not a requirement to add unused imports or dependencies.
No shipping library depends on `tacacsrs-test-support` in its production dependency section.

The IPC server owns a small operation-handler interface expressed in protocol-domain types.
The daemon supplies an adapter from that interface to the agent handle.
Thus, the IPC package does not import the agent, and the agent does not import IPC.
The same interface supports a test handler without constructing the production runtime.

The raw proxy remains a dedicated adapter module in the agent package initially.
It consumes client conversations and routes. It does not interpret YANG or install signal handlers.
A separate proxy crate is unnecessary until a real consumer needs independent packaging.

## Disposition of current packages

| Current package | Proposed disposition |
| --- | --- |
| `tacacsrs-messages` | Become the wire portion of `tacacsrs-protocol`. Harden public construction and parsing. |
| `tacacsrs-flows` | Merge pure operation descriptors into `tacacsrs-protocol`. Remove the separate package. |
| `tacacsrs-networking` | Become `tacacsrs-client`. Remove the configuration-schema dependency and add reusable routing. |
| `tacacsrs-secrets` | Retain as a small leaf package. Move format-specific serialization to adapters. |
| `tacacsrs-config` | Retain the canonical YANG model and builders. Own snapshot validation and the preparation pipeline. |
| `tacacsrs-credential-resolution` | Become `tacacsrs-credentials`. Move generated-model projection into configuration code. |
| `tacacsrs-datastore` | Merge the source contract into `tacacsrs-config::source`. Remove the package. |
| `tacacsrs-cli-datastore` | Merge file and input adapters into configuration modules. Keep clap out of the library. |
| `tacacsrs-sonic` | Retain as an optional Linux integration. Normalize ConfigDB into canonical YANG snapshots before preparation. |
| `tacacsrs-agent` | Move reusable routing down to the client. Absorb generic supervision from the daemon. |
| `tacacsrs-agent-client` | Become `tacacsrs-ipc`. Move logical operation types into the protocol package. |
| `tacacsrs-agentd` | Retain as the composition root and process host. |
| `tacacsrs-agent-health` | Retain as a small IPC-only probe. A lightweight probe has a separate operational purpose. |
| `tacon` | Retain. Build each logical operation once, then select direct or IPC execution. |
| `tacacsrs-bash-plugin` | Retain only as an optional host adapter after the authorization and ABI gates pass. |
| `session-wrapper` | Remove from the supported product path. Preserve as an explicitly experimental component pending a threat model. |
| `tacacsrs-agent-ipc-emulator` | Move deterministic scenarios into development support. Keep Rego only if required scenarios justify it. |
| `tacacsrs-agent-ipc-emulatord` | Replace the separate product with a development scenario executable when process tests need it. |

The wrapper recommendation is not a claim that seccomp supervision has no value.
Its fork, process-tree, mutable-memory, and enforcement concerns form a separate security product.
A small toolkit team must not imply that command interception alone provides a general sandbox.
Reintroduction requires a named maintainer, defined attacker model, and native acceptance tests.

The Bash plugin also remains a limited integration, not a general host security boundary.
Its supported hook coverage, nesting behavior, failure policy, and fork assumptions must be explicit.

## Protocol package

### Wire invariants

The protocol package owns the TACACS+ header and every implemented message body.
Parsing has explicit input-consumption rules:

- Complete-frame parsing rejects truncation and surplus bytes.
- Prefix parsing returns both the decoded value and the consumed byte count.
- Encoding computes lengths from the actual body.
- Frame limits are checked before allocation in the streaming decoder.
- Structured operation parsing rejects invalid field combinations and out-of-range values.

Public fields must not let callers invalidate a checked packet after construction.
Validated identifiers, privilege levels, argument lengths, and sequence values use domain types where they prevent real mistakes.
The design does not require a wrapper around every integer or string.

Wire bytes and human-readable text remain distinct.
Opaque data must not undergo lossy UTF-8 conversion.
Adapters can impose text-only restrictions, but the restriction must be explicit and tested.

### Operations and exchange descriptions

The package owns accounting, authorization, and PAP request/reply semantics.
It also owns the fixed-exchange description currently defined by networking.
An exchange describes packet kind, version, body encoding, and reply interpretation without performing I/O.

The client supplies session IDs, sequence progression, transport flags, and deadlines.
The protocol package supplies a pure conversation validator for multi-packet exchanges.
Raw conversations and typed fixed exchanges remain different APIs.

Authorization arguments preserve order, repeated names, and mandatory/optional status.
They are not flattened into a map that loses repeated `cmd-arg` values.
Shell command builders are convenience APIs over the same operation model used by direct and IPC callers.

### Response interpretation

The toolkit exposes the server response independently of a host enforcement decision.
A pure interpreter applies the RFC-defined addition or replacement rules and produces effective authorization attributes.
The host adapter declares which attributes and changes it can enforce.

Unknown mandatory attributes fail authorization.
Known mandatory changes must be applied before execution.
Recognized attributes that leave the effective command unchanged do not require a fake mutation.
Optional attributes can be ignored only where the protocol permits that behavior.

This contract replaces adapter-specific status-only decisions.
The interpreter does not invent local fallback policy or change a denial into a connectivity error.

### Failure facts

The pure failure model carries facts useful across direct and IPC boundaries:

| Fact | Meaning |
| --- | --- |
| Category | Invalid request, unsupported capability, unavailable configuration, capacity, transport, protocol, deadline, cancellation, or internal failure |
| Phase | Admission, connection, negotiation, request transmission, reply, or conversation continuation |
| Delivery | `NotSent` or `OutcomeUnknown` for a failed attempt |
| Retry advice | Do not retry, retry only a known-unsent request, or retry under an explicit caller policy |
| Context | Stable operation and endpoint identifiers, without secrets or full command arguments |

Valid server denials and valid server error replies remain response values.
They are not indistinguishable transport exceptions.
Native error chains remain local diagnostic context. They do not become arbitrary public IPC messages.

## Client package

### API levels

The client offers two concrete entry points over shared implementation:

| Entry point | Consumer need |
| --- | --- |
| Single-endpoint client | Direct operation against one prepared server |
| Routed client | Ordered eligible servers, per-operation recovery, and bounded failover |

A caller can execute a typed exchange or open a sequential conversation.
The library supports Tokio deliberately. It does not add a runtime abstraction without a second supported runtime.
Public futures remain `Send`.

Public APIs expose domain values and handles, not mutexes, routing indices, or native OpenSSL structures.
Internal sharing can use `Arc`, short lock scopes, and existing session abstractions.
Cheaply cloned client handles share owned runtime resources.

Toolkit configuration APIs accept YANG-aligned builders or snapshots through the configuration package.
Direct consumers and the daemon use the same preparation pipeline.
The client executes prepared values without requiring its connection and session code to interpret YANG.

### Endpoint and transport types

`EndpointSpec` is a derived preparation input that identifies an endpoint and its supported operation kinds.
It contains a hostname or IP address, port, timeout policy, connection mode, and a transport choice.
It is not an independently editable configuration object and introduces no independent defaults.
DNS names must not be forced into `SocketAddr` before resolution.

The transport choice is a sum type, not a collection of independent optional security fields:

| Variant | Required material |
| --- | --- |
| Legacy TCP | Explicit body-protection policy and any shared secret |
| Certificate TLS | Peer identity, trust policy, and client certificate identity for the RFC 9887 profile |
| TLS 1.3 EPSK | External identity, key material, hash/importer parameters, and key-exchange policy |

Server identity verification and SNI are separate fields.
Changing SNI must not silently disable peer verification.
Unsupported source binding, interface, or VRF settings produce explicit errors.
No adapter silently discards them to fit a smaller runtime model.

`prepare_endpoint` converts a resolved specification into a connection-ready endpoint.
It validates DER, key relationships, supported algorithms, and backend capabilities before publication.
Prepared native objects remain private to the client.
The operation path does not repeatedly interpret generated schema fields.

The default native TLS backend remains OpenSSL.
The existing EPSK callback bridge has a specific purpose that a replacement must support.
Native callbacks receive only narrow prepared state and cannot perform provider I/O or access a datastore.

### Routing and execution

Move the existing routing, circuits, reconnect serialization, and shared retry executor into this package.
Remove dependencies on IPC service names and daemon health publishers during extraction.
Consumers select a typed routing policy at construction or generation publication.

Routing captures a request lease with one eligible server set, one policy, and one deadline.
Mutable circuit observations are separate from immutable endpoint definitions.
Each attempt records its endpoint and connection generation.
Stale failures cannot invalidate a replacement connection.

The proxy pins a conversation after it forwards the first accepted reply.
No continuation packet changes servers.
Unknown outcomes are not replayed by default, including authentication.
An explicit policy can permit a documented replay risk for a specific operation.

The client owns bounded connection queues and a defined slow-consumer policy.
Application admission cannot be the only protection for users who call the library directly.
Shutdown, cancellation, and retirement details are specified in the runtime contract document.

## Configuration and credentials

### Canonical YANG contract

[RFC 9887 Section 6.3](https://www.rfc-editor.org/rfc/rfc9887.html#section-6.3) identifies the TACACS+ YANG model.
[RFC 9950](https://www.rfc-editor.org/rfc/rfc9950.html) defines that model, including TLS support.
The repository already pins its module revision in the [generation manifest](../../libraries/tacacsrs_config/yang/generation-manifest.json).
The refactor retains the generated model, reviewed feature selection, and YANG-aligned construction APIs.

There is no independent desired-configuration schema.
In this design, desired configuration means the current authoritative YANG snapshot, not another family of configuration types.
CLI flags, file inputs, and SONiC data normalize into this model.
Neither SONiC nor a direct toolkit consumer bypasses its configuration semantics through a parallel model.

One preparation pipeline owns schema validation, local bundle expansion, credential resolution, and projection into native transport preparation.
Its stages can remain separate modules and use existing provider boundaries.
Necessary transformations remain. Repeated interpretation and duplicated defaults do not.
State-specific wrappers can prove validation or resolution without defining another configuration schema.

The accepted snapshot stays immutable and retains credential references and source provenance.
Resolution creates staged material or side tables, not a rewrite of the authoritative snapshot.
The derived generation contains prepared TLS contexts, credential handles, routing indexes, and its source revision.
It cannot become a separately persisted or editable configuration source.
Operational observations remain runtime state and can guide execution only within configured policy.

The preparation contract preserves supported YANG choices, defaults, units, ordering, identities, references, and constraints.
Unsupported configured features produce explicit errors rather than silently disappearing during conversion.
Controls absent from the standard model use documented, namespaced YANG augmentations.
An augmentation adds product policy without redefining a standard leaf or creating a parallel configuration schema.

YANG validation alone does not prove RFC 9887 runtime compliance.
Behavior tests also enforce TLS version requirements, mutual authentication, no obfuscation over TLS, and no TLS-to-plaintext fallback.
Every supported configuration field has a trace from its YANG path through preparation to observable behavior.

### Configuration states

The preparation pipeline has four distinct states, but only one authoritative configuration model:

| State | Owner | Permitted contents |
| --- | --- | --- |
| Source input | YANG, CLI/file, or SONiC adapter | Input representation and normalization into YANG |
| Canonical YANG snapshot | Configuration package | Validated operator intent, credential references, source revision, and provenance |
| Resolved candidate | Preparation pipeline plus credential resolver | Staged material and revisions derived from an unchanged YANG snapshot |
| Prepared generation | Client plus publication controller | Connection-ready endpoints, derived policy, source provenance, and generation ID |

The configuration source never supplies an unchecked runtime generation.
The TLS backend never receives unresolved references.
Only the preparation pipeline produces runtime generations from canonical snapshots.
It distinguishes a schema-valid empty server set from invalid input or source failure.
An empty set cannot bypass YANG constraints that require an authentication server in the applicable system context.
YANG export uses the authoritative snapshot and preserves references, not materialized runtime credentials.

### Source ownership

The source interface returns an owned observation session.
That session supplies an authoritative initial YANG snapshot and later snapshot or invalidation events.
It also owns its watcher tasks and their cancellation.
The application chooses fail-fast or retry behavior. A backend reports its observation capabilities.

File sources and policy files share one watcher mechanism and event contract.
Separate files can remain separate operator inputs without separate supervision designs.
Existing policy-file inputs normalize into documented YANG augmentations instead of maintaining an independent policy schema.
The preparation pipeline records the source revisions used for one candidate.
It does not claim a cross-file transaction that the storage backend cannot provide.

### Provider ownership

Credential providers interpret provider-local references and retrieve typed material.
The generic credential package owns request/result matching, not YANG field paths.
Schema adapters retain field paths only as diagnostic provenance.

Providers return a revision or an explicit statement that revision guarantees are unavailable.
Change notifications invalidate material. They do not directly replace active endpoint state.
Resolution and publication remain separate operations.

Retain the SONiC provider's descriptor-relative reads, ownership checks, bounded reads, and protected buffers.
Other providers must state equivalent guarantees for their storage model.
Do not extract a generic filesystem security framework solely to serve one implementation.

### Secret boundaries

Protected values redact `Debug` and zeroize owned allocations on release where the underlying libraries permit it.
Unprotected transfers to protobuf or native libraries are explicit and narrowly scoped.
The design does not promise that every copy inside those libraries is zeroized.

Diagnostic serialization and configuration export are different APIs.
A redacted diagnostic snapshot is not a round-trippable configuration file.
Export preserves credential references by default and never silently substitutes redaction markers for usable credentials.

## Agent runtime and applications

The agent runtime owns one configuration controller and one client runtime.
It publishes typed health and accepts explicit start, reload, drain, and stop requests.
It works in an embedded host without taking over operating-system signals or installing a global logger.

The daemon assembles source adapters, providers, listeners, IPC handlers, and host integration.
Its signal handlers translate process events into runtime shutdown requests.
Systemd and gRPC health consumers project the same health snapshot.
Blocking host helper execution must not block asynchronous request workers.

The CLI constructs an operation once.
Direct execution uses the client. IPC execution uses the local API adapter.
Batch scheduling, output formatting, password input, and process exit policy remain CLI concerns.
Batch mode does not create a second connection or failover implementation.

The health executable remains IPC-only and small.
It must not acquire the direct client's TLS or configuration dependencies merely to query process health.

## Platforms and features

Preserve Linux GNU for the complete supported product.
Preserve Windows MSVC for direct toolkit/client use and `tacon` unless measured maintenance cost justifies a separate removal decision.
Neither platform requires unsupported-platform fallback implementations in product crates.

Core protocol tests must run without OpenSSL, protobuf generation, Redis, or libseccomp.
The client adds native TLS only for enabled transport support.
The IPC adapter owns protobuf generation.
The SONiC and host integrations own their Linux prerequisites.

Features add capability and do not change unrelated type semantics.
Keep feature combinations few and documented: protocol-only, direct client, local IPC, and full Linux agent profiles.
Do not introduce a feature for each internal module.

## Maintenance rules

Every public behavior has one named owner and one observable test contract.
Traits exist at real substitution boundaries: transport, source, provider, and IPC operation handler.
Internal policy functions remain ordinary functions or methods when no substitution is needed.

Generated YANG types remain intentional configuration APIs, but native callbacks and client execution do not interpret them.
Conversion functions live at the boundary they serve.
Configuration changes preserve the canonical YANG contract and the field-to-behavior trace.
The architecture check rejects forbidden production dependencies and tests the supported feature profiles.
It does not enforce arbitrary file-length limits or a fixed crate count.

The package migration table is complete, but acceptance depends on behavior, not renamed directories.
A stage is not complete while consumers still reconstruct superseded contracts locally.