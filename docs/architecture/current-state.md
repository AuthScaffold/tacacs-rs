# Architecture Review: Current State

## Purpose and baseline

This assessment supports a reusable TACACS+ toolkit for one or a few maintainers.
Applications are consumers of the toolkit, not its organizing center.
Backward compatibility does not constrain the target design. Migration stages must remain deployable.

The baseline is checkout `a561cfa` plus the working-tree changes present on 2026-09-23.
The review made documentation changes only.
The [initial assessment](initial-assessment.md) records the first pass and the user's product decisions.

The review traced representative operations across every workspace area.
It examined implementation owners, call sites, state transitions, tests, configuration generation guidance, and selected delivery scripts.
It did not inspect every statement in every source or generated file.
This is an architecture assessment, not a complete security audit or RFC conformance certification.

## Findings

P1 findings affect behavioral contracts or resource ownership and deserve early migration work.
P2 findings increase change cost or obscure responsibilities.
Source evidence establishes the described code paths. It does not replace a targeted reproduction where one is still required.

### F1. Authorization interpretation differs between host adapters

**Priority: P1. Confidence: confirmed response-handler behavior.**

The Bash plugin maps `PassAdd` and `PassRepl` directly to `Allow`.
It does not inspect returned authorization arguments.
The session wrapper denies these statuses when mandatory arguments cannot be applied.

- [Bash decision](../../libraries/tacacsrs_bash_plugin/src/authorization.rs#L73)
- [Wrapper decision](../../executables/session_wrapper/src/supervisor.rs#L343)
- [Mandatory argument contract](../../libraries/tacacsrs_protocol/src/operations.rs#L234)

Both adapters consume the same service domain contract but reconstruct its enforcement meaning separately.
That duplication can turn a protocol status into different local security decisions.

**Target:** one pure response interpreter with explicit adapter capabilities.
An adapter must apply mandatory changes or reject the authorization result.
The interpreter must not convert server denial into service unavailability.

**Acceptance evidence:** the same response fixtures produce consistent decisions across both adapters.
Fixtures must include mandatory and optional arguments, replacement results, malformed arguments, denial, and transport failure.

### F2. Connection retirement has no awaitable completion contract

**Priority: P1. Confidence: confirmed ownership structure. The resource-retention scenario needs a dedicated test.**

The multiplexed runtime spawns a task and discards its join handle.
That task retains an `Arc` to the connection.
The session manager retains its outbound sender while the writer waits on the receiver.

The public stop method removes the cached connection and disables new sessions.
The session-close notification only fires for `NotSupported`, not for a retired, supported single-connect connection.
An idle retired connection can therefore retain its driver until another event, such as peer closure, terminates it.

- [Driver task ownership](../../libraries/tacacsrs_networking/src/runtime/multiplexed/mod.rs#L78)
- [Client retirement](../../libraries/tacacsrs_networking/src/client/mod.rs#L315)
- [Session removal and close notification](../../libraries/tacacsrs_networking/src/session/manager.rs#L383)

This is more than an API naming problem.
A library consumer cannot request bounded drain and then await completion through the current public client API.

**Target:** explicit task ownership, `close`/drain semantics, and an awaitable termination result.
Drop must provide a cancellation fallback without an ownership cycle.

**Acceptance evidence:** an idle peer keeps its socket open while the client retires.
The driver and socket must close within the configured drain bound.
Repeated reloads must not accumulate idle retired drivers.

### F3. Source loading and subscription lack a gap-free contract

**Priority: P1. Confidence: source-demonstrated race window. No forced interleaving test ran.**

`ConfigDatastore` exposes separate `load` and `subscribe` methods without a revision cursor.
The supervisor loads and applies configuration before it subscribes.
The CLI datastore takes its own baseline snapshot before it installs its file watcher.
It does not publish that baseline as an initial change event.

- [Source interface](../../libraries/tacacsrs_datastore/src/lib.rs#L183)
- [Supervisor subscription](../../executables/tacacsrs_agentd/src/config_supervisor.rs#L268)
- [File watcher setup](../../libraries/tacacsrs_cli_datastore/src/datastore.rs#L63)

A file change between the applied load and watcher setup can become the watcher's baseline without reaching the runtime.
A later event can repair the state, but the contract does not guarantee that event.
The reconnect path also loads before it subscribes.

**Target:** one source session establishes observation and supplies an authoritative snapshot.
Lossy backends must signal a resynchronization requirement and reload after observation starts.
Periodic reconciliation covers notification loss that the backend cannot report.

**Acceptance evidence:** barriers force a change between load and subscription.
The runtime must converge without another external change.
The same test must cover reconnect and subscription disposal.

### F4. IPC errors discard replay-safety information

**Priority: P1. Confidence: confirmed information loss, not proof of an automatic retry by current callers.**

The network client distinguishes `NotSent` from `OutcomeUnknown`.
The shared failover plan uses that distinction to avoid replaying accounting with an unknown outcome.
The client API bridge converts both failure classes to a `ServiceError` with `retriable: true`.

- [Transmission classification](../../libraries/tacacsrs_networking/src/exchange_error.rs#L1)
- [Accounting replay rule](../../libraries/tacacsrs_agent/src/upstream/failover.rs#L26)
- [IPC error conversion](../../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/routed.rs#L86)
- [Service error shape](../../libraries/tacacsrs_protocol/src/operations.rs#L797)

An outer caller cannot recover the distinction from the typed IPC contract.
Retry eligibility and certainty about delivery are different facts.

**Target:** preserve delivery state, failure category, operation phase, and retry advice through every adapter.
Do not infer replay safety from a generic transient-error flag.
Unknown authentication outcomes also need explicit policy because authentication can affect counters and lockout state.

### F5. Packet invariants depend on the entry point

**Priority: P1 for toolkit reuse. Confidence: confirmed constructor behavior.**

`Packet::new` rejects a body shorter than the declared length but accepts a longer body.
`Packet::from_bytes` parses the header and copies the remaining bytes without checking their declared length.
The asynchronous reader applies a body limit and reads exactly the declared size.

- [Packet construction and parsing](../../libraries/tacacsrs_protocol/src/packet.rs#L20)
- [Header parsing](../../libraries/tacacsrs_protocol/src/header.rs#L29)
- [Network reader limits](../../libraries/tacacsrs_networking/src/codec/reader.rs#L72)

The network reader's checks do not establish the same invariant for direct toolkit users.
The packet type also has obfuscation helpers that assume construction produced a consistent body.

**Target:** strict complete-frame parsing and a separately named prefix parser that returns the consumed length.
Packet construction computes or verifies the exact body length.
The stream decoder retains allocation limits and partial-frame state.
This finding does not assert a demonstrated exploit through the protected network-reader path.

### F6. Configuration preparation lacks an explicit readiness boundary

**Priority: P2. Confidence: confirmed preparation paths and shared source/runtime types.**

Clarification on 2026-09-24: canonical YANG configuration is an intentional standards-based design choice.
Using its generated types across configuration components is not itself a defect.
The concern is preparation ownership and readiness, not the choice of configuration model.

Datastores return the generated-model family.
Credential materialization mutates that family into inline values.
The agent stores those server values, and TLS backends interpret them again during connection establishment.
Even the OpenSSL PSK callback state retains the full generated server type.

- [Materialization result type](../../libraries/tacacsrs_credential_resolution/src/materialization.rs#L122)
- [Runtime routing inputs](../../libraries/tacacsrs_agent/src/upstream/manager/server_set.rs#L16)
- [Certificate transport conversion](../../libraries/tacacsrs_networking/src/transport/tls/from_server.rs#L1)
- [PSK callback state](../../libraries/tacacsrs_networking/src/transport/tls_psk/ffi/mod.rs#L29)

An unresolved server and a connection-ready server have the same Rust type.
Readiness therefore depends on conventions rather than an explicit preparation result.
Schema validation, credential resolution, and native TLS preparation remain necessary transformations.
An empty runtime also has different needs from strict document validation, which rejects an empty server list.

**Target:** preserve canonical YANG snapshots and normalize CLI and SONiC inputs into that model.
One preparation pipeline derives resolved material and connection-ready endpoints without mutating the authoritative snapshot or its references.
Stage-specific types establish readiness, but do not introduce an independent configuration schema or duplicate defaults.
The native callback retains only the prepared identity and key material it needs.
Field-to-behavior tests preserve YANG semantics and reject unsupported configured features explicitly.

### F7. Reusable operation semantics live above transport-specific dependencies

**Priority: P2. Confidence: confirmed package and call-site structure.**

`FixedExchange` lives in networking, so the small flow package depends on networking to describe protocol operations.
The IPC client package owns logical requests, response interpretation helpers, and protobuf conversion.
The CLI builds similar authorization requests through different direct and IPC paths.

- [Exchange trait](../../libraries/tacacsrs_protocol/src/exchange.rs#L1)
- [PAP descriptor](../../libraries/tacacsrs_protocol/src/exchange/authentication.rs#L1)
- [IPC domain types](../../libraries/tacacsrs_protocol/src/operations.rs#L1)
- [CLI authorization paths](../../executables/tacon/src/commands/authorization.rs#L13)

**Target:** a pure protocol package owns operation values, exchange descriptions, and response semantics.
Networking and IPC adapt those values.
Direct and IPC modes can still expose different transport metadata without duplicating logical command construction.

### F8. Application and process ownership overlap

**Priority: P2. Confidence: confirmed ownership split.**

The agent library installs process signal handlers and starts listeners.
The daemon owns generic configuration recovery, credential materialization, and policy-file supervision.
The agent also contains upstream routing that a non-daemon toolkit consumer can need.

- [Signal ownership](../../libraries/tacacsrs_agent/src/runtime/client_service.rs#L292)
- [Generic daemon supervision](../../executables/tacacsrs_agentd/src/config_supervisor.rs#L77)
- [Policy supervision](../../executables/tacacsrs_agentd/src/policy_supervisor.rs#L1)

**Target:** the network client owns reusable endpoint routing and replay policy.
The application runtime owns configuration publication and coordinated lifecycle.
The executable owns signals, argument parsing, logging setup, and process-manager integration.
The library accepts a shutdown request from its host instead of claiming the process signal namespace.

### F9. Generation and admission semantics need a narrower contract

**Priority: P2. Confidence: confirmed reads and mutations. Interleaving effects need focused tests.**

Routing uses immutable snapshots, but admission state can be updated in place and reused by later snapshots.
A request obtains admission, builds a failover plan, and binds attempts through separate calls.
Those calls can read current runtime state at different times.

- [Runtime snapshot publication](../../libraries/tacacsrs_agent/src/upstream/manager/mod.rs#L165)
- [Mutable admission budget](../../libraries/tacacsrs_agent/src/upstream/admission.rs#L29)
- [Request sequence](../../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/routed.rs#L122)

**Target:** a request lease captures its routing generation and retry policy once.
Global capacity remains mutable by design and spans generations.
Capacity changes must not reset permits or double the allowed concurrency during reload.
The contract must state how already-admitted retries use retired endpoints.

### F10. Test breadth does not prove cross-adapter equivalence

**Priority: P2. Confidence: confirmed suite result and selected coverage limits.**

The workspace has transport mocks, upstream fakes, inline tests, process tests, and an IPC emulator.
These are useful layers, but they do not yet form one explicit conformance model.
For example, the policy emulator returns an unsupported result for PAP authentication.
The fuzz manifest lists header and accounting targets, not every implemented message family.

- [Emulator PAP result](../../libraries/tacacsrs_agent_ipc_emulator/src/service.rs#L50)
- [Fuzz target inventory](../../fuzz/Cargo.toml#L1)
- [Wrapper mandatory-argument tests](../../executables/session_wrapper/src/supervisor.rs#L1008)

Some existing assertions also need review before they become migration gates.
For example, the successful-header test returns successfully from its parse-error branch.

- [Header success test](../../libraries/tacacsrs_protocol/src/header.rs#L142)

**Target:** shared contract fixtures, deterministic failure schedules, and a small set of real process tests.
Test completion counts supplement these contracts. They do not replace them.

### F11. Release machinery exceeds the current distribution contract

**Priority: P2. Confidence: confirmed release mechanisms. Effort estimates were not measured.**

The workspace describes its crates as internal and unpublished.
Release automation computes independent library SemVer, propagates dependency changes, and hydrates manifests and lockfiles.
Applications use a different version scheme.

- [Version computation action](../../.github/steps/compute-versions/action.yml#L1)
- [Version hydration](../../.github/steps/inject-versions/hydrate_versions.py#L1)
- [Product matrix](../../.github/workflows/reusable-pipeline.yml#L65)

**Target:** one coordinated workspace release version and one source tag for shipping products.
Keep provenance, SBOMs, checksums, platform packaging, and reproducible source identification.
Do not keep independent internal API compatibility machinery without independent consumers that require it.

### F12. Documentation drift hides existing improvements

**Priority: P2. Confidence: confirmed examples.**

Some guidance describes removed crates, superseded connection mapping types, and accounting-based wrapper authorization.
The code already has newer boundaries and authorization behavior.
Architecture work based only on those descriptions can duplicate work or remove a needed safeguard.

- [Initial evidence](initial-assessment.md)
- [Current wrapper request](../../executables/session_wrapper/src/supervisor.rs#L293)

**Target:** one ownership map, executable public examples, and decision records next to the relevant contracts.
Package inventories can be generated. Design rationale still needs human review.

## Strengths to retain

The target is not a rejection of the current implementation.
Several mechanisms already support the desired architecture:

| Mechanism | Evidence | Design value |
| --- | --- | --- |
| Shared failover executor | [Executor](../../libraries/tacacsrs_agent/src/upstream/executor.rs#L1) | One retry control path for typed operations and proxy attempts |
| Conservative delivery classification | [Exchange errors](../../libraries/tacacsrs_networking/src/exchange_error.rs#L1) | Foundation for safe retry advice |
| Proxy conversation pinning | [Proxy session](../../libraries/tacacsrs_agent/src/services/tacacs_proxy/upstream_bridge/session.rs#L1) | Preserves upstream state after a valid reply |
| Stale result rejection | [Materialization coordinator](../../executables/tacacsrs_agentd/src/materialization_coordinator.rs#L181) | Prevents old credential work from replacing new desired state |
| Server-slot reuse | [Reload implementation](../../libraries/tacacsrs_agent/src/upstream/manager/mod.rs#L287) | Avoids reconnecting unchanged endpoints |
| Secret wrappers | [Secret ownership](../../libraries/tacacsrs_secrets/src/lib.rs#L1) | Redaction and bounded secret ownership |
| Confined credential reads | [SONiC provider](../../libraries/tacacsrs_sonic/src/provider.rs#L283) | Descriptor-relative reads, metadata checks, and protected buffers |
| Typed health model | [Health state](../../libraries/tacacsrs_agent/src/runtime/health.rs#L1) | Common input for gRPC and host adapters |
| Pinned schema generation | [Generation procedure](../../DEVELOPMENT.md#L251) | Reproducible external schema inputs |

## Coverage Ledger

Every current package has a target disposition in the architecture specification.
This ledger distinguishes detailed boundary review from remaining specialist validation.

| Package or area | Review performed | Remaining validation |
| --- | --- | --- |
| `tacacsrs-messages` | Header/packet invariants, serialization boundaries, tests, fuzz inventory | Complete body-parser and RFC audit |
| `tacacsrs-flows` | Fixed exchange ownership and PAP behavior | Every operation's semantic edge cases |
| `tacacsrs-networking` | Client negotiation, shared driver, session routes, retirement, error classes, TLS projection | Forced races, native TLS interoperability, and performance bounds |
| `tacacsrs-secrets` | Ownership, redaction, zeroization, and transfer APIs | Native and generated-buffer lifetime audit |
| `tacacsrs-config` | Generated-model boundary, enumeration, validation, generation procedure | Generator implementation and all schema choices |
| `tacacsrs-credential-resolution` | Materialization state, resolver boundary, result handling | All provider result combinations and expiry semantics |
| `tacacsrs-datastore` | Source events, delta model, initial-load/subscription contract | Backend conformance under loss and reconnect |
| `tacacsrs-cli-datastore` | File watcher lifecycle and snapshot sequence | Forced watch-registration races and filesystem variants |
| `tacacsrs-sonic` | Snapshot read, provider confinement, binding inputs | Live ConfigDB/QEMU behavior and platform policy |
| `tacacsrs-agent` | Routing, retry, admission, generation updates, listeners, health, and shutdown ownership | End-to-end cancellation and concurrent reload stress |
| `tacacsrs-agent-client` | Domain ownership, protobuf conversion surface, error model | Wire conformance and connection deadline tests |
| `tacacsrs-agentd` | Bootstrap, configuration/policy supervision, materialization, host integration | Real process manager and credential-revocation scenarios |
| `tacacsrs-agent-health` | Exit statuses, health lookup, and process-test inventory | Deployment contract across service modes |
| `tacon` | Mode dispatch and direct/IPC authorization construction | Full batch equivalence and output stability |
| `tacacsrs-bash-plugin` | FFI decision path and authorization handling | ABI, fork/runtime safety, and enforcement threat model |
| `session-wrapper` | Authorization mapping, argument reads, documented process model | Fork/seccomp audit and adversarial enforcement tests |
| Emulator library and daemon | RPC behavior, PAP limitation, process bootstrap | Full policy behavior and fixture migration |
| CI, containers, and release | Product matrix, workflow structure, version hydration, image recipe | Full script audit, image build, SBOM and release reproduction |

Untracked reference documents and local experiment copies are not product dependencies.
The review left them and existing user changes untouched.

## Verification

The following checks ran against the current implementation:

```bash
cargo metadata --no-deps --format-version 1 --offline
cargo test -p tacacsrs-agent --lib upstream::executor --locked
cargo test --workspace --all-features --locked
```

The focused executor run passed all five tests.
The workspace suite passed, including doctests. Two networking tests were ignored.
Their annotations identify manual routing baselines, not tests that this review executed.

The first offline test attempt failed because the local registry lacked `vstd` metadata required by `regorus`.
The locked run with registry access succeeded.
No implementation, dependency declaration, or lockfile change was needed.

No live SONiC/QEMU test, container build, Miri run, fuzz campaign, benchmark, or release rehearsal ran.
The review did not run the full lint or rustdoc gates because it changed no Rust implementation.
The container does not expose `mdbook` on `PATH`.

## Reading order

1. [Target architecture](target-architecture.md)
2. [Runtime contracts](runtime-contracts.md)
3. [Migration and decisions](migration-and-decisions.md)