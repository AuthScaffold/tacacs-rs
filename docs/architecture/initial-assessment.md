# Architecture Review: Initial Assessment

## Status and scope

This document records the first pass of a maintainability review.
It is not the final architecture specification or a complete defect audit.
The review covers the workspace, integration components, tests, and delivery tooling.
Implementation changes are outside this review.

Review date: 2026-09-23. Checkout: `a561cfa` plus the existing working-tree changes.
The initial pass is complete. This document preserves its findings before the detailed review.
The product decisions below guide the subsequent architecture documents.

The detailed review continues in the [current-state assessment](current-state.md).
The proposal consists of the [target architecture](target-architecture.md), [runtime contracts](runtime-contracts.md), and [migration plan](migration-and-decisions.md).

Backward compatibility does not constrain the target design.
Protocol correctness, credential safety, and explicit operational behavior remain necessary.
The review must distinguish an intentional behavior change from an accidental regression.

The baseline is the current working tree, not only the checked-in documentation.
Git reports widespread modifications that mostly disappear when it ignores end-of-line whitespace.
Three existing files still have text differences at the start of this review.
The review leaves those changes intact.

## Working definition of maintainability

A maintainer can identify the owner of a behavior before changing it.
A common change affects a small, predictable set of modules.
Types state the important invariants, and tests demonstrate the observable contracts.
Failures have explicit recovery rules and useful, secret-safe diagnostics.

The review will evaluate designs against these change scenarios:

1. Add a configuration source without changing connection or request logic.
2. Add a credential provider without changing the protocol implementation.
3. Change retry policy without separate implementations for each ingress service.
4. Add an authentication conversation without changing unrelated accounting behavior.
5. Rotate credentials while requests use an older configuration generation.
6. Diagnose a failed startup, reload, or shutdown without reading several task loops.
7. Remove an integration without weakening the core library contracts.

Crate count and file length are indicators, not success criteria.
A new abstraction must reduce a demonstrated maintenance cost.

## Current workspace inventory

Cargo metadata identifies 18 workspace packages.
The following inventory describes package roles, not review completion.

| Area | Packages | Initial role |
| --- | --- | --- |
| Wire protocol | `tacacsrs-messages` | TACACS+ messages and serialization |
| Network client | `tacacsrs-networking`, `tacacsrs-flows` | Connections, sessions, and protocol operations |
| Configuration | `tacacsrs-config`, `tacacsrs-datastore`, `tacacsrs-cli-datastore` | YANG model, source contract, and CLI/file inputs |
| Credentials | `tacacsrs-secrets`, `tacacsrs-credential-resolution` | Secret types and credential resolution contracts |
| Runtime | `tacacsrs-agent`, `tacacsrs-agentd` | Request services, upstream management, and daemon supervision |
| Local API | `tacacsrs-agent-client`, `tacacsrs-agent-health` | IPC contract, clients, and health command |
| SONiC | `tacacsrs-sonic` | ConfigDB and credential integration |
| Host integrations | `tacacsrs-bash-plugin`, `session-wrapper` | Shell integration and Linux session interception |
| CLI | `tacon` | Direct and agent-backed operations |
| Emulation | `tacacsrs-agent-ipc-emulator`, `tacacsrs-agent-ipc-emulatord` | Local API emulation and its process host |

Production dependencies do not match every architecture sketch in the repository guidance.
For example, the current workspace does not contain `tacacsrs-flow-abstractions` or `tacacsrs-libtac`.
Production dependency edges also differ from test dependency edges.
The review excludes development dependencies when it evaluates production layering.

## Initial Findings

Priority indicates review order and potential maintenance impact, not a confirmed runtime defect.

### A1. Configuration preparation needs explicit ownership and readiness guarantees

**Priority: high. Evidence: confirmed preparation boundaries and shared source/runtime types.**

Revision on 2026-09-24: YANG is the authoritative configuration model by design.
Passing its generated types between configuration components is not itself a defect.
[RFC 9887](https://www.rfc-editor.org/rfc/rfc9887.html#section-6.3) identifies the TACACS+ YANG model.
[RFC 9950](https://www.rfc-editor.org/rfc/rfc9950.html) defines that model, including TLS support.

The datastore contract returns `TacacsPlus`, the YANG-aligned configuration model.
The agent accepts that model during construction and reload.
Its materialized reload API still accepts `TacacsPlusServer` values.
The networking transport dispatcher also accepts `TacacsPlusServer`.

Evidence:

- [Datastore contract](../../libraries/tacacsrs_datastore/src/lib.rs#L183)
- [Runtime construction and reload](../../libraries/tacacsrs_agent/src/runtime/client_service.rs#L113)
- [Transport establishment](../../libraries/tacacsrs_networking/src/establish/mod.rs#L100)

The concern is distributed interpretation and readiness that depends on conventions around a general configuration type.
Schema validation, credential resolution, and native transport preparation are necessary transformations.
Their ownership and completion guarantees need to be explicit.

**Candidate direction:** normalize CLI and SONiC inputs into the canonical YANG model and retain each authoritative snapshot unchanged.
One preparation pipeline validates the snapshot, resolves credentials, and prepares an immutable runtime generation.
That generation is a derived execution artifact, not a second configurable model with independent defaults or validation policy.
Stage-specific types distinguish unresolved references from connection-ready material without replacing YANG as the configuration authority.

**Discriminating check:** trace one credential rotation through materialization, publication, and connection reuse.
Verify that the original YANG snapshot and credential references remain unchanged.
Trace each supported YANG field through preparation to an observable behavior test.
Reject transformations that duplicate interpretation or silently discard unsupported configuration features.

### A2. Domain ownership sits inside the IPC client package

**Priority: high. Evidence: confirmed dependency and exports.**

The client package owns domain requests, responses, errors, generated protobuf types, and the persistent gRPC client.
The agent depends on this package.
Thus, the package combines the service contract with one transport implementation and its client.

Evidence:

- [Client package exports](../../libraries/tacacsrs_agent_client/src/lib.rs#L17)
- [Agent dependencies](../../libraries/tacacsrs_agent/Cargo.toml)

**Candidate direction:** give service operations and outcomes an explicit transport-independent owner.
Put protobuf conversion and tonic code outside that owner.
This does not require a generic RPC framework or a replacement for gRPC.

**Discriminating check:** trace one authorization request through the CLI, IPC conversion, agent bridge, and protocol flow.
Determine which duplicated types express different semantics and which only repeat the same contract.

### A3. Runtime supervision spans the daemon and agent

**Priority: high. Evidence: confirmed ownership split. Maintenance impact remains a hypothesis.**

The daemon owns datastore recovery and credential notification supervision.
The agent owns applied server state, listener lifetime, and runtime health publication.
The daemon supervisor calls agent reload methods and updates shared health state.

Evidence:

- [Daemon supervisor](../../executables/tacacsrs_agentd/src/config_supervisor.rs#L1)
- [Agent runtime](../../libraries/tacacsrs_agent/src/runtime/client_service.rs#L58)

The split can be valid, but its lifecycle contract needs explicit documentation.
A maintainer currently needs both sides to understand startup and reload.

**Candidate direction:** define one application lifecycle contract and one owner for each transition.
Keep platform integration and process bootstrap outside the reusable runtime.
Consider moving generic supervision into a library, but do not assume that all daemon logic belongs there.

**Discriminating check:** trace initial source failure, rejected reload, credential rotation, and shutdown during an active request.
Identify who owns each task, cancellation signal, generation, and health transition.

### A4. Host integrations interpret authorization replies differently

**Priority: high. Evidence: confirmed behavior in the two response handlers.**

The Bash plugin allows `PassAdd` and `PassRepl` without inspecting response arguments.
The session wrapper denies these results when they contain mandatory arguments that it cannot apply.
The two integrations therefore disagree on a security-relevant service result.

Evidence:

- [Bash authorization decision](../../libraries/tacacsrs_bash_plugin/src/authorization.rs#L73)
- [Session-wrapper authorization decision](../../executables/session_wrapper/src/supervisor.rs#L343)

**Candidate direction:** define one authorization interpretation contract with explicit host capabilities.
Keep process interception and FFI in their platform adapters.
Do not make each adapter reconstruct the meaning of a protocol success status.

**Discriminating check:** pass identical `PassAdd` and `PassRepl` replies with mandatory arguments to both adapters.
The target contract must state whether each adapter applies the arguments or denies the operation.
This comparison is source-based. No live host enforcement test ran during this pass.

### A5. Existing architecture guidance can misdirect a maintainer

**Priority: medium. Evidence: confirmed examples of drift.**

The root README still describes a `ServerConnectionConfig` mapping.
The configuration mapping source states that bundle enumeration replaced the old mapping types.
Some repository guidance also names crates absent from the current workspace.
The session-wrapper README describes accounting-based decisions, but the implementation calls `send_authorization`.

Evidence:

- [Root README](../../README.md)
- [Mapping replacement note](../../libraries/tacacsrs_config/src/mapping.rs#L1)
- [Current workspace members](../../Cargo.toml#L1)
- [Session-wrapper guide](../../executables/session_wrapper/README.md#L9)
- [Session-wrapper request](../../executables/session_wrapper/src/supervisor.rs#L293)

**Candidate direction:** maintain one architecture map with named owners and dependency rules.
Generate the package inventory where practical.
Keep rationale and behavioral contracts as reviewed prose.

## Existing structure to preserve or evaluate first

The failover executor already centralizes retry control for different service bridges.
Its tests distinguish accepted results, server rejection, transport failure, and aborted requests.
A redesign must account for this existing separation before it proposes another policy engine.

- [Shared failover executor](../../libraries/tacacsrs_agent/src/upstream/executor.rs#L1)

The runtime already documents complete replacement of materialized server sets.
Bound requests retain the previous immutable server set.
This is a useful contract to examine and preserve unless the target behavior changes explicitly.

- [Materialized reload contract](../../libraries/tacacsrs_agent/src/runtime/client_service.rs#L250)

The configuration and credential crates already expose provider boundaries.
The review will evaluate their contracts before it proposes replacement abstractions.

Secret ownership, redacted formatting, and zeroization have a dedicated package and focused tests.
Credential materialization already provides an all-or-nothing result for a server set.
These mechanisms deserve preservation or an explicit replacement contract.

- [Secret ownership](../../libraries/tacacsrs_secrets/src/lib.rs#L1)
- [Credential materialization](../../libraries/tacacsrs_credential_resolution/src/materialization.rs#L139)

The network client separates typed fixed exchanges from raw packet conversations.
The target must preserve that semantic distinction even if it changes package boundaries.
A raw proxy can carry a conversation that a fixed PAP operation cannot represent.

- [Network client](../../libraries/tacacsrs_networking/src/client/mod.rs#L1)
- [Fixed PAP exchange](../../libraries/tacacsrs_protocol/src/exchange/authentication.rs#L1)

## Provisional Architectural Direction

The leading option is a modular system with explicit domain and lifecycle ownership.
There is no evidence from this pass that separate services or a general plugin framework will improve maintainability.
The review also does not assume that more crates produce better boundaries.

The following responsibilities form the candidate design:

1. Source adapters normalize YANG files, CLI inputs, and SONiC data into canonical YANG snapshots.
2. One preparation pipeline validates snapshots, resolves credentials, and derives immutable runtime generations without changing configuration authority.
3. An application runtime owns publication, admission, routing, recovery, health, and shutdown contracts.
4. Domain operations own AAA request and result semantics independently of gRPC.
5. Ingress adapters translate local API requests or preserve raw TACACS+ conversations.
6. A network client owns connections, sessions, framing, and transport behavior.
7. Host adapters apply authorization decisions according to explicit enforcement capabilities.

These are responsibility boundaries, not seven mandatory new crates.
The detailed design must identify which current components already implement each responsibility.
It must compare extraction, consolidation, and removal before it selects a package layout.

## First-Pass Coverage

The package inventory covers the whole workspace. Implementation review remains selective.
The following table states the depth of this first pass.

| Area | Examined evidence | Still required |
| --- | --- | --- |
| Messages and flows | Packet construction, secret handling, fixed PAP exchange, and nearby tests | All message families, parse invariants, and fuzz contracts |
| Networking | Client state ownership, connection negotiation, and transport dispatch | Session cleanup, cancellation, framing, TLS backends, and task ownership |
| Agent | Runtime construction, reload APIs, and shared failover executor | Complete request paths, routing generations, admission, proxy behavior, and health transitions |
| Configuration and datastores | Model ownership, datastore contract, and CLI file subscription | Generated-model validation, source consistency, and subscription recovery |
| Secrets and credentials | Secret wrappers, materialization, and SONiC provider boundary | Credential lifetime, stale results, rotation ordering, and provider filesystem guarantees |
| SONiC | Redis snapshot path, binding inputs, and credential provider setup | Mapping rules, notification behavior, container integration, and deployment contract |
| CLI | Direct versus service dispatch and platform conditions | Operation parity, batch behavior, output contracts, and credential inputs |
| Host integrations | Bash authorization and wrapper response interpretation | FFI, fork safety, seccomp limits, failure policy, and complete enforcement tests |
| Local API and health | Package exports, domain ownership, and health executable | Conversion semantics, deadlines, error taxonomy, and readiness definitions |
| Emulator | Service handlers and process host | Policy model, scenario coverage, and equivalence to production contracts |
| Delivery | CI product matrix, job structure, documentation setup, and test inventory | Release/version scripts, code generation, native dependencies, and executable checks |

The emulator currently returns an unsupported result for PAP authentication.
Its presence therefore does not establish test support for every production operation.
The detailed review must distinguish transport mocks, domain fakes, IPC emulation, and process tests.

- [Emulator PAP behavior](../../libraries/tacacsrs_agent_ipc_emulator/src/service.rs#L50)
- [Current delivery matrix](../../.github/workflows/reusable-pipeline.yml#L65)

## Deep Review Plan

The detailed review will follow behavior across boundaries, not only inspect files by size.
Every package will receive an explicit review status and evidence references.

| Workstream | Main questions | Required output |
| --- | --- | --- |
| Protocol and transport | Who owns framing, sequence state, cancellation, replay safety, and backpressure? | Ownership model and protocol invariants |
| Operations and ingress | Which semantics belong to AAA operations, IPC, and raw proxy sessions? | Domain contract and adapter boundaries |
| Configuration and credentials | What constitutes a complete generation? Who resolves, validates, publishes, and retires it? | Configuration pipeline and rotation contract |
| Runtime lifecycle | Who owns tasks, retries, health transitions, draining, and cleanup? | State transitions and failure matrix |
| Platform and host integrations | Which product capabilities remain necessary? Where must unsafe and platform-specific code stop? | Product boundaries and platform contracts |
| Tests and delivery | Which contracts have deterministic tests? Which gates detect architectural drift? | Verification model and delivery changes |

The target documents will contain:

1. A current-state assessment with evidence, risks, strengths, and coverage limits.
2. A target architecture with dependency direction, type ownership, and concrete request flows.
3. Runtime contracts for configuration generations, retries, cancellation, health, and shutdown.
4. Decisions with alternatives, rejected options, and maintenance tradeoffs.
5. A migration sequence with acceptance criteria and explicit removal of superseded components.

Package names and exact crate boundaries remain provisional until the behavior review is complete.
The target can remove or merge components when that improves maintainability.
It must also explain any product capability that the change removes.

## Questions Before the Deep Review

The user supplied these decisions after the first-pass findings:

| Question | Decision |
| --- | --- |
| Primary product | A reusable TACACS+ toolkit. Applications are adapters. |
| Capability scope | Evaluate every capability and recommend retirement of low-value components. |
| Maintainer group | One or a few maintainers. Minimize concepts and operational burden. |
| Migration | Keep intermediate stages deployable. Old APIs need not remain compatible. |
| Configuration authority, clarified 2026-09-24 | Preserve canonical YANG configuration. Derive runtime artifacts without a competing configuration model. |

The review can propose technology changes, but each replacement needs a concrete maintenance benefit.
YANG remains authoritative under the clarified product requirement.
The user did not require replacement of gRPC, OpenSSL, or Rego.
Those choices remain architecture decisions, not preset rewrite goals.

## Verification and Limits

Cargo metadata supplied the package inventory and dependency evidence.
This first pass reads source code and selected tests. It does not establish runtime correctness.
No Rust implementation changed, and no Rust test suite ran for this document.
Detailed protocol, security, concurrency, and operational claims require the deeper review.
The assessment's local source links were checked.
The container does not expose `mdbook` on `PATH`, so an HTML documentation build is not available for this pass.