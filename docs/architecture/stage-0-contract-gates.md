# Stage 0: Contract Gates

## Status

Implementation date: 2026-09-24. Starting revision: `a561cfa`.
Stage 0 adds contract tests and focused corrections without changing package ownership or the authoritative YANG model.
The [migration plan](migration-and-decisions.md) defines the later extraction stages.

The user permits focused local commits and a final single-PR integration.
Each implementation stage remains buildable. Separate production deployment of every stage is not required.

The code and tests in this checkpoint are implemented.
Strict Clippy and supplemental native validation have exceptions listed below.
This checkpoint does not declare the entire target architecture implemented or certify RFC compliance.

## Corrections and Regressions

| Finding | Implemented behavior | Regression evidence |
| --- | --- | --- |
| F1: Host authorization | The Bash hook rejects mandatory response arguments that it cannot apply. Optional-only pass replies remain allowed. | `mandatory_response_changes_are_denied`, `pass_replies_without_mandatory_changes_are_allowed`, and `nonpass_responses_never_allow_local_fallback` |
| F2: Retired connections | Idle retired shared connections close without peer cooperation. Active routes finish before closure. Registration and retirement share the route lock. | `retirement_closes_idle_transport_without_peer_cooperation` and `retirement_waits_for_active_session_then_closes_transport` |
| F3: File observation | File subscriptions register observation before reading and publishing their initial snapshot. Dropped subscribers stop idle watcher tasks. | `subscription_recovers_change_between_load_and_watch` and existing file/certificate update tests |
| F4: Retry advice | Unknown outcomes do not advertise safe IPC retry. Later unsent failures cannot erase an earlier uncertain attempt. | `uncertain_accounting_failure_does_not_retry`, `later_bind_failure_preserves_unknown_delivery_advice`, and `unsent_accounting_bind_failure_remains_retriable` |
| F5: Packet length | Packet construction and complete-buffer parsing require exact body lengths. The successful-header test fails on unexpected parse errors. | `packet_construction_requires_exact_body_length`, `complete_packet_parser_requires_exact_body_length`, and `complete_packet_parser_round_trips_exact_frames` |

These behavioral regressions failed against the previous implementation before the corresponding corrections.
The F4 checks include protobuf conversion and existing gRPC handler tests.
No protobuf schema changed.

Implementation owners:

- [Bash authorization](../../libraries/tacacsrs_bash_plugin/src/authorization.rs)
- [Session registry](../../libraries/tacacsrs_networking/src/session/manager.rs)
- [Connection contract tests](../../libraries/tacacsrs_networking/src/runtime/multiplexed/tests.rs)
- [File datastore](../../libraries/tacacsrs_cli_datastore/src/datastore.rs)
- [Routed operations](../../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/routed.rs)
- [Retry contract tests](../../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/routing_tests.rs)
- [Packet construction](../../libraries/tacacsrs_protocol/src/packet.rs)

### Forced interleavings

`blocked_old_resolution_cannot_replace_new_yang_snapshot` pauses an older credential resolution at a notification barrier.
The test publishes the newer revision, releases the old resolver, and rejects its late result.
It also checks that the current source snapshot still contains its original references.

`credential_rotation_preserves_authoritative_yang_references` covers failed and successful same-reference rotation.
Failed resolution retains the known-good server. Successful rotation changes material without changing the authoritative source.

`cancelled_fixed_exchange_releases_route_and_allows_retirement` cancels an exchange after its packet enters the outbound queue.
The test rejects a late reply for that route and confirms that cancellation does not prevent retirement.
Cancellation does not claim that the request was never transmitted.

These tests use explicit scheduling points rather than arbitrary delay windows.
Timeouts bound failures so the tests cannot wait indefinitely.

## Scenario Baseline

| Scenario | Executable evidence | Coverage limit |
| --- | --- | --- |
| Direct packet and session behavior | Message, flow, and networking tests | Not an external TACACS+ server interoperability test |
| IPC failures and retry advice | Agent bridge tests, gRPC handler tests, and domain/protobuf conversion | Full typed delivery facts remain a later IPC change |
| Raw proxy conversations | Existing multi-turn authentication, out-of-order replies, and uncertain accounting replay tests | No live remote proxy deployment ran |
| Configuration update | File and certificate notification tests, including initial snapshot replay | Other backend observation guarantees need their own contracts |
| Credential rotation | Materialization tests with explicit resolver barriers and unchanged source snapshots | Provider expiry and revocation policy remain later work |
| Source equivalence | `equivalent_cli_sonic_and_yang_inputs_preserve_canonical_values` in agentd | Explicit common legacy-TCP values, not every TLS variant or source default |

The source-equivalence fixture compares complete `TacacsPlus` values, including secrets through protected equality.
It supplies common names, port, timeout, connection mode, and credentials explicitly.
SONiC priority produces the same server order as the CLI adapter and YANG fixture.
Existing tests separately characterize adapter defaults. This stage does not silently make those defaults identical.

## Product and Platform Baseline

This matrix records the support scope for the refactor. It does not change manifests or remove products in Stage 0.

| Product or component | Platform | Refactor status |
| --- | --- | --- |
| Protocol, flows, networking, configuration, secrets, CLI/file datastore | Linux GNU and Windows MSVC direct-client dependency set | Retain and extract according to the plan |
| `tacon` direct mode | Linux GNU and Windows MSVC | Retain |
| Agent, daemon, local IPC, and health probe | Linux GNU | Retain |
| SONiC configuration and credential integration | Linux GNU in the supported SONiC environment | Retain, with separate native acceptance tests |
| Bash plugin | Linux GNU with the SONiC Bash ABI | Conditional integration support, not a general security boundary |
| `session-wrapper` | Linux GNU x86-64 | Experimental proof of concept. Existing tests remain in the workspace for now. |
| IPC emulator and its process host | Linux GNU | Development/test tooling. Rego retirement requires scenario inventory first. |

No macOS or musl support is added.
Windows validation did not run in this Linux container.
Host ABI, fork, seccomp, and QEMU certification are not implied by passing Rust unit tests.

## YANG Baseline

The [generation manifest](../../libraries/tacacsrs_config/yang/generation-manifest.json) remains authoritative for the generated input revision.
This checkpoint records:

- Module: `ietf-system-tacacs-plus@2026-03-31.yang`, corresponding to RFC 9950.
- Upstream repository: `YangModels/yang`.
- Pinned commit: `97ca2414920c0de09171327b84aa11395f79e284`.
- Generator dependency: `pyang` 2.7.1.
- Feature selection: [feature-flags.ini](../../libraries/tacacsrs_config/yang/feature-flags.ini).
- Project augmentation: [tacacsrs@2026-05-20.yang](../../libraries/tacacsrs_config/yang/modules/tacacsrs@2026-05-20.yang).

Enabled features cover credential bundles, cleartext protected key inputs, inline and central keystore/truststore references, TLS 1.3, and EPSK.
The project augmentation enables ordered `psk-dhe-ke-groups` on reusable and per-server EPSK identities.
Raw-public-key authentication, general TLS hello parameters, hidden/encrypted keys, CSR generation, and certificate-expiration notifications remain disabled.
The truststore `public-keys` feature is enabled, but that does not enable the disabled TLS raw-public-key features.

Generated feature support does not prove that a concrete provider implements every credential kind.
The SONiC provider's implemented material source remains EPSK. Other provider capabilities need explicit validation.

### Field-to-behavior inventory

This is a baseline inventory, not a claim of complete implementation.
Stage 2 must preserve implemented semantics and explicitly resolve or reject the listed gaps.

| YANG field family | Current owner and evidence | Baseline status |
| --- | --- | --- |
| `server/name`, `server-type`, ordered server list | Configuration builders, source-equivalence fixture, agent operation catalogs | Canonical values and operation eligibility have tests |
| `address`, `port` | CLI/SONiC mapping and networking establishment | Explicit values have coverage. TLS default-port behavior needs a separate RFC 9887 conformance check. |
| `timeout`, `single-connection` | Configuration defaults and client negotiation tests | Parsing, explicit source equivalence, and shared/dedicated behavior have coverage |
| `shared-secret`, security choice | Configuration choice validation, secret wrappers, codec | Legacy obfuscation and invalid choice tests exist. This is not TLS encryption. |
| `domain-name`, `sni-enabled` | Configuration validation and TLS backend server-name helpers | Dependency and mapping tests exist. Full peer-identity verification remains native conformance work. |
| Client/server local credential bundles | Configuration enumeration tests | Expansion and preservation of external references have tests |
| Central key/certificate/trust references | Central validation, round-trip, resolver, and materialization tests | References remain opaque in canonical configuration and survive rotation |
| Certificate material and key-format identities | CLI credential readers and certificate TLS preparation | DER conversion and builder tests exist. Chain, pinning, revocation, and mutual-authentication compliance need native evidence. |
| EPSK identity, hash, context, target protocol/KDF | Generated types, central enumeration, credential projection, PSK backend | Metadata preservation has tests. Interoperability evidence remains distinct from schema coverage. |
| Augmented `psk-dhe-ke-groups` | Generated field tests, CLI choices, PSK context tests | Ordered group mapping and invalid group rejection have tests |
| `source-ip`, `source-interface`, `vrf-instance` | Model validation and SONiC mapping | Represented in configuration. The current connection dispatcher does not establish full source/VRF enforcement. |
| Read-only `statistics` | Configuration statistics types and runtime observations | Complete publication into YANG operational data remains a later integration contract |
| Disabled schema features | Pinned feature selection and parsing/validation tests | Keep explicit rejection and do not silently enable them during extraction |

Relevant test collections:

- [Configuration validation](../../libraries/tacacsrs_config/tests/parse_validation.rs)
- [Generated types](../../libraries/tacacsrs_config/tests/generated_types.rs)
- [Central reference round trips](../../libraries/tacacsrs_config/tests/central_roundtrip.rs)
- [Enumeration](../../libraries/tacacsrs_config/tests/enumeration_integration.rs)
- [Materialization and rotation](../../executables/tacacsrs_agentd/src/materialization_coordinator.rs)
- [Cross-adapter fixture](../../executables/tacacsrs_agentd/src/main.rs)

No generated YANG files, feature selections, dependency declarations, or lockfiles change in Stage 0.

## Validation Record

Focused regressions and the final workspace suite pass.
The workspace suite includes doctests and leaves two existing manual networking benchmarks ignored.
The workspace build, warnings-as-errors rustdoc task, and nightly formatting check pass.

Strict workspace Clippy stops on the existing `clippy::comparison_chain` warning in the untouched admission module.
The same command passes with only that lint allowed:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::comparison_chain
```

This command does not replace the repository's strict gate. No permanent lint allowance was added.
The existing warning remains visible for the next validation pass.

The container lacks `cargo-fuzz`, `cargo-llvm-cov`, `buf`, and `mdbook`.
No fuzz smoke run, coverage run, HTML book build, Windows run, QEMU run, or live native interoperability test ran.
No protobuf schema changed, so a protobuf breaking check is not required for this checkpoint.
No unsafe implementation or C ABI changed. Native host certification remains outside this checkpoint.

## Later-stage Obligations

Stage 0 does not implement an awaitable public client close/join API or all connection cancellation cases.
Its connection fix covers retirement of shared connections at the existing owner.
The later client extraction still owns bounded forced drain and embedded-client lifetime guarantees.

IPC still uses the existing error shape. Retry advice is now conservative, but a false flag cannot distinguish unknown delivery from permanent failure.
Typed delivery facts remain part of the planned domain and IPC contract change.

File sources now replay an authoritative watched snapshot.
The generic source-session API, source epochs, periodic reconciliation, and other backends remain later work.
No unsupported YANG field becomes silently acceptable because Stage 0's selected tests pass.