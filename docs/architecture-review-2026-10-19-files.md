# File Ledger

This ledger accompanies the [architecture review](architecture-review-2026-10-19.md#findings) of `main` at `ac40f27`.
It includes every tracked Rust file beneath the 17 workspace members' source directories: 293 paths.
Build scripts, integration tests, generators, and delivery tools have an additional ownership map after the source inventory.

The inventory is complete for that definition of source files.
Inspection depth varies: facades, consumers, implementation sections, and selected tests establish each disposition.
Long implementations and native TLS code did not receive an exhaustive line-by-line security audit.
Generated output received representative inspection against its generator and consumers.
Tests and fixtures were not counted as production complexity merely because they share a source directory.

“Retain” means no restructuring recommendation from the available evidence.
It is not a correctness certification.
R1 through R15 refer to the main report.
All decisions assume that breaking changes remain available.

## Protocol

The pure protocol boundary remains useful.
Its wire types and logical operation types have different consumers.
R6 can connect them through immutable prepared operations without adding I/O to this crate.

| Source file | Disposition |
| --- | --- |
| [lib.rs](../libraries/tacacsrs_protocol/src/lib.rs#L1) | Retain a small crate facade. |
| [body.rs](../libraries/tacacsrs_protocol/src/body.rs#L1) | Retain the body codec contract. |
| [constants.rs](../libraries/tacacsrs_protocol/src/constants.rs#L1) | Retain named protocol limits. |
| [enumerations.rs](../libraries/tacacsrs_protocol/src/enumerations.rs#L1) | Retain wire enums and flags. |
| [header.rs](../libraries/tacacsrs_protocol/src/header.rs#L1) | Retain header parsing and validation. |
| [packet.rs](../libraries/tacacsrs_protocol/src/packet.rs#L1) | Retain packet invariants and body ownership. |
| [obfuscation.rs](../libraries/tacacsrs_protocol/src/obfuscation.rs#L1) | Retain TACACS+ obfuscation, not encryption terminology. |
| [wire_io.rs](../libraries/tacacsrs_protocol/src/wire_io.rs#L1) | Retain narrow byte-reading primitives. |
| [privilege.rs](../libraries/tacacsrs_protocol/src/privilege.rs#L1) | Retain validated privilege semantics. |
| [conversation.rs](../libraries/tacacsrs_protocol/src/conversation.rs#L1) | Retain pure conversation validation. |
| [failure.rs](../libraries/tacacsrs_protocol/src/failure.rs#L1) | Retain shared failure facts and conservative retry advice. |
| [accounting/mod.rs](../libraries/tacacsrs_protocol/src/accounting/mod.rs#L1) | Retain the small module facade. |
| [accounting/request.rs](../libraries/tacacsrs_protocol/src/accounting/request.rs#L1) | Retain body encoding and decoding. |
| [accounting/reply.rs](../libraries/tacacsrs_protocol/src/accounting/reply.rs#L1) | Retain body encoding and decoding. |
| [authentication/mod.rs](../libraries/tacacsrs_protocol/src/authentication/mod.rs#L1) | Retain the small module facade. |
| [authentication/start.rs](../libraries/tacacsrs_protocol/src/authentication/start.rs#L1) | Retain authentication start-body semantics. |
| [authentication/continue_packet.rs](../libraries/tacacsrs_protocol/src/authentication/continue_packet.rs#L1) | Retain continuation-body semantics. |
| [authentication/reply.rs](../libraries/tacacsrs_protocol/src/authentication/reply.rs#L1) | Retain reply-body semantics. |
| [authorization/mod.rs](../libraries/tacacsrs_protocol/src/authorization/mod.rs#L1) | Retain the small module facade. |
| [authorization/request.rs](../libraries/tacacsrs_protocol/src/authorization/request.rs#L1) | Retain body encoding and decoding. |
| [authorization/reply.rs](../libraries/tacacsrs_protocol/src/authorization/reply.rs#L1) | Retain body encoding and decoding. |
| [exchange.rs](../libraries/tacacsrs_protocol/src/exchange.rs#L1) | Retain the I/O-free fixed-exchange contract. |
| [exchange/accounting.rs](../libraries/tacacsrs_protocol/src/exchange/accounting.rs#L1) | Retain typed reply validation. |
| [exchange/authentication.rs](../libraries/tacacsrs_protocol/src/exchange/authentication.rs#L1) | Retain fixed PAP exchange semantics. |
| [exchange/authorization.rs](../libraries/tacacsrs_protocol/src/exchange/authorization.rs#L1) | Retain typed reply validation. |
| [operations.rs](../libraries/tacacsrs_protocol/src/operations.rs#L1) | Retain logical-operation exports. |
| [operations/accounting.rs](../libraries/tacacsrs_protocol/src/operations/accounting.rs#L1) | R6: distinguish input from immutable validated operation. |
| [operations/authentication.rs](../libraries/tacacsrs_protocol/src/operations/authentication.rs#L1) | R6: prepare once without weakening password ownership. |
| [operations/authorization.rs](../libraries/tacacsrs_protocol/src/operations/authorization.rs#L1) | R6 and R15: reuse validation and the existing builder. |
| [operations/arguments.rs](../libraries/tacacsrs_protocol/src/operations/arguments.rs#L1) | Retain ordered mandatory/optional argument semantics. |
| [operations/enforcement.rs](../libraries/tacacsrs_protocol/src/operations/enforcement.rs#L1) | Retain shared unchanged-command decisions. |
| [operations/wire.rs](../libraries/tacacsrs_protocol/src/operations/wire.rs#L1) | R6: centralize validated body preparation. |

## Secrets And Credential Contracts

Keep secret ownership separate from provider resolution.
The provider-neutral crate must not acquire YANG, HTTP, Redis, OpenSSL, or Tokio dependencies to support orchestration policy.

| Source file | Disposition |
| --- | --- |
| [secrets/lib.rs](../libraries/tacacsrs_secrets/src/lib.rs#L1) | Retain existing wrappers. Extend their use in R1 and R3 before replacing the crate. |
| [credential_resolution/lib.rs](../libraries/tacacsrs_credential_resolution/src/lib.rs#L1) | Retain the neutral facade. |
| [credential_resolution/request.rs](../libraries/tacacsrs_credential_resolution/src/request.rs#L1) | Retain typed kinds, contexts, and deterministic resolution slots. |
| [credential_resolution/material.rs](../libraries/tacacsrs_credential_resolution/src/material.rs#L1) | Retain typed material and protected aggregate formatting. |
| [credential_resolution/result_set.rs](../libraries/tacacsrs_credential_resolution/src/result_set.rs#L1) | Retain closed-result validation, independent of response order. |
| [credential_resolution/resolver.rs](../libraries/tacacsrs_credential_resolution/src/resolver.rs#L1) | R14: document plan-level budget expectations. Keep scheduling outside the neutral contract. |
| [credential_resolution/error.rs](../libraries/tacacsrs_credential_resolution/src/error.rs#L1) | Retain sanitized typed failures and field context. |
| [credential_resolution/change.rs](../libraries/tacacsrs_credential_resolution/src/change.rs#L1) | Clarify stream-drop ownership and provider worker lifetime. |
| [credential_resolution/validity.rs](../libraries/tacacsrs_credential_resolution/src/validity.rs#L1) | Retain half-open provider intervals, independent of certificate dates. |
| [credential_resolution/fake.rs](../libraries/tacacsrs_credential_resolution/src/fake.rs#L1) | Retain deterministic test and example support. |

## Configuration

Keep canonical YANG authoritative.
The opportunities concern typed stage boundaries, complete choice validation, secret-safe adapters, and owned observation reuse.
Do not replace meaningful schema, materialization, and runtime-readiness checks with one untyped validation hook.

| Source file | Disposition |
| --- | --- |
| [lib.rs](../libraries/tacacsrs_config/src/lib.rs#L1) | Retain the curated parsing and model facade. |
| [generated.rs](../libraries/tacacsrs_config/src/generated.rs#L1) | Generated: fix R2 through the generator, never by hand. |
| [parse.rs](../libraries/tacacsrs_config/src/parse.rs#L1) | Retain unknown-field and trailing-input rejection. Extend behavioral choice tests for R2. |
| [validation.rs](../libraries/tacacsrs_config/src/validation.rs#L1) | R2: enforce nested alternatives and audit inline mandatory choices. |
| [builders.rs](../libraries/tacacsrs_config/src/builders.rs#L1) | Clarify unchecked server construction versus validated root construction. Coordinate with R7. |
| [central_references.rs](../libraries/tacacsrs_config/src/central_references.rs#L1) | R5: retain typed usage through installation. |
| [enumeration.rs](../libraries/tacacsrs_config/src/enumeration.rs#L1) | Retain source-preserving local bundle expansion. |
| [extensions.rs](../libraries/tacacsrs_config/src/extensions.rs#L1) | R11: stop converting host and port into a runtime parsing problem. |
| [input/mod.rs](../libraries/tacacsrs_config/src/input/mod.rs#L1) | Retain the executable-neutral input facade. |
| [input/model.rs](../libraries/tacacsrs_config/src/input/model.rs#L1) | R1: protect and redact every secret-bearing input type. |
| [input/address.rs](../libraries/tacacsrs_config/src/input/address.rs#L1) | R11: consolidate string parsing around structured addresses. |
| [input/builder.rs](../libraries/tacacsrs_config/src/input/builder.rs#L1) | Retain normalization through canonical builders and explicit relaxations. |
| [input/files.rs](../libraries/tacacsrs_config/src/input/files.rs#L1) | Retain encoding normalization separate from native certificate verification. |
| [local_services.rs](../libraries/tacacsrs_config/src/local_services.rs#L1) | Retain preparation of immutable listener settings without binding. |
| [policy.rs](../libraries/tacacsrs_config/src/policy.rs#L1) | Retain canonical policy validation and generated defaults. |
| [proxy_policy.rs](../libraries/tacacsrs_config/src/proxy_policy.rs#L1) | Retain unavailable versus explicitly unobfuscated states. |
| [serde_helpers.rs](../libraries/tacacsrs_config/src/serde_helpers.rs#L1) | Retain RFC 7951 binary and empty-value representation. |
| [prepare/mod.rs](../libraries/tacacsrs_config/src/prepare/mod.rs#L1) | R7: make stage postconditions clear in the public facade. |
| [prepare/formats.rs](../libraries/tacacsrs_config/src/prepare/formats.rs#L1) | Retain exhaustive encoding conversions at the schema boundary. |
| [prepare/planning.rs](../libraries/tacacsrs_config/src/prepare/planning.rs#L1) | R5: associate slots with typed installation targets. |
| [prepare/materialization.rs](../libraries/tacacsrs_config/src/prepare/materialization.rs#L1) | R5, R7, R14: typed installation, explicit stage result, complete-candidate limits. |
| [prepare/readiness.rs](../libraries/tacacsrs_config/src/prepare/readiness.rs#L1) | Retain runtime-capability checks. Do not confuse them with schema acceptance. |
| [prepare/endpoint.rs](../libraries/tacacsrs_config/src/prepare/endpoint.rs#L1) | R4 and R7: consume explicit security preparation while retaining native validation. |
| [source.rs](../libraries/tacacsrs_config/src/source.rs#L1) | Retain owned baseline/change observation and complete snapshots. |
| [source/static_datastore.rs](../libraries/tacacsrs_config/src/source/static_datastore.rs#L1) | Retain worker-free baseline observation. Keep caller-validation assumptions explicit. |
| [source/directory_watch.rs](../libraries/tacacsrs_config/src/source/directory_watch.rs#L1) | Retain the platform boundary beneath R13. |
| [source/file.rs](../libraries/tacacsrs_config/src/source/file.rs#L1) | R13: share debounce and retained-read mechanics without losing accepted-snapshot history. |
| [source/policy.rs](../libraries/tacacsrs_config/src/source/policy.rs#L1) | R13: reuse observation mechanics, not configuration parsing or policy acceptance state. |
| [statistics.rs](../libraries/tacacsrs_config/src/statistics.rs#L1) | Retain bounded operational serialization outside desired configuration. |
| [statistics/diagnostics.rs](../libraries/tacacsrs_config/src/statistics/diagnostics.rs#L1) | Retain explicit projection of observed values and unsupported fields. |

## Networking

Keep catalog, client, connection, session, and promotion lifetimes distinct.
Native TLS and revocation received boundary-level assessment and selected consumer/test inspection, not a fresh cryptographic audit.
The existing task, transport, and cache owners encode cancellation and shutdown guarantees that generic middleware does not replace.

| Source file | Disposition |
| --- | --- |
| [lib.rs](../libraries/tacacsrs_networking/src/lib.rs#L1) | Retain schema-free exports. |
| [admission.rs](../libraries/tacacsrs_networking/src/admission.rs#L1) | Retain bounded active/pending capacity and synchronous cancellation cleanup. |
| [deadline.rs](../libraries/tacacsrs_networking/src/deadline.rs#L1) | Retain immutable absolute deadlines. Copies must not renew budgets. |
| [destination.rs](../libraries/tacacsrs_networking/src/destination.rs#L1) | R11: remove string heuristics, retain fresh resolution and host guards. |
| [endpoint.rs](../libraries/tacacsrs_networking/src/endpoint.rs#L1) | R4 and R11: single security selection and structured address ownership. |
| [exchange_error.rs](../libraries/tacacsrs_networking/src/exchange_error.rs#L1) | Retain explicit delivery classification. |
| [establish/mod.rs](../libraries/tacacsrs_networking/src/establish/mod.rs#L1) | Retain transport establishment and execution controls. Do not erase stage timeout distinctions. |
| [statistics.rs](../libraries/tacacsrs_networking/src/statistics.rs#L1) | Retain one coherent endpoint counter snapshot. |
| [statistics/diagnostics.rs](../libraries/tacacsrs_networking/src/statistics/diagnostics.rs#L1) | Retain bounded connection records, measured gauges, and explicit TLS error categories. |
| [client/mod.rs](../libraries/tacacsrs_networking/src/client/mod.rs#L1) | Retain the public client owner and terminal lifecycle API. |
| [client/exchange.rs](../libraries/tacacsrs_networking/src/client/exchange.rs#L1) | R6: accept prepared bodies without moving session-header ownership into protocol operations. |
| [client/lifecycle.rs](../libraries/tacacsrs_networking/src/client/lifecycle.rs#L1) | Retain setup and native transport ownership. Do not merge it blindly with routed lifecycle. |
| [client/preflight.rs](../libraries/tacacsrs_networking/src/client/preflight.rs#L1) | Retain explicit configured preflight, not unsolicited diagnostic traffic. |
| [client/selection.rs](../libraries/tacacsrs_networking/src/client/selection.rs#L1) | Retain dedicated/shared selection and negotiation ownership. |
| [client/tests.rs](../libraries/tacacsrs_networking/src/client/tests.rs#L1) | Test-only: retain cancellation, native closure, and reuse regressions. |
| [codec/mod.rs](../libraries/tacacsrs_networking/src/codec/mod.rs#L1) | Retain the codec facade. Evaluate buffering replacement only with equivalent delivery guarantees. |
| [codec/reader.rs](../libraries/tacacsrs_networking/src/codec/reader.rs#L1) | R3: retain protected key ownership. Preserve pre-allocation frame limits. |
| [codec/writer.rs](../libraries/tacacsrs_networking/src/codec/writer.rs#L1) | R3: retain protected key ownership and contiguous packet writes. |
| [connection/mod.rs](../libraries/tacacsrs_networking/src/connection/mod.rs#L1) | Retain explicit connection-runtime exports. |
| [connection/task.rs](../libraries/tacacsrs_networking/src/connection/task.rs#L1) | Retain owned task join/abort behavior. |
| [connection/dedicated/mod.rs](../libraries/tacacsrs_networking/src/connection/dedicated/mod.rs#L1) | R3: eliminate ordinary key copies. Retain one-exchange ownership. |
| [connection/dedicated/tests.rs](../libraries/tacacsrs_networking/src/connection/dedicated/tests.rs#L1) | Test-only: retain invalid-header and dedicated I/O regressions. |
| [connection/multiplexed/mod.rs](../libraries/tacacsrs_networking/src/connection/multiplexed/mod.rs#L1) | R3: protected key transfer. Retain driver ownership and session routing. |
| [connection/multiplexed/write_loop.rs](../libraries/tacacsrs_networking/src/connection/multiplexed/write_loop.rs#L1) | Retain serialized complete-packet writes and bounded delivery behavior. |
| [connection/multiplexed/tests.rs](../libraries/tacacsrs_networking/src/connection/multiplexed/tests.rs#L1) | Test-only: retain routing, concurrent I/O, and driver cleanup coverage. |
| [retry/mod.rs](../libraries/tacacsrs_networking/src/retry/mod.rs#L1) | Retain the shared retry facade. |
| [retry/plan.rs](../libraries/tacacsrs_networking/src/retry/plan.rs#L1) | Retain explicit attempt budgets and dispositions. |
| [retry/executor.rs](../libraries/tacacsrs_networking/src/retry/executor.rs#L1) | Retain the existing typed/raw retry engine. Do not add another. |
| [routed/mod.rs](../libraries/tacacsrs_networking/src/routed/mod.rs#L1) | Retain routing contracts and documented ownership. |
| [routed/catalog.rs](../libraries/tacacsrs_networking/src/routed/catalog.rs#L1) | Retain immutable endpoint identity and operation eligibility. |
| [routed/circuit.rs](../libraries/tacacsrs_networking/src/routed/circuit.rs#L1) | Retain operation-scoped recovery state. |
| [routed/client.rs](../libraries/tacacsrs_networking/src/routed/client.rs#L1) | R10: keep binding-owned outcomes and generation-fenced failure observation. |
| [routed/connector.rs](../libraries/tacacsrs_networking/src/routed/connector.rs#L1) | Retain the generic connector contract and native implementation. |
| [routed/lifecycle.rs](../libraries/tacacsrs_networking/src/routed/lifecycle.rs#L1) | Retain pending handoff, historical endpoint retirement, and owned cleanup. |
| [routed/operation.rs](../libraries/tacacsrs_networking/src/routed/operation.rs#L1) | Retain the small routing-operation enum. |
| [session/mod.rs](../libraries/tacacsrs_networking/src/session/mod.rs#L1) | Retain the session facade. |
| [session/channel.rs](../libraries/tacacsrs_networking/src/session/channel.rs#L1) | Retain transport-independent session channels. |
| [session/conversation.rs](../libraries/tacacsrs_networking/src/session/conversation.rs#L1) | Retain public interactive-conversation ownership. |
| [session/dedicated.rs](../libraries/tacacsrs_networking/src/session/dedicated.rs#L1) | Retain first-response promotion semantics and completion cleanup. |
| [session/handle.rs](../libraries/tacacsrs_networking/src/session/handle.rs#L1) | Retain explicit session operation contracts. |
| [session/id.rs](../libraries/tacacsrs_networking/src/session/id.rs#L1) | Retain reserved session-ID ownership. |
| [session/manager.rs](../libraries/tacacsrs_networking/src/session/manager.rs#L1) | Retain session-ID routing and route cleanup. |
| [session/shared.rs](../libraries/tacacsrs_networking/src/session/shared.rs#L1) | Retain shared interactive-session lifetime. |
| [session/shared_fixed.rs](../libraries/tacacsrs_networking/src/session/shared_fixed.rs#L1) | Retain the fixed-exchange specialization. |
| [single_connect/mod.rs](../libraries/tacacsrs_networking/src/single_connect/mod.rs#L1) | Retain an explicit promotion boundary. |
| [single_connect/cache.rs](../libraries/tacacsrs_networking/src/single_connect/cache.rs#L1) | Retain generation/closed fences and cache identity. |
| [single_connect/promotion.rs](../libraries/tacacsrs_networking/src/single_connect/promotion.rs#L1) | Retain first-reply latch, abandonment, and fenced publication. |
| [single_connect/state.rs](../libraries/tacacsrs_networking/src/single_connect/state.rs#L1) | Retain negotiation epoch separate from connection generation. |
| [single_connect/tracker.rs](../libraries/tacacsrs_networking/src/single_connect/tracker.rs#L1) | Retain narrow wire capability tracking. |
| [transport/mod.rs](../libraries/tacacsrs_networking/src/transport/mod.rs#L1) | Retain transport exports. |
| [transport/abstractions/mod.rs](../libraries/tacacsrs_networking/src/transport/abstractions/mod.rs#L1) | Retain the read/write split contract. No demonstrated benefit from another trait hierarchy. |
| [transport/boxed.rs](../libraries/tacacsrs_networking/src/transport/boxed.rs#L1) | Retain type erasure at the transport boundary. |
| [transport/managed.rs](../libraries/tacacsrs_networking/src/transport/managed.rs#L1) | Retain force-close, wakeup, activity, and revocation-evidence expiry ownership. |
| [transport/tcp/mod.rs](../libraries/tacacsrs_networking/src/transport/tcp/mod.rs#L1) | Retain the small TCP facade. |
| [transport/tcp/tcp.rs](../libraries/tacacsrs_networking/src/transport/tcp/tcp.rs#L1) | Retain the native TCP implementation. |
| [transport/tls/mod.rs](../libraries/tacacsrs_networking/src/transport/tls/mod.rs#L1) | Retain TLS exports and configuration roles. |
| [transport/tls/config.rs](../libraries/tacacsrs_networking/src/transport/tls/config.rs#L1) | Boundary review: retain prepared native trust and identity. R4 can clarify construction. |
| [transport/tls/config_builder.rs](../libraries/tacacsrs_networking/src/transport/tls/config_builder.rs#L1) | Boundary review: retain exact trust-role and native verification behavior. |
| [transport/tls/tls.rs](../libraries/tacacsrs_networking/src/transport/tls/tls.rs#L1) | Boundary review: retain handshake verification before TACACS+ traffic. |
| [transport/tls/validity.rs](../libraries/tacacsrs_networking/src/transport/tls/validity.rs#L1) | Retain authentication-date and revocation-evidence distinctions from #277. |
| [transport/tls/revocation.rs](../libraries/tacacsrs_networking/src/transport/tls/revocation.rs#L1) | Boundary review: retain explicit fail-closed policy. |
| [transport/tls/revocation/crls.rs](../libraries/tacacsrs_networking/src/transport/tls/revocation/crls.rs#L1) | Boundary review: retain bounded evidence and native selected-path verification. |
| [transport/tls/revocation/crl_delta.rs](../libraries/tacacsrs_networking/src/transport/tls/revocation/crl_delta.rs#L1) | Boundary review: retain typed pairing and strict metadata constraints. |
| [transport/tls/revocation/crl_scope.rs](../libraries/tacacsrs_networking/src/transport/tls/revocation/crl_scope.rs#L1) | Boundary review: retain coverage and overlap rules. No generic ASN.1 replacement established. |
| [transport/tls/revocation/responder.rs](../libraries/tacacsrs_networking/src/transport/tls/revocation/responder.rs#L1) | Boundary review: retain responder authorization and evidence requirements. |
| [transport/tls_psk/mod.rs](../libraries/tacacsrs_networking/src/transport/tls_psk/mod.rs#L1) | Retain explicit external-PSK transport. |
| [transport/tls_psk/config.rs](../libraries/tacacsrs_networking/src/transport/tls_psk/config.rs#L1) | Boundary review: retain hash/group/mode preparation. |
| [transport/tls_psk/context.rs](../libraries/tacacsrs_networking/src/transport/tls_psk/context.rs#L1) | Boundary review: retain callback/context ownership. |
| [transport/tls_psk/ffi/mod.rs](../libraries/tacacsrs_networking/src/transport/tls_psk/ffi/mod.rs#L1) | Native boundary: retain localized unsafe APIs and safety contracts. |
| [transport/mock/mod.rs](../libraries/tacacsrs_networking/src/transport/mock/mod.rs#L1) | Test support: retain the established mock facade. |
| [transport/mock/channel_reader.rs](../libraries/tacacsrs_networking/src/transport/mock/channel_reader.rs#L1) | Test support: retain channel-based reader behavior. |
| [transport/mock/mock_read_half.rs](../libraries/tacacsrs_networking/src/transport/mock/mock_read_half.rs#L1) | Test support: retain controlled read completion. |
| [transport/mock/mock_write_half.rs](../libraries/tacacsrs_networking/src/transport/mock/mock_write_half.rs#L1) | Test support: retain controlled write completion. |
| [transport/mock/mock_state.rs](../libraries/tacacsrs_networking/src/transport/mock/mock_state.rs#L1) | Test support: retain shared fixture state. |
| [transport/mock/mock_transport.rs](../libraries/tacacsrs_networking/src/transport/mock/mock_transport.rs#L1) | Test support: retain the transport implementation. |
| [transport/mock/mock_transport_coordinator.rs](../libraries/tacacsrs_networking/src/transport/mock/mock_transport_coordinator.rs#L1) | Test support: retain deterministic coordination. |

## Agent

The concrete public facade and generic internal implementation remain justified by the connector compiler tests.
The strongest simplifications are prepared publication, explicit coordinator states, narrower update APIs, and binding-owned outcomes.
The publication callback already updates bookkeeping atomically.

| Source file | Disposition |
| --- | --- |
| [lib.rs](../libraries/tacacsrs_agent/src/lib.rs#L1) | R9: curate the embedding API, not internal connector machinery. |
| [config.rs](../libraries/tacacsrs_agent/src/config.rs#L1) | Retain service construction configuration. Clarify managed versus unmanaged modes in R9. |
| [config/policy.rs](../libraries/tacacsrs_agent/src/config/policy.rs#L1) | Retain validated runtime projection and failover budgets. |
| [runtime/mod.rs](../libraries/tacacsrs_agent/src/runtime/mod.rs#L1) | Retain runtime exports; narrow them only with caller evidence. |
| [runtime/client_service.rs](../libraries/tacacsrs_agent/src/runtime/client_service.rs#L1) | R9: reduce construction and reload variants. Keep read-only weak diagnostics handles. |
| [runtime/client_service/engine.rs](../libraries/tacacsrs_agent/src/runtime/client_service/engine.rs#L1) | R7: shorten prepared-candidate publication. Retain concrete facade and generic `Send` proof. |
| [runtime/client_service/tests.rs](../libraries/tacacsrs_agent/src/runtime/client_service/tests.rs#L1) | Test-only: retain public facade, reload, lifecycle, and shutdown contracts. |
| [runtime/config_filter.rs](../libraries/tacacsrs_agent/src/runtime/config_filter.rs#L1) | Retain host filtering as an injected boundary. |
| [runtime/config_supervisor.rs](../libraries/tacacsrs_agent/src/runtime/config_supervisor.rs#L1) | Retain owned initialization and joined supervision loops. R14 clarifies candidate work limits. |
| [runtime/config_supervisor/observation.rs](../libraries/tacacsrs_agent/src/runtime/config_supervisor/observation.rs#L1) | R7: consume prepared candidates while retaining revision admission before asynchronous work. |
| [runtime/config_supervisor/expiry.rs](../libraries/tacacsrs_agent/src/runtime/config_supervisor/expiry.rs#L1) | Retain independent stale and absolute-validity expiry. Do not serialize behind provider I/O. |
| [runtime/config_supervisor/refresh.rs](../libraries/tacacsrs_agent/src/runtime/config_supervisor/refresh.rs#L1) | Retain provider refresh independent of expiry. Do not renew unchanged validity. |
| [runtime/config_supervisor/tests.rs](../libraries/tacacsrs_agent/src/runtime/config_supervisor/tests.rs#L1) | Test-only: retain source/provider recovery, cancellation, stale work, and expiry cases. |
| [runtime/credential_lifetime.rs](../libraries/tacacsrs_agent/src/runtime/credential_lifetime.rs#L1) | Retain wall-clock and conservative monotonic bounds. |
| [runtime/health.rs](../libraries/tacacsrs_agent/src/runtime/health.rs#L1) | Retain lifecycle, readiness, and degradation as different dimensions. |
| [runtime/listener_service.rs](../libraries/tacacsrs_agent/src/runtime/listener_service.rs#L1) | Retain host-injected listener ownership without an IPC production dependency. |
| [runtime/materialization_coordinator.rs](../libraries/tacacsrs_agent/src/runtime/materialization_coordinator.rs#L1) | R7 and R8: typed desired/applied states and shorter preparation-to-commit path. |
| [runtime/materialization_coordinator/tests.rs](../libraries/tacacsrs_agent/src/runtime/materialization_coordinator/tests.rs#L1) | Test-only: retain before/after commit cancellation and revision-fenced bookkeeping regressions. |
| [runtime/policy_supervisor.rs](../libraries/tacacsrs_agent/src/runtime/policy_supervisor.rs#L1) | Retain independent policy observation and fenced admission. |
| [runtime/proxy_loop_guard.rs](../libraries/tacacsrs_agent/src/runtime/proxy_loop_guard.rs#L1) | Retain execution-time checks against actual listener state. |
| [runtime/request_tracker.rs](../libraries/tacacsrs_agent/src/runtime/request_tracker.rs#L1) | Retain RAII draining ownership. Do not add a cross-crate abstraction for a tiny counter alone. |
| [runtime/revision.rs](../libraries/tacacsrs_agent/src/runtime/revision.rs#L1) | Retain separate source, credential, policy, and material identities. |
| [runtime/server_catalog.rs](../libraries/tacacsrs_agent/src/runtime/server_catalog.rs#L1) | R7: make validation stage postconditions explicit. |
| [runtime/shutdown.rs](../libraries/tacacsrs_agent/src/runtime/shutdown.rs#L1) | Retain runtime-owned shutdown and listener registration. |
| [services/mod.rs](../libraries/tacacsrs_agent/src/services/mod.rs#L1) | Retain listener options and service organization. |
| [services/client_api/mod.rs](../libraries/tacacsrs_agent/src/services/client_api/mod.rs#L1) | Retain the domain API facade. |
| [services/client_api/handle.rs](../libraries/tacacsrs_agent/src/services/client_api/handle.rs#L1) | Retain the host-adaptable typed handle. |
| [services/client_api/upstream_bridge/mod.rs](../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/mod.rs#L1) | R10: remove router retention only when bindings own outcome operations. |
| [services/client_api/upstream_bridge/accounting.rs](../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/accounting.rs#L1) | R6: prepare once, retain canonical response interpretation. |
| [services/client_api/upstream_bridge/authentication.rs](../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/authentication.rs#L1) | R6: prepare PAP once with protected material. |
| [services/client_api/upstream_bridge/authorization.rs](../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/authorization.rs#L1) | R6: remove body construction solely for sizing. |
| [services/client_api/upstream_bridge/routed.rs](../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/routed.rs#L1) | R10: binding-owned outcomes, not a new retry engine. |
| [services/client_api/upstream_bridge/routing_tests.rs](../libraries/tacacsrs_agent/src/services/client_api/upstream_bridge/routing_tests.rs#L1) | Test-only: retain request-snapshot, deadline, failover, and cancellation tests. |
| [services/tacacs_proxy/mod.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/mod.rs#L1) | Retain the raw proxy facade. |
| [services/tacacs_proxy/service.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/service.rs#L1) | Retain proxy dependencies and service lifecycle. |
| [services/tacacs_proxy/listener/mod.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/listener/mod.rs#L1) | Retain bounded acceptance, task reaping, and drain behavior. |
| [services/tacacs_proxy/listener/tcp.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/listener/tcp.rs#L1) | Retain actual-bind registration for loop protection. |
| [services/tacacs_proxy/listener/unix.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/listener/unix.rs#L1) | Retain shared trusted Unix binding owner. |
| [services/tacacs_proxy/upstream_bridge/mod.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/upstream_bridge/mod.rs#L1) | Retain bounded reservations, connection multiplexing, and physical reply acknowledgement. |
| [services/tacacs_proxy/upstream_bridge/session.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/upstream_bridge/session.rs#L1) | R10: share narrow outcomes, retain first-packet retry and pinned continuations. |
| [services/tacacs_proxy/upstream_bridge/error.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/upstream_bridge/error.rs#L1) | Retain upstream/downstream error distinction. |
| [services/tacacs_proxy/upstream_bridge/error_reply.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/upstream_bridge/error_reply.rs#L1) | Retain local protocol error construction. |
| [services/tacacs_proxy/upstream_bridge/packet_io.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/upstream_bridge/packet_io.rs#L1) | Retain cancellation-aware framing and downstream obfuscation. |
| [services/tacacs_proxy/upstream_bridge/reply_action.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/upstream_bridge/reply_action.rs#L1) | Retain operation-specific terminal/error classification. |
| [services/tacacs_proxy/upstream_bridge/session_mapping.rs](../libraries/tacacsrs_agent/src/services/tacacs_proxy/upstream_bridge/session_mapping.rs#L1) | Retain downstream/upstream session-ID mapping. |
| [upstream/mod.rs](../libraries/tacacsrs_agent/src/upstream/mod.rs#L1) | Retain internal ownership vocabulary and explicit exports. |
| [upstream/admission.rs](../libraries/tacacsrs_agent/src/upstream/admission.rs#L1) | R10: put lease-only operations on the lease, retaining common overload errors. |
| [upstream/attempt.rs](../libraries/tacacsrs_agent/src/upstream/attempt.rs#L1) | Retain delivery-aware request errors. |
| [upstream/connection.rs](../libraries/tacacsrs_agent/src/upstream/connection.rs#L1) | Retain the operation transport contract and generic testing boundary. |
| [upstream/network.rs](../libraries/tacacsrs_agent/src/upstream/network.rs#L1) | R6: adapt prepared bodies to native execution. Retain concrete production connection. |
| [upstream/proxy_transport.rs](../libraries/tacacsrs_agent/src/upstream/proxy_transport.rs#L1) | Retain captured downstream settings. |
| [upstream/router.rs](../libraries/tacacsrs_agent/src/upstream/router.rs#L1) | R10: retain service-scoped capture, remove behavior-free outcome forwarding. |
| [upstream/manager/mod.rs](../libraries/tacacsrs_agent/src/upstream/manager/mod.rs#L1) | R7 and R10: retain catalog owner, reduce request-only forwarding. |
| [upstream/manager/binding.rs](../libraries/tacacsrs_agent/src/upstream/manager/binding.rs#L1) | R10: keep validity/availability adaptation, remove pure outcome hops. |
| [upstream/manager/prepared_server.rs](../libraries/tacacsrs_agent/src/upstream/manager/prepared_server.rs#L1) | R7: form part of one checked prepared-catalog result. |
| [upstream/manager/publication.rs](../libraries/tacacsrs_agent/src/upstream/manager/publication.rs#L1) | R7: prepare outside the short commit where safe. Preserve atomic callback and urgent retirement. |
| [upstream/manager/server_set.rs](../libraries/tacacsrs_agent/src/upstream/manager/server_set.rs#L1) | Retain immutable snapshot/lease identity and revocation-sensitive replacement. |
| [upstream/manager/tests.rs](../libraries/tacacsrs_agent/src/upstream/manager/tests.rs#L1) | Test-only: retain generation-aware routing and recovery cases. |
| [test_support/mod.rs](../libraries/tacacsrs_agent/src/test_support/mod.rs#L1) | Test support: retain test-only erased adapters, not erased production architecture. |
| [test_support/fake_upstream.rs](../libraries/tacacsrs_agent/src/test_support/fake_upstream.rs#L1) | Test support: retain deterministic failure and connection control. |
| [test_support/listeners.rs](../libraries/tacacsrs_agent/src/test_support/listeners.rs#L1) | Test support: retain owned listener fixtures. |
| [test_support/requests.rs](../libraries/tacacsrs_agent/src/test_support/requests.rs#L1) | Test support: retain shared request fixtures. |

## IPC

Keep generated protobuf bindings separate from domain operations and from the agent implementation.
The JSON diagnostics contract is an intentional schema boundary, not an absent type system.

| Source file | Disposition |
| --- | --- |
| [lib.rs](../libraries/tacacsrs_ipc/src/lib.rs#L1) | Retain the SDK and adapter facade. |
| [proto.rs](../libraries/tacacsrs_ipc/src/proto.rs#L1) | Generated-binding boundary: retain, with schema changes made in protobuf inputs. |
| [client.rs](../libraries/tacacsrs_ipc/src/client.rs#L1) | R15: use existing consuming conversions. Retain reusable channels and conservative failures. |
| [convert.rs](../libraries/tacacsrs_ipc/src/convert.rs#L1) | R6: clarify boundary validation versus prepared operations. Retain fallible inbound conversion. |
| [convert/failure.rs](../libraries/tacacsrs_ipc/src/convert/failure.rs#L1) | Retain validation of remote delivery facts and retry advice. |
| [endpoint.rs](../libraries/tacacsrs_ipc/src/endpoint.rs#L1) | R15: share a narrow channel connector with the emulator. |
| [diagnostics.rs](../libraries/tacacsrs_ipc/src/diagnostics.rs#L1) | Retain read-only bounded JSON service and sanitized provider errors. |
| [health.rs](../libraries/tacacsrs_ipc/src/health.rs#L1) | Retain standard health client separately from diagnostic export. |
| [server/mod.rs](../libraries/tacacsrs_ipc/src/server/mod.rs#L1) | Retain the server facade. |
| [server/handler.rs](../libraries/tacacsrs_ipc/src/server/handler.rs#L1) | Retain the agent-independent domain handler. |
| [server/grpc.rs](../libraries/tacacsrs_ipc/src/server/grpc.rs#L1) | Retain protobuf/domain adaptation and request validation. |
| [server/listener.rs](../libraries/tacacsrs_ipc/src/server/listener.rs#L1) | Retain composed health/diagnostics service and owned Unix lifecycle. |
| [server/health.rs](../libraries/tacacsrs_ipc/src/server/health.rs#L1) | Retain standard health projection. |
| [server/limited_incoming.rs](../libraries/tacacsrs_ipc/src/server/limited_incoming.rs#L1) | Retain connection lifetime, stream limits, and force-close behavior. |
| [server/request_tracker.rs](../libraries/tacacsrs_ipc/src/server/request_tracker.rs#L1) | Retain adapter-local draining. Similarity to agent tracking alone does not justify a new shared crate. |

## Concrete Providers And Unix Binding

Provider retrieval remains separate from cryptographic verification.
HTTP source registration authorizes retrieval; an opaque reference is not a path or an automatically authorized URL.

| Source file | Disposition |
| --- | --- |
| [credential_http/lib.rs](../libraries/tacacsrs_credential_http/src/lib.rs#L1) | Retain a narrow evidence-provider facade. |
| [credential_http/source.rs](../libraries/tacacsrs_credential_http/src/source.rs#L1) | Rename CRL-only limits where they govern both CRL and OCSP. Retain explicit authorization. |
| [credential_http/resolver.rs](../libraries/tacacsrs_credential_http/src/resolver.rs#L1) | R14: clarify per-fetch limits. Rename the combined evidence resolver without splitting identical retrieval machinery. |
| [sonic/lib.rs](../libraries/tacacsrs_sonic/src/lib.rs#L1) | Retain the Linux integration facade. |
| [sonic/mapping.rs](../libraries/tacacsrs_sonic/src/mapping.rs#L1) | R1: redact raw tables. Retain deterministic mapping and compatibility isolation. |
| [sonic/datastore.rs](../libraries/tacacsrs_sonic/src/datastore.rs#L1) | Retain owned Pub/Sub pump, subscribe-before-baseline, and retained reload future. |
| [sonic/provider.rs](../libraries/tacacsrs_sonic/src/provider.rs#L1) | Retain descriptor-relative EPSK access and stable-read/metadata checks. |
| [sonic/store.rs](../libraries/tacacsrs_sonic/src/store.rs#L1) | Retain atomic Redis snapshots and owned credential watcher. |
| [unix_socket/lib.rs](../libraries/tacacsrs_unix_socket/src/lib.rs#L1) | Retain a minimal platform-resource facade. |
| [unix_socket/listener.rs](../libraries/tacacsrs_unix_socket/src/listener.rs#L1) | Retain advisory locking, trusted-directory assumptions, and identity-aware cleanup. |

## Executables

Keep operating-system signals and process-manager integration in the daemon.
Its composition spans startup and supervision but does not require a new application framework.
An explicit prepared-daemon value can improve topology visibility if it deletes forwarding rather than adding another builder layer.

| Source file | Disposition |
| --- | --- |
| [agentd/main.rs](../executables/tacacsrs_agentd/src/main.rs#L1) | Retain logger/runtime entry and host-owned signals. |
| [agentd/cli.rs](../executables/tacacsrs_agentd/src/cli.rs#L1) | Retain explicit source and listener conflicts. Avoid a second desired-configuration schema. |
| [agentd/startup.rs](../executables/tacacsrs_agentd/src/startup.rs#L1) | R9: show one waiting-service/supervisor construction path. |
| [agentd/local_services.rs](../executables/tacacsrs_agentd/src/local_services.rs#L1) | Retain CLI/SONiC adaptation into canonical listener configuration. |
| [agentd/config_filter.rs](../executables/tacacsrs_agentd/src/config_filter.rs#L1) | Retain host-specific loop filtering, with networking execution-time guards as the final check. |
| [agentd/credential_provider.rs](../executables/tacacsrs_agentd/src/credential_provider.rs#L1) | Retain explicit HTTP/SONiC composition and startup-only retrieval authorization. |
| [agentd/client_api_listener.rs](../executables/tacacsrs_agentd/src/client_api_listener.rs#L1) | Retain the composition root for domain handler, health, and diagnostics adapters. |
| [agentd/host_integration.rs](../executables/tacacsrs_agentd/src/host_integration.rs#L1) | OSS experiment: direct notification can remove subprocess discovery/execution. Preserve bounded shutdown. |
| [agentd/signals.rs](../executables/tacacsrs_agentd/src/signals.rs#L1) | Retain owned process signal streams. |
| [agentd/statistics.rs](../executables/tacacsrs_agentd/src/statistics.rs#L1) | Retain protected atomic file publication and explicit failure handling. |
| [agentd/supervision.rs](../executables/tacacsrs_agentd/src/supervision.rs#L1) | Retain peer cancellation and one absolute cleanup deadline. Make topology explicit without merging independent observations. |
| [agent_health/main.rs](../executables/tacacsrs_agent_health/src/main.rs#L1) | Retain explicit health checks, timeout, and exit codes. |
| [agent_health/statistics.rs](../executables/tacacsrs_agent_health/src/statistics.rs#L1) | Retain structured JSON parsing, unknown values, and terminal escaping. Do not generate a renderer framework yet. |
| [tacon/main.rs](../executables/tacon/src/main.rs#L1) | Retain command/backend orchestration. |
| [tacon/backend.rs](../executables/tacon/src/backend.rs#L1) | Retain existing direct/IPC operation dispatch. R15 reduces downstream clones. |
| [tacon/cli.rs](../executables/tacon/src/cli.rs#L1) | Retain explicit modes and parser conflicts. |
| [tacon/config.rs](../executables/tacon/src/config.rs#L1) | Retain canonical input adaptation and selected server policy. |
| [tacon/connection.rs](../executables/tacon/src/connection.rs#L1) | Retain direct connection-mode policy separate from logical operations. |
| [tacon/commands/mod.rs](../executables/tacon/src/commands/mod.rs#L1) | Retain the small command facade. |
| [tacon/commands/accounting.rs](../executables/tacon/src/commands/accounting.rs#L1) | Retain operation construction and shared response conversion. |
| [tacon/commands/authentication.rs](../executables/tacon/src/commands/authentication.rs#L1) | Retain password acquisition separate from prepared execution. |
| [tacon/commands/authorization.rs](../executables/tacon/src/commands/authorization.rs#L1) | Retain builder-based command/session conversion. |
| [tacon/batch/mod.rs](../executables/tacon/src/batch/mod.rs#L1) | Retain batch parsing with file context. |
| [tacon/batch/types.rs](../executables/tacon/src/batch/types.rs#L1) | Retain the JSON workload contract and nonzero concurrency. |
| [tacon/batch/progress.rs](../executables/tacon/src/batch/progress.rs#L1) | R15: use the existing completion count rather than recounting stored flags. |
| [tacon/batch/executor/mod.rs](../executables/tacon/src/batch/executor/mod.rs#L1) | Retain the small execution facade. |
| [tacon/batch/executor/common.rs](../executables/tacon/src/batch/executor/common.rs#L1) | R15: delete proportional Boolean result storage, retain draining and first-failure semantics. |
| [tacon/batch/executor/direct.rs](../executables/tacon/src/batch/executor/direct.rs#L1) | Retain direct mode selection and setup-error context. |
| [tacon/batch/executor/dedicated.rs](../executables/tacon/src/batch/executor/dedicated.rs#L1) | Retain per-request connection ownership and failure results. |
| [tacon/batch/executor/multiplexed.rs](../executables/tacon/src/batch/executor/multiplexed.rs#L1) | Retain the small adaptive setup boundary. File count alone is not a reason to inline it. |
| [tacon/batch/executor/service.rs](../executables/tacon/src/batch/executor/service.rs#L1) | Retain persistent IPC setup and shared scheduler delegation. |

## Shell Integration And Experiments

Keep the Bash host contract, shared domain enforcement, and experimental wrapper process boundary separate.
The emulator deliberately supports transport-level status behavior that the production domain handler does not express.
Do not force the complete emulator through that handler without deciding which fault-simulation behavior remains required.

| Source file | Disposition |
| --- | --- |
| [bash_plugin/lib.rs](../libraries/tacacsrs_bash_plugin/src/lib.rs#L1) | Retain narrow exported ABI and localized unsafe allowances. |
| [bash_plugin/ffi.rs](../libraries/tacacsrs_bash_plugin/src/ffi.rs#L1) | Retain ABI result mapping and remote-user/local-fallback policy. |
| [bash_plugin/c_strings.rs](../libraries/tacacsrs_bash_plugin/src/c_strings.rs#L1) | Retain documented trusted-pointer preconditions and copied ownership. |
| [bash_plugin/config.rs](../libraries/tacacsrs_bash_plugin/src/config.rs#L1) | Retain SONiC-compatible parsing and endpoint precedence. |
| [bash_plugin/authorization.rs](../libraries/tacacsrs_bash_plugin/src/authorization.rs#L1) | R15: use the shared builder with exact mandatory argument semantics. |
| [bash_plugin/runtime.rs](../libraries/tacacsrs_bash_plugin/src/runtime.rs#L1) | Retain pending fork/callback evidence. Do not add speculative global channel reuse. |
| [bash_plugin/session.rs](../libraries/tacacsrs_bash_plugin/src/session.rs#L1) | Retain host identity, TTY, task, and remote-address discovery. |
| [bash_plugin/logging.rs](../libraries/tacacsrs_bash_plugin/src/logging.rs#L1) | Retain fixed-format syslog boundary. |
| [session_wrapper/main.rs](../executables/session_wrapper/src/main.rs#L1) | Retain the experimental Linux GNU x86_64 platform gate. |
| [session_wrapper/linux.rs](../executables/session_wrapper/src/linux.rs#L1) | Retain fork-before-runtime orchestration. |
| [session_wrapper/cli.rs](../executables/session_wrapper/src/cli.rs#L1) | Retain caller identity, command, and policy inputs. |
| [session_wrapper/allowlist.rs](../executables/session_wrapper/src/allowlist.rs#L1) | Retain exact-path policy lookup. No new shell parser is justified. |
| [session_wrapper/deny.rs](../executables/session_wrapper/src/deny.rs#L1) | Retain denial presentation outside authorization policy. |
| [session_wrapper/process.rs](../executables/session_wrapper/src/process.rs#L1) | Retain descriptor, readiness/error, and descendant ownership. |
| [session_wrapper/process_reader.rs](../executables/session_wrapper/src/process_reader.rs#L1) | Native boundary: retain Linux process-memory access isolation. Live-process verification remains separate. |
| [session_wrapper/seccomp.rs](../executables/session_wrapper/src/seccomp.rs#L1) | Retain declarative rules and existing libseccomp integration. |
| [session_wrapper/supervisor.rs](../executables/session_wrapper/src/supervisor.rs#L1) | Retain process supervision, cached IPC client, and shared domain enforcement. |
| [emulator/lib.rs](../libraries/tacacsrs_agent_ipc_emulator/src/lib.rs#L1) | Retain the experimental public facade. |
| [emulator/client.rs](../libraries/tacacsrs_agent_ipc_emulator/src/client.rs#L1) | R15: delete duplicate endpoint connector, retain controller RPCs. |
| [emulator/controller.rs](../libraries/tacacsrs_agent_ipc_emulator/src/controller.rs#L1) | Retain generated controller bindings. |
| [emulator/emulator.rs](../libraries/tacacsrs_agent_ipc_emulator/src/emulator.rs#L1) | R15: compile once during startup. Retain controller/listener composition. |
| [emulator/policy.rs](../libraries/tacacsrs_agent_ipc_emulator/src/policy.rs#L1) | R15: separate source/data loading from explicit compilation. |
| [emulator/protocol.rs](../libraries/tacacsrs_agent_ipc_emulator/src/protocol.rs#L1) | Retain policy projection; document domain-validation fidelity separately from fault simulation. |
| [emulator/service.rs](../libraries/tacacsrs_agent_ipc_emulator/src/service.rs#L1) | Retain deliberate raw gRPC status behavior unless that product contract changes. |
| [emulator/state.rs](../libraries/tacacsrs_agent_ipc_emulator/src/state.rs#L1) | Retain compile-before-swap and exclusive policy evaluation. |
| [emulator/tests.rs](../libraries/tacacsrs_agent_ipc_emulator/src/tests.rs#L1) | Test-only: retain policy/controller/transport-status behavior. |
| [emulatord/main.rs](../executables/tacacsrs_agent_ipc_emulatord/src/main.rs#L1) | R15 affects policy preparation. Retain thin process composition. |

## Additional Ownership Map

These entries cover important non-source-tree boundaries.
They are not an exhaustive inventory of every fixture, workflow action, deployment document, or local smoke script.

| Surface | Disposition |
| --- | --- |
| [Workspace manifest](../Cargo.toml#L1) | Retain 17 explicit members and supported default members. No crate merge is justified by size alone. |
| [Development guide](../DEVELOPMENT.md#L1) | Keep the reading map aligned with implemented ownership, not proposed abstractions. |
| [YANG generator](../libraries/tacacsrs_config/yang/plugins/yang2rust.py#L1) | R2: preserve conditional nested choices. Retain secret manifests and qualification rules. |
| [YANG expansion](../libraries/tacacsrs_config/yang/expand_yang_tree.py#L1) | Retain pinned upstream input and explicit feature selection. |
| [Generation verification](../libraries/tacacsrs_config/yang/verify_generated.py#L1) | Retain the distinction between offline hash consistency and actual regeneration. |
| [Generator default tests](../libraries/tacacsrs_config/yang/test_yang2rust_defaults.py#L1) | R2: add nested-choice fixtures rather than trusting current generated constants. |
| [Parser integration tests](../libraries/tacacsrs_config/tests/parse_validation.rs#L1) | R2: add behavioral rejection tests for nested identity and inline-key choices. |
| [Materialization tests](../libraries/tacacsrs_config/tests/materialization.rs#L1) | Preserve source immutability, transactional failure, and provider validity. |
| [Resolution tests](../libraries/tacacsrs_config/tests/resolution.rs#L1) | Preserve missing, duplicate, unexpected, and wrong-kind result rejection. |
| [Connector boundary tests](../libraries/tacacsrs_networking/tests/connector_boundary.rs#L1) | Required gate before altering generic propagation or erasure. |
| [Connector compiler reproducer](../libraries/tacacsrs_networking/tests/fixtures/connector_send.rs#L1) | Retain evidence for the deliberate generic implementation. |
| [Shared authorization cases](../libraries/tacacsrs_protocol/test_support/authorization.rs#L1) | Retain shared consumer conformance data without creating a production test-only crate. |
| [HTTP evidence tests](../libraries/tacacsrs_credential_http/tests/http_crls.rs#L1) | Retain bounded retrieval, cancellation, no-fallback, and authorization tests. |
| [SONiC provider tests](../libraries/tacacsrs_sonic/tests/credential_provider_linux.rs#L1) | Retain native object/metadata and sanitized-failure cases. Some checks require root. |
| [SONiC watcher tests](../libraries/tacacsrs_sonic/tests/credential_watch_linux.rs#L1) | Retain watcher ownership and root-replacement cases. |
| [Daemon prepared-source tests](../executables/tacacsrs_agentd/tests/prepared_sources.rs#L1) | Retain cross-layer transport, credential, and revocation evidence tests. |
| [Daemon process tests](../executables/tacacsrs_agentd/tests/process_lifecycle.rs#L1) | Retain host-signal, cancellation, and shutdown-deadline tests. |
| [IPC build script](../libraries/tacacsrs_ipc/build.rs#L1) | Retain reproducible bindings and tool-selection behavior. Do not edit generated code for lints. |
| [CI caller](../.github/workflows/ci.yml#L1) | R12: consume the product registry. Retain release permissions and hydrated-source publication. |
| [PR caller](../.github/workflows/pullrequest_workflow.yml#L1) | R12: consume the same product registry without release writes. |
| [Reusable pipeline](../.github/workflows/reusable-pipeline.yml#L1) | R12: remove duplicated defaults. Preserve required aggregate gates and platform execution. |
| [Pages workflow](../.github/workflows/pages.yml#L1) | Retain documentation delivery outside runtime ownership. |
| [Cargo metadata helper](../.github/steps/cargo-metadata/workspace.py#L1) | Retain one authority for actual workspace membership and target names. |
| [Architecture checker](../.github/steps/check-architecture/check_architecture.py#L1) | Retain normal dependency checks and supported consumer profiles. |
| [Architecture rules](../.github/steps/check-architecture/rules.json#L1) | Retain explicit allowed direction, provider neutrality, IPC independence, and experimental isolation. |
| [Version computation](../.github/steps/compute-versions/compute_versions.py#L1) | Retain current policy unless a separate decision removes per-library release classification. |
| [API analysis caller](../.github/steps/compute-versions/api_analysis.py#L1) | Retain structured tool results and actual failure handling. Keep best-effort limitations explicit. |
| [Version hydration](../.github/steps/inject-versions/hydrate_versions.py#L1) | Evaluate TOML Kit for structural edits. Keep Cargo metadata membership. |
| [Hydration tests](../.github/steps/inject-versions/test_hydrate_versions.py#L1) | Add comments, alternate formatting, and lockfile association cases before replacing regexes. |
| [Release manifest](../.github/steps/release-manifest/release_manifest.py#L1) | Retain offline artifact verification and source/version association. |
| [Build provenance](../.github/steps/release-manifest/build_provenance.py#L1) | Retain per-product source and dependency evidence. Distinguish integrity from signed attestation. |
| [Linux rehearsal](../.github/steps/release-manifest/rehearse_linux.py#L1) | R12: derive products, retain reuse of CI scripts, private source export, and offline verification. |
| [Workflow contracts](../.github/steps/release-manifest/test_workflow_contracts.py#L1) | Retain independent supported-product and required-gate assertions after registry extraction. |
| [SBOM staging](../.github/steps/stage-sbom-files/stage_sbom.py#L1) | Retain actual Cargo artifact names and version checks. |
| [API classifier entry](../.github/tools/api-classifier/src/main.rs#L1) | Retain the typed tool boundary while best-effort classification remains required. |
| [API additive analysis](../.github/tools/api-classifier/src/additive.rs#L1) | Retain documented limitations. Do not claim exhaustive inherited API detection. |
| [API feature analysis](../.github/tools/api-classifier/src/features.rs#L1) | Retain explicit feature-surface classification. |
| [API breaking analysis](../.github/tools/api-classifier/src/semver_checks.rs#L1) | Retain mature upstream analysis rather than replacing it with local signature heuristics. |
| [API worktree handling](../.github/tools/api-classifier/src/worktree.rs#L1) | Retain owned temporary-worktree cleanup and read-only source comparison. |

Container recipes, local smoke tools, and documentation received integration-boundary consideration.
No container image, release archive, live switch, or CI runner was recreated for this review.
Those surfaces do not receive a file-by-file correctness claim from this ledger.