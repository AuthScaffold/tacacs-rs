# Stage 5: Adapters and Supported Products

## Status

Stage 5 started on 2026-10-14 from `76be797`, after the Stage 4 supported-profile closure.
The user authorizes autonomous implementation, breaking API changes, nearby corrections, and incremental local commits.
Canonical YANG, source immutability, security, and retained capabilities remain requirements. No push is authorized.

## Independent Plan Review

Claude Opus 4.8 reviewed this plan before any code change.
The review identified failure information loss as the first substantive problem, not the mechanical IPC package move.
The domain error and protobuf error currently retain only a message, server, and retry flag.
The agent bridge reduces unknown delivery and invalid requests to the same retry advice.

The review also found existing shared client execution, canonical preparation, and unchanged-command authorization interpretation.
These findings require verification, not replacement abstractions. The daemon already delegates supervision and materialization to the agent.
The Rego dependency is isolated, but supported release artifacts still need an explicit experimental-product boundary.

The revised plan keeps one IPC crate with client and server modules. It does not split generated contracts into another package.
The agent must not depend on generated IPC bindings. IPC server adaptation must not expose networking connector generics.
No replacement-capable authorization interpreter is planned without a consumer that can apply replacement attributes.
CLI multi-server failover is not a prerequisite for removing duplicate execution paths.

## Implementation Plan

- [x] S5-01: Commit `1ad1630` adds pure failure facts and preserves them through the agent, protobuf conversion, and SDK. Unknown delivery, invalid input, and known-unsent failures remain distinct. See [failure contract](#failure-contract).
- [x] S5-02: Commit `726f805` consolidates IPC ownership and moves server adaptation outside the agent. All consumers use the reusable channel SDK and the same failure schema. See [IPC ownership](#ipc-ownership).
- [x] S5-03: Commit `7785706` unifies direct and IPC domain responses and batch rendering. Shared request construction and canonical preparation remain unchanged. Four conformance tests cover response and failure projection.
- [x] S5-04: Commit `c3dcab9` shares 25 enforcement cases across Bash and the wrapper. Daemon composition contains no duplicate routing or materialization algorithm. Unsupported mandatory attributes remain denied.
- [x] S5-05: Cargo defaults now select the 13 supported core packages. Experimental wrapper and Rego packages remain explicit workspace selections and CI test targets. Existing release product lists exclude them.
- [ ] S5-06: Run matched-set process tests, dependency guards, native integration, and complete relevant workspace gates. Record supported capabilities, exceptions, and the final package graph.

Each increment runs its cheapest behavior check before wider checks or the next change.
Code and checkpoint commits preserve completed evidence and state remaining work explicitly.
Questionable design choices receive another independent review before implementation.

## First Discriminating Check

The first hypothesis is that the client-API bridge discards delivery facts when it constructs `ServiceError`.
A focused test must distinguish an unknown-outcome failure from invalid input even when neither permits replay.
The protocol error remains runtime-independent. Networking facts map into that vocabulary rather than the protocol crate importing networking.
The schema migration follows the domain change and must reject unspecified or malformed failure facts conservatively.

## Verification Requirements

Relevant package tests run first, followed by affected consumers, strict Clippy, formatting, build, and warnings-as-errors documentation.
Dependency changes require unused-dependency analysis, audit, and architectural dependency checks.
Protobuf changes require compatibility analysis and matched-set process verification. Old schemas do not constrain the new design.
Shared conformance fixtures cover observable semantics, not identical implementation structure.
Native FFI and process checks remain necessary where Miri cannot execute the boundary.
The Stage 4 supported-profile exclusions remain unchanged.

## Failure Contract

Commit `1ad1630` introduces protocol-owned `FailureFacts` with category, phase, and conservative delivery state.
Replay advice derives from those facts. Unknown delivery never permits automatic replay.
`ServiceError` requires explicit facts and retains optional server identity, captured runtime generation, and a nonzero attempt number.
It implements the standard Rust error contract, so `anyhow` boundaries retain its structured value.

The agent maps request, admission, routing, and exchange failures where those facts remain available.
The shared failover executor already stops unknown outcomes, so the bridge's duplicate unknown-outcome flag is removed.
The raw TACACS+ proxy retains its protocol-defined error replies and conservative delivery policy. It does not send IPC metadata over TACACS+.

The protobuf error carries explicit category, phase, delivery, retry advice, generation, and attempt fields.
Decoding rejects unspecified or unknown enum values, contradictory replay advice, and a present zero attempt number.
The SDK returns `Result<T, ServiceError>` without formatting the error into a string.
In-flight gRPC failures remain unknown outcomes. Malformed or absent reply results produce conservative IPC protocol failures.
The emulator retains its existing retry flag only as a scenario input, mapped into facts for its simulated unsent operation.

### Verification

All-feature workspace tests, strict Clippy, build, formatting, and warnings-as-errors documentation pass.
The agent has 198 passing tests. The SDK has 31 unit tests and three doctests. The emulator has 12 unit tests and one doctest.
Regressions verify structured SDK errors, malformed replies, uncertain RPC delivery, and generation and attempt metadata through protobuf conversion.
Both pure failure invariants pass under Miri. Audit reports no vulnerabilities, and unused-dependency analysis passes.
The SDK adds a development-only `tokio-stream` edge. No locked package version changes.
Existing audit index-lock and nightly `fetch_update` warnings remain unrelated to this increment.

This checkout has no local `main` ref, so the standard compatibility command cannot resolve that baseline.
`buf breaking --against '.git#ref=76be797'` passes against the completed Stage 4 commit under the configured `WIRE_JSON` rules.
The removed retry field's tag and name are reserved. Wire compatibility does not imply semantic compatibility: updated error decoding requires the new facts.
The daemon, SDK, clients, and emulator therefore remain one matched deployment set.
No native TLS, YANG, or FFI implementation changes occur in this increment.

## IPC Ownership

Commit `726f805` renames the former client package to `tacacsrs-ipc` and consolidates its client and server transport ownership.
The package owns generated bindings, conversion, the reusable channel SDK, bounded Unix listeners, and standard gRPC health publication.
Its server `Handler` uses protocol-domain operations. It has no dependency on agent routing, generated configuration, or networking connectors.
The agent exposes a domain `ClientApiHandle` and accepts host-composed listeners through `RuntimeListenerService`.
The daemon maps prepared listener values and health into IPC inputs. Agent shutdown, admission, and raw TACACS+ proxy ownership remain unchanged.

MAI reviewed the inversion before implementation. After restart recovery, Claude Opus 4.8 reviewed the completed extraction and found no blocking defects.
The follow-up removes a spawned health forwarder. The listener now owns that future directly and drops it on cancellation.
No duplicate routing or materialization algorithm was added to the daemon.
Production dependency guards prohibit IPC or tonic in the agent and agent or configuration dependencies in IPC.
Agent tests can compose IPC through development dependencies.

### Verification

All-feature workspace tests, strict Clippy, build, formatting, and warnings-as-errors rustdoc pass.
The extracted packages have 191 agent tests and 44 IPC tests. Moved tests retain listener limits, health, cancellation, and socket-cleanup coverage.
All 70 daemon unit tests, 42 prepared-source tests, and eight process-lifecycle tests pass.
Health-probe, emulator, CLI, wrapper, and Bash adapter tests pass as part of the matched workspace.
Both new production dependency guards, unused-dependency analysis, audit, and all 46 version-computation tests pass.
Audit reports no vulnerabilities in 323 locked packages. Existing index-lock and nightly `fetch_update` warnings remain.

`buf breaking --against '.git#ref=76be797'` passes. The schema package and wire file contents do not change in this extraction.
Only the Cargo package and source directory move. S5-01's matched-set semantic deployment requirement remains in effect.
No locked package version, YANG model, protocol parser, or native FFI implementation changes.
Live SONiC, isolated Redis, external TACACS+ peer, Windows, and container checks were not rerun for this ownership increment.

## CLI and Adapter Conformance

Claude Opus 4.8 reviewed the remaining CLI and product work before these changes.
Existing canonical request builders and networking execution already supply shared behavior. No extra routing abstraction or replacement-capable authorization API was needed.

Commit `7785706` makes direct accounting, authorization, and PAP commands return the existing protocol-domain response types used by IPC.
The CLI connection retains the configured server name for those responses. Protocol conversion preserves statuses and ordered authorization arguments.
Direct accounting now prints a response like IPC mode. Batch modes share one renderer and one unsupported-PAP message.
The renderer labels a completed exchange as a response, not a policy success. Denial and protocol ERROR statuses remain visible.
Batch summaries retain their existing exchange-completion semantics. Text rendering is the final CLI boundary, not a reusable error API.

All 56 CLI tests pass, including four new conformance cases.
The cases compare direct responses with IPC round trips for all accounting and authorization statuses, structured failure facts, and batch PAP rejection.
Targeted strict Clippy, build, formatting, and warnings-as-errors documentation pass.
No connection mode, canonical preparation, retry rule, or password-input behavior changes.

Commit `c3dcab9` supplies one shared 25-case response fixture to the Bash and seccomp adapters.
Both use the protocol's unchanged-command interpreter and allow only supported pass responses.
Mandatory command changes, mandatory privilege changes, malformed names, and non-pass statuses result in denial, not unavailability.
The wrapper retains denial metadata without applying its unavailable-service fail policy to a server response.
Its existing fail-open option remains specific to unavailable IPC. No new replacement or argument-injection capability is claimed.
All 36 wrapper tests and four Bash tests pass, including the shared matrix. Targeted strict Clippy and formatting pass.
No native FFI or enforcement implementation changes occur in this test increment.

## Supported Product Profile

`default-members` selects the 13 core workspace packages. Plain Cargo builds and tests exclude the experimental trio.
The excluded defaults are `session-wrapper`, `tacacsrs-agent-ipc-emulator`, and `tacacsrs-agent-ipc-emulatord`.
Explicit package selection and full workspace builds retain them. Their source and CI tests remain available.
The wrapper and emulator documentation identify this status and the explicit commands.

Existing release product lists already contain only `tacon`, `tacacsrs-agentd`, `tacacsrs-agent-health`, and the Bash plugin.
The supported Linux profile uses GNU. Windows releases remain limited to direct `tacon` and its dependency crates.
No release-matrix redesign or new package versioning scheme was needed. That broader work remains Stage 6.

Cargo metadata verifies exactly 13 defaults and three retained experimental members.
A CI dependency guard prevents wrapper, emulator, Rego, and seccomp dependencies from entering the default core graph.
The default build, explicit experimental builds, warnings-as-errors emulator documentation, book build, and whitespace checks pass.