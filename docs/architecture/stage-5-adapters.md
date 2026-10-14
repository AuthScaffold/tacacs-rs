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

- [ ] S5-01: Define pure failure facts in the protocol crate and populate them where networking and agent code know the facts. Preserve category, phase, delivery, retry advice, and server identity without inventing certainty. Test unknown delivery separately from invalid input and known-unsent failure.
- [ ] S5-02: Consolidate IPC ownership in `tacacsrs-ipc`. Move server adaptation outside the agent, preserve a reusable channel SDK, and carry failure facts through the schema. Update all consumers as a matched set. Record intentional protobuf compatibility breaks.
- [ ] S5-03: Unify CLI direct and IPC operation results and remove proven command or batch duplication. Keep canonical preparation and existing connection modes. Add direct/IPC conformance cases as the acceptance gate for the failure and IPC changes.
- [ ] S5-04: Verify daemon composition and retained enforcement adapters. Remove only named duplicate algorithms. Verify shared unchanged-command interpretation and fail-closed handling of unsupported mandatory attributes.
- [ ] S5-05: Mark experimental wrapper and Rego products explicitly and exclude them from supported core release artifacts. Retain their source, opt-in builds, and tests. Leave the broader delivery redesign to Stage 6.
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