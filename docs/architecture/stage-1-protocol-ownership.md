# Stage 1: Protocol Ownership

## Status

Implementation date: 2026-09-24.
Branch: `refactor/yang-first-toolkit`, created at the Stage 0 commit `f77b203f`.
This stage changes ownership and Rust APIs. It does not change the protobuf schema or authoritative YANG model.

The workspace now has one pure protocol package instead of separate message and flow packages.
Consumers import logical operations directly from that owner.
Temporary compatibility re-exports are removed.

## Ownership Changes

| Previous owner | Current owner | Contract |
| --- | --- | --- |
| `tacacsrs-messages` | `tacacsrs-protocol` message modules | Header, packet, accounting, authentication, and authorization wire types |
| `tacacsrs-flows` | `tacacsrs-protocol::exchange` | Pure fixed-exchange descriptions |
| Networking exchange trait | `tacacsrs_protocol::exchange::FixedExchange` | Body encoding and reply decoding without I/O |
| Networking conversation validation | `tacacsrs_protocol::conversation::ConversationState` | Session identity, alternating sequence, outstanding reply, and sequence exhaustion |
| Agent-client logical types | `tacacsrs_protocol::operations` | Shared operations, outcomes, builders, and argument semantics |
| Agent request/reply mapping | Protocol operation methods | One logical-to-wire conversion used by direct and IPC consumers |
| Host response interpretation | `AuthorizationResponseStatus::unchanged_execution` | One conservative rule for hosts that cannot apply server attributes |
| Agent-client protobuf conversion | Private `convert` module in agent-client | `From` and `TryFrom` between domain values and generated messages |

The [protocol package guide](../../libraries/tacacsrs_protocol/README.md) documents its public modules and an executable operation example.
The [IPC client guide](../../libraries/tacacsrs_agent_client/README.md) documents its reduced responsibility.

## API Changes

Consumers replace `tacacsrs_messages` imports with `tacacsrs_protocol`.
Fixed exchanges live under `tacacsrs_protocol::exchange`.
The old `tacacsrs-flows` package and networking's exchange re-export no longer exist.

Logical requests and responses come from `tacacsrs_protocol::operations`, not the agent-client facade.
Protobuf conversion uses standard conversion traits rather than methods attached to domain types.
Generated protobuf bindings still belong to agent-client.

`PrivilegeLevel` stores values from 0 through 15.
PAP and authorization operations store this type instead of an unrestricted integer.
The authorization builder validates raw numeric input before constructing the operation.
IPC decoders apply the same bounded type, so transport conversion cannot introduce an invalid privilege level.

Authorization arguments remain ordered typed values.
Repeated names and mandatory/optional separators survive conversion.
This stage does not wrap every string or vector in another type.

The direct and IPC CLI paths now construct the same logical operations.
Batch authorization also uses one operation builder before choosing a transport.
The old shell-exchange construction helpers and agent mapping module are removed rather than retained as parallel policies.

## Runtime Boundary

`ConversationState` owns no sockets, tasks, timers, or locks.
It rejects overlapping requests, unsolicited replies, identity changes, and sequence exhaustion.
Networking delegates header validation to it and still owns transport I/O and session cleanup.

The shared host interpreter explicitly represents an unchanged-command capability.
It allows valid pass replies only when no mandatory response changes require application.
It rejects invalid arguments and never converts server denial into service unavailability.
Both Bash and session-wrapper use it while retaining platform-specific diagnostics and failure handling.

This is not a general attribute-application engine.
A future host that can change effective command attributes needs a separately specified application contract.
No such capability is implied for the existing hooks.

## Configuration Boundary

Canonical YANG configuration, generated fields, feature selection, and credential materialization remain unchanged.
The protocol package does not own configuration defaults, provider resolution, or prepared endpoint publication.
Those responsibilities remain with the existing configuration/runtime components until Stage 2.

Neither operation extraction nor dependency cleanup introduces an independent desired-configuration model.
The Stage 0 YANG source-equivalence and immutable-reference tests remain workspace gates.

## Test and Build Gates

The following focused checks pass:

- Pure wire, operation, bounded privilege, and conversation-state tests.
- Existing networking conversation integration tests.
- Direct/IPC accounting, PAP, and authorization fixtures with byte-identical TACACS+ request bodies.
- Invalid IPC privilege rejection and secret-redaction checks.
- Existing Bash and session-wrapper authorization tests through the shared interpreter.
- CLI command and batch tests through shared logical construction.
- Public examples in the protocol and IPC guides.

The complete workspace test suite passes, including doctests.
Two existing manual networking baselines remain ignored.
The workspace build, warnings-as-errors rustdoc build, and nightly formatting check also run for this stage.

The pure dependency tree contains no Tokio, OpenSSL, tonic, prost, Redis, configuration, networking, or agent package.
The shared CI test action now checks this boundary before running tests.
The Windows direct-mode package list and local test scripts use the new protocol package.
No Windows build ran in this Linux container.

The fuzz workspace compiles against `tacacsrs-protocol`.
The existing accounting round-trip harnesses now handle fallible serialization.
A new `fuzz_protocol_parse` entry point exercises packet parsing and all implemented body families.
The CI fuzz smoke action includes this entry point.

Full fuzz execution, dependency audit, and unused-dependency analysis require tools absent from this container.
Compilation of the fuzz targets is not a substitute for a sanitizer-backed fuzz run.
The known pre-existing `clippy::comparison_chain` warning in the admission module remains outside this extraction.
The lint validation command allows only that known warning and does not add a permanent repository allowance.
Workspace Clippy passes with that exception, and the final CLI slice passes strict Clippy.
The renamed release-graph fixtures could not run because Python lacks pytest and `ensurepip`/venv support.
An attempted temporary test environment did not change repository dependencies.

## Remaining Work

Stage 2 owns YANG snapshot preparation and removal of generated configuration interpretation from client execution.
The agent still owns multi-server routing and process/lifecycle behavior pending their planned extraction.
The agent-client package retains its current name until the later IPC package stage.
The protobuf error shape remains unchanged, including Stage 0's conservative retry advice.

The existing architecture assessments describe the earlier baseline.
Their source links follow current module locations, while their findings retain historical context.