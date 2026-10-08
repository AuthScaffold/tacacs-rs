# Stage 3: Routed Client and Owned Runtime

## Status

Stage 3 is in progress. Stage 2's canonical configuration and prepared-endpoint boundaries remain in place.
The first increment transfers retry decisions and execution into networking and makes ordered retries conservative for every operation.
It does not yet provide an agent-free routed client or a public close/join API.

Fix nearby issues within the current increment when practical. Add a new item only when the work needs a distinct implementation step.
Keep completed items visible with verification evidence. Preserve canonical YANG and do not retain obsolete APIs only for compatibility.

## Checklist

- [x] S3-01: Move the retry plan and executor into networking and migrate both IPC and proxy callers. Commit `10058a5` stops uncertain-outcome replay for every operation and verifies bounded attempts, reply cleanup, cancellation, and adapter behavior. See [retry ownership](#retry-ownership).
- [ ] S3-02: Capture one routing generation and retry policy per admitted request. Start at the operation router and server-set owner. Force reload between attempts and verify that a request cannot switch to a new endpoint set.
- [ ] S3-03: Extract endpoint catalogs, circuits, and reconnect serialization into a routed client over prepared endpoints and neutral failures. Migrate both ingress paths, remove duplicate agent routing state, and run an agent-free routed-client example.
- [ ] S3-04: Apply one absolute request deadline to admission, resolution, connection/TLS setup, attempts, and response waits. Keep global capacity shared across generations and bound pending work. Verify cancellation cleanup and exhausted budgets.
- [ ] S3-05: Add explicit connection/runtime close and join ownership with bounded drain. Verify resource release after idle/active retirement, cancellation, repeated reload, and embedded shutdown.
- [ ] S3-06: Complete Stage 3 integration gates, remove temporary adapters, and update this checkpoint and the migration plan together. Preserve ordering, operation eligibility, prepared credentials, timeout semantics, and loop exclusion.

## Retry Ownership

`tacacsrs_networking::retry` now owns `FailoverPlan`, `AttemptDisposition`, `Attempt`, `FailoverAttempt`, `FailoverOutcome`, and `run_with_failover`.
Commit `10058a5` implements this boundary on 2026-10-08.
The existing executor moved from the agent rather than gaining a parallel implementation.
Its inputs contain no generated configuration, IPC types, health publishers, or agent routing state.
Callers supply attempt results and endpoint selection. The executor alone decides whether another attempt is permitted.

The plan accepts an explicit attempt budget. One attempt implements deferred behavior; zero performs no attempts.
The agent derives that budget from canonical service policy and the eligible-server count.
It retains one reporting attempt for an empty catalog, preserving the existing unavailable-response path.
The old agent executor/plan modules and forwarding exports are removed. IPC and proxy implementations import the networking API directly.

`ordered-safe-retry` now stops after an unknown outcome for authentication, authorization, and accounting.
The previous plan automatically replayed uncertain authentication and authorization operations.
The conservative-policy regression failed before the correction. No uncertain-outcome replay opt-in is introduced by this increment.
Proven-unsent requests and explicit server errors can use the remaining configured attempt budget. Valid denials remain final.
The default `deferred-failover` strategy still performs one attempt. No YANG field or default changed.

The executor closes discarded reply values before another attempt and starts no background task.
Cancellation drops the active attempt future and prevents later attempts. Runner-owned resources must have appropriate drop cleanup.
This does not claim complete connection shutdown or cancellation-safe asynchronous discard; S3-05 owns the runtime lifetime guarantees.

Focused tests cover accepted/rejected/aborted attempts, exhaustion, unknown delivery, zero budget, and cancellation cleanup.
IPC tests verify no backup attempt and non-retriable errors for uncertain authentication and authorization.
The proxy regression covers uncertain first requests of all three operation kinds.
Explicit authentication and accounting server-error failover and networking's not-sent retry tests remain passing.

Request leases, absolute deadlines, routing extraction, and runtime ownership remain open above.

## Verification

The first increment passes all eleven networking retry tests, the public retry example, and the complete workspace suite.
Workspace build, nightly formatting, warnings-as-errors rustdoc, and the documentation book pass.
Workspace Clippy uses only the previously recorded `comparison_chain` exception in admission.
Networking's CI dependency-boundary check and workspace unused-dependency checks pass.
The dependency audit found no vulnerabilities in 301 locked packages, with the existing crates.io index-refresh lock warning.

Networking now declares the existing `async-trait` package. No external version, generated YANG artifact, protobuf contract, or native transport changed.
Windows, live SONiC, and the external-server matrix did not run for this retry-only increment.
The ordinary workspace suite still runs the local prepared-source and native handshake fixtures.