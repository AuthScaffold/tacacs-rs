# Stage 3: Routed Client and Owned Runtime

## Status

Stage 3 is in progress. Stage 2's canonical configuration and prepared-endpoint boundaries remain in place.
The first increment transfers retry decisions and execution into networking and makes ordered retries conservative for every operation.
The second increment captures routing inputs before admission and retains them across retries and proxy continuations.
It does not yet provide an agent-free routed client or a public close/join API.

Fix nearby issues within the current increment when practical. Add a new item only when the work needs a distinct implementation step.
Keep completed items visible with verification evidence. Preserve canonical YANG and do not retain obsolete APIs only for compatibility.

## Checklist

- [x] S3-01: Move the retry plan and executor into networking and migrate both IPC and proxy callers. Commit `10058a5` stops uncertain-outcome replay for every operation and verifies bounded attempts, reply cleanup, cancellation, and adapter behavior. See [retry ownership](#retry-ownership).
- [x] S3-02: Capture one routing generation and retry policy before admission. Commit `c3b6fd3` retains endpoints, body limits, and recovery policy across reloads. IPC and TCP-backed proxy regressions verify retries and continuations. See [request generations](#request-generations).
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

Absolute deadlines, routing extraction, and explicit runtime ownership remain open above.

## Request Generations

Commit `c3b6fd3` adds `RequestRouting` and `RoutingLease` at the existing operation router and server-set owner.
IPC operations capture their lease before admission waits. The proxy captures its lease when it receives the first packet.
Each lease retains one published snapshot with its generation ID, ordered eligible servers, prepared endpoint material, and runtime policy.
The retry budget, body-size limit, and recovery interval come from that snapshot. Later attempts cannot read a replacement snapshot.
Circuit observations can still change endpoint selection within the captured set.
The old latest-snapshot admission, binding, size-validation, and retry-plan entry points are removed.

Concurrency remains global across generations. A policy update changes the shared admission pool without replacing it.
Body-size validation is separate from that pool and uses the request's captured policy.
An already-waiting request retains its original size limit and endpoints after reload.
Reducing concurrency does not give new leases a second pool or release capacity still held by older work.
Proxy continuations retain the same size policy and remain pinned to their upstream session.

Availability observations now carry the captured server-set epoch, including retries that start after reload.
Old attempts cannot mark replacement endpoints available or unavailable.
Server publication resets that epoch while holding the publication lock.
Policy updates retain the current server snapshot under the same lock instead of copying a separately read snapshot.

The lease lifetime check exposed an existing shared-cache leak.
An old request can open a retained endpoint after reload, but its final client drop previously left the multiplexed driver active.
`SharedConnectionCache` now signals retirement when its last client or promotion owner drops.
Existing sessions can finish. Late promotion retains cache ownership and retires the connection when that ownership ends.
This fix adds no cleanup task and does not mutate prepared credentials or authoritative configuration.
It does not implement public close/join, forced-retirement bounds, or absolute deadlines. S3-04 and S3-05 retain those obligations.

The forced IPC reload test failed before the lease fix: the retry selected the replacement instead of the original backup.
Its health assertion also failed before epoch propagation. The final-owner transport test failed before cache retirement.
Further tests cover admission waits, capacity reductions, captured recovery timing, and active-session retirement.
The TCP-backed proxy test reloads after the first request, retries the original backup, and completes a continuation under the old size limit.
Its next independent request uses the replacement endpoint.

## Verification

### S3-01

The first increment passes all eleven networking retry tests, the public retry example, and the complete workspace suite.
Workspace build, nightly formatting, warnings-as-errors rustdoc, and the documentation book pass.
This increment used the previously recorded `comparison_chain` exception in admission for workspace Clippy.
Networking's CI dependency-boundary check and workspace unused-dependency checks pass.
The dependency audit found no vulnerabilities in 301 locked packages, with the existing crates.io index-refresh lock warning.

Networking now declares the existing `async-trait` package. No external version, generated YANG artifact, protobuf contract, or native transport changed.
Windows, live SONiC, and the external-server matrix did not run for this retry-only increment.
The ordinary workspace suite still runs the local prepared-source and native handshake fixtures.

### S3-02

All 105 agent library tests pass. Networking passes 122 library tests, with two existing ignored tests.
The complete all-features workspace suite, workspace build, nightly formatting, and warnings-as-errors rustdoc pass.
Strict workspace Clippy passes without exceptions. The admission update now uses a comparison match in the touched function.
The documentation book and whitespace checks pass.

All nine independent `tac_plus-ng` runner cases pass: TCP, certificate TLS, mTLS, required-client-certificate rejection, and PSK variants.
The package suites also cover final-owner cleanup for idle connections, active sessions, and late single-connect promotion.
No dependency version, generated YANG artifact, protobuf contract, or native credential policy changed.
Windows, live SONiC, and Miri were not run for this increment.