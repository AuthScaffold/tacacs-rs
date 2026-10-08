# Stage 3: Routed Client and Owned Runtime

## Status

Stage 3 is in progress. Stage 2's canonical configuration and prepared-endpoint boundaries remain in place.
The first increment transfers retry decisions and execution into networking and makes ordered retries conservative for every operation.
The second increment captures routing inputs before admission and retains them across retries and proxy continuations.
The third increment extracts an agent-free routed client into networking and migrates both ingress paths.
S3-04 now provides bounded shared admission and canonical total request deadlines across both ingress paths.
Ingress-task and downstream delivery bounds remain open within S3-04. A public close/join API remains S3-05 work.

Fix nearby issues within the current increment when practical. Add a new item only when the work needs a distinct implementation step.
Keep completed items visible with verification evidence. Preserve canonical YANG and do not retain obsolete APIs only for compatibility.

## Checklist

- [x] S3-01: Move the retry plan and executor into networking and migrate both IPC and proxy callers. Commit `10058a5` stops uncertain-outcome replay for every operation and verifies bounded attempts, reply cleanup, cancellation, and adapter behavior. See [retry ownership](#retry-ownership).
- [x] S3-02: Capture one routing generation and retry policy before admission. Commit `c3b6fd3` retains endpoints, body limits, and recovery policy across reloads. IPC and TCP-backed proxy regressions verify retries and continuations. See [request generations](#request-generations).
- [x] S3-03: Extract endpoint catalogs, circuits, and reconnect serialization into networking. Commit `861a40b` migrates both ingress paths, removes duplicate agent routing state, fixes stale recovery and connection-failure races, and runs an agent-free example. See [routed client](#routed-client).
- [ ] S3-04: Apply one absolute request deadline across execution and bound pending work. Commit `97db77a` completes shared bounded admission; `5e0f1e3` completes canonical deadline policy and propagation. Ingress-task and downstream delivery bounds remain open. See [admission progress](#admission-progress) and [deadline progress](#deadline-progress).
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

Ingress bounds and explicit runtime ownership remain open above.

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

## Routed Client

Commit `861a40b` adds `tacacsrs_networking::routed` with `RoutedClient`, `Endpoint`, `BoundEndpoint`, `EndpointConnector`, `NativeConnector`, and `OperationKind`.
Networking owns ordered eligible catalogs, operation cursors, circuits, connection caches, reconnect serialization, and binding outcome handling.
Its inputs contain prepared endpoints and explicit operation eligibility. No generated configuration, credential provider, IPC, listener, or health publisher enters this boundary.
`NativeConnector` creates adaptive `TacacsClient` connections. A host can supply another connector for testing or exchange adaptation.
Bindings expose their selected endpoint and connection. They record outcomes against the catalog and connection that the request used.
The existing neutral retry executor and transmission-state classification remain unchanged.

Cloning a routed client retains its catalog. `with_endpoints` creates a replacement without changing existing clients or requests.
Cloning an `Endpoint` preserves its cache identity; a newly constructed endpoint gets independent connection and circuit state.
The agent compares materialized source values before it reuses an endpoint identity. Credential changes therefore produce fresh identities and caches.
Replacement catalogs retain eligible active-server preference by endpoint name.
After publication, `retire_replaced` drains caches for removed identities. Existing bindings and captured clients retain their allowed work.
The S3-02 cache-owner cleanup still handles connections opened by old requests after reload.

The agent now pairs source metadata with networking endpoints in `PreparedServer`.
Its manager retains configuration preparation, policy publication, admission, proxy settings, and generation-aware health.
`ServiceConnector` adapts existing exchange interfaces without retaining routing state.
Both IPC and proxy bindings delegate to the same networking client.
The old agent circuit, operation identity, routing implementation, and server-cache modules are removed rather than copied behind compatibility wrappers.
The empty-catalog waiting response remains in the agent because it describes service configuration state.

Two local concurrency fixes accompany the extraction:

- Recovery permits carry a circuit revision. Stale success, failure, and cancellation cannot resolve a newer failure or release a newer trial. Both new regressions failed before the correction.
- Cached handles retain their connection generation as one value. Failed connection attempts also retain their generation, so delayed failure handling cannot evict a replacement connection.

Recovery success and failure serialize through the endpoint reconnect lock before changing the preferred route.
Direct networking tests cover reconnect sharing, cancellation, eligibility, identity reuse, catalog replacement, and stale failure isolation.
The existing agent tests continue to cover service policy, source reload, health, and proxy continuations.

The [routed accounting example](../../libraries/tacacsrs_networking/examples/routed_accounting.rs) starts two local TCP peers and uses only networking and protocol APIs.
The primary returns a valid accounting `ERROR`; the conservative retry executor completes the request on the backup.
The example needs no agent process or configuration source:

```bash
cargo run -p tacacsrs-networking --example routed_accounting --locked --quiet
```

It prints `Accounting accepted by backup; no agent or configuration source was required.`
The example has a five-second outer test bound. Commit `5e0f1e3` also gives its accounting request one two-second deadline across binding and retries.
S3-04 owns the remaining ingress bounds. S3-05 owns public close/join and bounded retirement.

## Admission Progress

S3-04 is split at the admission boundary because end-to-end deadline policy affects server timeouts, retries, and proxy conversations together.
The existing server timeout does not define a distinct total request budget. This increment does not silently reinterpret it.
Commit `97db77a` completes the admission part without changing transport or replay behavior.

- [x] Shared bounded admission: networking owns FIFO waiters, active capacity, live-limit updates, and cancellation-safe release. Both service paths use the same operation pools across generations.
- [x] Canonical deadline policy and propagation: commit `5e0f1e3` adds the generated total-budget leaf, captures it before admission, and bounds binding, exchanges, retries, and continuations. Tests cover expiry before and after transmission, policy reload, and cancellation cleanup.
- [ ] Ingress bounds: limit work before session-task creation and during slow reply delivery. Verify that admission rejection cannot leave unbounded tasks outside the admission pool.

`tacacsrs_networking::admission::AdmissionPool` is reusable without the agent.
The agent derives both active and pending limits from the operation's canonical `max-concurrent-requests` value.
For limit `C`, the pool permits at most `C` active requests and accepts at most `C` pending waiters.
New arrivals cannot pass existing waiters. Once the queue is full, admission returns an immediate overload error without upstream I/O.
IPC reports overload as retriable. The proxy uses its existing local admission-error reply path.

Lowering the limit retains already-active requests and existing waiters, even if either count exceeds the new limit.
It accepts no extra waiters until the pending count is below the new limit.
It admits no waiting request until the active count is below that limit.
Increasing the limit wakes waiters. Pool clones and old routing generations never create independent capacity.

A single short-held mutex protects the live limit, active count, and FIFO queue.
This replaces the semaphore and separate permit-debt atomics, whose reduction and release steps could interleave.
Cancelling or expiring a waiter removes its queue entry. Dropping an active permit releases capacity synchronously.
The pool starts no cleanup task and observes notifications without holding its state lock across an await.
An empty eligible catalog keeps the agent's existing waiting-for-configuration response before capacity allocation.

Commit `97db77a` introduced `RequestDeadline` as one absolute expiry. Copying it does not extend its budget.
That increment used it only for admission. Commit `5e0f1e3` extends it through typed and proxy execution, as described below.
The primitive rejects expired work before polling it; direct tests verify that sequential stages share the same budget.
S3-04 remains unchecked because ingress-task and downstream delivery bounds are not complete.

The overload regression failed before the implementation: an excess request waited instead of returning an error.
Direct tests cover FIFO order, shared clones, cancellation, expiry, zero capacity, and limit reductions with retained waiters.
The service test holds an IPC request and a proxy waiter, verifies retriable overload without extra upstream I/O, and then cancels both.
The next IPC request succeeds, which verifies that both active and pending capacity were released.

## Deadline Progress

Commit `5e0f1e3` adds `request-timeout-seconds` to the canonical operation-limit grouping.
The generated default is 30 seconds for authentication, authorization, and accounting. Zero is rejected.
This field is a total request budget, separate from each server's timeout.
The [operator guide](../tacacsrs-agentd.md#runtime-policy) describes configuration and the interactive-authentication implications.
Generated Rust, the expanded tree, and the generation manifest are updated together. Pinned upstream modules remain unchanged.

`RoutingLease` captures one absolute deadline with its policy and endpoint snapshot before admission.
Admission retains the selected-server wait cap but cannot exceed the remaining total budget.
Binding runs inside the captured deadline, which bounds reconnect waits and asynchronous connection, DNS, TLS, and preflight work.
An expired bind does not mark servers unavailable because local budget exhaustion is not proof of server failure.
Typed attempts use the earlier of the total deadline and the selected server timeout.
Retries and policy reloads cannot renew an existing request's budget.

`TacacsClient::execute_classified_until` bounds session establishment and the fixed exchange.
An already-expired request opens no connection. Expiry during native session or TLS setup is `NotSent`.
After transmission starts, an expired exchange has `OutcomeUnknown` and cannot replay automatically.
Outcome reporting and session completion use the remaining budget. Cancellation still releases routes and permits through their existing drop ownership.

The proxy captures the deadline at its first packet and bounds the complete conversation future.
This includes admission, first-packet retries, upstream session setup, continuation waits, and reply queueing.
Server timeouts can shorten round trips but cannot extend the conversation deadline.
Expiry drops the conversation and releases admission capacity, even while it waits for a downstream continuation.

The typed regression spends two seconds in admission and two seconds on a primary `ERROR` response.
The backup receives only the last second of a five-second budget, even after policy reload raises the configured budget to 30 seconds.
Further tests cover a stalled TLS handshake, a sent request with no reply, connection-setup cancellation, and proxy continuation expiry after reload.
Native peer EOF checks verify transport release. Follow-up requests verify admission and reconnect-lock release.

The deadline starts when the request is captured, not when a listener accepts the connection.
It bounds proxy reply queueing, not physical downstream delivery after the session hands a reply to the connection writer.
The existing ingress-bounds item remains responsible for task creation before capture and slow downstream writers.
This increment does not claim completion of S3-04, forced retirement, or public close/join ownership.

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

### S3-03

All nine direct routed-client tests pass. Networking passes 131 library tests, with two existing ignored tests.
All 103 agent library tests pass. The two circuit tests moved from the agent into networking.
The full all-features workspace suite, strict workspace Clippy, workspace build, nightly formatting, and warnings-as-errors rustdoc pass.
The agent-free example and all nine independent `tac_plus-ng` runner cases pass.
The documentation book, editor diagnostics, and whitespace checks pass.

CI's networking dependency guard confirms no configuration, provider, IPC, agent, or SONiC dependency in normal builds.
Workspace unused-dependency checks pass. The audit found no vulnerabilities in 301 locked packages, with the known crates.io index-lock warning.
Networking enables Tokio `test-util` only for development tests. No external version, lockfile, generated YANG artifact, protobuf contract, or native credential policy changed.
Windows, live SONiC, and Miri were not run for this increment.

### S3-04 Admission Increment

All four direct admission tests and the absolute-deadline primitive test pass.
Networking passes 136 library tests, with two existing ignored tests. All 105 agent library tests pass.
The complete all-features workspace suite, strict workspace Clippy, nightly formatting, workspace build, and warnings-as-errors rustdoc pass.
The documentation book, editor diagnostics, and whitespace checks pass.

No dependency, lockfile, generated YANG artifact, protobuf contract, or native transport changed.
The external-server matrix, Windows, live SONiC, and Miri were not rerun for this admission-only increment.
The ordinary workspace suite still runs local transport and prepared-source fixtures.

### S3-04 Deadline Increment

All 108 agent library tests pass. Networking passes 138 library tests, with two existing ignored tests.
The full all-features workspace suite, strict workspace Clippy, nightly formatting, workspace build, and warnings-as-errors rustdoc pass.
The deadline-aware agent-free example and all nine independent `tac_plus-ng` runner cases pass.
All 13 generator tests and deterministic regeneration pass against the updated manifest.
The documentation book and whitespace checks pass.
Rust Analyzer reports `async-trait` type errors in `test_support/fake_upstream.rs`, but the compiler does not reproduce them.
A separate all-features test-target check passes. No source workaround was added for these editor-only diagnostics.

The generated Rust SHA-256 value is `03d3bccb1ea63c55056a873d3887c9224f0a7eaf4de23eaaadb87159fbf8f84e`.
No dependency, lockfile, protobuf contract, or native credential policy changed.
Windows, live SONiC, and Miri were not run for this increment.