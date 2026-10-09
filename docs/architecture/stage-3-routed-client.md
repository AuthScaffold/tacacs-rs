# Stage 3: Routed Client and Owned Runtime

## Status

Stage 3 is in progress. Stage 2's canonical configuration and prepared-endpoint boundaries remain in place.
The first increment transfers retry decisions and execution into networking and makes ordered retries conservative for every operation.
The second increment captures routing inputs before admission and retains them across retries and proxy continuations.
The third increment extracts an agent-free routed client into networking and migrates both ingress paths.
S3-04 now provides bounded shared admission and canonical total request deadlines across both ingress paths.
Commit `41d29d5` completes ingress-task and downstream delivery bounds. S3-04 is complete.
S3-05 now provides terminal client shutdown for shared drivers, dedicated transports, and in-progress setup.
Commit `468fdcb` integrates routed retirement and embedded service shutdown under one budget. S3-05 is complete.
S3-06 remains open for the final integration gates and Stage 3 closure.

Fix nearby issues within the current increment when practical. Add a new item only when the work needs a distinct implementation step.
Keep completed items visible with verification evidence. Preserve canonical YANG and do not retain obsolete APIs only for compatibility.

## Checklist

- [x] S3-01: Move the retry plan and executor into networking and migrate both IPC and proxy callers. Commit `10058a5` stops uncertain-outcome replay for every operation and verifies bounded attempts, reply cleanup, cancellation, and adapter behavior. See [retry ownership](#retry-ownership).
- [x] S3-02: Capture one routing generation and retry policy before admission. Commit `c3b6fd3` retains endpoints, body limits, and recovery policy across reloads. IPC and TCP-backed proxy regressions verify retries and continuations. See [request generations](#request-generations).
- [x] S3-03: Extract endpoint catalogs, circuits, and reconnect serialization into networking. Commit `861a40b` migrates both ingress paths, removes duplicate agent routing state, fixes stale recovery and connection-failure races, and runs an agent-free example. See [routed client](#routed-client).
- [x] S3-04: Apply one absolute request deadline across execution and bound pending work. Commits `97db77a`, `5e0f1e3`, and `41d29d5` complete shared admission, canonical deadlines, and ingress/delivery bounds. See [admission progress](#admission-progress), [deadline progress](#deadline-progress), and [ingress bounds](#ingress-bounds).
- [x] S3-05: Complete terminal client/runtime shutdown and bounded retirement. Commits `d93c584`, `1928c29`, and `d4f6c6c` establish task ownership and terminal client shutdown. Commit `468fdcb` integrates routed retirement and service shutdown. See [shared-driver progress](#shared-driver-progress), [terminal client progress](#terminal-client-progress), and [integrated retirement](#integrated-retirement).
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

Explicit runtime ownership remains open above.

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
S3-04's ingress bounds and S3-05's public close/join and bounded retirement are complete.

## Admission Progress

S3-04 is split at the admission boundary because end-to-end deadline policy affects server timeouts, retries, and proxy conversations together.
The existing server timeout does not define a distinct total request budget. This increment does not silently reinterpret it.
Commit `97db77a` completes the admission part without changing transport or replay behavior.

- [x] Shared bounded admission: networking owns FIFO waiters, active capacity, live-limit updates, and cancellation-safe release. Both service paths use the same operation pools across generations.
- [x] Canonical deadline policy and propagation: commit `5e0f1e3` adds the generated total-budget leaf, captures it before admission, and bounds binding, exchanges, retries, and continuations. Tests cover expiry before and after transmission, policy reload, and cancellation cleanup.
- [x] Ingress bounds: commit `41d29d5` reserves capacity before proxy session-task creation, bounds accepted transports and HTTP/2 streams, and retains proxy admission through physical reply delivery. Flood, expiry, and capacity-release tests pass.

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
Commit `41d29d5` completes the remaining ingress-task and downstream delivery bounds described below.

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
At `5e0f1e3`, it bounded proxy reply queueing but not physical delivery. Commit `41d29d5` closes that gap and bounds listener transports.
The deadline increment alone did not complete S3-04. Forced retirement and public close/join remain separate S3-05 obligations.

## Ingress Bounds

Commit `41d29d5` completes S3-04 without adding parallel admission or routing state.
Networking's `AdmissionPool::reserve` synchronously returns an `AdmissionReservation` that owns an active slot or bounded pending entry.
Its `wait` and `wait_until` methods convert that reservation into an active permit without renewing its deadline.
Dropping an unpolled reservation, cancelled waiter, or active permit releases capacity through the same pool.

The proxy captures routing inputs and reserves capacity in the connection reader before it creates a session task.
Overload and size rejection produce a local error in the bounded reply queue, without creating a session task or starting upstream I/O.
A full reply queue closes the connection. A full or closed continuation queue also closes the connection instead of blocking other sessions.
Completed session tasks are reaped before more packets are dispatched. Completed connection tasks are reaped during normal listener operation, not only during shutdown.

Each proxy reply carries its request deadline and a delivery acknowledgement.
The session keeps its admission permit until the connection writer acknowledges the physical write.
Expired queued replies emit no bytes. A partial write that expires closes the connection because resuming a partial frame is not safe.
The writer is owned by the connection future rather than detached in a spawned task.
Normal connection exits cancel and join session tasks. Dropping the connection also drops the writer and aborts its session task set.
This does not replace S3-05's explicit runtime close/join contract.

Canonical `local-services` now defines startup ingress controls:

| Leaf | Default | Scope |
| --- | --- | --- |
| `max-connections` | 64 | Maximum served connections per enabled listener |
| `max-client-api-streams` | 64 | Maximum HTTP/2 streams and concurrent handlers per client API connection |
| `connection-lifetime-seconds` | 300 | Maximum served transport lifetime, including setup, requests, and physical reply delivery |

All three values must be nonzero. Changes require restart, like other listener settings.
The proxy pauses accept at capacity and applies the lifetime to each connection task.
The client API reserves a connection permit before accept. Its transport owns that permit and separate read/write expiry timers.
Tonic enforces the configured HTTP/2 stream and handler limits. TACACS+ IPC request and response protobuf messages have a 128 KiB ceiling.
Unaccepted connections remain in the operating system's bounded listen backlog; no unbounded application accept queue is created.
The limits are global to each listener, not separate per peer. These are capacity bounds, not per-peer fairness guarantees.

Proxy physical replies use the request deadline. Client API physical delivery uses the connection lifetime, independently of upstream operation deadlines.
Connection lifetime expiry can interrupt active requests; clients must reconnect. The [operator guide](../tacacsrs-agentd.md#canonical-listener-resource) documents this behavior.

The stalled proxy writer regression failed before deadline enforcement.
Further tests verify pre-spawn flood rejection, final-reply capacity retention, zero-byte expired replies, cancelled reservations, and FIFO capacity recovery.
IPC transport tests verify accept capacity and both read/write expiry. The proxy listener test verifies capacity reuse after connection expiry and task reaping.
All prior deadline, reload, safe-retry, and source-preservation regressions remain passing.

## Shared-Driver Progress

Commit `d93c584` replaces detached multiplexed driver tasks with explicit task owners.
The driver holds its I/O runtime state, not the connection handle that owns its join handle. This avoids a self-retaining task cycle.
Active shared sessions retain the connection owner so ordinary cache retirement does not cancel sessions that can still finish.
Final driver-owner drop requests cancellation. An explicit join, not drop alone, confirms task completion.

`DriverTask` retains its join handle across cancelled join futures.
A shorter concurrent join can abort a driver while another caller waits with a longer deadline.
At expiry, the owner aborts the driver and awaits task cleanup before returning.
Driver cleanup disables new sessions, closes reply routes, and wakes active readers even if the task is cancelled before its first poll.
Completed joins are repeatable. No extra cleanup task is spawned.

`TacacsClient::retire_shared_until(deadline)` drains and joins the cached and retained retired shared drivers.
The cache retains retiring handles so cancelling this call does not lose the completion path.
One absolute deadline applies to all tracked drivers; expiry forces remaining driver cleanup.
Retirement advances a cache generation, which prevents an older dedicated negotiation from restoring the shared cache after retirement.
This method does not close the client or stop dedicated sessions. Callers must quiesce new operations when using it as a shutdown step.

Commit `1928c29` fixes a related dedicated-session deadlock found during the ownership review.
The packet reader held the transport mutex while invalid-header handling tried to acquire the same mutex again.
The regression failed before the fix. The reader now removes the invalid transport through its existing guard, and the peer receives EOF promptly.
This local correction does not complete dedicated-session shutdown ownership.

S3-05 completed these acceptance steps:

- [x] Own shared driver tasks, support bounded explicit drain/join, retain handles across cancelled waits, and reject stale promotion. Verify idle, active, forced, repeated, and final-owner cleanup.
- [x] Add terminal client shutdown covering dedicated transports, in-progress connection setup, and shared sessions. Commit `d4f6c6c` rejects new work and verifies socket release even when callers retain idle conversations or leave reads and setup futures unpolled.
- [x] Integrate close/join with routed catalog retirement and agent shutdown. Commit `468fdcb` applies an explicit cutoff to removed endpoints and one deadline to service drain and historical endpoint cleanup. Native tests cover repeated catalogs, setup cancellation, embedded shutdown, and cancellation of serving.

Tests cover graceful active-session drain, forced shutdown with an active reader, final-owner abort, concurrent deadlines, and cancelled retirement retried across eight cycles.
Native peer EOF checks prove transport release. The late-promotion test verifies that an old negotiation cannot repopulate a retired cache.
The shared-driver increment alone did not provide terminal client shutdown. The following increments add terminal client and embedded-service integration.

## Terminal Client Progress

Commit `d4f6c6c` adds terminal lifecycle ownership to `TacacsClient`.
`close()` permanently rejects new operations, cancels in-progress connection setup, and prevents late single-connect promotion.
`close_and_join(deadline)` also drains existing transports, forces remaining sockets closed at expiry, and joins owned setup and shared-driver tasks.
Closing is idempotent. A closed client cannot reopen.
Cancelling a join leaves the client closed and retains its cleanup ownership, so another caller can retry the join.

Managed transport controls own the actual native read and write halves.
Their locks exist only during an I/O poll, not while the caller waits for readiness.
Shutdown can therefore drop the socket even when a dedicated-session future still holds its outer session mutex and is no longer polled.
Forced closure wakes registered I/O waiters. Retained handles subsequently return a closed-transport error.
An activity counter records completed native transport closure, including concurrent close callers and handles retained after closure.

Connection setup now runs in owned tasks that report their result through a one-shot channel.
The client retains their driver handles and uses weak lifecycle references inside the tasks to avoid self-retaining cycles.
Caller cancellation aborts setup. Terminal close cancels and joins setup without requiring that caller to poll its future again.
Transport registration and close use the same state lock, and session publication rechecks terminal state.
Requests cannot publish new transports or sessions after terminal close wins.

Dropping the final client requests immediate cleanup and closes its registered sockets.
Keeping a `ClientConversation` does not keep the originating client alive; callers must retain the client while using its conversations.
Drop also seals the shared cache so an old negotiation cannot start a new driver after client destruction.
Use `close_and_join` when the host needs confirmation that owned tasks and sockets are finished.

`retire_shared_until` remains a nonterminal shared-cache operation. It does not replace terminal client shutdown.
At `d4f6c6c`, agent and routed connector interfaces did not yet use terminal close/join.
Commit `468fdcb` completes that integration, as described below.

Native tests cover retained idle conversations, parked dedicated reads, stalled TLS setup, cancelled joins, shorter concurrent deadlines, and graceful dedicated/shared drain.
Peer EOF verifies socket release before the retained caller future resumes. Post-close requests fail before request transmission.
Another test verifies that final client drop prevents an old negotiation from publishing a shared driver.

## Integrated Retirement

Commit `468fdcb` extends `EndpointConnector` and the agent connection contract with terminal `close` and deadline-bound `close_and_join` methods.
The native implementation delegates to `TacacsClient`. Test connectors must implement the same lifecycle contract rather than silently skipping shutdown.
Routed endpoint owners retain setup tasks and connection owners until cleanup completes.
Unused connections are closed and joined before later setup releases their ownership.

Related catalogs share one routing runtime. This registry includes endpoints removed by earlier replacements, even when old request snapshots still hold them.
`RoutedClient::close_and_join` rejects new work throughout that family and joins historical and current resources under one absolute deadline.
Late setup results cannot publish into retired endpoints. Parked bind futures do not prevent owned setup cancellation.
The connector contract requires deadline-respecting cleanup and cancellation-safe ownership; a custom connector must uphold those requirements.

`retire_replaced_until` schedules terminal retirement without delaying publication.
Captured old catalogs remain usable before the cutoff. At expiry, the owner rejects bindings, cancels setup, closes connections, and joins their tasks.
Unchanged identities remain active. Rescheduling cannot extend a previous cutoff.
The manager schedules this cutoff in the publication transition and serializes server reloads.
The cutoff uses the maximum canonical operation request budget captured when preparation starts. All endpoints removed by that update share it.
This is a derived runtime deadline, not a second configuration model or a new default.

Admission now has a terminal closed state. Closure wakes pending waiters, rejects unpolled reservations, and cannot be reversed by a limit update.
Manager closure also prevents later server publication or captured-route binding. Runtime-policy updates after closure do not reopen it.
Closed-service admission errors are not retriable.

`TacacsClientService::serve_until(stop_future)` lets an embedded host run and stop listeners without process signal handlers.
The existing `serve()` method wraps the same path with an owned signal future, rather than a detached monitor task.
Shutdown withdraws serving health and closes admission and new upstream work.
One deadline, derived from the maximum current operation budget, covers listener drain and every historical/current endpoint join.
Remaining listener tasks are cancelled and joined at expiry. Native clients then force remaining transport cleanup under that same deadline.
A successfully stopped service rejects reload and cannot be served again.

Cancellation of a serving future drops an owned guard that schedules immediate upstream retirement.
The host can call the service's `close_and_join(deadline)` to confirm upstream cleanup after cancellation or without starting listeners.
An active listener run must be stopped through its `serve_until` trigger and awaited for full listener completion.
The IPC health bridge now runs inside its listener future. Listener-owned transport guards close accepted Unix sockets even when Tonic retains its connection objects.
This closes native sockets without relying on the connection-lifetime fallback or process exit.

Tests verify a removed endpoint closes at its cutoff without closing its replacement, and old catalogs cannot bind after retirement.
A four-generation native test retains old conversations and verifies peer EOF after family-wide join.
Further tests cover parked setup cancellation, closed admission, rejected publication, embedded shutdown, restart rejection, and cancelled serving futures.
The earlier single-poll tests now use request-entry notifications because routed setup runs in owned tasks.
No new standalone work item was needed. S3-06 retains the planned final integration review and gates.

## Connector Boundary Investigation

On 2026-10-09, the proposed generic dynamic-connector consolidation failed the Rust `Send` checks in agent service futures.
The experiment was restored to commit `7d616eb` before further investigation. The concrete `ServiceConnector` boundary remains unchanged and working.
All 118 agent library tests and 12 routed-client tests passed after restoration.
This investigation does not complete S3-06 or introduce a new production connector API.

The isolated [cross-crate tests](../../libraries/tacacsrs_networking/tests/connector_boundary.rs) compare four connector shapes:

| Factory | Connection | Generic service implementation |
| --- | --- | --- |
| Concrete | Concrete | Pass |
| Concrete | Erased | Pass |
| Generic wrapper around a dynamic factory | Concrete | Pass |
| Generic wrapper around a dynamic factory | Erased | Pass |

These tests check `Send` for lookup, bind, replacement, and shutdown futures.
They also run binding and close/join through a generic service implementation erased as an outer service trait object.
The generic networking core does not inherently reject dynamic connectors or erased connections.

The failure occurs when a nongeneric service implementation specializes its field to the generic wrapper with an erased associated connection type.
Boxing that service's async future produces a higher-ranked lifetime/`Send` proof error when it awaits the generic engine's lookup.
The direct lookup future still passes a `Send` assertion. Changing the service implementation to remain generic makes the boxed future compile.
Explicit `Send + Sync` and object-lifetime bounds alone did not fix the original experiment.

The [standalone fixture](../../libraries/tacacsrs_networking/tests/fixtures/connector_send.rs) reproduces the failure with only standard-library types.
It needs no `async-trait`, Tokio, networking implementation, or agent code.
It contains a generic engine, stored associated connection data, an erased connection type, and an explicitly boxed `Send` future.
This isolates a Rust higher-ranked lifetime/proof limitation in the proposed shape rather than a runtime networking failure or an `async-trait`-specific problem.
It is not a general prohibition on type erasure, and no upstream compiler issue number is assigned here.

| Installed compiler | Specialized erased adapter | Generic adapter |
| --- | --- | --- |
| Rust 1.88.0, workspace MSRV | Expected compile failure: `Send` is not general enough | Pass |
| Rust 1.98.1 stable | Same compile failure | Pass |
| Rust 1.100.0-nightly, 2026-09-24 | Higher-ranked lifetime coercion failure | Pass |

The fixture is outside Cargo's automatic integration-test targets because its default variant intentionally does not compile.
Its failure is diagnostic evidence, not a permanent requirement that future compilers reject it.
Run its two variants from the workspace root:

```bash
# Expected to fail on the recorded compilers.
rustc --edition=2021 libraries/tacacsrs_networking/tests/fixtures/connector_send.rs --emit=metadata -o /tmp/connector-specialized.rmeta

# Expected to compile, including on the MSRV.
rustc --edition=2021 --cfg generic_adapter libraries/tacacsrs_networking/tests/fixtures/connector_send.rs --emit=metadata -o /tmp/connector-generic.rmeta

cargo test -p tacacsrs-networking --test connector_boundary --locked
```

The selected direction is a generic networking core and generic service/router implementations with a concrete production connector and concrete production connection type.
Test connectors instantiate those same generic implementations. Optional type erasure belongs at the outer service boundary, after the generic implementation establishes `Send`.
The passing matrix also permits dynamic test factories through that generic adapter; it does not require them in production.
The next implementation increment must propagate the connector parameter through the agent's request and service owners before removing their concrete adapter.
Do not replace the working adapter with the failed specialized dynamic shape or raise the MSRV as a workaround.

The investigation changed tests and documentation only. Production code, dependencies, toolchain settings, and runtime behavior remain at the restored boundary.

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

### S3-04 Closure

All 114 agent library tests pass. Networking passes 139 library tests, with two existing ignored tests; configuration passes 73 library tests.
The full all-features workspace suite, strict workspace Clippy, nightly formatting, workspace build, and warnings-as-errors rustdoc pass.
All 13 generator tests, deterministic regeneration, and all nine independent native peer cases pass.
The documentation book and whitespace checks pass. No dependency version, lockfile, protobuf schema, or native credential policy changed.
The generated Rust SHA-256 value is `ca5afc9ae88960ebdf10f1d1cfe082a555b51c162fad908abb1664ca9d6b78d7`.
The known Rust Analyzer `async-trait` diagnostics remain in test support; Cargo does not reproduce them.
Windows, live SONiC, and Miri were not run for this increment.

### S3-05 Shared-Driver Increment

The driver extraction passes the complete workspace suite, strict workspace Clippy, nightly formatting, workspace build, and warnings-as-errors rustdoc.
All nine independent native peer cases pass. Agent library coverage remains 114 passing tests.
After the dedicated cleanup correction, networking passes 149 library tests, with two existing ignored tests, and strict package Clippy.
The invalid-header regression failed before that correction and now verifies immediate error and peer EOF.
The documentation book and whitespace checks pass. The touched networking files have no editor diagnostics.
No dependency, lockfile, generated YANG artifact, protobuf schema, or native credential policy changed.
Windows, live SONiC, and Miri were not run for this increment.

### S3-05 Terminal Client Increment

The full workspace suite, strict workspace Clippy, nightly formatting, workspace build, and warnings-as-errors rustdoc pass.
All nine independent native peer cases pass with managed transports and owned setup tasks.
The final drop-publication correction passes all 157 networking library tests, with two existing ignored tests, and strict package Clippy.
Agent coverage remains 114 passing library tests. The documentation book and whitespace checks pass.
The touched networking files have no editor diagnostics. No dependency, lockfile, generated YANG artifact, protobuf schema, or native credential policy changed.
Windows, live SONiC, and Miri were not run for this increment.

### S3-05 Closure

All 118 agent library tests pass. Networking passes 161 library tests, with two existing ignored tests, including 12 routed-client tests.
The full all-features workspace suite, strict workspace Clippy, nightly formatting, workspace build, and warnings-as-errors rustdoc pass.
All nine independent native peer cases pass. The final serving-cancellation regression and strict package Clippy also pass.
The documentation book and whitespace checks pass. No dependency, lockfile, generated YANG artifact, protobuf schema, or native credential policy changed.
The known editor-only `async-trait` diagnostics remain in agent test support; Cargo does not reproduce them.
Windows, live SONiC, and Miri were not run for this increment.