# Stage 4: Configuration Controller and Lifecycle

## Status

Stage 4 is in progress as of 2026-10-12. Commit `6a11a83` completes the first increment.
Commit `1cca6a4` moves configuration recovery and materialization coordination into the agent.
Commit `75aac8b` adds canonical observation sessions and file watcher ownership. The supervisor now uses observations for startup and recovery.
Commit `8381d4f` completes S4-02 with owned SONiC observations and removal of transitional APIs.
Commit `899ca75` starts S4-03 with atomic runtime and applied-health publication.
Commit `a3f1727` adds active materialization bookkeeping to the same commit and closes its cancellation window.
Canonical YANG remains authoritative. Prepared runtime policy remains a derived value.
This increment does not complete the shared configuration controller or credential lifecycle.

Fix nearby findings within each increment when practical. Keep completed items and their verification evidence.
The startup race and closed-runtime publication fix belong to S4-01, not separate work items.

## Checklist

- [x] S4-01: Own canonical policy observation in configuration and policy supervision in the agent. Commit `6a11a83` removes daemon policy algorithms and closes the startup race. See [policy observation](#policy-observation).
- [x] S4-02: Commit `1cca6a4` moves recovery and materialization into the agent. Commit `75aac8b` owns file observations and migrates supervision. Commit `8381d4f` owns SONiC Redis and credential streams and removes transitional APIs. Native cleanup, cancellation, and recovery tests pass. See [S4-02 closure](#s4-02-closure).
- [ ] S4-03: Commits `899ca75` and `a3f1727` publish runtime generations, applied health, and active materialization bookkeeping together while retaining global admission. Source/credential revisions and stale supervisor health updates remain open. See [materialization commit](#materialization-commit).
- [ ] S4-04: Remove process signal ownership from libraries. Apply explicit host cancellation, stale-material budgets, expiry rules, and bounded drains across controller/provider work. Verify shutdown with active and cancelled observations.
- [ ] S4-05: Add canonical client-chain inputs and the credential-provider contract. Verify complete, missing, and incorrect intermediate chains with native mTLS peers. Preserve source references during preparation.
- [ ] S4-06: Define revocation freshness and unavailable-status behavior. Obtain revocation evidence and reject revoked credentials before use. Integrate the controller/provider lifecycle with TLS verification.
- [ ] S4-07: Populate and export YANG `ServerStatistics` from runtime events. Keep read-only counters outside desired configuration. Verify counters and generation association, then run the complete Stage 4 gates.

## Policy Observation

Configuration owns [the policy source and observation contract](../../libraries/tacacsrs_config/src/source/policy.rs).
`PolicyFile::observe()` installs a directory watch before its first baseline read.
`PolicyObservation::next()` supplies complete generated `RuntimePolicy` snapshots, candidate rejections, or observation failure.
Snapshots use `Arc` ownership and remain unchanged during runtime projection.

The observation owns its native watcher. No detached async worker owns the session.
Dropping the observation releases the watcher. Cancellation during debounce or a pending read retains reconciliation state for a later call.
Tokio still owns its internal blocking filesystem operations. This contract does not claim immediate cancellation of operating-system file I/O.

The watcher callback uses a coalesced invalidation channel. It does not block on a bounded event queue.
Intermediate writes can coalesce. The next read reconciles the latest file contents, and invalidations during a read remain available for another read.
Read-access events do not trigger a reload loop. Rescan events trigger reconciliation.

Source paths become absolute, and observation resolves the parent directory before registration.
Atomic replacement of the policy file remains observable through the parent watch.
Loss or renaming of the watched directory ends observation instead of silently retaining an unobserved policy.
The host must restore a failed observation or stop. Automatic policy-source reconnection is not part of this increment.

## Agent Supervision

The [agent policy supervisor](../../libraries/tacacsrs_agent/src/runtime/policy_supervisor.rs) owns the observation and accepts an explicit stop future.
It projects generated policy values through the existing `RuntimePolicy::try_from` implementation.
Invalid source candidates or invalid projections retain the last-known-good policy and set `CandidatePolicyRejected`.
A successful publication clears that reason. The supervisor does not install process signal handlers.

Cancellation can interrupt observation, debounce, file reads, and publication lock acquisition.
Observation failure or unexpected completion returns an error to the host.
The daemon treats an unexpected policy-supervisor exit as a supervised service failure.
An unavailable source is not reported as an accepted policy.

`TacacsClientService::reload_runtime_policy()` now returns an error after terminal closure.
The manager reports publication success under its existing publication lock.
Thus, the supervisor cannot log success or clear policy rejection for a policy that the closed runtime ignored.
Policy and health updates still use separate owners. S4-03 must make generation publication and applied-health metadata one controller operation.

The daemon now keeps one observation from the initial snapshot through live supervision.
Its former policy-file and policy-supervisor modules are removed.
The daemon no longer depends directly on `notify`. Configuration enables Tokio's filesystem feature explicitly.
No dependency version, YANG schema, generated artifact, or IPC schema changes in this increment.

## Regression Evidence

The old daemon loaded policy before it registered a watcher.
A change in that interval could remain unapplied indefinitely.
The initial regression `change_between_initial_load_and_watch_start_is_reconciled` failed with `policy health transition: Elapsed(())` before correction.
Its coverage now lives with the configuration-owned observer.

Focused tests verify:

- Reconciliation of a change before observation starts, followed by atomic replacement and a canonical snapshot.
- An invalidation after the baseline read but before supervision begins.
- Cancellation during debounce, followed by a resumed read after 10,000 coalesced invalidations.
- Explicit observation failure after deletion of the watched directory.
- Policy rejection, later recovery, and unchanged absent containers in the canonical source value.
- Rejection after service closure without clearing existing rejection health.
- Cancellation of an actively waiting observation, owner cleanup, and unexpected observation completion.

## Verification

The following checks pass for commit `6a11a83`:

- Four focused configuration observation tests and three focused agent supervisor tests.
- Daemon tests: 84 unit tests and seven prepared-source integration tests. Eight opt-in native peer tests remain ignored by this command.
- The complete all-feature workspace test suite, strict all-target/all-feature Clippy, workspace build, nightly formatting, and warnings-as-errors rustdoc.
- All four CI dependency-boundary guards and the workspace unused-dependency check.
- Dependency audit: no vulnerabilities reported in 301 locked packages. Advisory loading succeeded despite the existing crates.io index-lock warning.

Nightly emits an unrelated `Atomic::fetch_update` deprecation warning in a configuration-supervisor test during `udeps`.
The stable/MSRV strict Clippy gate passes. The suggested nightly replacement is not adopted because this workspace retains Rust 1.88 compatibility.

The checkpoint book build and whitespace check validate the documentation update.
Native external-peer, Windows, and live SONiC tests were not rerun for this policy-only increment.
No protocol or TLS implementation changes. Miri was not run because nightly `rust-src` remains unavailable in this container.

## Remaining Contracts

Runtime supervision uses `ConfigDatastore::observe()`. Independent one-shot `load()` remains, but the subscription method and observation adapter are removed.
Native SONiC ownership is complete. Revision and publication coordination remain S4-03.
The agent now owns configuration recovery and materialization coordination. The daemon retains host-specific filtering and process composition.
This increment does not introduce source revision semantics or retain canonical policy history in the controller.

Credential-only updates must derive new generations from unchanged YANG snapshots with separate credential revisions.
Preparation and publication must not rewrite authoritative credential references.
Client-chain provisioning, revocation retrieval, and operational statistics retain their explicit owners and acceptance criteria above.
Current verification does not claim full RFC 9887 conformance.

## Configuration Supervision

Commit `1cca6a4` moves the existing supervisor and materialization coordinator into the agent runtime, including their regression tests.
The public `runtime::ConfigSupervisor` accepts a source, service, health publisher, and host filter.
Builder methods attach a credential resolver and optional credential notifications.
Notifications without a resolver fail before source I/O. Replacing a resolver invalidates completed initialization.

`initialize_until(stop)` supports fail-fast preparation before listener startup.
`run_until(stop)` consumes the supervisor and starts configuration and credential supervision together.
Successful initialization is retained. A cancelled initialization does not mark the supervisor initialized.
The host owns cancellation and signal handling for this API. The supervisor starts no detached worker task.

The filter contract and its no-op implementation now belong to the agent.
The daemon retains proxy self-loop filtering because it depends on host listeners and local interfaces.
The materialization coordinator still retains authoritative source values separately from filtered working copies and derived credentials.
This move does not replace those values with a competing desired-configuration model.

### Nearby Fixes

The recovery loop previously awaited a reload without observing cancellation.
The regression `cancellation_interrupts_recovery_reload` failed before the fix because the supervisor remained blocked after cancellation.
It now stops promptly and preserves the previously applied server set.
The public `run_until` also bounds pending filtering, resolution, and publication lock acquisition with the host stop future.

The daemon's fail-fast branch previously ran only configuration notifications after its initial load.
It omitted credential notifications. Both startup policies now enter the same agent lifecycle after optional initialization.
A regression verifies that credential recovery runs after fail-fast initialization without a second source load.
Another regression cancels a blocked resolver and verifies that the known-good server set remains applied.

### Verification

The following checks pass for `1cca6a4`:

- Nineteen supervisor tests, including the failed-before cancellation regression and new public lifecycle tests.
- Full all-feature workspace tests: 150 agent tests, 60 daemon tests, and seven prepared-source integration tests pass.
- Strict workspace Clippy, nightly format check, workspace build, and warnings-as-errors rustdoc.
- Four CI dependency-boundary guards, unused-dependency analysis, and dependency audit.

Dependency changes move existing dependency edges into the agent. No package version, protocol, YANG schema, or native TLS behavior changes.
Audit reports no vulnerabilities in 301 locked packages, with the existing index-lock warning.
The existing nightly `fetch_update` deprecation warning now appears in the moved agent test. Rust 1.88 remains supported.
The documentation update is checked through the book build and warnings-as-errors rustdoc.
External-peer, Windows, live SONiC, and Miri tests were not rerun for this ownership increment.

### S4-02 Remainder After Ownership Transfer

At commit `1cca6a4`, configuration startup and reconnection still used separate load and subscribe operations.
File and SONiC backends published post-subscription baselines, but the source trait did not express that contract.
Their subscription workers needed explicit lifetime ownership. Dropping supervisor futures did not prove that all backend tasks stopped.
The file watcher callback also retained its blocking queue behavior.

The following increment addresses the file observer and runtime contract. SONiC worker ownership remained open until `8381d4f`.

## Owned Configuration Observations

Commit `75aac8b` adds `ConfigDatastore::observe()` and the `ConfigObservation` contract.
An observation supplies canonical `ConfigChangeEvent` values, including its baseline. Cancelled reads must retain pending work.
Snapshots remain `Arc<TacacsPlus>` values. No competing desired-configuration model or revision scheme is introduced.

The agent retains one observation across successful initialization and live updates.
After observation failure or completion, it drops the session, waits through backoff, and opens observation before reading the replacement baseline.
The supervisor no longer calls `load()` or `subscribe()` directly.
Credential supervision and the materialization coordinator remain unchanged.

Static sources produce one baseline and then end, without a worker task.
At `75aac8b`, a transitional default adapted immutable loads or continuous subscriptions to the new contract.
Continuous adapters require a post-subscription baseline. They do not provide backend task ownership by themselves.
SONiC used that adapter until `8381d4f` supplied native ownership and removed it.

### File Session Lifetime

The file observation owns its native watcher, debounce state, pending read, and last valid snapshot.
Its callback coalesces invalidations through a watch channel. No callback blocks on a full event queue.
There is no detached async reload worker. The legacy file subscription forwards to the owned session without starting another task.

Read-access events no longer trigger reloads. Rescan and pathless invalidations require reconciliation.
Watcher errors remain latched. Removal or renaming of the watched directory returns an observation error.
Rejected candidates retain the last valid snapshot for subsequent deltas.

Reads and watches use the same captured canonical parent paths for configuration and credential files.
Retargeting a parent-directory symlink does not move reads outside the watched directory. A new observation captures a new target.
Configuration input normalization does not rewrite authoritative YANG snapshots or credential references.

Reads run on Tokio's blocking pool. Cancelling `next()` retains its pending read handle and does not consume later invalidations.
Dropping the session releases the watcher and aborts a read that has not started.
An operating-system read that already started can finish afterward, but its result cannot publish into the dropped session.
This is not a guarantee of immediate cancellation for blocking filesystem I/O.

### Cancellation and Regression Evidence

`observation_filters_access_but_reconciles_rescan_events` failed before the event-filter fix because read events triggered reloads.
`dropped_initialization_reopens_observation_before_retry` failed before its fix with a one-second timeout.
That case consumes a baseline, pauses filtering, drops initialization, and retries without another source event.
Both initialization retry and `run_until` now discard incomplete sessions before obtaining a fresh baseline.

Tests also cover native watcher release, 10,000 coalesced invalidations, cancellation during debounce and a pending read, directory loss, and symlink retargeting.
A cross-crate file test changes configuration between initialization and serving, then verifies convergence.
A drop-tracked source rejects legacy calls and proves that initialization and updates share one observation until cancellation.
Recovery tests verify observation setup before replacement baselines, including failed setup and failed baseline reads.

### Verification and Remaining Work

Verification for `75aac8b` passes: 83 configuration tests, 22 supervisor tests, and the complete all-feature workspace suite with 153 agent tests.
Strict workspace Clippy, build, formatting, warnings-as-errors rustdoc, all four dependency guards, unused-dependency checks, and audit pass.
Audit reports no vulnerabilities in 301 locked packages, with the existing index-lock warning.
The existing nightly `fetch_update` deprecation warning remains. Rust 1.88 remains supported.

`futures-util` moves from configuration's development dependencies into its normal dependencies for the task-free stream adapter.
No dependency version, lockfile, YANG schema, generated artifact, or native TLS behavior changes.
Documentation is checked through rustdoc and the book build.
External-peer, Windows, live SONiC, and Miri checks were not rerun for this increment.

At `75aac8b`, remaining S4-02 work covered native SONiC ownership, Redis cleanup tests, and removal of transitional subscription APIs.
One-shot configuration loading can remain where a caller genuinely needs it.
Unified generation/health publication, source and credential revision semantics, and the other Stage 4 obligations remain unchanged.

## S4-02 Closure

Commit `8381d4f` completes the remaining source-observation ownership work.
The SONiC datastore implementation now lives in its own module. The crate root contains declarations and intentional exports.
Static, file, and SONiC sources each implement `ConfigDatastore::observe()` explicitly.
The default observation adapter and datastore `subscribe()` method are removed. One-shot loading remains where callers need it.

### SONiC Resources

The observation establishes `PSUBSCRIBE` before it reads the baseline.
It owns a notification pump that coalesces invalidations through a watch channel. A slow consumer cannot block notification delivery.
The session stores its reload future instead of starting a separate reload worker.
Cancellation retains that future and invalidations received during the read. Dropping the session cancels the pump and drops the read future.

Pub/Sub loss returns an observation error, including while a reload is pending.
The agent reopens observation before reading a replacement baseline.
Mapping failures emit candidate rejection without replacing the previous valid snapshot.
Forwarder changes still report restart requirements independently of upstream server changes.
Removing the final servers publishes an empty canonical snapshot with removal deltas.

Credential change streams also own their watcher workers and cancel them on drop.
The old spawn-and-return-a-receiver helpers are removed. `watch_credential_changes` returns the owned stream directly.
Rescan events request complete reconciliation. Failed root-watch re-registration reports unavailability and ends the stream.
The watch example uses one observation for baseline and updates, and no longer prints the Redis URL.

### Native Regression Evidence

`redis_idle_subscription_drop_closes_pubsub_connection` failed before the fix with a one-second timeout.
The old notifier remained connected while idle after its consumer was dropped.
The test now checks Redis client state and confirms connection closure without another ConfigDB event.

Further native checks verify:

- Cancellation of a pending reload retains concurrent invalidations and reconciles the latest snapshot.
- Pub/Sub disconnect interrupts a pending reload, and a new observation reads a fresh baseline.
- Dropping an observation during a real paused Redis read closes both the snapshot and Pub/Sub connections.
- Forwarder changes preserve restart reporting, rejected candidates retain the old snapshot, and final-server deletion publishes an empty snapshot.
- Repeated idle credential-stream drops finish their workers without waiting for a filesystem event.
- Credential rescan, atomic replacement, root replacement, and overflow reconciliation remain covered.

### Verification

The isolated native fixture used Redis 7.2.5, built under `/tmp`, with a private Unix socket, no TCP listener, and no persistence.
No system package or service was installed. The fixture was stopped after testing and removed its socket.
Tests used database 15 and ran serially because the native cases reset the private database and inspect its client list.

```bash
TACACSRS_SONIC_TEST_REDIS_URL=unix:///path/to/private/redis.sock \
	cargo test --workspace --all-features --locked -- --test-threads=1
```

The complete workspace suite passes with native Redis enabled: 46 SONiC unit tests, eight provider tests, and five credential-watch tests pass.
The suite also passes 153 agent tests, 83 configuration tests, 60 daemon tests, and seven prepared-source integration tests.
Strict workspace Clippy, build, formatting, warnings-as-errors rustdoc, all four dependency guards, unused-dependency checks, and audit pass.
Audit reports no vulnerabilities in 301 locked packages, with the existing index-lock warning.
The existing nightly `fetch_update` warning remains. Editor-only coercion diagnostics conflict with successful Cargo checks and native tests.

Configuration's `futures-util` dependency returns to development-only use after removal of the stream adapter.
No dependency version, lockfile, generated YANG artifact, protocol, or TLS implementation changes.
The documentation update passes rustdoc and the book build.
The live SONiC VM was not changed or restarted. Live-VM, external TACACS+ peer, Windows, and Miri checks were not rerun.

S4-03 remains open for one generation/health publication controller and separate source and credential revisions.
Host signal ownership, stale-material policy, certificate chains, revocation retrieval, and operational statistics remain the later Stage 4 obligations.

## Runtime Publication

Commit `899ca75` establishes the first S4-03 publication boundary.
`PublicationController` serializes catalog commits with generation-scoped availability observations.
The manager holds its runtime write lock, then the publication controller lock, then the health watch write lock.
Catalog replacement occurs inside that health mutation, before the new health snapshot becomes visible.
The commit contains no asynchronous waits.

Initial runtime attachment, catalog replacement, materialized-server replacement, and policy updates all use this boundary.
The health snapshot now exposes a typed `RuntimeGeneration` identifier.
It records the published runtime snapshot, not a canonical source revision or a credential revision.
A waiting runtime can publish policy and a generation identifier without claiming that source configuration has been applied.

The commit updates generation, applied status, eligible-server count, and any required availability reset together.
Availability and its `UpstreamsUnavailable` degradation reason also change in one health mutation.
An old availability attempt cannot cross the replacement epoch and overwrite the new generation's state.
Policy-only publication and unchanged catalogs preserve observed availability.
The admission registry remains shared across generations. Existing request-generation and admission tests still pass.

### Nearby Defect

The service previously cleared upstream availability after the manager returned from every reload.
That late write erased valid availability on unchanged reloads and could overwrite an observation made after catalog publication.
`unchanged_reload_preserves_observed_upstream_availability` failed before the fix: health changed from `Available` to `Unknown`.
The service no longer performs post-publication count, applied-status, or availability writes.

### Verification

New tests cover initial generation identity, policy-only publication, waiting-runtime policy, catalog replacement, unchanged reload, and rejected candidates.
A barrier-driven test pauses publication while an old availability result and a health reader compete with the commit.
The observed health contains the replacement generation, count, applied status, and availability reset together.

All 157 agent tests and the complete all-feature workspace suite pass.
Strict workspace Clippy, nightly formatting, workspace build, warnings-as-errors rustdoc, and the documentation book build pass.
Edited files have no editor diagnostics.
No dependency, lockfile, schema, protocol, or native transport changes occur in this increment.
Native Redis, live SONiC, external TACACS+ peer, Windows, and Miri checks were not rerun for this publication-only work.

### S4-03 Remainder

Runtime generation identity does not replace source and credential revisions. Those revisions still need explicit types and publication semantics.
At `899ca75`, the materialization coordinator still recorded active servers after an awaited service reload.
Commit `a3f1727` resolves that gap by moving the bookkeeping into the runtime commit, as described below.

Configuration and policy supervisors still publish candidate-health status separately after asynchronous preparation or application.
Their success and failure updates need revision checks so stale completions cannot clear or set health for a newer candidate.
The final controller must combine those decisions with canonical source ownership and credential-only updates.
The existing source snapshots and credential references must remain unchanged throughout preparation and publication.

These obligations remain within S4-03. This increment does not claim completion of the shared configuration controller.

## Materialization Commit

Commit `a3f1727` makes active materialization bookkeeping part of the runtime publication transaction.
The coordinator checks that the prepared attempt is current and constructs the next active server set before publication.
It passes that set and a private, synchronous commit callback through the service to the manager.
The callback updates active servers and the active source generation inside the existing runtime and health commit.
There is no asynchronous wait between runtime replacement and these bookkeeping updates.

The callback consumes the coordinator state guard. Its completion releases that guard before asynchronous connection retirement starts.
The callback must not fail, block, or acquire runtime or health locks.
It is an internal publication mechanism, not a new public extension point.
Existing public reload methods preserve their signatures and use an empty bookkeeping callback.

Preparation, stale-attempt rejection, credential validation, and native context construction still precede the commit.
If cancellation occurs before publication, the previous runtime, applied health, and active material remain unchanged.
If cancellation occurs after publication during retirement, all three already describe the replacement generation.
The existing bounded retirement scheduling remains in place. This change adds no detached production task.

### Regression Evidence

The test `cancellation_after_runtime_publication_retains_matching_active_material` pauses the reload immediately after publication and cancels the caller.
Before the fix, the runtime reported an applied server while the coordinator's active-server vector was empty.
The failed assertion reported `left: 0`, `right: 1`.

The expanded test publishes two servers and confirms that the coordinator is readable while retirement remains paused.
After cancellation, a change to one credential selects only its dependent server. The other server retains its existing shared material.
The retained canonical source equals the original value, including its credential references.
The next successful refresh advances runtime health to the next generation.

A second test cancels publication while it waits for the service publication lock.
No runtime or active-material change occurs, and the health snapshot remains unchanged.
Existing native-credential rejection, stale-result rejection, and dependency-index tests continue to pass.

### Verification and Remaining Work

All 11 materialization-coordinator tests and 159 agent tests pass.
The complete all-feature workspace suite, strict workspace Clippy, build, nightly formatting, and warnings-as-errors rustdoc pass.
The documentation update passes the book build and rustdoc. Edited files have no editor diagnostics.
No dependency, lockfile, schema, protocol, native TLS, or public API changes occur in this increment.
Native Redis, live SONiC, external TACACS+ peer, Windows, and Miri checks were not rerun for this agent-only publication change.

S4-03 still needs explicit source and credential revisions and revision-fenced supervisor health decisions.
Configuration and policy supervisors still update candidate-health status after awaited operations.
Those success and failure updates must not describe an older candidate after a newer candidate becomes authoritative.
The final controller must preserve canonical source ownership and global admission while it combines those decisions.