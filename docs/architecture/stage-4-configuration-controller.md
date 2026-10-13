# Stage 4: Configuration Controller and Lifecycle

## Status

Stage 4 is in progress as of 2026-10-13. Commit `6a11a83` completes the first increment.
Commit `1cca6a4` moves configuration recovery and materialization coordination into the agent.
Commit `75aac8b` adds canonical observation sessions and file watcher ownership. The supervisor now uses observations for startup and recovery.
Commit `8381d4f` completes S4-02 with owned SONiC observations and removal of transitional APIs.
Commit `899ca75` starts S4-03 with atomic runtime and applied-health publication.
Commit `a3f1727` adds active materialization bookkeeping to the same commit and closes its cancellation window.
Commit `044518c` adds independent materialization revisions and protects credential health from stale results.
Commit `3f72a8f` moves source admission before filtering and unifies source publication and health across both resolver modes.
Commit `907cff1` completes S4-03 with revision-fenced policy decisions and atomic policy-health publication.
Commit `36d9cbc` starts S4-04 with daemon-owned signals and coordinated cancellation from bootstrap through serving.
Canonical YANG remains authoritative. Prepared runtime policy remains a derived value.
The publication contract is complete. The remaining Stage 4 lifecycle, certificate, revocation, and statistics work is still open.

Fix nearby findings within each increment when practical. Keep completed items and their verification evidence.
The startup race and closed-runtime publication fix belong to S4-01, not separate work items.

## Checklist

- [x] S4-01: Own canonical policy observation in configuration and policy supervision in the agent. Commit `6a11a83` removes daemon policy algorithms and closes the startup race. See [policy observation](#policy-observation).
- [x] S4-02: Commit `1cca6a4` moves recovery and materialization into the agent. Commit `75aac8b` owns file observations and migrates supervision. Commit `8381d4f` owns SONiC Redis and credential streams and removes transitional APIs. Native cleanup, cancellation, and recovery tests pass. See [S4-02 closure](#s4-02-closure).
- [x] S4-03: Commits `899ca75` and `a3f1727` unify runtime, health, and materialization commits. Commit `044518c` adds revision fencing, and `3f72a8f` coordinates source admission and health. Commit `907cff1` completes policy admission and atomic policy-health publication. See [S4-03 closure](#s4-03-closure).
- [ ] S4-04: Commit `36d9cbc` removes library signal ownership and verifies native bootstrap cancellation, service drain, and peer cleanup. Stale-material budgets, expiry rules, and explicit controller/provider teardown bounds remain open. See [host signal ownership](#host-signal-ownership).
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
At `6a11a83`, policy and health updates still used separate owners. S4-03 later unifies generation publication and applied-health metadata.

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
Native SONiC ownership and revision/publication coordination are complete through S4-03.
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

At the S4-02 checkpoint, S4-03 remained open for generation/health coordination and separate source and credential revisions.
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

Runtime generation identity does not replace source and credential revisions. Commit `044518c` adds those types for coordinated materialization.
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

After `a3f1727`, explicit source and credential revisions and revision-fenced supervisor health decisions remained open.
Configuration and policy supervisors still update candidate-health status after awaited operations.
Those success and failure updates must not describe an older candidate after a newer candidate becomes authoritative.
The final controller must preserve canonical source ownership and global admission while it combines those decisions.

## Revision-Aware Materialization

Commit `044518c` introduces `SourceRevision`, `CredentialRevision`, and their applied pair, `MaterializationRevision`.
The materialization coordinator assigns these values without changing canonical snapshots or credential references.
The source counter advances for each accepted canonical candidate, including repeated observations and preparation retries.
The credential counter advances independently when a credential invalidation schedules materialization.
An unrelated credential event does not advance the counter when all accepted work is already applied.

These counters identify observations within one coordinator instance. They are not provider revisions, content hashes, or globally ordered identifiers.
The pair replaces the coordinator's primitive source-generation and attempt-ID checks.
A failed, cancelled, or superseded attempt does not change the applied pair.

`RuntimeHealthSnapshot::materialization_revision()` returns the applied pair with its runtime generation.
The coordinator returns the pair from the synchronous commit callback, after it updates active material.
The health publisher records the pair and clears `CredentialResolutionFailed` before it releases the health mutation lock.
Policy-only publication preserves the pair. Direct server publication clears it because no coordinated materialization revision describes that update.
The IPC health contract is unchanged; this metadata is available through the Rust health snapshot API.

### Stale Outcome Fix

The regression `older_publication_completion_cannot_clear_newer_credential_failure` failed before the fix.
It pauses an older successful publication during retirement, completes a newer credential failure, then resumes the older caller.
The older completion previously erased the newer `CredentialResolutionFailed` state.

Successful materialization now clears credential failure during commit, not after the reload future returns.
Failure reporting compares the attempt pair with the current pair and mutates health under the same coordinator lock.
There is no unlocked check-then-update window for that credential failure flag.
Superseded results do not update it, and cancellation after publication cannot prevent successful credential-health recovery.

### Overlapping Credential Changes

The previous selective-refresh logic considered only whether the source generation had changed.
A second credential event could supersede an unfinished first event and select only its own server, leaving the first server's material stale.
Selection now compares the complete active and desired revision pairs.
If any accepted work remains unapplied, the next attempt selects all current dependencies.
After complete publication, a known credential event again selects only its affected servers.
This conservative retry rule also covers cancelled or failed credential materialization.

### Verification

The 12 materialization tests and 23 supervisor tests pass.
They cover independent counters, unchanged source references, overlapping invalidations, stale success, stale failure, and cancellation at publication.
Tests also verify that policy updates preserve applied metadata and direct server updates clear it.
The complete all-feature workspace suite passes, including all 161 agent tests.
Strict workspace Clippy, build, formatting, warnings-as-errors rustdoc, and the documentation book build pass.
Edited files have no editor diagnostics.

No dependency, lockfile, configuration schema, IPC schema, protocol, or TLS changes occur in this increment.
Native Redis, live SONiC, external TACACS+ peer, Windows, and Miri checks were not rerun for this agent-only change.

### S4-03 Remainder

At `044518c`, materialization revisions began after asynchronous host filtering.
Commit `3f72a8f` assigns source identity before filtering and includes no-resolver sources in the same revision contract.

At that checkpoint, configuration-source and policy rejection status still had separate supervisor updates after asynchronous work.
The following increment completes source-result coordination. Policy health remains within S4-03.

## Source Admission and Health

Commit `3f72a8f` assigns each source candidate a revision before host filtering starts.
Admission retains the canonical candidate and invalidates older filtered work.
Filtered acceptance checks the admitted source revision before it records the derived runtime candidate or schedules materialization.
Late filter success and failure cannot replace or reject a newer admitted source.

Every supervisor now owns a coordinator. The resolver is optional, rather than the coordinator itself.
Inline configuration uses the same revision, validation, publication, and health path as resolver-backed configuration.
Without a resolver, unresolved central credential references still fail before publication.
The accepted inline generation also records a materialization revision with its independent credential counter.

Source admission clears the previous filtered candidate until the new filter result is accepted.
Credential notifications during this interval advance the credential revision without republishing the previous source.
The eventual accepted filter result captures the latest credential revision and prepares the new source.
Rejected observations advance source identity and invalidate pending work while leaving the active runtime unchanged.

### Source Health Ownership

The coordinator checks source rejection under its state lock and publishes rejection health in one mutation.
Materialization failures also publish their credential and source flags together, conditional on the attempt still being current.
Successful publication carries source-current status into the existing runtime and health commit.
The supervisor no longer marks a source current or rejected after a completed publication future returns.
Thus, late retirement completion cannot clear a newer source rejection.

Observation loss marks the retained source unavailable without discarding valid active material.
Credential refresh can still rotate that retained material, but its commit does not claim that the source recovered.
An admitted valid source restores current status only when its generation is published.
Canonical snapshots and credential references remain unchanged by filtering and materialization.

### Regression Evidence

`older_filter_completion_cannot_replace_a_newer_source` failed before the change: the old candidate reported `Published`, not `Superseded`.
The test now covers old filter success and failure, both with and without a resolver.
The newer server set and health snapshot remain unchanged in all four cases.

Additional tests verify:

- Source health is current before asynchronous retirement completes.
- A rejected observation remains rejected when an older publication returns.
- Credential refresh during a source outage preserves stale source health and unavailable-notification status.
- Credential invalidation during filtering is retained without reusing the old filtered source.
- Central references fail without a resolver, while a later valid inline candidate recovers through the same publication path.

### Verification and Remaining Work

All 166 agent tests pass, including 27 supervisor tests and the materialization regressions.
The complete all-feature workspace suite, strict workspace Clippy, build, nightly formatting, and warnings-as-errors rustdoc pass.
The documentation update passes the book build and rustdoc. Edited files have no editor diagnostics.
No dependency, lockfile, configuration schema, IPC schema, protocol, or TLS changes occur in this increment.
Native Redis, live SONiC, external TACACS+ peer, Windows, and Miri checks were not rerun for this agent-only change.

At `3f72a8f`, S4-03 remained open for policy admission identity and policy candidate-health publication.
The policy supervisor still applied prepared policy and updated rejection health separately.
The following increment closes that boundary while preserving global admission and canonical policy authority.

## S4-03 Closure

Commit `907cff1` completes policy revision fencing and the shared publication contract.
`PolicyRevision` is a runtime-local admission counter, independent of source and credential revisions.
The controller assigns it before canonical validation or an asynchronous publication-lock wait.
Newer admission supersedes older work, even if the newer candidate is rejected or cancelled.
Admission alone does not change the applied policy or its health snapshot.

### Policy Decisions

`TacacsClientService::apply_policy_candidate` accepts a borrowed generated policy, or `None` for a source rejection.
Canonical validation produces derived runtime policy without changing the source.
`reload_runtime_policy` accepts an already prepared policy and enters the same admission path.
Both return `PolicyUpdate`, which distinguishes applied, rejected, and superseded decisions.
Closed runtimes return an error without changing rejection health.

The manager holds the runtime lock before checking the current admission under the publication-controller lock.
Successful policy publication updates the policy, runtime generation, global admission limits, applied policy revision, and rejection recovery inside one health mutation.
No asynchronous wait separates these updates.
Rejection checks the same admission identity under the same lock order and retains the last applied policy.
Stale success and failure return `Superseded` without a health mutation or generation advance.

`RuntimeHealthSnapshot::applied_policy_revision()` records the last committed update.
It is `None` before the first update, including when startup supplied a prepared policy.
Rejected and cancelled revisions can leave gaps in the counter. The value is diagnostic, not a persistent provider revision or content hash.
Policy updates preserve applied configuration status, source/credential revisions, server count, upstream availability, and captured request policy.
Server updates preserve the applied policy revision. Global admission retains the same shared registry across both update types.

`PolicySupervisor::new` now takes only an observation and service.
It no longer owns an independent health publisher or writes rejection health after an awaited service call.
It reports explicit update outcomes instead of logging every completed call as applied.

### Regression Evidence

`delayed_policy_cannot_overwrite_a_newer_rejection` failed before the fix.
An older valid candidate waited for the publication lock while another supervisor rejected a newer observation.
After release, the older call previously published its policy and cleared the newer rejection.
The new admission check leaves the applied generation and rejection unchanged.

Further tests verify:

- A newer valid canonical candidate supersedes a prepared-policy update waiting for publication.
- Cancelling a publication wait retains the previous policy and rejection state; a later retry can apply.
- Invalid canonical policy and source rejection preserve applied revision and generation.
- Closed runtimes reject both valid updates and rejection observations without changing health.
- Stale controller success and failure cannot mutate health or execute a commit callback.
- A barrier-driven health reader sees policy revision, runtime generation, and rejection recovery together.
- Policy and materialization updates preserve each other's applied revision metadata, and admission retains shared identity across replacement.

### Verification

All 172 agent tests and the complete all-feature workspace suite pass.
The focused policy selection runs 20 tests. Daemon checks pass 60 unit tests and seven prepared-source integration tests.
Strict workspace Clippy, build, nightly formatting, warnings-as-errors rustdoc, and the documentation book build pass.
Edited files have no editor diagnostics.
No dependency, lockfile, configuration schema, IPC schema, protocol, or native TLS changes occur in this increment.
Rust API changes are intentional: policy methods return explicit outcomes, and the supervisor constructor no longer accepts a health publisher.
Native Redis, live SONiC, external TACACS+ peer, Windows, and Miri checks were not rerun for this publication-only work.

### Next Boundary

S4-04 owns process signal removal from libraries, host cancellation, stale-material budgets, expiry behavior, and bounded drains.
Client certificate chains, revocation evidence retrieval, and operational statistics retain their separate Stage 4 acceptance criteria.
This closure does not claim completion of Stage 4 or full RFC 9887 conformance.

## Host Signal Ownership

Commit `36d9cbc` removes the agent library's `serve()` methods and process signal future.
The only listener entry point is `serve_until(stop_future)`. Agent code no longer uses `tokio::signal` or requests Tokio's signal feature directly.
The embedding host owns signal selection and error handling.

The daemon registers SIGINT and SIGTERM once, before asynchronous bootstrap.
It polls the signal future alongside the application instead of starting a detached signal task.
One cancellation token covers forwarder bootstrap, local-service and policy loading, initial configuration, observation, and serving.
Registration errors fail startup explicitly. Requested cancellation during asynchronous bootstrap returns successfully without binding listeners.

`PreparedService` separates completed bootstrap from the running service.
Fail-fast initialization observes the same host cancellation token. If it is cancelled, the daemon does not spawn listener or peer tasks.
The ready-stop library path also skips binding, closes upstream runtime state, and publishes `Stopped` after cleanup.
The regression preserves an unrelated regular file at the configured endpoint, proving that cancellation did not attempt socket preparation.

### Supervision Cleanup

The daemon keeps the service future alive after a host or configuration task failure.
It cancels the shared token, awaits service drain, and joins both peer tasks before returning.
Requested shutdown is selected before expected peer exits, so those exits do not produce a false fatal error.
Unexpected peer exits and cleanup errors preserve a failed lifecycle while the original error remains available to the caller.
An ownership guard cancels and aborts peer tasks if the supervision future itself is dropped.

The existing listener and upstream drain deadline remains derived from the maximum current operation budget.
This increment does not add a separate process-wide deadline for every controller or provider cleanup operation.
Started blocking filesystem work also retains the cancellation limitations documented in the observation increments.

### Nearby Defects

`host_panic_cancels_and_joins_configuration_before_returning` failed before the fix because an early `?` bypassed cancellation.
Cleanup no longer returns early before joining the other peer. The regression checks both cancellation and completed joining before return.

`already_stopped_host_does_not_attempt_listener_binding` also failed before the fix.
The old path started listener preparation after the stop future was already ready and rejected the unrelated file at its endpoint.
The new path does not attempt binding.

Native all-feature tests exposed an unconditional Tokio Console startup panic without `tokio_unstable`.
The daemon now enables profiling only when the feature and instrumentation cfg are both present.
Other console-feature builds report disabled profiling and use normal logging. Cargo explicitly accepts the instrumentation cfg.
The instrumented profiling mode itself was not exercised in this increment.

### Native Verification

The process tests start the built daemon as a child process. They use private temporary directories and kill-on-drop cleanup.
Linux `/proc` state confirms that both signal handlers are registered before the tests deliver a signal to that child PID.
Both SIGINT and SIGTERM cancel SONiC bootstrap when its configured Redis endpoint is unavailable.
The serving test holds an idle Unix IPC connection, sends SIGTERM, and verifies successful exit, transport closure, and socket removal.
That test uses a one-second operation budget to exercise bounded listener and upstream cleanup.
The tests pass in both default and all-feature builds without changing or restarting the SONiC VM.

All 173 agent tests, 64 daemon unit tests, seven prepared-source tests, and two native process tests pass.
The complete all-feature workspace suite, strict Clippy, build, formatting, warnings-as-errors rustdoc, and book build pass.
Unused-dependency analysis passes. Audit reports no vulnerabilities in 301 locked packages, with the existing index-lock warning.
The existing nightly `fetch_update` deprecation warning remains. Edited files have no editor diagnostics.

Dependency features change only for signal ownership and native process tests. No package version, lockfile, schema, protocol, or TLS implementation changes.
Native Redis, live SONiC, external TACACS+ peer, Windows, and Miri checks were not rerun.

### S4-04 Remainder

Define canonical stale-material budgets and expiry behavior instead of retaining unavailable credentials indefinitely by accident.
Apply explicit teardown budgets to controller/provider work and verify both cooperative and non-cooperative dependencies.
Preserve last-known-good source semantics, generation identity, and bounded connection retirement while adding these policies.
S4-04 remains open. Certificate chains, revocation evidence retrieval, and statistics remain the later Stage 4 obligations.