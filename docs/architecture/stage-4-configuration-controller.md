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
Commit `37faec2` adds canonical graceful-teardown budgets and verifies cancellation of a stalled native host helper.
Commit `e91fe02` adds stale-source expiry with recoverable upstream withdrawal.
Commit `ed47f41` adds independent referenced-credential expiry and revalidation while preserving source-expiry enforcement.
Commit `8ff62cd` adds absolute provider validity metadata, publication checks, request deadline bounds, and owned expiry supervision.
Commit `23e7f98` adds intrinsic configured client-certificate validity, including inline identities and cached sessions.
Commit `7b3eed7` completes S4-04 with negotiated peer-path expiry and owned idle-transport retirement.
Commit `3897414` completes S4-05 with canonical client-chain provisioning and native mTLS verification.
Commit `567ec16` starts S4-06 with canonical required issuer-signed OCSP stapling and bounded evidence lifetime.
Commit `d78cf06` adds delegated OCSP signer authorization and responder-certificate lifetime bounds.
Commit `a06fced` adds canonical full-CRL materialization, native CA-path validation, and evidence-bounded catalog lifetime.
Commit `f55973a` immediately cuts off replaced endpoints when changed CRL policy or evidence commits, including older draining generations.
Commit `5b9ba63` adds proactive provider revalidation before expiry without requiring credential notifications.
Canonical YANG remains authoritative. Prepared runtime policy remains a derived value.
The publication, lifecycle, and client-chain contracts are complete. Revocation and statistics remain open.

Fix nearby findings within each increment when practical. Keep completed items and their verification evidence.
The startup race and closed-runtime publication fix belong to S4-01, not separate work items.

## Checklist

- [x] S4-01: Own canonical policy observation in configuration and policy supervision in the agent. Commit `6a11a83` removes daemon policy algorithms and closes the startup race. See [policy observation](#policy-observation).
- [x] S4-02: Commit `1cca6a4` moves recovery and materialization into the agent. Commit `75aac8b` owns file observations and migrates supervision. Commit `8381d4f` owns SONiC Redis and credential streams and removes transitional APIs. Native cleanup, cancellation, and recovery tests pass. See [S4-02 closure](#s4-02-closure).
- [x] S4-03: Commits `899ca75` and `a3f1727` unify runtime, health, and materialization commits. Commit `044518c` adds revision fencing, and `3f72a8f` coordinates source admission and health. Commit `907cff1` completes policy admission and atomic policy-health publication. See [S4-03 closure](#s4-03-closure).
- [x] S4-04: Commits `36d9cbc` and `37faec2` establish host signals and teardown budgets. Commits `e91fe02` and `ed47f41` enforce independent source and credential staleness budgets. Commit `8ff62cd` enforces provider validity; `23e7f98` enforces configured client-certificate validity. Commit `7b3eed7` completes peer-path expiry and owned transport retirement. Blocking-code limits remain explicit. See [S4-04 closure](#s4-04-closure).
- [x] S4-05: Commit `3897414` adds canonical client-chain inputs and provider/PEM adapters. Native mTLS tests cover complete, missing, incorrect, and out-of-order intermediates. Source references remain unchanged. See [S4-05 closure](#s4-05-closure).
- [ ] S4-06: Commits `567ec16` and `d78cf06` enforce required stapling and authorized delegated responders. Commit `a06fced` adds full CRLs; `f55973a` adds refresh retirement, and `5b9ba63` adds proactive provider revalidation. Built-in remote retrieval and unsupported evidence forms remain open. See [proactive provider refresh](#proactive-provider-refresh).
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

## Bounded Graceful Teardown

Commit `37faec2` adds `shutdown-timeout-seconds` to the project-owned YANG runtime-policy resource.
The field is a nonzero unsigned 32-bit number of seconds, with a generated default of 30.
Configuration validation rejects zero. The agent derives a `Duration` without changing the source value.
Generated Rust, the expanded tree, and the generation manifest are updated from the pinned YANG inputs.

The daemon reads the applied budget when it begins cleanup after a shutdown request or a supervised task exit.
It computes one absolute deadline before cancelling the shared token.
Service drain, configuration-supervisor completion, and host-task completion consume the same budget.
Later steps cannot start a fresh timeout, and a policy update cannot extend the captured deadline.

At expiry, the daemon marks health failed, drops the service future, aborts pending peers, and joins their cancelled tasks.
Forced teardown returns an error rather than reporting clean shutdown.
If another failure triggered cleanup, that original error remains primary.
The library independently caps listener and upstream drain by the smaller of the shutdown policy and maximum current operation budget.
Endpoint retirement during configuration reload retains its request-based cutoff.

### Native Host Helper Ownership

The systemd adapter previously used a synchronous process wait, which could block a runtime worker and prevent task cancellation.
It now awaits an owned Tokio child process with kill-on-drop behavior.
Helper availability checks inspect executable metadata instead of running an unbounded `--version` subprocess during selection.
Health snapshots are cloned before awaiting notifications; no health borrow is held across the process wait.
Existing ready/stopping retry semantics remain unchanged.

### Regression Evidence

`stalled_peer_cannot_hold_shutdown_open_indefinitely` failed before the fix after its 31-second test limit.
The daemon waited forever for a peer that ignored cancellation.
The final paused-time tests verify the generated default, one deadline across sequential cleanup phases, unchanged deadlines after policy changes, and preserved primary errors.
Another test verifies that the budget begins at cleanup, not at process startup.

The native process test installs a private fake `systemd-notify` helper that never completes within the test budget.
It starts the daemon with a one-second canonical shutdown budget, sends SIGTERM, and checks failed exit, helper termination, and socket removal.
This proves cancellation of a real child-process dependency, not only a mocked pending future.
The normal serving and bootstrap signal tests remain passing.

### Verification

The complete all-feature workspace suite passes, including 174 agent tests, 68 daemon unit tests, seven prepared-source tests, and three native process tests.
Strict workspace Clippy, build, formatting, warnings-as-errors rustdoc, and the documentation book build pass.
All 13 generator tests and deterministic regeneration checks pass. The pinned upstream module is unchanged.
Generated Rust SHA-256: `44efbc8d9993099759f27ba3e0a66bef949b2ddf5aff3e3215aeba3b16f85f74`.
All four dependency-boundary guards, unused-dependency analysis, and dependency audit pass.
Audit reports no vulnerabilities in 301 locked packages, with the existing index-lock warning. The existing nightly deprecation warning remains.
Edited files have no editor diagnostics after the final lint correction.

The daemon adds a direct `async-trait` dependency and enables Tokio process support for production host integration.
No package version, TACACS+ wire behavior, IPC schema, or TLS implementation changes.
Native Redis, live SONiC, external TACACS+ peer, Windows, and Miri checks were not rerun.

### Remaining Lifecycle Policy

The deadline bounds graceful asynchronous waits. Abort and join still require Rust futures and destructors to yield or complete.
An arbitrary blocking call, non-yielding task, or already-started blocking filesystem operation cannot be forcibly preempted inside this runtime.
Deployments require process-supervisor termination limits for those cases. This increment does not claim a hard wall-clock bound for arbitrary code.

S4-04 still needs canonical stale-material budgets and expiry behavior, with fail-closed handling where those policies require it.
Preserve source revisions, last-known-good semantics, and bounded endpoint retirement while adding those decisions.
Certificate chains, revocation evidence retrieval, and operational statistics remain the later Stage 4 work.

## Stale-Source Expiry

Commit `e91fe02` adds `source-stale-timeout-seconds` to the canonical project runtime-policy resource.
It is a nonzero unsigned 32-bit seconds value with a generated default of 300.
The agent projects it into a duration without changing the canonical policy value.
Generated Rust, the expanded tree, and their manifest hashes are regenerated from the pinned inputs.

### Grace Interval

The configuration supervisor owns an expiry future alongside source and credential observation. It starts no detached timer task.
For an applied, nonempty catalog, the monitor captures a deadline from the first stale or unavailable source-health snapshot it observes.
The applied canonical budget supplies the interval.
Repeated failures, rejected candidates, credential-only refreshes, and policy updates do not renew that deadline.
Changed policy budgets apply to a later stale interval, not one already captured.

A successful source publication ends the old interval. A later outage receives a new interval.
The monitor compares published source revisions so this reset survives coalesced health updates that omit the brief current state.
Credential revision changes alone cannot reset source grace.
No expiry is needed before the first applied source or when the current catalog is already empty.

### Withdrawal and Recovery

At the deadline, the monitor requests withdrawal of the still-stale applied revision.
The coordinator rechecks the applied revision and current source health under its state lock.
A stale expiry request cannot remove a newer recovered generation.
The transaction publishes an empty upstream catalog, clears active materialization bookkeeping, and marks `SourceExpired` together.
The canonical desired source remains available for future preparation.

Removed endpoints receive an immediate retirement cutoff before replacement health becomes visible.
Retained old routing handles cannot establish new bindings to those endpoints. Global admission remains the same shared registry.
The applied materialization revision becomes absent because the withdrawn catalog no longer represents applied source material.
The runtime retains completed-startup state, but zero eligible servers withdraw readiness.
Liveness, listeners, and configuration observation remain active.

A valid source publication clears expiry and restores the upstream set through the normal revision-checked commit.
An unavailable expired source cannot be revived by credential-only refresh or a longer policy budget.
Expiry does not falsely clear an existing credential-resolution failure.
The runtime remains recoverable rather than entering terminal process shutdown.

### Regression Evidence

`unavailable_source_does_not_serve_past_the_default_stale_budget` failed before the change after 301 virtual seconds.
The runtime retained its upstreams indefinitely after source loss.
It now withdraws them at the configured grace deadline while the supervisor remains active.

Further tests verify:

- Repeated source failures, credential refresh, and a policy increase do not extend the current interval.
- Expiry withdraws readiness while preserving startup and liveness health.
- A valid source restores service, and an older expiry request cannot remove that generation.
- Coalesced recovery and failure transitions reset the interval for the new source revision.
- Immediate retirement blocks retained old bindings, and recovery reuses the global admission registry.

### Verification and Remaining Work

All 178 agent tests and the complete all-feature workspace suite pass, including the existing three native process tests.
Strict workspace Clippy, build, nightly formatting, warnings-as-errors rustdoc, and the documentation book build pass.
All 13 generator tests and deterministic regeneration checks pass. The pinned upstream YANG module remains unchanged.
Generated Rust SHA-256: `ddfa160deaf1c1f33f94481a36a1dfa945147f990bcacdf33005487c8120ba42`.
Edited files have no editor diagnostics. No dependency, lockfile, IPC schema, or TLS implementation changes occur.
Native Redis, live SONiC, external TACACS+ peer, Windows, and Miri checks were not rerun.

This interval addresses stale source configuration, not every form of stale credential material.
At `e91fe02`, credential-provider failure while the source remained current still needed a separate budget and recovery contract.
Certificate validity deadlines and revocation evidence remain separate requirements.
Expiry uses the asynchronous runtime and serialized publication path; existing limits for non-yielding code and blocking I/O still apply.
These remaining policies stay within S4-04 and the later certificate/revocation stages. S4-04 is not complete.

## Credential Freshness Expiry

Commit `ed47f41` adds canonical `credential-stale-timeout-seconds`, a nonzero unsigned 32-bit seconds value with a generated default of 300.
It bounds referenced credential staleness independently of source configuration freshness.
The coordinator records whether the applied catalog depends on provider references. Inline-only material is not expired because an unused credential watcher is unavailable.

Relevant invalidation marks `CredentialsStale` before resolution begins. Failed refresh or notification loss leaves that state set.
An owned monitor captures the applied policy budget when it observes stale material.
Repeated failures, retries, and policy changes do not renew the interval.
Successful materialization resets freshness using the applied revision pair, including when watch updates coalesce.
A resolver that remains pending cannot avoid the timer by withholding its error result.

### Withdrawal and Revalidation

At expiry, the coordinator rechecks the active revision and stale state before withdrawing the complete upstream catalog.
The commit clears active material, publishes `CredentialsExpired`, and installs the same immediate retirement cutoff used by source expiry.
Readiness is withdrawn while liveness, source observation, and credential observation remain active.
Source health remains current if configuration itself is still current.

Credential expiry advances the credential revision so work started before withdrawal is superseded, even if it later resolves successfully.
Recovery requires a new complete materialization. It can use the unchanged canonical source, but it cannot reuse incomplete pre-expiry results.
Successful publication clears credential expiry and staleness when notifications are available.
If notifications remain unavailable, a successful revalidation begins a fresh grace interval rather than claiming continuous observation.

Source and credential expiry use explicit independent states: neither, source, credentials, or both.
The last withdrawn revision remains available for the second expiry check after the first has emptied the catalog.
Thus, credential recovery cannot revive configuration whose source budget expired later.
A stale expiry result cannot remove a newly revalidated generation.
An intentionally empty applied catalog does not start a material expiry timer.

### Recovery Ordering Fix

The new tests exposed a health ordering defect after notification reconnect.
Successful materialization could retain `CredentialsStale` because `CredentialNotificationsUnavailable` was cleared only after the commit returned.
That could expire healthy credentials later.
The supervisor now records recovered notification delivery before revalidation, while the commit controls material freshness.
If revalidation fails, material remains stale without falsely reporting that the notification connection is still unavailable.

### Regression Evidence

`failed_credentials_expire_even_while_source_is_current` failed before the fix after 301 virtual seconds.
It now withdraws last-known-good credentials while preserving source-current health.
`recovered_notifications_and_revalidation_clear_credential_staleness` also failed before its ordering fix.

Further tests verify:

- Repeated refresh failures and a larger policy budget do not postpone expiry.
- A pending resolver expires, and its late result cannot restore old material.
- Complete revalidation restores readiness with the same source revision and a newer credential revision.
- Notification loss expires referenced material but not an inline-only catalog.
- Both source-first and credential-first expiry preserve the second deadline after withdrawal.
- Credential recovery cannot bypass expired source configuration.

### Verification and Remaining Work

All 184 agent tests and the complete all-feature workspace suite pass, including the existing native process tests.
Strict workspace Clippy, build, formatting, warnings-as-errors rustdoc, and the documentation book build pass.
All 13 generator tests and deterministic regeneration checks pass. The pinned upstream YANG input is unchanged.
Generated Rust SHA-256: `c233c0d7dbf74b549cc3094e64e4e8d9aa5f0b449a21301f56b422b16e32ddef`.
Edited files have no editor diagnostics. No dependency, lockfile, IPC schema, or native TLS implementation changes occur.
Native Redis, live SONiC, external TACACS+ peer, Windows, and Miri checks were not rerun.

S4-04 remains open for absolute validity metadata and expiry, distinct from observed staleness.
Certificate-chain provisioning and revocation evidence remain the later Stage 4 contracts.
Expiry still depends on a yielding async runtime and serialized publication; it does not make blocking code preemptible or establish full RFC 9887 conformance.

## Absolute Provider Validity

Commit `8ff62cd` adds `CredentialValidity` to the provider-neutral credential contract.
Every resolved key, certificate identity, and certificate bag carries explicit validity metadata.
The interval includes its start and excludes its end. Missing bounds are unbounded; empty intervals are rejected.
Existing providers explicitly return unbounded metadata. This does not assert that encoded certificates remain valid indefinitely.

### Materialization and Publication

Configuration materialization intersects every provider interval used by a server.
It rejects conflicting intervals and material that is expired or not yet valid.
`MaterializedServer` returns the derived generated server together with its provider bounds.
Canonical YANG snapshots and credential references remain unchanged. No new desired-configuration field stores these runtime values.

The coordinator retains each active server's interval and monotonic deadline.
A partial refresh preserves unchanged servers' deadlines. The complete catalog uses the earliest deadline and the intersection of all intervals.
The manager checks validity again after preparation and publication-lock acquisition, before replacing the runtime.
Runtime routing and applied health receive the same validity metadata in the publication commit.
`RuntimeHealthSnapshot::credential_validity()` exposes the provider interval without credential material.

### Expiry and Clocks

An owned supervisor future monitors validity independently of source and credential staleness.
No notification failure is required to trigger expiry. Grace periods and policy changes cannot extend a validity deadline.
Expiry withdraws the complete upstream catalog, retires its endpoints, and publishes `CredentialsExpired` through the existing revision-fenced transaction.
Source-first withdrawal retains validity metadata so credential expiry still occurs independently.
Recovery requires complete valid materialization. Expired provider results cannot restore the catalog, and an old expiry cannot remove a recovered generation.

The runtime checks absolute bounds against the wall clock. It also captures a conservative monotonic expiry during preparation.
Retained material must satisfy both clocks. A backward clock change cannot extend its captured deadline.
The monitor rechecks wall time at most one second after a clock change, subject to runtime scheduling and publication locks.
Request binding checks wall and monotonic validity before and after connection acquisition.
Captured request deadlines never exceed the credential deadline, including after policy reload or admission waits.
Existing in-flight work after a forward wall-clock jump is withdrawn when the monitor runs; this is not hard real-time preemption.

### Verification

The focused provider, configuration, and agent tests pass. All 189 agent tests pass after the final clock regression.
The all-feature workspace suite passes, including native prepared-source and daemon process tests.
Strict workspace Clippy, workspace build, nightly formatting, and warnings-as-errors rustdoc pass.
Editor diagnostics and patch whitespace checks are clear. The documentation book also builds successfully.

New regressions cover:

- Half-open intervals, empty intersections, and source immutability.
- Not-yet-valid and expired provider results, with sanitized materialization errors.
- Expiry after preparation and while publication waits for a lock.
- Partial refresh and policy reload without renewal of retained deadlines.
- Expiry without notification failure and after source withdrawal.
- Rejection of expired replacement material and revision-fenced recovery.
- Old and new request bindings after expiry, with capped request deadlines.
- Forward and backward wall-clock boundaries and conservative monotonic intersection.

No dependency, lockfile, YANG artifact, IPC schema, or native TLS implementation changes occur.
Native Redis, live SONiC, the external TACACS+ peer matrix, Windows, and Miri checks were not rerun.

### Remaining Work

S4-04 remains open for intrinsic certificate validity extraction and lifecycle enforcement, including certificates configured inline.
Provider validity constrains resolved material but does not replace native certificate verification or revocation checks.
Canonical client-chain provisioning, revocation evidence, and operational statistics remain S4-05 through S4-07.
Expiry still requires a yielding runtime; arbitrary blocking work needs deployment limits.

## Client Certificate Lifetimes

Commit `23e7f98` closes the configured client-identity validity gap without adding a provider dependency to networking.
OpenSSL previously accepted expired local certificates during context construction. The failed-before regression confirms this behavior.
Native preparation now rejects expired and not-yet-valid client identities, even when the development option disables peer verification.

### Ownership and Enforcement

Networking owns `CertificateValidity` and decodes X.509 dates with OpenSSL ASN.1 APIs, without parsing formatted date strings.
Runtime use includes the start and excludes the end. Native chain construction intersects the supplied local certificate dates.
Canonical client-chain provisioning remains S4-05 work; the public identity input still accepts one certificate.
`PreparedEndpoint::client_certificate_validity()` exposes these intrinsic bounds separately from provider metadata and negotiated peer certificates.

The prepared TLS context retains a conservative monotonic deadline and checks the wall clock before and after use.
Direct client construction rejects expired prepared identities. Session creation checks validity even when a shared connection is cached.
Fixed exchanges and conversations cannot run past the captured certificate deadline, including when the caller supplies no deadline.
A longer caller deadline cannot extend certificate validity. Expiry during TLS setup remains `NotSent`; expiry after exchange entry is conservative about delivery.

The agent retains each prepared server's certificate lifetime across unchanged-slot reuse.
Publication intersects intrinsic and provider bounds, rechecks them, and commits the combined lifetime with routing and applied health.
The existing owned expiry monitor withdraws inline-certificate catalogs without a provider or credential notification failure.
Withdrawal preserves the expired metadata needed for independent source and credential expiry checks. Canonical snapshots remain unchanged.

### Native Test Fixture Fix

The workspace run exposed a collision in the process-test directory helper.
PID and wall-clock nanoseconds did not distinguish concurrent tests when clock timestamps matched.
The helper now adds a process-local sequence and retries occupied paths without reusing or deleting another test's directory.
A deterministic equal-timestamp regression verifies the fix.

### Verification

All-feature workspace tests pass, including 189 agent tests, ten prepared-source tests, and four native process tests.
Networking tests pass with two existing ignored tests. New regressions cover:

- Rejection of expired and future client identities with peer verification enabled or disabled.
- Native timestamp conversion before the Unix epoch and across the UTC/generalized-time range.
- Cached native TLS sessions and retained conversations after identity expiry.
- Cancellation of a stalled TLS handshake before a longer request deadline.
- Supervised inline-certificate withdrawal, policy reload, combined health bounds, and source immutability.

All nine independent TACACS+ peer cases pass, including certificate TLS, required mTLS, PSK, and plain or obfuscated TCP.
The peer binary reports `278d8c738cfb2ed8ba505fd1b60575fcc3fadca5` with OpenSSL 3.0.20.
Strict workspace Clippy, default-feature agent Clippy, workspace build, nightly formatting, warnings-as-errors rustdoc, and the networking dependency guard pass.
The documentation book builds. Final editor diagnostics and whitespace checks are clear.
No dependency, lockfile, YANG artifact, or IPC schema changes occur. Native Redis, live SONiC, Windows, and Miri were not rerun.

### Remaining Scope

S4-04 remains open for negotiated peer-chain validity and lifecycle behavior for alternative trust paths and pins.
Trust bags contain alternatives, not one required identity chain; this increment does not intersect every trust certificate into a catalog-wide expiry.
Existing native handshake verification remains in place, but peer-certificate expiry after connection establishment is not yet a lifecycle deadline.

Direct clients enforce configured identity validity on use; they do not add an idle-socket retirement task. Hosts retain explicit close/join ownership.
The supervised agent withdraws expired catalogs through its owned monitor. Wall-clock jumps and non-yielding work retain the documented scheduling limits.
Canonical chains, revocation evidence, and operational statistics remain S4-05 through S4-07. This work does not establish full RFC 9887 conformance.

## Negotiated Peer Lifetimes

Commit `7b3eed7` applies certificate validity to each established TLS transport.
The native idle-session regression failed before this change: the connection remained open after its authenticated peer certificate expired.

### Selected Path Metadata

Networking retains validity from the path accepted for that connection, not an intersection of all configured trust alternatives.
Platform trust uses OpenSSL's verified chain. An exact peer pin uses the matched leaf's dates.
Explicit CA validation uses the verified CA path, including its intermediates and trust anchor.
If an intermediate peer pin masks a separate CA path, alternate verification supplies the dates of the CA path it accepts.
Unused pins and other trust alternatives do not shorten that connection's lifetime.

The verifier records the selected interval in per-SSL data. One process-wide typed OpenSSL index avoids repeated index allocation on context reload.
Each SSL connection owns its metadata slot; connections do not share selected certificate dates.
The development verification override still checks the presented leaf's dates, but does not claim a verified chain.
`CertificateLifetime` replaces the narrower internal client-identity name and intersects local and peer bounds without extending either captured deadline.
Canonical snapshots, provider references, and prepared endpoint configuration remain unchanged.

### Owned Transport Expiry

Established transports carry their lifetime into the existing managed transport control.
That control owns an expiry task which holds only a weak reference back to the control.
Expiry closes both native transport halves and wakes pending I/O, even when an application retains an idle conversation.
Each read, write, flush, and shutdown poll also checks validity before native I/O, independently of timer execution.
This also closes idle transports when their configured local certificate expires.

Client lifecycle state retains expiry task handles and joins them during `close_and_join`.
Dropping the transport aborts its timer without a reference cycle. Dropping the client still closes its registered transports.
Cancellation-safe task handles remain available when a join is interrupted.
A completed driver can return its certificate-expiry I/O error after cleanup; native regressions distinguish that error from failed cleanup.

The monitor checks wall time at one-second intervals and observes the captured monotonic deadline.
Per-I/O checks apply the same bounds. Runtime scheduling and short native critical sections still limit physical closure timing.
This is not preemption of arbitrary blocking code, and a clock change does not undo completed I/O.

### Request and Recovery Semantics

Expiry after request transmission reports unknown delivery. It does not permit replay of that operation.
An expired peer connection does not make the canonical source stale or permanently withdraw its configured server.
A later connection can validate a fresh peer certificate through the unchanged endpoint and trust configuration.
Expired provider or configured client material still follows the existing catalog-level revalidation rules.

### Verification

New regressions cover idle cached peer expiry, retained sessions, in-flight unknown delivery, and fresh-certificate recovery without configuration reload.
Native path tests cover ordinary CA validation, alternate CA verification, and exact pins with shorter unused trust entries.
Managed transport tests prove that timer cancellation cannot permit expired I/O and that timer handles do not retain dropped transport owners.
Native closure checks accept EOF, reset, or broken pipe where TLS post-handshake writes encounter a closed socket; unexpected application bytes still fail.

All-feature workspace tests pass: 189 agent tests, 85 configuration tests, 166 networking tests with two existing ignored tests, and twelve prepared-source tests.
All four native process tests pass. All nine independent TACACS+ peer cases pass with the existing OpenSSL 3.0.20 peer binary.
Strict workspace Clippy, workspace build, nightly formatting, warnings-as-errors rustdoc, and the documentation book build pass.
The networking and credential dependency guards pass. Unused-dependency analysis passes; audit reports no vulnerabilities in 301 locked packages.
Audit retains the existing crates.io index-refresh lock warning. Editor diagnostics and whitespace checks are clear.

The only manifest change enables Tokio `test-util` for configuration's development dependency.
No package version, lockfile, YANG artifact, IPC schema, or unsafe-code changes occur.
Native Redis, live SONiC, Windows, and Miri were not rerun.

## S4-04 Closure

S4-04 is complete across seven implementation increments: `36d9cbc`, `37faec2`, `e91fe02`, `ed47f41`, `8ff62cd`, `23e7f98`, and `7b3eed7`.
Hosts own signals and cancellation. Canonical policies bound graceful teardown and stale source or credential use.
Provider, configured identity, and negotiated peer validity now bound their corresponding runtime resources.
Revision fencing preserves recovery and source authority, while owned tasks provide explicit cancellation and join paths.
Deployment limits for non-yielding code and started blocking I/O remain part of the lifecycle contract.

Stage 4 remains open for S4-05 canonical client-chain provisioning, S4-06 revocation evidence and freshness, and S4-07 operational statistics.
The next increment must provision canonical client chains before native tests for complete, missing, and incorrect intermediate chains.
No full RFC 9887 conformance claim is made.

## Canonical Client Chains

### Rationale

Mutual TLS requires the server to verify the client's certificate path, not merely receive its leaf certificate.
Many deployments trust a root CA but do not store every issuing intermediate.
A server can therefore reject a valid client identity when the client sends only its leaf certificate.
Explicit chain provisioning supplies the missing public certificates without assuming server-side retrieval or changing the server's trust policy.
The [configuration guide](../yang-config-guide.md#client-certificate-chains) explains the certificate hierarchy and when intermediates are needed.

### Canonical Input

Commit `3897414` adds the project-owned `tacacsrs:intermediate-certificate` leaf-list beneath client certificate `inline-definition`.
It applies to per-server identities and reusable `client-credentials` bundles. The existing `cert-data` field remains the leaf certificate.
Each ordered list entry contains one DER intermediate, encoded as RFC 7951 base64 in JSON.
Entries start with the leaf's issuer and proceed toward the root. The list excludes the leaf and self-signed root.
Canonical validation rejects empty or duplicate entries; native preparation validates certificate contents and the supplied path.

The existing generator supports ordered binary lists. Generated Rust adds `intermediate_certificate: Vec<Vec<u8>>` with the existing base64 serializer.
No generator algorithm or pinned upstream YANG source changes. Updated Rust, tree, and module hashes are recorded in the generation manifest.

### Provider and Input APIs

`CertificateWithKeyMaterial::intermediates` carries ordered provider bytes using the existing non-revealing `PublicBytes` wrapper.
Materialization moves those bytes into a derived inline identity. It leaves authoritative configuration and central references unchanged.
Provider validity still applies to the complete result. Intrinsic native validity intersects all supplied client certificates.

`CertificateIdentity::intermediates` borrows ordered DER slices. `with_tls_client_certificate_chain` constructs the canonical builder value.
The existing single-certificate builder methods delegate with an empty chain.
The CLI file loader now returns `ClientCertificateChain`, with separate leaf and intermediate fields.
PEM files accept the leaf followed by ordered intermediates; DER files still contain exactly one certificate.
The CLI adapter preserves the chain in canonical configuration, and both executable help texts describe the input order.

### Native Validation and Transmission

Native preparation requires one DER object per entry and rejects duplicate certificates, incorrect issuer order, and supplied self-signed roots.
OpenSSL checks the supplied path and client purpose using its highest supplied intermediate as a temporary validation anchor.
This validates supplied material without declaring that intermediate trusted by the remote peer.
The peer remains responsible for verifying a path to its own trust anchor; a missing upper intermediate can still fail during the handshake.
The development peer-verification override does not bypass local chain validation.

The reusable TLS context installs the leaf and ordered intermediates separately. The private key must match the leaf.
The earliest certificate expiry bounds the configured identity through the existing lifetime enforcement.
No canonical field becomes runtime state, and no source reference is rewritten.

### Verification

The native mTLS matrix uses a leaf, two distinct intermediates, and a root-only peer trust store.
Complete chains authenticate from inline, reusable-bundle, provider, and normalized PEM inputs.
Missing chains, a missing upper issuer, incorrect or reversed intermediates, duplicates, a repeated leaf, supplied roots, and concatenated DER entries fail.
Successful peers verify the supplied intermediates. Tests also check source immutability and the earliest intermediate's expiry bound.

Canonical tests cover ordered base64 round trips for both YANG locations and rejection of empty, duplicate, or malformed entries.
Provider tests cover intermediate transfer and non-revealing debug output. PEM tests use distinct certificate values to verify input order.
The all-feature workspace suite passes, including 189 agent tests, 86 configuration tests, 31 generated-type tests, and the existing native process tests.
Strict workspace Clippy, build, nightly formatting, warnings-as-errors rustdoc, and the documentation book build pass.
The affected crate dependency guards pass. All nine independent TACACS+ peer cases pass.
All 13 generator tests and deterministic regeneration pass. The pinned upstream module remains unchanged.

Artifact SHA-256 values:

- Generated Rust: `cf33c18b807f59a528f155bc2bf0d0bc202340f8cc38556c6c0e91f7a124ade0`.
- Expanded tree: `b4ef257bc03d9107c0418ddc6e2d62ae8aafb9c433aead41a1471fd273b39490`.
- Project YANG module: `3a42ef9eaabd127aa77b51c64a3d034eba008bea7ee5741895d0fd9023acd895`.

No dependency, lockfile, IPC schema, or unsafe-code changes occur. Editor diagnostics and whitespace checks are clear.
Native Redis, live SONiC, Windows, and Miri were not rerun.

## S4-05 Closure

S4-05 is complete. Canonical configuration owns ordered client chains, and providers or file adapters populate that same model.
Native preparation and mTLS tests enforce the supplied-chain contract while preserving source authority.
Stage 4 remains open for S4-06 revocation policy, evidence retrieval, freshness, and unavailable-status behavior, followed by S4-07 operational statistics.
This work does not implement revocation retrieval or establish full RFC 9887 conformance.

## Required Stapled Evidence

Commit `567ec16` adds an opt-in `tacacsrs:require-stapled-ocsp` presence container to server authentication and reusable server-credential bundles.
Its `max-response-age-seconds` leaf is a positive `uint32`, with a generated default of 300.
An absent container preserves existing certificate verification without adding a revocation requirement.
Bundle expansion copies the canonical policy into the derived server. Source snapshots and references remain unchanged.
Required evidence rejects PSK combinations and the development certificate-verification override before connection establishment.

### Verification and Freshness

Networking exposes `CertificateRevocationPolicy` and applies it to a prepared certificate TLS endpoint.
The client requests a staple and verifies it through OpenSSL's status callback during the handshake.
Native mTLS tests confirm that rejected evidence prevents client-certificate transmission, not only later TACACS+ traffic.
One typed OpenSSL index identifies per-connection policy, issuer inputs, and the verified interval or sanitized failure.

This increment accepts responses signed directly by the authenticated peer leaf's issuer.
The issuer must match the leaf's issuer relationship and verify its signature; candidates come from TLS chains and configured CA material.
OCSP verification uses only that issuer as a signer candidate. Embedded or delegated signing certificates are not accepted.
SHA-1 and SHA-256 certificate IDs are supported. Evidence must cover the actual peer certificate and report `GOOD`.
Missing, malformed, unsuccessful, wrongly signed, wrong-certificate, unknown, revoked, or stale responses fail closed.
The parser rejects staples over 64 KiB and DER responses with trailing data.

The accepted interval begins at `thisUpdate` and ends at the earlier of `nextUpdate` and `thisUpdate` plus the configured age.
When `nextUpdate` is absent, the configured age still limits use. There is no clock-skew allowance or stale grace.
The interval intersects certificate validity and flows into the existing monotonic and wall-clock transport lifetime.
Existing owned expiry tasks close idle or active transports when evidence expires. Reconnection must validate new evidence; no background responder query is added.

### Native Time Bridge

OpenSSL's safe Rust wrapper exposes OCSP timestamps as `Asn1GeneralizedTimeRef`, but its time-difference API requires `Asn1TimeRef`.
A small local unsafe bridge reborrows the native object for a read-only conversion. No reference escapes the call.
The installed C headers define both types as `ASN1_STRING`; the bridge records that safety requirement beside the cast.
Native tests cover pre-epoch, epoch, and generalized-time boundary values.

### Generator Repair

The first canonical policy test rejected the qualified JSON container name.
The generator applied project-module qualification to leaves and leaf-lists, but omitted it for containers and lists.
Both paths now receive parent-module context and use the existing RFC 7951 naming rule.
A generator regression covers qualified project containers and lists. The runtime policy test covers both direct and bundled inputs.
This fix stays within S4-06 because the new canonical policy exposed it.

### Verification

All-feature workspace tests pass, including 189 agent tests, 86 configuration tests, 33 generated-type tests, and thirteen prepared-source tests.
Networking passes 169 tests with two existing ignored tests. Native process tests also pass.
The native OCSP matrix uses locally generated, issuer-signed responses and checks good, missing, revoked, unknown, wrong-certificate, tampered, malformed, and unsuccessful evidence.
It also verifies client-authentication protection and idle expiry for both a short `nextUpdate` and absent `nextUpdate`.
Pure tests cover future and stale intervals, exclusive expiry, nonrenewal, and policy age bounds.

Strict workspace Clippy, build, nightly formatting, warnings-as-errors rustdoc, and the documentation book build pass.
Affected dependency guards pass. All nine independent TACACS+ peer cases pass with the new requirement disabled by default.
All 14 generator tests and deterministic regeneration pass; the pinned upstream YANG module remains unchanged.
Editor diagnostics and whitespace checks are clear. No dependency, lockfile, or IPC schema changes occur.

The user installed nightly `rust-src`, and Miri prepared its sysroot successfully.
Both pure revocation tests pass under Miri. The native bridge test cannot run because Miri does not support `OPENSSL_init_ssl`.
This is an interpreter limitation, not a passed FFI check. The bridge and complete OCSP path pass native tests.
Native Redis, live SONiC, and Windows checks were not rerun.

Artifact SHA-256 values:

- Generated Rust: `a7f98f8ad9a949887258f702805cd04eb4a949ab441ff83f4d65c569c35ba9c2`.
- Expanded tree: `fb513c5d60fca78d91292178dff9cf266f630422f7ac51fadb3657edaa806bad`.
- Project YANG module: `d20fbfcfc7bf1e1b7363512cebb799bf3530715be70efc71dd0f066dbdc77d1f`.

### S4-06 Remainder

S4-06 remains open. This mode covers issuer-signed peer-leaf staples, not complete revocation checking.
Remaining work includes delegated responders, issuer/intermediate revocation, and controller/provider integration for broader OCSP or CRL retrieval and refresh.
Future modes must retain explicit freshness, failure behavior, source authority, cancellation ownership, and native verification tests.
S4-07 operational statistics remains open. No full RFC 9887 conformance claim is made.

## Delegated Responders

Commit `d78cf06` extends the existing required-staple policy to authorized OCSP responders issued directly by the peer certificate's issuer.
The policy's shape, default maximum age, and failure behavior remain unchanged. Updated YANG descriptions state the delegated-responder requirements.
The original issuer-signed path remains supported.

### Authorization and Rationale

A CA can delegate OCSP signing to a separate certificate rather than use its issuing key for every status response.
The responder certificate must carry `id-kp-OCSPSigning`. If its key-usage extension is present, it must permit digital signatures.
The peer's issuer must issue and sign that responder certificate directly. Embedded certificates do not become trust anchors.

OpenSSL verifies the response signature, certificate path, and OCSP authorization against an issuer-scoped store.
Verification disables fallback to unrelated explicit OCSP trust grants. It does not disable signature, chain, or authorization checks.
The native signer accessor identifies the certificate actually used by verification, including an embedded delegated certificate.
Additional explicit checks enforce direct issuance and signing-key usage.

This increment requires exactly one noncritical `id-pkix-ocsp-nocheck` extension whose value is DER NULL.
No Check permits omission of a separate responder-certificate revocation check during that certificate's validity period.
Without it, a delegated responder would need its own revocation evidence. That retrieval path remains unimplemented, so those responses fail closed.
Malformed, duplicate, or critical No Check extensions are rejected.

### Lifetime and Ownership

The accepted evidence interval intersects the actual signer certificate's validity, the issuer's validity, and the existing response freshness limits.
A short-lived responder therefore retires the connection before a longer OCSP deadline.
Unused certificates embedded in the response do not shorten the selected signer's interval.
Existing owned transport expiry, handshake-time rejection, and client-authentication protection remain in place.
No canonical source, reference, or runtime revision semantics change.

The small native adapter keeps the response and supplemental certificate stack alive while reading their borrowed signer and extension data.
It checks returned pointers and indices and returns only owned timestamp values. It does not free borrowed native objects or export raw pointers.
Each unsafe operation records its ownership and lifetime assumptions. The native matrix exercises issuer and delegated signer paths.

### Nearby Defect

The rejection matrix initially accepted a responder whose key usage allowed encryption but not signing.
OpenSSL's OCSP authorization alone did not reject that case in the tested native version.
An explicit digital-signature check now rejects it. An absent key-usage extension remains valid because it imposes no usage restriction.

### Verification

The authorized-delegation regression failed against the issuer-only implementation and passes after this change.
Native tests verify accepted delegation, responder-limited idle expiry, absent key usage, and an unrelated expired certificate embedded in a valid response.
They reject missing or wrong OCSP usage, encryption-only key usage, missing or invalid No Check, expired or future responders, and wrong issuer signatures.
The existing issuer-signed status, signature, freshness, and mTLS protection matrix also passes.

All-feature workspace tests pass, including 189 agent tests, 86 configuration tests, 169 networking tests with two existing ignored tests, and fifteen prepared-source tests.
Strict workspace Clippy, workspace build, nightly formatting, warnings-as-errors rustdoc, and the documentation book build pass.
All nine independent TACACS+ peer cases pass. All 14 generator tests and deterministic regeneration pass.
Both pure revocation tests pass under Miri. Native OpenSSL calls remain unsupported by Miri; the new native adapter is not Miri-verified.
Editor diagnostics and whitespace checks are clear. Native Redis, live SONiC, and Windows checks were not rerun.

No dependency, lockfile, IPC schema, or canonical field-shape changes occur. Only the policy descriptions and their generated documentation hashes change.
Generated Rust SHA-256: `ba4a5e0e8c740c911acde3781b05970c75d6f49f0b7cae39db20109cfec5da0f`.
Project module SHA-256: `a387521446fe568cf1f86f879049085aa411a717101f0b5c84e50bc0fab2d350`.
The expanded-tree hash remains `fb513c5d60fca78d91292178dff9cf266f630422f7ac51fadb3657edaa806bad`.

### Remaining Work

S4-06 remains open for responder revocation without No Check, issuer/intermediate revocation, and broader evidence retrieval and refresh.
This implementation checks the peer leaf's stapled status. It does not establish complete revocation coverage or full RFC 9887 conformance.
S4-07 operational statistics remains open.

## Full CRL Evidence

Commit `a06fced` adds the opt-in `tacacsrs:require-crls` presence container to server authentication and reusable server-credential bundles.
It requires exactly one evidence source: an inline `crl` array or an opaque `evidence-reference`.
Each inline value contains one complete DER CRL, encoded as RFC 7951 base64. `max-age-seconds` is positive and defaults to 300.
This mode rejects exact peer pins, PSK, required stapled OCSP, and disabled certificate verification.

### Provider and Source Ownership

The provider-neutral crate adds a closed `CertificateRevocationLists` request kind, opaque reference, and typed result variant.
`CertificateRevocationListsMaterial` carries public byte wrappers and independent provider validity. Debug output omits evidence and raw reference values.
CRL slots follow the existing credential slots in deterministic order. Result-set construction still checks request kinds, slots, and response variants.

Configuration inspection, planning, bundle expansion, and materialization handle CRLs through the same abstractions as other provider material.
Only the derived server receives inline evidence; its authoritative source and provider references remain unchanged.
The existing dependency index and credential-change contract can trigger CRL revalidation and generation replacement.
The stock SONiC resolver does not implement this material kind. Hosts must supply a compatible resolver, or use inline evidence in canonical JSON.
This increment adds no HTTP client, distribution-point fetcher, or detached retrieval task.

### Native Verification

Prepared evidence is limited to 4 MiB and one CRL per issuer name.
Preparation checks exact DER framing, required `nextUpdate`, signed freshness bounds, and a nonempty interval across the complete set.
Delta CRLs, issuing-distribution-point extensions, and freshest-CRL references are rejected explicitly.
The implementation supports unscoped full CRLs only; it does not silently treat partial evidence as complete.

During TLS verification, OpenSSL revalidates the accepted CA path using the same selected anchor and supplied CRLs.
Native CRL flags enforce signature verification, issuer coverage, and revocation checking across that path.
Revoked leaves, revoked intermediates, incorrect signatures, and missing issuer evidence reject the connection before client authentication or TACACS+ data.
Per-SSL result state records completion and native failure details. A successful handshake cannot produce a usable transport without the required CRL check.
The native store retains its own references to CRLs; local unsafe calls document ownership and borrow requirements.

### Lifetime and Refresh

Every supplied CRL contributes to the prepared evidence interval, including lists not selected by a later connection.
The end is the earliest `nextUpdate` or `thisUpdate` plus maximum age. Provider and client-certificate bounds can shorten it further.
`PreparedEndpoint::prepared_credential_validity()` exposes these combined preparation constraints separately from the client-certificate-only getter.
Direct clients check the combined lifetime, and the agent publishes it with routing and applied health.
The existing owned expiry monitor withdraws an expired catalog even while the source remains current.

Fresh inline configuration or provider invalidation uses the existing materialization and revision-fenced publication path.
New generations use new evidence. In-flight requests retain the existing generation, request deadline, and bounded retirement contract.
Immediate retirement based on newly observed revocation requires further controller integration; this increment does not claim that behavior.

### Generator Fix

The new evidence choice exposed an optional-binary-list generator defect.
The Rust field became `Option<Vec<Vec<u8>>>`, but the generator selected the non-optional base64 serializer, causing compilation to fail.
An optional-list serializer now preserves absence and base64 values, and the generator selects it for optional binary vectors.
A focused generator regression and canonical round-trip test cover the correction. Evidence-choice validation rejects empty lists and conflicting sources.

### Verification

Native tests cover inline, provider, and reusable-bundle evidence, bad signatures, stale lists, trailing DER data, and idle transport expiry.
A root-and-intermediate fixture verifies that complete evidence authenticates and that revoked intermediates or missing issuer CRLs fail before client authentication.
A supervisor test advances past evidence freshness and observes catalog withdrawal without source failure or canonical-source mutation.
Provider tests cover byte preservation, redaction, typed references, and closed result matching.

All-feature workspace tests pass, including 189 agent tests, 86 configuration tests, 34 generated-type tests, and eighteen prepared-source tests.
Networking passes 169 tests with two existing ignored tests. Native process tests pass.
Strict workspace Clippy, build, nightly formatting, warnings-as-errors rustdoc, and the documentation book build pass.
Affected crate dependency guards and all nine independent TACACS+ peer cases pass.
All 15 generator tests and deterministic regeneration pass. The pinned upstream module is unchanged.
The new provider material test passes under Miri. Native OpenSSL remains unsupported by Miri, so native CRL verification is not Miri-verified.
Editor diagnostics and whitespace checks are clear. Native Redis, live SONiC, and Windows checks were not rerun.

Artifact SHA-256 values:

- Generated Rust: `9c3736c6fa7849e0fe8e8baead09c6b80a5dc2b1ece92433494bfc66db0dc804`.
- Expanded tree: `47a8af50174b77018a950e2e014d696afae98cd5d2290d0e67f4c5c76b12b08a`.
- Project module: `2b40bc4a65bb771b0f8461edaafe3a583d4021a0f03781ad45dc2b5a7c0db454`.

No dependency, lockfile, or IPC schema changes occur.
S4-06 remains open for built-in remote retrieval, proactive refresh and retirement, responder revocation without No Check, and additional evidence forms or combinations.
S4-07 statistics remains open. No complete revocation-coverage or full RFC 9887 conformance claim is made.

## CRL Refresh Retirement

Commit `f55973a` closes the normal-drain gap after accepted CRL changes.
Previously, replacing CRL evidence prepared new endpoints but left old endpoints usable until the ordinary request-based retirement deadline.
That grace period could retain active connections authenticated with earlier evidence.

### Publication Policy

Before publication, the agent compares the current and replacement CRL policy for each retained server name.
A changed CRL set or policy marks that server for immediate retirement. Identical evidence does not.
The comparison occurs outside the runtime publication lock; it does not compare large evidence buffers during the commit.

After preparation and final publication checks succeed, the manager installs the selected cutoffs before exposing the new runtime and health generation.
Replaced endpoints for marked servers receive one immediate cutoff. Other replaced endpoints retain the normal drain deadline.
Rejected preparation leaves the applied generation and active connections unchanged.
The coordinator's existing revision fencing still excludes superseded source or credential work before it reaches this publication path.

This policy is conservative: an accepted evidence change invalidates old sessions without claiming that each peer was individually proved revoked.
It can interrupt in-flight work. Unknown delivery remains non-retriable under the existing conservative retry contract.
The rule applies to CRL changes for an existing configured server name. It does not redefine ordinary server removal or renaming semantics.

### Historical Generations

`RoutedClient::retire_replaced_with_deadlines` selects a deadline from each removed endpoint's name.
The existing uniform-deadline method delegates to it. Earlier cutoffs cannot be extended by a later call.
The selection also visits already-retiring endpoints from older catalogs in the same runtime family.
Retained identities and unpublished candidate endpoints are excluded.

This closes a second gap: an ordinary reload can start draining one generation before a later CRL update arrives.
The later update now shortens the older endpoint's cutoff too, rather than considering only the immediately previous catalog.
The lifecycle registry retains only the endpoint name for this selection, not a copy of its prepared TLS context or credential material.

The cutoff synchronously rejects new bindings through affected endpoints.
Existing owned retirement tasks cancel setup, close native connections, and join cleanup. Socket closure still depends on runtime scheduling and yielding code.
This is not hard real-time preemption, and already completed I/O cannot be withdrawn.

### Verification

Focused networking tests cover immediate and graceful endpoints in one replacement, unchanged identity reuse, and nonrenewable deadlines.
They also cover older draining generations and prove that an unpublished candidate remains usable.
Both new pure lifecycle tests pass under Miri.

The native regression runs the public agent through IPC and holds a transmitted accounting request on a real mTLS connection.
An identical reload and a rejected malformed CRL candidate leave the peer open. An ordinary timeout reload also retains its grace interval.
A later accepted CRL update closes that older peer within the test's one-second bound, without consuming the normal request budget.
The request fails, the generation remains unchanged on rejection, and the host shuts down and joins its tasks.

The all-feature workspace suite passes, including 189 agent tests, 171 networking tests with two existing ignored tests, and nineteen prepared-source tests.
Strict workspace Clippy, workspace build, nightly formatting, warnings-as-errors rustdoc, and the documentation book build pass.
The affected tests and package Clippy checks pass after the final metadata ownership refinement. Editor diagnostics and whitespace checks are clear.
No dependency, lockfile, generated YANG, IPC schema, or unsafe-code changes occur.
Native Redis, live SONiC, the external peer matrix, and Windows checks were not rerun for this publication/lifecycle increment.

S4-06 remains open for built-in remote evidence retrieval, proactive refresh, responder revocation without No Check, and additional evidence forms or combinations.
The CRL refresh cutoff is implemented within the existing work item. S4-07 statistics remains open.

## Proactive Provider Refresh

Commit `5b9ba63` adds an owned refresh future alongside source observation, credential notifications, and the existing expiry monitors.
The supervisor now revalidates provider-backed material without waiting for a notification or an outage.
The failed-before regression supplied renewed provider validity without an event; the old supervisor never fetched it before expiry.

### Canonical Scheduling Policy

The project runtime-policy resource adds `credential-refresh-interval-seconds`, a positive unsigned 32-bit value with a generated default of 60.
The agent projects it to a `Duration`; it does not introduce another desired-policy model.
The scheduler uses the smaller of that interval and half the remaining prepared lifetime, with a one-second minimum spacing.
Material without an upper bound uses the configured interval. Expired or withdrawn material can be retried at that interval.

The next interval starts after the previous attempt completes. This is a scheduling bound, not a timeout for provider I/O.
A pending deadline can move earlier after a shorter policy or material lifetime, but unrelated health updates cannot postpone it.
There is no detached task or busy retry loop. Without a resolver, the refresh future only waits for cancellation.
An inline-only accepted source has no automatic resolution work, even when the host supplies an otherwise unused resolver.

### Admission and Publication

Scheduled refresh enters the same materialization coordinator and credential revision sequence as observed changes.
It selects the accepted source's provider-backed work and uses existing complete materialization and revision-fenced publication.
Source revisions, canonical snapshots, and credential references remain unchanged.
The loop cannot refresh an expired configuration source or reuse a source projection still waiting for filtering.

A timer tick does not mark valid material stale. A failed refresh uses the existing credential-resolution failure and stale-grace rules.
Successful revalidation commits freshness and validity through the existing publication transaction.
The absolute-validity and stale-material monitors remain independently polled while a provider call is pending.
Host stop drops the owned refresh future, including its in-progress resolution or publication wait.
Providers remain responsible for bounded, cooperative retrieval operations; this does not make blocking code preemptible.

### Unchanged Validity Protection

Repeated preparation previously constructed a new monotonic cutoff from the provider's absolute bounds.
Automatic revalidation makes it important not to renew that cutoff for an unchanged interval.
When the same server receives unchanged provider bounds, the coordinator intersects the new lifetime with the earlier active lifetime.
This preserves the original monotonic expiry even when wall time moves backward or tests advance only the monotonic clock.
Genuinely renewed validity can publish a later interval, subject to native certificate and signed-evidence bounds.

### Verification

The failed-before test now refreshes a provider before expiry without a notification source, retaining the source revision and advancing the credential revision.
Further tests cover unchanged-bound expiry, longer policy updates without postponement, shorter policy updates, and inline-only catalogs.
Failure tests verify stale expiry and later recovery without notifications.
A pending provider does not block independent expiry or host cancellation, and a scheduled attempt alone does not set `CredentialsStale`.

The native CRL test uses a reusable credential bundle and provider reference, then changes provider validity without sending an event.
Scheduled materialization preserves the canonical source and reference, publishes renewed validity, and keeps the catalog available.
It still uses the signed CRL's intrinsic deadline; unbounded provider metadata does not remove that limit.

The all-feature workspace suite passes, including 195 agent tests, 87 configuration tests, and twenty prepared-source tests.
Strict workspace Clippy, build, nightly formatting, warnings-as-errors rustdoc, and the documentation book build pass.
The pure refresh-delay test passes under Miri. Existing nightly manifest and `fetch_update` warnings remain; Rust 1.88 compatibility is unchanged.
All 15 generator tests and deterministic regeneration pass. Editor diagnostics and whitespace checks are clear.
No dependency, lockfile, IPC schema, or unsafe-code changes occur.
Native Redis, live SONiC, the external peer matrix, and Windows checks were not rerun for this controller scheduling increment.

Artifact SHA-256 values:

- Generated Rust: `6dbff05d85ed3dc99c6b286734083677280e95fe7d4f0d170579dff4e733a91e`.
- Expanded tree: `0c3ced4aacc7b3ec4253a823687f1cb998ae27858a7667e5917a11faf0ebcefa`.
- Project module: `dcbd5f56fb29b978c7eed779576e685c20c9a2a951ed74b3facb294e0648aa28`.

S4-06 remains open for built-in remote evidence retrieval, responder revocation without No Check, and other evidence forms or combinations.
This increment orchestrates attached providers; it does not add an HTTP client or distribution-point discovery.
S4-07 operational statistics remains open. No full RFC 9887 conformance claim is made.