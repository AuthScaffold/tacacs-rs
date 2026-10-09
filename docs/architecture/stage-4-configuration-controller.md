# Stage 4: Configuration Controller and Lifecycle

## Status

Stage 4 is in progress as of 2026-10-09. Commit `6a11a83` completes the first increment.
Commit `1cca6a4` moves configuration recovery and materialization coordination into the agent. S4-02 is partially implemented.
Commit `75aac8b` adds canonical observation sessions and file watcher ownership. The supervisor now uses observations for startup and recovery.
Canonical YANG remains authoritative. Prepared runtime policy remains a derived value.
This increment does not complete the shared configuration controller or credential lifecycle.

Fix nearby findings within each increment when practical. Keep completed items and their verification evidence.
The startup race and closed-runtime publication fix belong to S4-01, not separate work items.

## Checklist

- [x] S4-01: Own canonical policy observation in configuration and policy supervision in the agent. Commit `6a11a83` removes daemon policy algorithms and closes the startup race. See [policy observation](#policy-observation).
- [ ] S4-02: Replace configuration load/subscribe startup with owned observations for every retained source. Commit `1cca6a4` moves recovery and materialization into the agent. Commit `75aac8b` completes file observation ownership and migrates supervision. Native SONiC observation ownership and transitional API removal remain open. See [owned configuration observations](#owned-configuration-observations).
- [ ] S4-03: Publish generations and applied-health metadata through one controller. Track source and credential revisions separately. Reject stale completions and retain global admission across replacement.
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

Runtime supervision now uses `ConfigDatastore::observe()`. The separate `load()` and `subscribe()` methods remain transitional APIs.
Native SONiC ownership and adapter removal remain S4-02. Revision and publication coordination remain S4-03.
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

The following increment addresses the file observer and runtime contract. SONiC worker ownership remains open.

## Owned Configuration Observations

Commit `75aac8b` adds `ConfigDatastore::observe()` and the `ConfigObservation` contract.
An observation supplies canonical `ConfigChangeEvent` values, including its baseline. Cancelled reads must retain pending work.
Snapshots remain `Arc<TacacsPlus>` values. No competing desired-configuration model or revision scheme is introduced.

The agent retains one observation across successful initialization and live updates.
After observation failure or completion, it drops the session, waits through backoff, and opens observation before reading the replacement baseline.
The supervisor no longer calls `load()` or `subscribe()` directly.
Credential supervision and the materialization coordinator remain unchanged.

Static sources produce one baseline and then end, without a worker task.
The transitional default adapts immutable loads or continuous subscriptions to the new contract.
Continuous adapters require a post-subscription baseline. They do not provide backend task ownership by themselves.
SONiC still uses this adapter. S4-02 stays open until its Redis notification and reload workers have an explicit owner.

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

Remaining S4-02 work: native SONiC observation ownership, Redis cleanup tests, and removal of the transitional default and legacy subscription APIs.
One-shot configuration loading can remain where a caller genuinely needs it.
Unified generation/health publication, source and credential revision semantics, and the other Stage 4 obligations remain unchanged.