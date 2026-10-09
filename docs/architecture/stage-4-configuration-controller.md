# Stage 4: Configuration Controller and Lifecycle

## Status

Stage 4 is in progress as of 2026-10-09. Commit `6a11a83` completes the first increment.
Canonical YANG remains authoritative. Prepared runtime policy remains a derived value.
This increment does not complete the shared configuration controller or credential lifecycle.

Fix nearby findings within each increment when practical. Keep completed items and their verification evidence.
The startup race and closed-runtime publication fix belong to S4-01, not separate work items.

## Checklist

- [x] S4-01: Own canonical policy observation in configuration and policy supervision in the agent. Commit `6a11a83` removes daemon policy algorithms and closes the startup race. See [policy observation](#policy-observation).
- [ ] S4-02: Replace configuration load/subscribe startup with owned observations for every retained source. Move generic recovery and materialization supervision out of the daemon. Verify startup races, subscription recovery, and source cancellation.
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

`ConfigDatastore` still exposes separate `load()` and `subscribe()` methods. Its controller migration remains S4-02/S4-03.
The daemon still owns configuration recovery and materialization coordination.
This increment does not introduce source revision semantics or retain canonical policy history in the controller.

Credential-only updates must derive new generations from unchanged YANG snapshots with separate credential revisions.
Preparation and publication must not rewrite authoritative credential references.
Client-chain provisioning, revocation retrieval, and operational statistics retain their explicit owners and acceptance criteria above.
Current verification does not claim full RFC 9887 conformance.