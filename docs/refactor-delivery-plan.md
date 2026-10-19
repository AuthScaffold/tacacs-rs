# General Refactor Delivery Plan

## Authority And Scope

The source baseline is `ac40f27db8c47a291cd9ec245ae4d5831ecfa860` on `main`.
The tracking branch is `refactor/general`.
The [architecture review](architecture-review-2026-10-19.md) and [source ledger](architecture-review-2026-10-19-files.md) define the starting evidence.
This delivery plan supersedes the review's suggested implementation order.

The user authorizes implementation subagents, separate worktrees, commits, pushes, and stacked GitHub pull requests.
This authority applies to later implementation, not to a plan-review-only invocation.
Every iteration can introduce breaking changes and remove obsolete APIs.
Do not preserve compatibility aliases, duplicate execution paths, or obsolete configuration forms merely for compatibility.
Propagate each intentional change through all affected consumers, tests, documentation, and tooling.

Canonical YANG, protocol correctness, protected secrets, explicit ownership, and supported platforms remain requirements.
Per-library SemVer, executable CalVer, and hydrated release commits remain the current release policy.
Do not merge PRs, publish releases, create release tags, or change that policy without separate authorization.
Do not modify the existing diagnostics worktree.

## Review Provenance

The required reviewer routes are `GPT-6 Astra (copilot)` and `Claude Opus 5.5 (copilot)`.
The tool accepted both routes for the initial sequence review.
The first Astra request used an invalid identifier, failed before execution, and was retried with the accepted identifier.
Model routing comes from tool invocation metadata, not a reviewer's self-description.
The initial sequence reviews do not satisfy the written-plan review gate.
GPT-6 Astra must directly review and revise this plan first.
Claude Opus 5.5 must then directly review and revise the resulting plan.
Complete both reviews and necessary follow-up before the tracking commit or implementation.

Initial feedback changes the delivery design as follows:

- Add a regression-protected stacked-base CI filter in iteration 01.
- Expand secret ownership to downstream proxy keys and promotion copies.
- Include every certificate-evidence attachment method in the endpoint redesign.
- Separate prepared operations from outcome-forwarding changes.
- Establish candidate budgets before prepared-catalog publication.
- Type coordinator state before changing preparation and commit boundaries.
- Separate embedding API reduction from candidate-budget policy.
- Keep file observation independent of source and policy acceptance semantics.
- Keep product registry extraction separate from TOML tooling evaluation.
- Isolate OSS prototypes and integrate only accepted implementations.
- Record required platform evidence without treating skipped or unavailable checks as executed.

Plan review status:

- [x] GPT-6 Astra reviewed the written plan and applied necessary revisions.
- [x] Claude Opus 5.5 reviewed the resulting written plan and applied necessary revisions.
- [x] Material review changes received the necessary follow-up review.
- [x] Plan links, recommendation coverage, branch names, and gates pass validation.

## Stack And Worktrees

The tracking commit contains the two review documents and this complete plan.
Implementation branches start from that reviewed commit, then from the final locally verified predecessor head.
PR 01 targets `main` and includes the planning commit.
Each subsequent PR targets its immediate predecessor branch.
The tracking branch remains a stable planning anchor, not an unreviewed integration branch.

Branch names use `refactor/general-iterations/<slug>`.
Do not use `refactor/general/<slug>`: the existing tracking ref prevents that Git ref hierarchy.
Before creation, check local and remote refs for exact-name and ancestor/descendant conflicts.
Record the exact predecessor SHA and PR base branch, not only an iteration number.
Do not use the tracking branch as PR 01's base or advance it with implementation commits.
Worktrees use `$HOME/tacacs-rs-<slug>`.
Build caches use `$HOME/.cache/tacacs-rs-<slug>` and remain separate between worktrees.
Set `CARGO_TARGET_DIR` to that cache in every build shell.
Use `git worktree list` to verify ownership before creation or cleanup.
An existing branch, worktree, or cache requires an ownership check, not automatic reuse or deletion.

| Iteration | Slug | Recommendations | Predecessor |
| --- | --- | --- | --- |
| 01 | `01-secret-boundaries` | R1, R3, stacked CI prerequisite | Reviewed tracking commit |
| 02 | `02-yang-choices` | R2 | 01 |
| 03 | `03-endpoint-addresses` | R4, R11 | 02 |
| 04 | `04-credential-targets` | R5, provider naming and ownership contracts | 03 |
| 05 | `05-candidate-budgets` | R14 | 04 |
| 06 | `06-prepared-operations` | R6, R15 consuming IPC and Bash builder | 05 |
| 07 | `07-binding-outcomes` | R10 | 06 |
| 08 | `08-file-observation` | R13 | 07 |
| 09 | `09-coordinator-state` | R8 | 08 |
| 10 | `10-prepared-publication` | R7 | 09 |
| 11 | `11-embedding-api` | R9 | 10 |
| 12 | `12-load-scheduler` | R15 result storage | 11 |
| 13 | `13-emulator-cleanup` | R15 endpoint connector and policy compilation | 12 |
| 14 | `14-product-registry` | R12 | 13 |
| 15 | `15-toml-editing` | TOML Kit versus existing Rust TOML editing | Last accepted stack head |
| 16 | `16-systemd-notifications` | Direct notification library evaluation | Last accepted stack head |
| 17 | `17-codec-evaluation` | Tokio-util framing evaluation | Last accepted stack head |
| 18 | `18-packaging-evaluation` | `dist` local packaging evaluation | Last accepted stack head |

For iterations 15 through 18, the predecessor is the previous reviewed integration or documentation-only decision head.
Rejected experimental commits never become a predecessor.
Independent work can use separate commits or delegated file scopes inside an iteration.
Only one writer owns a file at a time.
Do not run builds concurrently against one target directory.
Do not start descendant implementation while predecessor review revisions remain unresolved.

## Common Iteration Procedure

1. Verify the predecessor SHA, branch, worktree state, and applicable crate guides.
2. Create the named branch and worktree from the exact verified predecessor.
3. Assign implementation to a subagent with that worktree as its exclusive source root.
4. Add failing regressions for defects, or characterization tests for structural changes.
5. Make the smallest coherent change and run its focused check immediately.
6. Run the required local gates for the completed iteration.
7. Route the first direct review through `GPT-6 Astra (copilot)` in that worktree.
8. Rerun affected gates. Route the resulting tree through `Claude Opus 5.5 (copilot)` for direct review and necessary revisions.
9. Rerun affected gates. Return material revisions to each reviewer whose earlier conclusion they invalidate.
10. Record exact routes, input/output content hashes, findings, dispositions, and executed gate evidence in the iteration receipt.
11. Commit the final tested tree, push normally, and open the explicitly based stacked PR.
12. Verify the remote head, base branch, PR URL, required workflow start, and current CI status.

Give each reviewer the predecessor SHA, complete iteration diff, relevant contracts, and existing check results.
Require direct necessary revisions, not only review advice.
Reviewers run a focused check immediately after their first substantive edit.
Run the reviewers sequentially with exclusive write ownership, not against parallel copies of the same input.
A reviewer does not need to invent edits when no revision is necessary.
An unavailable named model blocks that review gate. Do not substitute another model silently.
Do not claim a final tree received both reviews if later edits invalidate one review.
Keep follow-up open until both reviews remain valid for the resulting content.
Each reviewer marks only their own status after resolving their blockers and checking their revisions.

Iteration receipts belong in the corresponding plan section or a linked PR body.
Update the implementation branch's plan copy, not the stable tracking branch.
Record status, branch, worktree, predecessor, tested head, reviewer evidence, PR URL, and unavailable gates.
Use content hashes that include uncommitted and new reviewed files. `HEAD` alone does not identify a dirty input.
For plan reviews, use `git hash-object docs/refactor-delivery-plan.md` before edits and after final validation.
Report the output hash outside the hashed file to avoid a self-referential receipt.
Do not put tokens, raw secrets, or operator credential contents in receipts or prompts.

### Local Gates

Every Rust iteration requires focused tests first, then these gates on the final tree:

```bash
cargo +nightly fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --document-private-items
cargo +stable build --workspace --locked
cargo +stable test --workspace --all-features --locked
cargo +1.88.0 check --workspace --all-targets --all-features --locked
```

The MSRV command mirrors the hosted `Minimum Rust 1.88` job. Tests run on the stable toolchain, as in hosted CI.
Use a working installed Clippy toolchain when the default toolchain lacks it.
Record the actual toolchain. Do not silently raise the product MSRV.
Before a gate starts, verify its toolchain, native dependencies, fixture prerequisites, and current entry point.
Record the exact command, exit status, and executed cases, including skips and expected compiler failures.
An unavailable required gate remains pending or blocked, not passed by documentation.
Documentation-only decisions require document validation and affected tooling checks, not unrelated Rust rebuilds.

When interfaces or dependency edges change, run the [architecture checks](../.github/steps/check-architecture/README.md) and affected consumer profiles.
Use the profile selections from the [reusable workflow](../.github/workflows/reusable-pipeline.yml), each with its own target directory beneath the worktree cache.
Local checks with native dependencies installed do not prove the hosted no-native-dependency profile.
For workflow, inventory, or release changes, run the applicable suites from this existing command:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider .github/steps/cargo-metadata .github/steps/check-architecture .github/steps/compute-versions .github/steps/inject-versions .github/steps/release-manifest
```

For YANG changes, use the pinned environment and regeneration commands in the [development guide](../DEVELOPMENT.md).
Offline manifest consistency does not substitute for actual regeneration.

Dependency changes also require audit, unused-dependency checks, lockfile review, and dependency freshness assessment.
Use the current [unused-dependency action](../.github/steps/check-unused-deps/action.yml), including its feature configuration.
Preserve its `RUSTFLAGS` addition of `--cfg tokio_unstable` when checking console-enabled builds.
The [freshness action](../.github/steps/check-outdated/action.yml) reports newer versions without making availability alone a failure.
Protobuf changes require `buf breaking --against ".git#ref=$PARENT_SHA"` with the recorded predecessor commit available locally.
Classify intentional schema breaks explicitly. A reviewed break is not a passing compatibility check.
Protocol/parser changes require relevant fuzz smoke tests.
Unsafe or FFI changes require relevant Miri/ABI checks. Native OpenSSL is not generally executable under Miri.
Coverage-sensitive ownership changes require focused coverage evidence or a documented limitation.

### Platform And Integration Gates

Affected Windows `tacon` and ARMhf execution remain required hosted CI gates.
Iteration 01 adds `refactor/general-iterations/**` to the PR base filter and tests that contract.
Require an actual workflow run for every PR, not merely a successful local YAML parse.

Hosted CI can run while the next iteration prepares its regression tests or implementation.
That scheduling does not make a pending predecessor merge-ready.
Do not publish a descendant as verified while a required predecessor gate fails.
Pause dependent work on a concrete failure and repair the lowest affected iteration.
Propagate fixes with normal forward merges and rerun descendant checks. Do not force-push published history.

For iterations 03, 05, 06, and 10, run applicable native prepared-source and independent TACACS+ interop cases.
Name executed cases and prerequisites. An early-return test is not native execution evidence.
Use private fixtures, local listeners, and owned Redis instances where needed. Do not contact operator endpoints.
Follow SONiC/QEMU and session-wrapper platform instructions when their files or tests are affected.

The connector boundary tests remain required for iterations 06 through 11.
The standalone `connector_send` fixture is not currently a CI gate.
For connector changes, run the [compiler fixture](../libraries/tacacsrs_networking/tests/fixtures/connector_send.rs) explicitly with Rust 1.88.
From the Linux worktree root, use these commands:

```bash
cargo +1.88.0 test -p tacacsrs-networking --test connector_boundary --all-features --locked
rustc +1.88.0 --edition=2021 --cfg generic_adapter --emit=metadata -o /dev/null libraries/tacacsrs_networking/tests/fixtures/connector_send.rs
rustc +1.88.0 --edition=2021 --emit=metadata -o /dev/null libraries/tacacsrs_networking/tests/fixtures/connector_send.rs
```

The generic positive case must compile. The monomorphic case must fail for the documented `Send`/lifetime reason.
A check runner must record the final command's expected nonzero status and diagnostic separately.
A missing compiler, unrelated syntax error, or zero selected tests does not satisfy that gate.

### Security And Identity Invariants

These invariants apply throughout the stack, especially iterations 03, 06, 07, 09, 10, and 17:

- Keep source, credential, and policy revisions distinct from runtime generations, counter epochs, connection generations, and negotiation epochs.
- Preserve first-response single-connect negotiation, stale-promotion rejection, and owned cleanup across cancellation and handoff.
- Preserve `OutcomeUnknown` for malformed IPC replies and gRPC transport failures. Neither proves `NotSent` or permits automatic replay.
- Keep one absolute request deadline across preparation, admission, and attempts.
- After request expiry, retain a separate bounded cleanup owner. Cleanup cannot renew the request deadline or authorize another attempt.
- Preserve connection-setup authentication-date checks from #277. Provider validity and revocation freshness remain separate runtime constraints.
- Keep HTTP retrieval explicitly authorized and fail-closed. A registered retrieval failure cannot fall back to another credential source.

## Iteration Plans

### 01: Secret Boundaries

Status: planned. Scope: R1, R3, and the stacked CI prerequisite.

Implementation:

- Protect or explicitly redact CLI security inputs, raw/base64 PSKs, and enclosing input types.
- Redact raw SONiC table values, including unknown credential columns, while retaining useful metadata.
- Keep codec and connection obfuscation keys in existing protected storage through dedicated, shared, and promotion lifetimes.
- Include downstream proxy key capture and cloning in the ownership audit.
- Reduce unnecessary public key accessors if callers do not require them.
- Add the new stacked PR base prefix and an independent workflow contract test.

Primary owners are configuration input types, SONiC mapping, networking codecs/connections, and the agent proxy bridge.
Use existing secret wrappers. No secret-library replacement or plaintext-body zeroization claim forms part of this iteration.

Acceptance:

- Ordinary/pretty formatting of direct, optional, vector, and enclosing values excludes fixed sentinels.
- Raw ConfigDB maps do not expose any values through their custom `Debug` implementation.
- Key-owned allocations remain protected until their last connection/codec owner drops.
- Obfuscation, promotion, dedicated/shared exchange, and shutdown regressions pass.
- The PR workflow accepts every planned implementation base branch.

Checks: focused redaction tests, networking and proxy tests, workflow contracts, common Rust gates, and affected hosted platforms.
Read the SONiC instruction file before changing mapping.

### 02: YANG Choices

Status: planned. Scope: R2.

Preserve nested choice groups and their parent-case activation conditions in the generator.
Enforce direct certificate-versus-EPSK exclusion during schema validation.
Audit mandatory inline keystore choices and add behavioral checks where emitted metadata is incomplete.
Do not edit generated Rust by hand or enforce inactive nested mandatory cases unconditionally.

Primary owners: `yang/plugins/yang2rust.py`, generated choice metadata, configuration validation, and existing generator/parser tests.

Acceptance:

- A minimal nested-choice fixture retains both levels and conditional mandatory semantics.
- Certificate-only and EPSK-only identities pass; their combination fails at parsing.
- Missing active inline key choices fail at the schema boundary.
- Secret annotations remain complete, and source serialization rules remain unchanged.
- Pinned regeneration runs twice with identical expected artifacts and manifests.

Checks: generator Python tests, parser/generated-type tests, actual regeneration, common Rust gates, and affected platform builds.

### 03: Endpoint Addresses

Status: planned. Scope: R4 and R11.

Use explicit TCP, certificate-TLS, and PSK construction with security selected once.
Attach stapled OCSP, fetched OCSP, and CRLs before producing an immutable prepared endpoint.
Remove public prepared-endpoint methods that replace transport kind or attach evidence afterward.
Introduce a schema-free host-and-port value and share one string-entry parser.
Pass canonical address fields directly; format them only for display.

Primary owners: networking endpoint/destination/establishment, TLS configuration, configuration preparation/input adapters, and direct consumers.

Acceptance:

- Security re-selection and policy-discard sequences are impossible or fail before I/O.
- Incompatible evidence modes retain immediate failure behavior.
- DNS, IPv4, bracketed/bare IPv6, omitted ports, empty hosts, and malformed ports have explicit tests.
- Decide port-zero and zone-ID policy explicitly. Ambiguous bare IPv6 is not guessed to contain a port.
- Parsing performs no I/O; connections still resolve DNS afresh and apply execution-time guards.
- All consumers use the new API without compatibility shims.

Checks: endpoint/parser/loop-guard tests, native TLS/PSK/revocation cases, independent interop, common gates, Windows and ARMhf.

### 04: Credential Targets

Status: planned. Scope: R5 and small provider-contract clarifications.

Retain typed installation targets from central-reference inspection through resolution-slot association and materialization.
Derive field paths for diagnostics rather than using those strings as control flow.
Replace the CA/peer Boolean with explicit target variants.
Rename combined CRL/OCSP implementation types to evidence-oriented names where that improves clarity.
Keep startup retrieval authorization explicit. Do not add a second desired-configuration model.
Document credential notification stream-drop and worker ownership contracts.

Acceptance:

- Every credential kind installs through a typed target.
- Missing, duplicate, unexpected, wrong-kind, and unresolved results fail with sanitized context.
- Canonical source values and opaque references remain unchanged.
- Provider-neutral contracts do not acquire YANG, HTTP, Redis, OpenSSL, or Tokio dependencies.
- Operator flag changes, if any, propagate to all docs and deployment callers rather than preserving redundant aliases.

Checks: resolution/materialization/source-immutability tests, provider suites, dependency guards, and common gates.

### 05: Candidate Budgets

Status: planned. Scope: R14. This defines the contract that iteration 10 consumes.

Add canonical runtime-policy controls for total preparation time, resolution request count, and retained credential/evidence bytes.
Use reviewed finite defaults and generated defaults rather than unrelated executable knobs.
Record units, defaults, valid ranges, and checked arithmetic in the policy contract before implementation review.
Resolve requests sequentially in existing server and slot order. Stop at the first failure.
Concurrency and context-insensitive deduplication are not required.

Budget semantics:

- Start one monotonic deadline at candidate admission, before asynchronous filtering, capacity waits, resolution, expansion, or native preparation.
- Include final publication-lock waits in that deadline. Substeps and successful requests cannot renew it.
- Capture the applied budget policy at admission. Policy changes cannot extend that deadline.
- Before commit, enforce any tighter current limits against the original admission time, cumulative requests, and current retained bytes.
- Count each resolution-slot attempt across all selected servers, including retries and repeated references. Check planned counts before retrieval.
- A request-count limit bounds resolver calls, not a provider's HTTP fan-out. Keep provider-specific fetch and response limits in force.
- Charge decoded credential/evidence payload lengths per installation, including inline values, expanded bundles, and retained servers in a partial refresh.
- Count additional owned staging copies while retained. Borrowing the same installed value does not add a copy charge.
- Reserve known byte charges before copies. Check returned material before acceptance or installation, with transactional rejection on overflow.
- Provider-internal allocations remain subject to provider-specific limits. The candidate limit does not bound raw source text, native allocations, or process RSS.
- The existing active and retiring catalogs remain outside the candidate's incremental ownership charge. Reused values still count toward complete-candidate size.
- Bound active materialization to one job per coordinator. Coalesce pending observations instead of retaining an unbounded candidate queue.
- A cancelled job keeps that slot until its blocking work exits. A replacement job cannot overlap it.
- Cancellation releases cooperative fetches and staged values. Already-started blocking work retains its capacity charge until it exits.

Apply this contract to startup, full reload, partial refresh, and inline-only preparation through the supervised update path.
Keep budget scheduling outside the provider-neutral crate.
Do not hold coordinator or publication locks during provider I/O.
Iteration 10 extends the same ownership bound through native preparation and final publication.
An asynchronous timeout does not prove hard preemption of blocking providers or native work.

Acceptance:

- Exact-limit and limit-plus-one cases cover request counts, inline material, expanded bundles, provider results, and merged partial refreshes.
- Zero/overflow inputs fail validation, and omitted values use the reviewed generated defaults.
- Several slow successful requests cannot renew the whole-candidate deadline.
- Oversized or expired candidates never publish partially.
- Cancellation releases HTTP capacity and staged material.
- Expiry monitors and host shutdown progress while providers stall.
- Burst replacement tests count cancelled-but-running work until it actually exits.
- Observed failure order is deterministic, and diagnostics are sanitized.

Checks: canonical policy/default tests, actual YANG regeneration, paused-time and native cancellation tests, common gates, and platform/native integration.

### 06: Prepared Operations

Status: planned. Scope: R6 and the consuming-IPC/Bash-builder portions of R15.

Prepare one immutable validated body and encoded length before admission.
Reuse that body for eligible attempts without renewing request deadlines.
Keep session ID, sequence, packet flags, and obfuscation in networking.
Keep prepared PAP material protected and redact its formatting.
Use existing consuming IPC conversions and the domain authorization builder in Bash.
Preserve mandatory `protocol=ssh`, task metadata, argument order, and `argv[0]` removal.

Acceptance:

- Admission size equals actual transmitted body size for all three operation types.
- Invalid fields cause no admission consumption or upstream I/O.
- Not-sent retries use new session IDs with identical unobfuscated body bytes.
- Unknown-outcome operations are never replayed automatically.
- Direct and IPC response interpretation and shared authorization conformance remain consistent.
- No stale-validation path exists through public mutable prepared fields.
- Input preparation cannot renew the captured request deadline or bypass existing protocol body limits.

Measure allocation or serialization changes before claiming a performance gain.
Checks: protocol/agent/networking/IPC/CLI/Bash tests, native interop, connector proof, relevant parser fuzz, common gates, and ARMhf length checks.

### 07: Binding Outcomes

Status: planned. Scope: R10.

Move lease-only admission operations onto captured requests and outcome recording onto bindings.
Remove behavior-free router/manager forwarding and unnecessary router retention from attempts.
Share narrow typed/raw outcome bookkeeping only where delivery semantics agree.
Keep service identity at capture and catalog publication in the manager.
Do not replace the existing failover executor or unify complete raw and typed conversations.

Acceptance:

- Reload during retry retains the captured runtime snapshot.
- Late outcomes cannot affect a replacement connection generation.
- Dropped bindings and cancelled I/O retain generation-fenced failure observation.
- Failure cleanup remains owned and bounded after request expiry, without replaying the expired request.
- Downstream continuation waits do not mark upstream failure.
- Raw pinning, session remapping, and physical reply acknowledgement remain intact.

Checks: typed/raw retry, cancellation, stale-outcome and continuation tests, connector proof, common gates, and relevant native cases.

### 08: File Observation

Status: planned. Scope: R13.

Extract one private owned file-observation mechanism for debounce, retained reads, failure priority, and cleanup.
Keep separate configuration and policy parsing, events, and accepted-snapshot state.
Preserve platform-specific parent-directory behavior and subscribe-before-baseline ordering.
Do not absorb Redis or credential-directory watchers into a universal abstraction.

Acceptance:

- Both consumers pass atomic replace, delete/recreate, directory replacement/loss, rescan, and cancellation cases.
- Cancelling `next()` does not discard pending reads or debounce state.
- Policy observation retains last-known-good behavior without configuration delta-history semantics.
- Drop releases observation-owned resources without detached reload workers.

Checks: both existing watcher suites, native lifecycle cases, Windows watcher CI, common gates, and platform instructions.

### 09: Coordinator State

Status: planned. Scope: R8. This iteration does not move preparation across locks.

Group filtered source, proxy policy, and dependency knowledge into explicit state.
Group applied material and revision separately from withdrawn material.
Distinguish unknown dependencies from known-empty dependencies and applied-empty catalogs from absent publication.
Keep distinct revision and epoch types.
Keep expensive I/O outside transition logic. Do not introduce an actor without a demonstrated net simplification.

Acceptance:

- Existing behavioral assertions remain unchanged; fixture adaptations are mechanical and documented.
- Source rejection, both expiry orders, recovery, and superseded work preserve current observable behavior.
- Atomic publication callbacks remain non-awaiting.
- The transition representation prevents invalid combinations rather than merely renaming fields.

Checks: unchanged coordinator/publication/supervisor regressions, connector proof, common gates, and focused ownership coverage.

### 10: Prepared Publication

Status: planned. Scope: R7, built on iterations 05 and 09.

Carry source metadata, prepared endpoint identity, validity, budgets, and admitted revisions in one derived candidate.
Move native preparation outside the final commit lock while keeping preparation concurrency explicitly bounded.
Use at most one active preparation per coordinator initially, including cancelled-but-running blocking work.
Cancel superseded cooperative work. Do not release its capacity before owned work actually exits.
Recheck revisions, closure, validity, budgets, retained identities, and merged-catalog invariants before committing.
Resolve endpoint reuse against the current committed state, not a stale preparation-time assumption.
Retain urgent revocation retirement and earlier conservative validity bounds.
Document unchecked server builders, validated roots, materialized values, and prepared candidates as distinct stages.
Keep schema acceptance, runtime capability checks, and native verification explicit rather than deleting them as duplicate validation.

Acceptance:

- Barrier tests cover newer source, credential change, expiry, policy update, host stop, and revocation change during preparation.
- Rejected/precommit-cancelled work never changes the active generation.
- Postcommit cancellation leaves routing, health, and coordinator bookkeeping coherent.
- Unchanged endpoints retain identities and counter epochs only when final reuse checks still hold.
- Replacement bursts cannot accumulate background native preparations beyond the bound.
- Expiry and shutdown remain independent of preparation locks. Document non-preemptible native-work limitations rather than promising hard cancellation.
- Complete-catalog checks survive partial refreshes; unchanged provider validity cannot extend monotonic cutoffs.
- Late success or failure cannot overwrite newer rejection or expiry state, even when newer work never publishes.
- Changed revocation evidence installs urgent retirement for affected historical endpoints, not only the current catalog.

Checks: deterministic interleaving tests, native prepared-source/retirement cases, connector proof, independent interop, common gates, and focused coverage.

### 11: Embedding API

Status: planned. Scope: R9.

Expose one supervised server-update path and one canonical policy-update path.
Keep lower-level commit callbacks and direct reload details private unless an actual embedding workflow requires them.
If unmanaged embedding remains useful, give it an explicit distinct contract rather than an ambiguous reload overload.
Migrate direct-reload test fixtures to internal support where appropriate.
Preserve independent source and policy observations.
Clarify daemon startup and supervision topology through the existing prepared-service owner.
Add no extra builder layer unless it removes existing forwarding.

Acceptance:

- Record the final public constructor/update method list and removed variants.
- The daemon has one clear construction path.
- Public examples demonstrate supervised embedding and terminal shutdown without internal revision/callback knowledge.
- Server-only and policy-only updates preserve unrelated state.
- All affected consumers use the new APIs without aliases retained for compatibility.

Checks: public facade/example compilation, daemon lifecycle and host cancellation, connector proof, dependency guards, and common gates.

### 12: Load Scheduler

Status: planned. Scope: the scheduler portion of R15.

Remove the workload-sized Boolean result vector and duplicate success recount.
Drain in-flight work and derive completion from the existing counter.
Do not add per-request history merely to replace deleted state.

Acceptance: zero requests, concurrency one, concurrent failures, first failure, cancellation, and successful in-flight completion preserve their contracts.
Checks: focused scheduler tests, complete CLI tests, and common Rust gates.
Do not claim a measured memory improvement without a measurement.

### 13: Emulator Cleanup

Status: planned. Scope: the emulator connector and compilation portions of R15.

Use one narrow IPC endpoint connection method for controller and service clients.
Remove connector-only dependencies that become unused.
Separate source/data loading from explicit policy compilation and compile the completed startup policy once.
Keep compile-before-swap on replacement and the intentional transport-fault boundary.
Use separate coherent commits for connector reuse and compilation cleanup.

Acceptance:

- Unix/TCP setup, connection errors, ephemeral ports, and channel reuse have coverage.
- An instrumented completed startup compiles once.
- Invalid startup data/source fails at the documented boundary.
- Failed replacement retains the active policy.
- Deliberate gRPC status simulation remains available.
- Document domain-validation fidelity separately from deliberate malformed or transport-fault simulation.

Checks: emulator/controller/daemon tests, IPC tests, audit and unused-dependency checks when dependencies change, and common gates.

### 14: Product Registry

Status: planned. Scope: R12.

Introduce one explicit product registry independent of Cargo workspace enrollment.
Compute caller/reusable workflow matrices through a job output or an equally direct single-source mechanism.
Derive Linux rehearsal selection from the same registry.
Validate package and target names through existing Cargo metadata helpers.
Retain independent golden expectations for supported product/platform policy.

Acceptance:

- Derived matrices equal the current supported product/platform records. Product/platform policy changes need separate authorization.
- A new workspace member is not silently released.
- Windows remains direct `tacon`; experiments remain excluded.
- ARMhf execution and required aggregate gates remain enforced.
- Rehearsal still reuses packaging scripts and verifies source/version/provenance association offline.

Checks: metadata/architecture/workflow/release Python suites, matrix golden tests, YAML validation, and hosted matrix execution.
Do not combine this extraction with a packaging-tool replacement.

## OSS Evaluation Plans

Each evaluation starts from the last reviewed integration or decision head.
Use `refactor/general-prototypes/<slug>` and `$HOME/tacacs-rs-<slug>-prototype` for isolated experiments.
Give each prototype a separate cache with the same `-prototype` suffix.
Reserve the table's `refactor/general-iterations/<slug>` branch and named worktree for integration.
Apply the same ref-conflict and ownership checks to both namespaces.
For adoption, transfer only the accepted implementation into that integration branch from the recorded predecessor.
Run the complete implementation/review/check procedure on the resulting integration tree, not only on the prototype.
For rejection, record the decision and reproducible evidence in a documentation-only commit on the integration branch.
Do not merge or cherry-pick rejected experimental code into that branch.
Both adoption and rejection receive both direct reviews and an explicitly based stacked PR.
The next iteration starts from this reviewed integration head, never from a rejected prototype.
Do not open a PR containing rejected experimental production code.

Each record names the version, license, MSRV, dependency additions, implementation removed, behavior checks, and adoption/rejection rationale.
Do not add dependencies or replace libraries just to close an evaluation checkbox.
Set a bounded prototype effort before coding. Stop when a required capability fails or no concrete deletion remains.

### 15: TOML Editing

Compare TOML Kit with the current hydration implementation.
Evaluate `toml_edit` only if an existing Rust tool can own the work without another executable.
Keep Cargo metadata authoritative for member discovery.

Adopt only if comments, alternate valid formatting, idempotence, and source-free lock entries remain correct.
Cover same-name external packages and dependency association.
Use golden semantic and unaffected-content comparisons against current outputs.
Pin new tooling consistently in every CI/development environment that invokes hydration.
Do not require byte identity where the intended structural edit legitimately changes formatting.

Checks: hydration/version/rehearsal Python suites, fixture-based no-publish rehearsal, dependency/tool installation checks, and review of all environment changes.

### 16: Systemd Notifications

Compare direct notification APIs with the subprocess owner.
Test pathname and abstract sockets, sender attribution, auto/strict selection, retries, and one-shot ready/stopping behavior.
Prove bounded behavior when the receiver does not drain its socket.
`spawn_blocking` alone is not evidence of bounded shutdown.

Adopt only if helper discovery/execution code disappears without weakening lifetime bounds or introducing native setup costs that exceed the benefit.
Keep process-manager integration daemon-owned.
Checks: private Unix datagram tests, process lifecycle/timeout cases, dependency/MSRV/audit checks, and hosted platform builds.

### 17: Codec Evaluation

Evaluate Tokio-util only for framing and buffering.
Keep packet semantics, session routing, delivery facts, obfuscation, and counters in their owning layers.
Test oversized headers before allocation, fragmented reads, partial writes, cancellation, and contiguous packet behavior.
Do not translate a cancelled `send()` into `NotSent`.

Adopt only if bespoke buffering disappears and all ownership/delivery contracts remain explicit.
Checks: networking/proxy native tests, relevant fuzz and allocation-bound checks, interop, and common gates.
Reject the prototype if custom adapters reproduce the deleted machinery without a clear reduction.

### 18: Packaging Evaluation

Evaluate `dist` local planning/build artifacts only after registry and hydration decisions settle.
Do not enable hosting, publication, tags, or generated release workflows during the experiment.
Prove bin/cdylib output, debug symbols, required SBOM formats, OpenSSL dependencies, Windows DLLs, and offline source/version/provenance verification.
Retain ARMhf execution and the existing release version/branch policy.

Adopt only with a concrete script-deletion map and successful required platform evidence.
Checks: private Linux rehearsal plus hosted Windows/ARMhf artifact contracts.
If required evidence is unavailable, record the evaluation as blocked or reject adoption. Do not claim equivalence.

## Explicit Non-Adoptions

Retain existing secret wrappers rather than introducing `secrecy` without a concrete net deletion.
Retain canonical YANG rather than generic configuration merging.
Retain the supported native TLS backend until all external-PSK and revocation contracts are proved elsewhere.
Retain separate client/routed lifecycles, dedicated/shared runtimes, and raw/typed conversations unless new evidence supports a narrower change.

## Recommendation Coverage

| Recommendation | Delivery |
| --- | --- |
| R1 | 01 |
| R2 | 02 |
| R3 | 01 |
| R4 | 03 |
| R5 | 04 |
| R6 | 06 |
| R7 | 10 |
| R8 | 09 |
| R9 | 11 |
| R10 | 07 |
| R11 | 03 |
| R12 | 14 |
| R13 | 08 |
| R14 | 05 |
| R15 | 06, 12, 13 |

Every substantive ledger opportunity belongs to one of these iterations or an explicit OSS adopt/reject decision.
New findings stay local when they are necessary for correctness. Record a scope revision when they change the dependency order or architectural target.

## Written-Plan Review Receipt

Reviewer route: `GPT-6 Astra (copilot)`. Date: 2026-10-19. Status: first direct review complete.
Input: `git hash-object docs/refactor-delivery-plan.md` returned `9afb7455b4b032eb5cb6f13a48165116f0319fae` before edits.
Inputs reviewed: this plan, the current architecture review, its source ledger, and the applicable prose instructions.

- Preserved all 18 stages, R1-R15 coverage, CI-prefix work in 01, R14 before prepared publication, and R8 before publication restructuring.
- Defined budget accounting, absolute deadlines, blocking-work ownership, replay restrictions, and distinct revision/epoch lifetimes.
- Added builder-stage, daemon-topology, and emulator-fidelity dispositions from the ledger without adding iterations.
- Clarified exact sequential direct-review routes, dirty-input hashes, follow-up requirements, branch ownership, and isolated prototype integration.
- Checked gate entry points against their sources. Added connector commands and clarified dependency, consumer-profile, and expected-failure evidence.

Validation run: a read-only Python structural check ran immediately after the first substantive edit and after the gate refinements.
Result: eight relative links exist, headings 01..18 occur once in order, and R1-R15 coverage is complete.
All 18 iteration refs and four prototype refs pass `git check-ref-format --branch`.
No conflicts exist against the inspected local and `origin` tracking refs. No remote ref refresh formed part of this review.
No trailing whitespace exists. `bash -n` accepts all three Bash examples without executing their commands.
The pragmatic prose check found no sentence above 20 words outside tables and code blocks.
Editor diagnostics reported no errors. No Rust, native integration, or hosted platform tests ran in this plan-only review.

No material first-review blocker remains. Claude Opus 5.5 and necessary follow-up remain open.
The combined validation checkbox awaits validation of the second review's resulting plan.

Reviewer route: `Claude Opus 5.5 (copilot)`. Date: 2026-10-19. Status: second direct review complete.
Input: `git hash-object docs/refactor-delivery-plan.md` returned `440077a2481c3decd4edf2bc788e8f588f3e9774` before edits.
Inputs reviewed: this plan, the architecture review, the PR and reusable workflows, and endpoint, codec, and proxy key sources.

- Revised local gates to mirror hosted CI: stable build and tests, plus the 1.88 `cargo check` job. Material: Astra must confirm.
- Stated that a cancelled job keeps the single materialization slot until its blocking work exits. This aligns 05 with 10.
- Removed the iteration 14 clause that implied product/platform policy changes without authorization.
- Confirmed without change: 01 key scope includes codec, connection, and proxy bridge copies.
- Confirmed without change: 03 covers `with_psk`, `with_certificate_tls`, and all three evidence attachers.
- Confirmed without change: stack order, R14 before R7, R8 before R7, CI filter, provenance invalidation, and prototype isolation.

Validation run: a read-only Python check ran after the edits. Eight relative links exist, and headings 01..18 occur once in order.
R1-R15 coverage is complete. All 36 iteration and prototype refs pass `git check-ref-format --branch`.
No trailing whitespace exists, and `bash -n` accepts all Bash examples. Local refs show no namespace conflict.
Editor diagnostics reported no errors. No Rust, native, or hosted tests ran in this review.

Astra follow-up on the gate revision remains open. The combined validation checkbox awaits that follow-up.
The final response records the output file hash outside this receipt.

Reviewer route: `GPT-6 Astra (copilot)`. Date: 2026-10-19. Status: final narrow follow-up complete.
The caller supplied this exact tool route for the direct follow-up. No substitute reviewer or subagent was invoked.
Input: `git hash-object docs/refactor-delivery-plan.md` returned `3715d90142183cd403a1e00ab310093f556fdaf9` before edits.
Inputs reviewed: this plan, the Opus receipt, the reusable workflow, and its test, build, and Rust setup actions.

- Accepted the CI toolchain split: stable build/tests and the Rust 1.88 all-targets/all-features check.
- Added explicit `+stable` selectors to the two build/test commands. The local default is Rust 1.88, not stable.
- Kept all three connector commands on Rust 1.88, including the separate positive and expected-failure compiler cases.
- Accepted without change: a cancelled preparation job retains the single slot until its blocking work exits. Replacement work cannot overlap.
- Accepted without change: registry extraction preserves release enrollment and product/platform policy. Policy changes require separate authorization.
- Marked material follow-up and final plan validation complete after the focused checks passed. No architecture or release-policy change was necessary.

Validation before closure: all eight local links resolve, headings 01..18 occur once in order, and R1-R15 mappings match the iteration table.
All 18 iteration refs and four applicable prototype refs pass `git check-ref-format --branch`.
No conflicts exist against local or cached `origin` refs. No remote ref refresh ran.
No trailing whitespace exists. `bash -n` accepts all three Bash examples without executing their commands.
The first checker incorrectly required a final newline. The corrected checker passed without a whitespace edit.
Editor diagnostics reported no errors. No Rust, native integration, or hosted tests ran in this plan-only follow-up.

No review blocker remains. This follow-up preserves Opus's conclusions and closes the written-plan review gate.
The final output hash follows the post-edit validation and remains outside this file.