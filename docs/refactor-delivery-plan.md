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
The user authorizes squash merges after GitHub Copilot review and resolution of actionable comments, with all required checks passing.
Do not publish releases, create release tags, or change release policy without separate authorization.
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
Architecture reviews, the source ledger, this plan, and iteration receipts remain on `refactor/general` only.
Implementation PR diffs must not include those tracking documents.
Preserve accumulated receipts on the tracking branch before removing implementation copies.
Implementation branches start from the verified predecessor, or updated `main` after the predecessor squash merge.
A staged descendant targets its immediate predecessor until that predecessor merges; then retarget it to `main`.
The tracking branch holds documentation and progress, not implementation integration commits.

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
| 05 | `05-candidate-budgets` | R14 configuration-material admission, registered provider work, final fence | 04 |
| 06 | `06-prepared-operations` | R6, R15 consuming IPC and Bash builder | 05 |
| 07 | `07-binding-outcomes` | R10 | 06 |
| 08 | `08-file-observation` | R13 | 07 |
| 09 | `09-coordinator-state` | R8 | 08 |
| 10 | `10-prepared-publication` | R7, R14 prepared-runtime completion | 09 |
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
Old-source or fail-before replay checkouts use their own target directories, never the active iteration cache.
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
13. Request GitHub Copilot review on the final PR head. Wait for a completed review, not merely an empty comment list.
14. Triage every review comment. Apply actionable fixes through the established two-model review and verification procedure.
15. Request Copilot re-review after material fixes. Squash-merge only after actionable comments are resolved and required checks pass.
16. Use a concise squash title and a description covering the change, review resolutions, checks, and material limitations.
17. Record the PR and squash SHA on the tracking branch and update descendants without losing work.
18. Confirm the merged iteration's worktree is clean and no process uses its resources. Remove its worktree, owned cache, and completed temporary artifacts.
19. Verify active/protected worktrees remain intact, then continue with the next iteration.

Cleanup starts only after merge and preservation of the review, generation, and verification receipts.
Use `git worktree remove` without forcing dirty worktrees. Do not delete branch history or shared toolchains/registries as cache cleanup.
Delete only exact iteration-owned paths. Already absent caches need no recovery or recreation.
Active iteration resources and the pre-existing diagnostics worktree are excluded.

Cleanup receipt, 2026-10-19: merged PRs #278 through #281 were confirmed merged and their worktrees clean and idle.
Their four implementation worktrees were removed without force. Iteration 01/02 caches were already absent; the remaining 03/04 caches occupied about 44 GiB and were removed.
Known completed PR drafts, merge descriptions, the test-alert reply draft, old CI watch log, and one owned completed interop directory were removed.
Branches, merge commits, GitHub review records, and this tracking evidence remain available.
The active iteration 05 worktree/cache/draft and the pre-existing diagnostics checkout were preserved and verified.

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
The coordinator updates the plan on `refactor/general`; implementation agents return receipts without adding tracking documents to their PRs.
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
After a squash merge, preserve unpublished descendant work before changing its base.
Verify the descendant diff against updated `main` excludes already-merged implementation and all tracking documents.

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

Status: implemented; both named reviews and the final Astra follow-up on the Opus revision are complete.
The final reviewed source fingerprint is `ab501f19db2266c3f2d9d34ee0350b327853aa1b3337cc5b5ff5f66754b3ba31`.
Final local workspace gates and refreshed hosted workflow `39198981281` passed.
PR #278 excluded all three tracking documents at reviewed head `c65d44ff63a4e123eb910faece355a0ca1b34ae2`.
GitHub Copilot review `5566880340` completed on that head and recommended approval with no open issues or inline comments.
PR #278 was squash-merged on 2026-10-19 as `b7ba4017188e4a02e0f5b7d8ff1645bdf58fb853`.
The merge used an expected-head guard and a description covering behavior, review revisions, validation, document exclusion, and scope limits.
Scope: R1, R3, and the stacked CI prerequisite.

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

#### Implementation Receipt

- Branch: `refactor/general-iterations/01-secret-boundaries`.
- Exclusive source root: `/home/vscode/tacacs-rs-01-secret-boundaries`.
- Predecessor and tested `HEAD`: `daddcf63d908716defa59fc99951eaf7bccea455`. Implementation changes are uncommitted.
- Source-diff blob: `a57cffc2fbc5c3ba25e67a19e7fd4af7665e9fe9`.
	Command: `git diff --binary -- . ':!docs/refactor-delivery-plan.md' | git hash-object --stdin`.
	This fingerprint excludes this receipt and includes every changed source, test, workflow, and crate guide.
- No subagents, branches, commits, pushes, or PRs were created. The tracking and diagnostics worktrees were not modified.
- PR base remains `main` for iteration 01. No remote workflow run exists for this uncommitted implementation.

CLI security values now redact shared secrets and raw/base64 PSKs through direct and enclosing `Debug` implementations.
Tests cover ordinary and pretty formatting, `Option`, `Vec`, security modes, CLI sources, and datastore inputs.
The base64 fixture uses valid encoded bytes and verifies unchanged decoding.
Raw SONiC table formatting exposes only column and row counts, never cell values, including unknown credential columns.

Codec constructors now accept `Option<SecretBytes>`. All affected consumers use that contract without compatibility adapters.
Dedicated, shared, promotion, and downstream proxy copies retain protected key owners.
The writer key accessor is crate-private and returns a protected owner reference.
Tests verify allocation-preserving constructor moves, shared final ownership, proxy capture/cloning, and an obfuscated exchange after promotion.
Existing plaintext-body semantics remain unchanged. This work does not claim that all temporary buffers zeroize.

The workflow accepts `refactor/general-iterations/**` as a PR base.
An independent contract test asserts this literal prefix in the actual workflow, without deriving it from this plan.

##### Regression Evidence

These commands ran before their corresponding production fixes. Rust tests failed with static assertion messages, not formatted key bytes.
The same focused commands passed after the fixes.

```bash
export CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-01-secret-boundaries
cargo +1.88.0 test -p tacacsrs-config --lib input::model::tests --locked
cargo +1.88.0 test -p tacacsrs-sonic --lib raw_table_debug_redacts --locked
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider .github/steps/release-manifest/test_workflow_contracts.py -k general_iteration
cargo +1.88.0 test -p tacacsrs-networking --lib owned_key_debug_is_redacted --locked
cargo +1.88.0 test -p tacacsrs-agent --lib downstream_key_capture_and_clone_debug_is_redacted --locked
```

Results before/after: CLI 2 failed/2 passed; SONiC 1 failed/1 passed; workflow 1 failed/1 passed; codec 2 failed/2 passed; proxy 1 failed/1 passed.
The complete workflow-contract file then passed all 11 tests.
The first proxy migration check found two unmigrated fixture arguments; both were corrected before the passing rerun.
The first promotion characterization check found a fixture packet move error; the corrected check passed.

##### Executed Gates

Cargo commands used the exported cache above. The direct consumer profile used its own target subdirectory.
Toolchains were Rust `1.88.0`, stable `1.99.1`, and nightly `1.101.0-nightly (7df81381d 2026-10-14)` for formatting and Clippy.
Nightly Clippy was `0.1.101 (7df81381d0 2026-10-14)`.
All commands below passed with exit status 0.

```bash
cargo +1.88.0 test -p tacacsrs-networking --lib protected_key --locked
cargo +stable test -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic --lib --all-features --locked --quiet
cargo +stable test -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic --all-features --locked --quiet
cargo +1.88.0 check -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic -p tacacsrs-agentd -p tacon --all-targets --all-features --locked --quiet
cargo +nightly clippy -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic -p tacacsrs-agentd -p tacon --all-targets --all-features --locked -- -D warnings
cargo +nightly fmt --all -- --check
RUSTDOCFLAGS='-D warnings' cargo +stable doc -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic --no-deps --all-features --document-private-items --locked --quiet
cargo +stable test --target-dir /home/vscode/.cache/tacacs-rs-01-secret-boundaries/consumer-direct --package tacacsrs-config --package tacacsrs-networking --target x86_64-unknown-linux-gnu --all-features --locked --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider .github/steps/cargo-metadata .github/steps/check-architecture .github/steps/compute-versions .github/steps/inject-versions .github/steps/release-manifest
PYTHONDONTWRITEBYTECODE=1 python3 .github/steps/check-architecture/check_architecture.py --workspace . --target x86_64-unknown-linux-gnu --all-features
PYTHONDONTWRITEBYTECODE=1 python3 .github/steps/check-architecture/check_architecture.py --workspace . --target x86_64-pc-windows-msvc --all-features
cargo +1.88.0 llvm-cov -p tacacsrs-networking -p tacacsrs-agent --lib --all-features --locked --lcov --output-path /home/vscode/.cache/tacacs-rs-01-secret-boundaries/key-ownership.lcov --quiet
```

- Stable affected-package tests: 764 reported passed; two networking benchmarks ignored.
	Two reported SONiC successes returned early because UID 1000 lacks their required root ownership.
	These cases are `wrong_file_owner_and_group_are_rejected_when_privileged` and `reloadable_provider_recovers_when_protected_root_appears`.
- Final redaction-test changes received another Rust 1.88 and stable focused run: CLI 2 passed, SONiC 1 passed.
	`cargo +nightly clippy -p tacacsrs-config -p tacacsrs-sonic --all-targets --all-features --locked -- -D warnings` also passed afterward.
- Direct-toolkit profile: 505 passed, two benchmarks ignored. Native dependencies are installed locally; this does not prove a hosted no-native profile.
- Delivery tooling: 256 passed. Actual architecture checks covered 17 packages and eight guards on each platform.
- Ownership coverage: 438 passed, two benchmarks ignored. The LCOV artifact remains outside the source tree in the iteration cache.
	Reader lines: 189/216 hit; writer: 170/185; dedicated runtime: 53/59; shared runtime: 183/217.
	Proxy bridge: 1632/1678; downstream packet I/O: 114/137. These totals include existing tests and are not full branch coverage claims.
- Rust 1.88 Clippy could not run strictly because existing source uses the newer `clippy::unused_async_trait_impl` lint.
	Stable Clippy is not installed. Installed nightly Clippy passed instead, with an existing Cargo advisory about optional `console-subscriber` usage.
- Formatting was limited to changed Rust files with `rustfmt +nightly --edition 2021 --config skip_children=true`, then the workspace format check passed.
	`git diff --check` passed. No dependencies or lockfiles changed.

##### Pending Coordination

- The coordinator reports no blocker from the main review. Independent implementation review evidence appears below.
	Both `GPT-6 Astra (copilot)` and `Claude Opus 5.5 (copilot)` reviews are complete, including Astra follow-up on the material Opus revision.
- Final local common gates passed after all source revisions; the coordinator receipt follows.
- Windows execution, ARMhf execution, the two privileged SONiC cases, and an actual PR workflow run remain pending.
	No SONiC VM, operator Redis instance, or operator credential source was accessed.
- No unsafe, FFI, protocol parser, protobuf, or dependency changes require additional iteration-specific gates.

#### Coordinator Final Gate Receipt

The final sequence completed successfully on the twice-reviewed source fingerprint above.
Every Cargo invocation used `/home/vscode/.cache/tacacs-rs-01-secret-boundaries`.
The following gates ran in order and passed:

```bash
cargo +nightly fmt --all -- --check
cargo +nightly clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo +stable doc --workspace --no-deps --all-features --document-private-items --locked --quiet
cargo +stable build --workspace --locked --quiet
cargo +stable test --workspace --all-features --locked --quiet
cargo +1.88.0 check --workspace --all-targets --all-features --locked --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider -q .github/steps/cargo-metadata .github/steps/check-architecture .github/steps/compute-versions .github/steps/inject-versions .github/steps/release-manifest
git diff --check
```

The complete Rust suite had no failures and ten existing ignored tests.
All 256 selected Python delivery tests passed.
The existing optional `console-subscriber` Cargo advisory did not fail strict Clippy.
Root-dependent early returns and hosted platform checks are not claimed as executed coverage.
Subsequent receipt-only edits do not alter the reviewed source fingerprint.
The tracking and diagnostics worktrees remain unchanged.

#### Astra Iteration 01 Review Receipt

Accepted invocation route: `GPT-6 Astra (copilot)`.
The main coordinator supplied this exact `model` argument to `runSubagent`, and the tool accepted and executed the request.
This provenance comes from invocation metadata, not the reviewer's self-description. Opus was pending at this first review.
Review source: `/home/vscode/tacacs-rs-01-secret-boundaries`, branch `refactor/general-iterations/01-secret-boundaries`, unchanged `HEAD` `daddcf63d908716defa59fc99951eaf7bccea455`.
Scope: the complete 16-file diff against `HEAD`, the iteration 01 contract, applicable instructions, crate guides, and adjacent ownership paths.

Input and output source fingerprints are identical:
`498f9862ffb36d2166c22cdf89a2886a6f2f577b852d8098f0cc16e8052baa51`.
Command: `git diff --binary -- . ':!docs/refactor-delivery-plan.md' | sha256sum`.
This receipt is outside that hash. No new source files exist outside the diff.

Findings and dispositions:

- No actionable defect or missing iteration 01 regression was found. No source or test revisions were necessary.
- Codec, dedicated, shared, promotion, and downstream proxy keys retain `SecretBytes` owners. Clones also own zeroizing allocations; no ordinary key vectors remain retained in these paths.
- The migration preserves cancellation, promotion fencing, transport shutdown, wire bytes, and key decoding. All affected callers compile on Rust 1.88.
- CLI direct and enclosing `Debug` paths redact shared secrets and raw/base64 PSKs. Raw SONiC formatting exposes counts only, including for unknown columns.
- New secret assertions do not print secret values on failure. The workflow contract reads the literal prefix from `on.pull_request.branches`, the base-branch filter.
- Revisions: this receipt and iteration status only. Earlier test and coverage evidence remains unchanged; this review does not claim to rerun that coverage.

Fresh commands below all returned exit status 0. The source root was the working directory, and every Cargo invocation used the exported cache.
Stable was Rust 1.99.1; MSRV was Rust 1.88.0; nightly was Rust 1.101.0-nightly (7df81381d 2026-10-14).
Stable Clippy is not installed. Nightly Clippy passed with the previously documented optional `console-subscriber` Cargo advisory.

```bash
export CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-01-secret-boundaries
cargo +stable test -p tacacsrs-config --lib input::model::tests --all-features --locked
cargo +stable test -p tacacsrs-sonic --lib raw_table_debug_redacts --all-features --locked
cargo +stable test -p tacacsrs-networking -p tacacsrs-agent --lib --all-features --locked --quiet
cargo +1.88.0 check -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic -p tacacsrs-agentd -p tacon --all-targets --all-features --locked --quiet
cargo +nightly clippy -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic -p tacacsrs-agentd -p tacon --all-targets --all-features --locked -- -D warnings
cargo +nightly fmt -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic -p tacacsrs-agentd -- --check
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider .github/steps/release-manifest/test_workflow_contracts.py .github/steps/check-architecture
PYTHONDONTWRITEBYTECODE=1 python3 .github/steps/check-architecture/check_architecture.py --workspace . --target x86_64-unknown-linux-gnu --all-features
PYTHONDONTWRITEBYTECODE=1 python3 .github/steps/check-architecture/check_architecture.py --workspace . --target x86_64-pc-windows-msvc --all-features
git diff --check
```

Results: CLI 2 passed; SONiC 1 passed; agent 198 passed; networking 240 passed and two existing benchmarks ignored.
Python: 46 passed, including 11 workflow contracts. Each platform metadata check covered 17 packages and eight dependency guards.
The reviewed source remains uncommitted. No branch, commit, push, PR, or subagent operation occurred; the tracking and diagnostics worktrees remain untouched.

Unverified gates at this first review: Opus review, final full-workspace gates, Windows/ARMhf execution, privileged SONiC cases, and an actual hosted PR run.
Existing coverage and consumer-profile evidence is retained, not replaced by a new execution claim.
No plaintext-body zeroization or iteration 02 work forms part of this review.

#### Opus Iteration 01 Review Receipt

Accepted invocation route: `Claude Opus 5.5 (copilot)`.
This provenance comes from the main coordinator's invocation metadata, not the reviewer's self-description.
Review source: `/home/vscode/tacacs-rs-01-secret-boundaries`, branch `refactor/general-iterations/01-secret-boundaries`, unchanged `HEAD` `daddcf63d908716defa59fc99951eaf7bccea455`.
Scope: the complete 16-file diff against `HEAD`, the iteration 01 contract, R1 and R3 in the architecture review, applicable instructions, and adjacent callers.

Source fingerprints use `git diff --binary HEAD -- . ':(exclude)docs/refactor-delivery-plan.md' | sha256sum`.

- Input: `498f9862ffb36d2166c22cdf89a2886a6f2f577b852d8098f0cc16e8052baa51`. This matches the Astra-reviewed source.
- Output: `ab501f19db2266c3f2d9d34ee0350b327853aa1b3337cc5b5ff5f66754b3ba31`. The output diff has 18 files.

Findings and dispositions:

- Defect, fixed: the `tacacsrs-agentd` `Cli` derives `Debug` but stored `shared_secret` and `psk_key` as raw `String` values.
	This is an enclosing CLI security input under R1. The same struct already protected `proxy_shared_secret`.
	Both fields now use `SecretString` through clap value parsers. Empty-value acceptance and help text are unchanged.
	The two consumers in `startup.rs` expose the value only to build `CliSecurityInputs`, as before.
- Confirmed without change: codec, dedicated, shared, promotion, and downstream proxy paths retain `SecretBytes` owners.
	Clones own separate zeroizing allocations. No ordinary key vector stays in these paths.
- Confirmed without change: `PacketWriter::obfuscation_key` is crate-private. Its only production caller is dedicated promotion.
- Confirmed without change: wire obfuscation, decoding, flags, timeout, cancellation, and promotion fencing are unchanged.
- Confirmed without change: CLI `Option`, `Vec`, and enclosing formatting tests and SONiC count-only formatting, including unknown columns.
- Confirmed without change: new assertions do not print secrets. The workflow test reads the literal prefix from `on.pull_request.branches`.
- `tacon` `Cli` does not derive `Debug`, so it needs no change.
- No zeroization claim covers temporary buffers, plaintext bodies, or the short-lived `CliSecurityInputs` copies.

Direct changes:

- `executables/tacacsrs_agentd/src/cli.rs`: `shared_secret` and `psk_key` use `SecretString`.
- `executables/tacacsrs_agentd/src/startup.rs`: consumers expose the values explicitly.
	A new `cli_shared_secret_and_psk_debug_is_redacted` regression covers `--shared-secret`, `-k`, and `--psk-key`.
	It checks ordinary, pretty, `Option`, and `Vec` formatting, and it checks unchanged raw PSK bytes.
	The test did not run before the fix. Derived `Debug` for `Option<String>` renders the value.

Commands below used `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-01-secret-boundaries`.
Toolchains were stable Rust 1.99.1, Rust 1.88.0, and nightly 1.101.0 for formatting and Clippy. Stable Clippy is not installed.

```bash
cargo +stable test -p tacacsrs-agentd --bin tacacsrs-agentd --all-features --locked cli_
cargo +nightly fmt --all -- --check
cargo +stable test -p tacacsrs-agentd --all-features --locked --quiet
cargo +1.88.0 check -p tacacsrs-agentd -p tacon -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic --all-targets --all-features --locked --quiet
cargo +nightly clippy -p tacacsrs-agentd -p tacon -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic --all-targets --all-features --locked --quiet -- -D warnings
cargo +stable test -p tacacsrs-networking -p tacacsrs-agent -p tacacsrs-config -p tacacsrs-sonic --lib --all-features --locked --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider -q .github/steps/release-manifest/test_workflow_contracts.py
RUSTDOCFLAGS='-D warnings' cargo +stable doc -p tacacsrs-agentd --no-deps --all-features --document-private-items --locked --quiet
git diff --check
```

- The first focused run failed to compile because of test-module paths. After the repair, the rerun passed 15 tests.
- All later commands returned exit status 0.
- `tacacsrs-agentd` tests: 72, 48, and 9 passed. The suite with eight existing ignored tests did not execute them.
- Library tests: agent 198, configuration 107, networking 240 with two benchmarks ignored, and SONiC 48 passed. Workflow contracts: 11 passed.
- Nightly Clippy reported only the existing optional `console-subscriber` Cargo advisory.

Material revision: the agentd CLI type change required Astra rereview against the output fingerprint. The final follow-up below completes that review.
Unverified gates at Opus handoff: Astra rereview, final full-workspace gates, Windows and ARMhf execution, privileged SONiC cases, and a hosted PR run.
This review did not run hosted Windows, ARMhf, or privileged tests. It did not rerun coverage or the consumer profile.
No branch, commit, push, PR, or subagent operation occurred.

#### Final Astra Follow-up Receipt

Accepted invocation route: `GPT-6 Astra (copilot)`, as supplied by the main coordinator's authoritative invocation metadata.
Source root: `/home/vscode/tacacs-rs-01-secret-boundaries`, branch `refactor/general-iterations/01-secret-boundaries`.
Unchanged `HEAD`: `daddcf63d908716defa59fc99951eaf7bccea455`.
Input and output source fingerprints are identical: `ab501f19db2266c3f2d9d34ee0350b327853aa1b3337cc5b5ff5f66754b3ba31`.
Command: `git diff --binary -- . ':!docs/refactor-delivery-plan.md' | sha256sum`.
The hash covers 17 changed files outside this plan. No untracked source files exist.

Scope: the Opus receipt, exact daemon CLI/startup diff, direct callers, secret wrappers, configuration conversion, and retained codec/proxy ownership changes.
The locked Clap 4.6.6 implementation and a probe against the actual daemon CLI definition supplied additional parser evidence.

Findings and disposition:

- No new actionable product defect or required source revision. The Opus fix closes the daemon's derived `Cli::Debug` disclosure.
- Both parsed fields and Clap's typed values use `SecretString`, with redacted formatting and zeroization on drop.
	Typed retrieval as `String` fails. Extraction into `Cli` preserves the secret bytes.
- Important boundary: Clap also retains raw `OsString` copies. `ArgMatches::get_raw` and ordinary/pretty `ArgMatches::Debug` expose those copies.
	The daemon uses `Cli::parse()` and does not retain or log `ArgMatches`. This existing parser boundary does not invalidate the `Cli` fix.
	This receipt does not certify raw argument redaction, process-argument secrecy, or temporary-buffer zeroization.
- Startup explicitly exposes values only for the existing configuration conversion. Agentd PSKs remain raw bytes, not base64-decoded values.
	Shared-secret short/long flags, attached/equal forms, empty-value parsing, PSK requirements, conflicts, and group selection retain their behavior.
- Missing-option, duplicate-option, credential-conflict, and invalid-UTF-8 diagnostics excluded the test secrets in `Display` and `Debug` checks.
	These checks do not certify arbitrary malformed command lines or secrets supplied to unrelated arguments.
- Existing regression coverage is sufficient for this change. The new daemon regression and adjacent conversion/group tests passed.
	Codec, dedicated, shared, promotion, and downstream proxy paths still retain protected key owners. No new password or key formatting path was found.
- Changes from this follow-up: receipt and status only. Both named source reviews now remain valid for the final fingerprint.
	No further Opus rereview is required. Final workspace gates remain the main coordinator's responsibility.

Fresh checks returned exit status 0 from the exclusive source root:

```bash
export CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-01-secret-boundaries
cargo +stable test -p tacacsrs-agentd --bin tacacsrs-agentd --all-features --locked cli_
CARGO_PKG_VERSION=0.0.0-dev CARGO_PKG_AUTHORS=review rustc +stable --edition=2021 --test --crate-name astra_cli_contract -L dependency=/home/vscode/.cache/tacacs-rs-01-secret-boundaries/debug/deps --extern clap=/home/vscode/.cache/tacacs-rs-01-secret-boundaries/debug/deps/libclap-3bc3f578271e26c3.rlib --extern tacacsrs_config=/home/vscode/.cache/tacacs-rs-01-secret-boundaries/debug/deps/libtacacsrs_config-21d7a0d337856bf0.rlib --extern tacacsrs_secrets=/home/vscode/.cache/tacacs-rs-01-secret-boundaries/debug/deps/libtacacsrs_secrets-c507a274f58a9124.rlib -o /home/vscode/.cache/tacacs-rs-01-secret-boundaries/astra-cli-contract -
/home/vscode/.cache/tacacs-rs-01-secret-boundaries/astra-cli-contract
git diff --check
```

The Rust compiler consumed the six-test probe from stdin; its source is in the review invocation record, not a new repository file.
The probe imports the unchanged daemon CLI definition and uses existing cached dependencies. The binary remains in the permitted cache.
Results: 15 daemon tests passed; six probe tests passed, with no ignored cases.
Probe cases covered protected shared-secret extraction, protected raw PSKs, empty values, raw Clap copies, parser errors, and invalid UTF-8 errors.
Only fixed test sentinels were used. Assertions did not print secret values.

Review gate: complete, with no source blocker. No full-workspace, hosted CI, Windows, ARMhf, privileged SONiC, coverage, or consumer-profile rerun is claimed.
No other worktree edits, branches, commits, pushes, PRs, subagents, or operator endpoint access occurred.

### 02: YANG Choices

Status: implemented; both named reviews and the final Opus follow-up on the Astra revision are complete.
Final local common gates passed. Published as [PR #279](https://github.com/AuthScaffold/tacacs-rs/pull/279) against updated `main`. Scope: R2.
Published head: `a8ce6952c932becd2e0ad01c061caefa6130c65c`; predecessor squash: `b7ba4017188e4a02e0f5b7d8ff1645bdf58fb853`.
The complete rebased tree equals tested checkpoint `62490f64e61ca4e68ca7c8424e2ec33187d5882a`.
Its PR diff contains exactly six configuration/generator files and no architecture or tracking documents.
GitHub Copilot review `5567124473` recommended approval with no open issues or inline comments on the published head.
Required workflow `39202018504` passed. PR #279 was squash-merged as `7d60ee481554ed98234b51a18d99475cf76939f7`.
The merge used the exact reviewed-head guard and a description covering the schema changes, review revisions, checks, and scope limits.

The read-only scheduling preflight identified discarded nested metadata and synthetic parent cases.
Implementation started from iteration 01's committed, locally verified head.
The required first regression failed before the collector or emitter changed.
The synthetic mandatory fixture checks conditional semantics independently of the optional client-identity choice.

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

#### Implementation Receipt: 2026-10-19

Ownership and tested source:

- Worktree: `/home/vscode/tacacs-rs-02-yang-choices` only.
- Branch: `refactor/general-iterations/02-yang-choices`.
- Predecessor and tested `HEAD`: `4a2edf667a3207a76cad6b1e80e82dc15a3af147`.
- Intended PR base: `refactor/general-iterations/01-secret-boundaries`. Main owns review, commit, push, and PR creation.
- Tested source fingerprint: `3df3bde3212f2ab4db8023e6c059b3883e9ec24557273782d600d3dea5cfea4d`.
- Fingerprint command: `git diff --binary HEAD -- . ':(exclude)docs/refactor-delivery-plan.md' | sha256sum`.
- The fingerprint includes all six changed source, test, and generation files. No new source files are untracked. This receipt is excluded.

Implementation scope:

- `libraries/tacacsrs_config/yang/plugins/yang2rust.py`: retain complete parent cases, all nested groups, stable paths, and ancestor activation chains.
- Choice fingerprints include mandatory constraints and activation. Nested constant names include their choice and case paths.
- `libraries/tacacsrs_config/yang/test_yang2rust_defaults.py`: add the required fixture, mandatory-constraint deduplication checks, and deeper activation-chain checks.
- `libraries/tacacsrs_config/src/validation.rs`: enforce the independent certificate/EPSK choice through generated activation metadata.
- The actual client-identity authentication choice remains optional. Mandatory children apply only when every ancestor case is active.
- Active `EndEntityCertWithKeyInlineDefinition::CHOICE_PRIVATE_KEY_TYPE` and `SymmetricKeyInlineDefinition::CHOICE_KEY_TYPE` now require a key selection.
- `libraries/tacacsrs_config/tests/parse_validation.rs`: cover certificate-only, EPSK-only, both alternatives, incomplete inline keys, and inactive central-reference branches.
- These parser checks cover direct and bundled credentials. Enumeration leaves the source unchanged.
- Extend the existing metadata audit to TACACS+ and keystore choices. Migrate the old synthetic-case error assertion and complete one certificate fixture.
- Regenerate `libraries/tacacsrs_config/src/generated.rs`; update only its hash in `libraries/tacacsrs_config/yang/generation-manifest.json`.
- Generated fields, serde attributes, secret annotations, dependencies, YANG inputs, and the expanded tree remain unchanged.
- No generated Rust was edited by hand. No generic backend behavior outside choices changed.

Failed-before evidence:

1. From `libraries/tacacsrs_config/yang`, run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_yang2rust_defaults.GeneratedDefaultsTests.test_nested_mandatory_choice_retains_parent_case_activation`.
	Exit 1 before the fix: the expected `explicit` case with label, certificate, and EPSK fields was absent.
	Output contained separate `explicit/auth-type` and `explicit` cases, with no child group. The same command passed after the collector change.
2. Run `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +1.88.0 test -p tacacsrs-config --test parse_validation client_identity_auth_type_is_exclusive --locked`.
	Exit 101 before validation changed: `unwrap_err()` received `Ok` for a combined certificate/EPSK identity. The same command passed afterward.
3. Run the same Cargo command with filter `active_inline_key_choices_require_key_material`.
	Exit 101 before validation changed: an empty certificate inline definition parsed successfully. The same test passed afterward.
	Filter `inline_key_choices` also passed both active-inline rejection and inactive-central acceptance tests.

Regeneration evidence:

- Copy the existing pinned upstream cache into this worktree's `libraries/tacacsrs_config/yang/.yang-cache/linux` before generation.
- All subsequent generator cache writes used that private copy. No shared cache was changed.
- Run `PYTHONDONTWRITEBYTECODE=1 python3 expand_yang_tree.py --features-ini feature-flags.ini --format rust --output ../src/generated.rs`.
- Run the same command with `--format tree --output expanded-tree.txt`.
- Run `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +nightly fmt --all` before recording the manifest hash.
- Existing formatter policy excludes generated Rust through `ignore` and `format_generated_files = false`. Its byte-exact generator output remains unchanged by formatting.
- Run `PYTHONDONTWRITEBYTECODE=1 python3 verify_generated.py`, without `--check`: exit 0.
- That command ran real tree and Rust regeneration twice, then compared both passes and the checked-in artifacts byte for byte.
- Both passes used pyang `2.7.1` and detached, clean upstream commit `97ca2414920c0de09171327b84aa11395f79e284`.
- Pinned upstream module SHA-256: `2a58836b7117320f847eb5965f851c9a83d2a13180ecd2f5a62daff5f607f9fd`.

| Artifact | First pass SHA-256 | Second pass SHA-256 |
| --- | --- | --- |
| Generated Rust | `a9ce045bf80767815c002ebb84ad46dcdaa2d21ac0c25db4b3d6713f7a6876a8` | `a9ce045bf80767815c002ebb84ad46dcdaa2d21ac0c25db4b3d6713f7a6876a8` |
| Expanded tree | `5cf7da89cd79ae2c1fbb54e42e2429975283991066a27c439d61e348a15e1420` | `5cf7da89cd79ae2c1fbb54e42e2429975283991066a27c439d61e348a15e1420` |

The updated generation manifest SHA-256 is `1c14fb718d4503d3c7b81b2f0e36d2c7a6536ceba51b418041c031a08a014c3f`.
The unchanged secret-field manifest SHA-256 is `223ac5374a618666581a11bf8bc2c15acec7ef41b0b64b5ee97b80adb11b9fb0`.

Executed checks:

- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v -p 'test_*.py'` from the generator directory: exit 0, 23 tests.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +1.88.0 test -p tacacsrs-config --lib validation::tests --locked`: exit 0, two activation tests.
- The expanded parser metadata audit passed. The full parser suite passed all 90 tests.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +1.88.0 test -p tacacsrs-config --all-features --locked --quiet`: exit 0.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +stable test -p tacacsrs-config --all-features --locked --quiet`: exit 0 on Rust 1.99.1.
- Each complete package run passed 262 tests and three doctests, with no ignored tests. This includes 34 generated-type and seven materialization tests.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +1.88.0 check -p tacacsrs-config --all-targets --all-features --locked`: exit 0.
- Stable Clippy was unavailable; its attempted command stopped before linting. No installation or toolchain mutation occurred.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +nightly clippy -p tacacsrs-config --all-targets --all-features --locked -- -D warnings`: exit 0.
- Nightly compiler: `1.101.0-nightly (7df81381d 2026-10-14)`.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices RUSTDOCFLAGS='-D warnings' cargo +stable doc -p tacacsrs-config --no-deps --all-features --document-private-items --locked`: exit 0.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +nightly fmt --all -- --check`: exit 0.
- Editor diagnostics for the changed handwritten source and tests: no errors. `git diff --check`: exit 0.

Pending ownership and limits:

- GPT-6 Astra direct review: PENDING, main owns this gate.
- Claude Opus 5.5 direct review: PENDING, main owns this gate.
- Final common workspace gates after both reviews: PENDING, main owns these gates.
- Hosted Windows and ARMhf builds and execution: PENDING. No hosted CI result is claimed.
- No full-workspace build, test, lint, or documentation rerun is claimed here. Package checks do not replace those final gates.
- No protocol, unsafe, FFI, dependency, or protobuf changes require additional parser fuzz, Miri, audit, or protobuf compatibility checks for this diff.
- Incomplete inline definitions now fail earlier at parsing. This is an intentional schema correction, not a compatibility exception.
- No subagents, named reviews, commits, branches, pushes, PRs, operator systems, or operator secrets were used by this implementation agent.
- No other worktree received edits. There is no implementation blocker; publication remains main's responsibility.

#### Astra Iteration 02 Review Receipt: 2026-10-19

Accepted invocation route: `GPT-6 Astra (copilot)`, established by the coordinator's accepted invocation metadata.
The first required iteration 02 review is complete. This receipt supersedes only the pending Astra gate above.
Worktree: `/home/vscode/tacacs-rs-02-yang-choices`; branch: `refactor/general-iterations/02-yang-choices`.
HEAD remains `4a2edf667a3207a76cad6b1e80e82dc15a3af147`.

Source fingerprints exclude this plan. Command: `git diff --binary HEAD -- . ':(exclude)docs/refactor-delivery-plan.md' | sha256sum`.

- Input: `3df3bde3212f2ab4db8023e6c059b3883e9ec24557273782d600d3dea5cfea4d`.
- Output: `9853bc2008574dfc48c7463b2196b1ad979110b86c5fdf2d8d5313a428e18ef8`.

Reviewed the full seven-file diff, iteration 02 plan and implementation receipt, current generated schema, generator fixtures, validation, enumeration, and runtime readiness.
No historical review notes supplied the findings.

Finding and disposition:

- P2, fixed: distinct valid choice paths produced duplicate Rust constant names. `source/explicit/auth-type` collided with `source-explicit-auth-type`.
- Choice names also collided with metadata suffixes, such as `source-path` versus the `source` path constant.
- The emitter now reserves each complete constant family and adds numeric suffixes on collision. Exact choice paths and activation references remain unchanged.
- Added `test_choice_constant_names_do_not_collide_with_paths_or_metadata`. The valid fixture failed before the fix: 24 constants had only 19 unique names.
- The same test passes after the fix. An initial fixture used invalid repeated sibling choice names; pyang rejected it before emission. The corrected fixture isolates the defect.
- No further source defect was identified in ancestor activation, complete parent cases, implicit cases, scoped mandatory validation, or choice-aware structural reuse.
- Central references remain schema-valid without inline keys. Bundle expansion preserves the source, and runtime publication reuses schema validation.
- Encrypted and hidden key features are disabled in the pinned schema. The new checks do not reject an enabled encrypted-key alternative.
- Review source revisions affect only the generator and its regression test. Canonical fields, custom defaults, secret annotations, Rust validation, and policy remain unchanged.

Executed checks, all final commands exit 0:

- From `libraries/tacacsrs_config/yang`: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_yang2rust_defaults.GeneratedDefaultsTests.test_choice_constant_names_do_not_collide_with_paths_or_metadata`. Exit 1 before the emitter fix; exit 0 afterward.
- From that directory: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v -p 'test_*.py'`: 24 tests passed.
- From that directory: `TMPDIR="$PWD" PYTHONDONTWRITEBYTECODE=1 python3 verify_generated.py --clean`: real tree and Rust regeneration passed twice from a fresh private pinned cache.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +1.88.0 test -p tacacsrs-config --test parse_validation --test generated_types --lib --all-features --locked --quiet`: 233 tests passed.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +stable test -p tacacsrs-config --all-features --locked --quiet`: 262 tests and three doctests passed.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +nightly clippy -p tacacsrs-config --all-targets --all-features --locked -- -D warnings`: passed.
- The emitted collision-fixture constant block compiled with `rustc +1.88.0 --crate-type lib --emit=metadata -o <private-cache-temporary-directory>/choices.rmeta -`. An earlier `/dev/null` output attempt failed on temporary-file permissions, not Rust diagnostics.
- Editor diagnostics reported no errors in the two revised Python files. `git diff --check` passed.

Both regeneration passes matched the checked-in artifacts. No generated output or manifest revision was necessary.
Generated Rust SHA-256: `a9ce045bf80767815c002ebb84ad46dcdaa2d21ac0c25db4b3d6713f7a6876a8`.
Expanded tree SHA-256: `5cf7da89cd79ae2c1fbb54e42e2429975283991066a27c439d61e348a15e1420`.

Claude Opus 5.5 must review the generator revision and output fingerprint. Its review remains PENDING.
Final common workspace gates and affected Windows/ARMhf execution remain PENDING with main. No hosted CI result is claimed.
There is no implementation blocker. No policy revision, other worktree edit, commit, branch, push, PR, subagent, or operator-secret access occurred.
Main retains publication ownership. Tracking, iteration 01, and diagnostics worktrees remain untouched by this review.

#### Claude Opus 5.5 Iteration 02 Review Receipt: 2026-10-19

Accepted invocation route: `Claude Opus 5.5 (copilot)`, established by the coordinator's accepted model argument and the session model metadata.
The second required iteration 02 review is complete. This receipt supersedes only the pending Claude Opus 5.5 gate above.
Worktree: `/home/vscode/tacacs-rs-02-yang-choices`; branch: `refactor/general-iterations/02-yang-choices`.
HEAD remains `4a2edf667a3207a76cad6b1e80e82dc15a3af147`.

Source fingerprints exclude this plan. Command: `git diff --binary HEAD -- . ':(exclude)docs/refactor-delivery-plan.md' | sha256sum`.

- Input: `9853bc2008574dfc48c7463b2196b1ad979110b86c5fdf2d8d5313a428e18ef8`. This matches the Astra output.
- Output: `11ce3f2a91ab7d2f570104033a60c101703ce82ff58e8efb8b0074b47f710b94`.

Reviewed the full seven-file diff, the iteration 02 plan, the implementation and Astra receipts, and the repository instructions.
Audited nested-choice flattening, activation chains, constant naming, structural deduplication, validation consumers, and runtime credential construction.

Finding and disposition:

- P2, fixed: structural fingerprints did not delimit nested members. A case `{a, b}` and a case `{a}` followed by a sibling leaf `b` produced equal fingerprints.
- The second structure was deduplicated into the first, so its type and choice constraints were wrong. Containers and lists had the same aliasing.
- `_fingerprint` now encloses container, choice, and case sub-fingerprints in brackets. No other generator logic changed.
- Added `test_case_membership_keeps_distinct_structures`. It failed before the fix: `pub struct Second` was absent. It passes after the fix.
- The pinned schema had no aliased structures. Real regeneration output is unchanged.

Audited with no further defect:

- Nested parent cases include all nested-choice fields. Every nested group keeps its full path and complete ancestor activation chain.
- The generator fingerprint uses the same path and activation encoding as the emitter. Mandatory status and leaf defaults stay in the key.
- Constant-family allocation is deterministic in document order. Numeric suffixes reserve the base, `_MANDATORY`, `_PATH`, and `_ACTIVATION` names together.
- The canonical `client-identity` `auth-type` choice is optional. Only the synthetic fixture is mandatory. Validation enforces at most one certificate or EPSK case.
- `validate_activated_choice` checks a nested choice only when every ancestor case is present. The parser metadata audit maps every generated mandatory constant to a validator.
- Inline key-type checks run only when `inline-definition` is present. Central keystore references and credential references stay valid without inline keys.
- Production builders and CLI input always supply a private key. Only `prepare_endpoint` negative tests omit it, and they do not call schema validation.
- Canonical YANG inputs, the expanded tree, secret annotations, and generated Rust are unchanged. No generated Rust was edited by hand.

Executed checks, all exit 0 unless noted:

- From the worktree root: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s libraries/tacacsrs_config/yang -p 'test_*.py' -k test_case_membership_keeps_distinct_structures`. Exit 1 before the fix; exit 0 afterward.
- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s libraries/tacacsrs_config/yang -p 'test_*.py'`: 25 tests passed.
- From `libraries/tacacsrs_config/yang`: `TMPDIR="$PWD" PYTHONDONTWRITEBYTECODE=1 python3 verify_generated.py --clean`: real tree and Rust regeneration passed twice from a fresh private pinned cache and matched the checked-in artifacts.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +1.88.0 test -p tacacsrs-config --test parse_validation --test generated_types --lib --all-features --locked --quiet`: 233 tests passed.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +stable test -p tacacsrs-config --all-features --locked --quiet`: 262 tests and three doctests passed.
- `CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +nightly clippy -p tacacsrs-config --all-targets --all-features --locked -- -D warnings`: passed.
- `git diff --check`: passed.

| Artifact | SHA-256 after both passes |
| --- | --- |
| Generated Rust | `a9ce045bf80767815c002ebb84ad46dcdaa2d21ac0c25db4b3d6713f7a6876a8` |
| Expanded tree | `5cf7da89cd79ae2c1fbb54e42e2429975283991066a27c439d61e348a15e1420` |
| Generation manifest | `1c14fb718d4503d3c7b81b2f0e36d2c7a6536ceba51b418041c031a08a014c3f` |
| Secret-field manifest | `223ac5374a618666581a11bf8bc2c15acec7ef41b0b64b5ee97b80adb11b9fb0` |

Unverified gates and ownership:

- The generator revision is material. GPT-6 Astra re-review of the fingerprint change is REQUIRED before publication.
- Final common workspace gates: PENDING, main owns these gates. No full-workspace build, test, lint, or documentation result is claimed.
- Hosted Windows and ARMhf builds and execution: PENDING. No hosted CI result is claimed.
- No stable Clippy, formatting, or documentation rerun occurred, because no Rust source changed in this review.
- No commit, branch, push, PR, subagent, other worktree edit, or operator-secret access occurred. Main retains publication ownership.

#### Final Astra Iteration 02 Follow-up Receipt: 2026-10-19

Accepted invocation route: `GPT-6 Astra (copilot)`, from the coordinator's invocation metadata for this follow-up, not reviewer self-identification.
This follow-up reviews the material Opus fingerprint revision. Earlier receipts remain historical evidence for their recorded source hashes.
Worktree: `/home/vscode/tacacs-rs-02-yang-choices` only; branch: `refactor/general-iterations/02-yang-choices`.
HEAD remains `4a2edf667a3207a76cad6b1e80e82dc15a3af147`.

Source fingerprints exclude this plan. Exact command: `git diff --binary -- . ':!docs/refactor-delivery-plan.md' | sha256sum`.

- Input: `11ce3f2a91ab7d2f570104033a60c101703ce82ff58e8efb8b0074b47f710b94`. This matches the Opus output and the supplied review input.
- Output: `800bd7089f910d1a8d485dbdb70b515b610ac0ba87eebe3ec347acfdeb56de23`.
- All changed source files are tracked. The source diff still has six files; this follow-up changes only the generator and its existing test file.

Finding and disposition:

- P2, fixed: bracket delimiters do not prevent fingerprint collisions when valid string defaults contain the same delimiter text.
- The new fixture places `a` inside `selector/one` and `b` outside that choice in both containers.
- The first container uses defaults `a = "x:M:false]]|L:b:string:D:y"` and `b = "z"`.
- The second uses defaults `a = "x"` and `b = "y:M:false]]|L:b:string:D:z"`.
- Both produce the same old key. The second container incorrectly reuses the first type and its `b` default.
- `test_default_delimiters_keep_distinct_structures` validates the fixture through pyang with no errors before generation.
- It failed before the fix because `pub struct Second` was absent. After the fix, both types and their distinct defaults are present.
- `_fingerprint` now returns a typed recursive tuple. The deduplication table uses `(module_name, fingerprint)` directly, without text encoding or escaping.
- Leaf values, mandatory values, ordered children, choice paths, activation chains, and nested case boundaries remain separate tuple members.
- The revision changes key representation only. It does not broaden the schema properties included in deduplication or rewrite collection and emission.

Reviewed preservation:

- The prior case-membership regression, nested mandatory and ancestor-activation tests, and constant-name collision test all pass.
- Conditional validation still requires every ancestor case to be active. No validation code changed during this follow-up.
- Canonical YANG inputs, real generated fields, serde attributes, defaults, secret annotations, and choice metadata remain byte-identical to the input revision.
- No generated Rust or manifest was edited. No dependency, platform, or runtime behavior changed outside the corrected generator reuse.
- No further source defect was identified within this follow-up's R2 scope.

Executed commands:

```bash
cd /home/vscode/tacacs-rs-02-yang-choices
TMPDIR="$PWD" PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s libraries/tacacsrs_config/yang -p 'test_*.py' -k test_default_delimiters_keep_distinct_structures
TMPDIR="$PWD" PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s libraries/tacacsrs_config/yang -p 'test_*.py' -v
cd /home/vscode/tacacs-rs-02-yang-choices/libraries/tacacsrs_config/yang
TMPDIR="$PWD" PYTHONDONTWRITEBYTECODE=1 python3 verify_generated.py --clean
cd /home/vscode/tacacs-rs-02-yang-choices
CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +stable test -p tacacsrs-config --all-features --locked --quiet
CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +1.88.0 test -p tacacsrs-config --test parse_validation --test generated_types --lib --all-features --locked --quiet
CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices cargo +nightly clippy -p tacacsrs-config --all-targets --all-features --locked -- -D warnings
git diff --check
git diff --binary -- . ':!docs/refactor-delivery-plan.md' | sha256sum
sha256sum libraries/tacacsrs_config/src/generated.rs libraries/tacacsrs_config/yang/expanded-tree.txt libraries/tacacsrs_config/yang/generation-manifest.json libraries/tacacsrs_config/yang/secret-fields.toml
git status --short --branch
git diff --numstat
```

The focused test returned exit 1 before the fix and exit 0 immediately after it. All later checks returned exit 0.
The expected string-expression assertions were aligned with the existing emitter's `to_owned()` spelling before the passing rerun.
Generator suite: 26 passed. Stable configuration suite: 262 tests and three doctests passed, with no ignored tests.
Rust 1.88 focused suite: 233 passed. Strict nightly package Clippy passed. Editor diagnostics reported no errors in both revised Python files.
The real regeneration command rebuilt tree and Rust output twice from a fresh private pinned cache; it was not an offline hash-only check.
Both passes matched each other and the checked-in artifacts. The secret-field manifest also passed its completeness checks.

| Artifact | SHA-256 after both passes |
| --- | --- |
| Generated Rust | `a9ce045bf80767815c002ebb84ad46dcdaa2d21ac0c25db4b3d6713f7a6876a8` |
| Expanded tree | `5cf7da89cd79ae2c1fbb54e42e2429975283991066a27c439d61e348a15e1420` |
| Generation manifest | `1c14fb718d4503d3c7b81b2f0e36d2c7a6536ceba51b418041c031a08a014c3f` |
| Secret-field manifest | `223ac5374a618666581a11bf8bc2c15acec7ef41b0b64b5ee97b80adb11b9fb0` |

Remaining gates and ownership:

- Astra follow-up: complete for the output fingerprint above. This does not mark both reviews complete for the final source.
- Claude Opus 5.5 follow-up: **PENDING and REQUIRED** because the structured-key revision is a new material source change.
- Main must run the final full-workspace gates and publish only after both required reviews cover the final source fingerprint.
- Full-workspace build, test, lint, formatting, documentation, MSRV checks, and affected hosted Windows/ARMhf execution remain with main.
- No fresh formatting or documentation run is claimed here; this follow-up changed no Rust source or generated output.
- No branch, commit, push, PR, subagent, other worktree edit, or operator access occurred. Prior receipts and unrelated changes remain intact.

#### Final Claude Opus 5.5 Iteration 02 Follow-up Receipt: 2026-10-19

Accepted invocation route: `Claude Opus 5.5 (copilot)`, from the coordinator's invocation metadata for this follow-up.
Worktree: `/home/vscode/tacacs-rs-02-yang-choices` only. HEAD remains `4a2edf667a3207a76cad6b1e80e82dc15a3af147`.

Source fingerprints exclude this plan. Exact command: `git diff --binary -- . ':!docs/refactor-delivery-plan.md' | sha256sum`.

- Input: `800bd7089f910d1a8d485dbdb70b515b610ac0ba87eebe3ec347acfdeb56de23`. This matches the Astra output.
- Output: `800bd7089f910d1a8d485dbdb70b515b610ac0ba87eebe3ec347acfdeb56de23`. This follow-up changed no source.

Reviewed the exact generator and test diff, the Astra follow-up receipt, and every `_fingerprint`, `_fingerprints`, `_flatten_choice`, and `choices` use.

Disposition of the Astra structured-key revision: accepted, no defect.

- Every fingerprint member is a `str`, `bool`, `None`, or nested tuple. Keys are hashable and compare structurally, so no delimiter or escape ambiguity remains.
- The only caller builds `(module_name, fingerprint)`. Deduplication stays per module, and recursion order follows document order.
- Leaf defaults and mandatory values stay separate members. Container, choice, and case bodies stay nested tuples.
- Choice keys hold the path tuple, mandatory status, and activation tuple. They match the `_flatten_choice` path and activation chains for nested choices.
- Containers and lists restart with an empty choice context, as `_fill_children` does. YANG identifiers cannot contain `/`, so the joined activation path is unambiguous.
- The emitter, constant naming, sequence suffixes, and validation consumers did not change. Real generated types are byte-identical.

Independent failed-before check: an in-memory patch encoded the top-level tuple as the old bracket string. No file was written.
With that patch, `test_default_delimiters_keep_distinct_structures` failed because `pub struct Second` was absent. Without it, the test passes.

Non-blocking observation, outside R2 and unchanged by this iteration: the fingerprint still uses `C` for both containers and lists and records only the type name.
A future generator iteration can add node kind and type arguments. The pinned schema output is unchanged, so no current defect is visible.

Executed checks, all exit 0:

```bash
cd /home/vscode/tacacs-rs-02-yang-choices
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s libraries/tacacsrs_config/yang -p 'test_*.py'
cd libraries/tacacsrs_config/yang && TMPDIR="$PWD" PYTHONDONTWRITEBYTECODE=1 python3 verify_generated.py --clean
cd /home/vscode/tacacs-rs-02-yang-choices
export CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-02-yang-choices
cargo +stable test -p tacacsrs-config --all-features --locked --quiet
cargo +1.88.0 test -p tacacsrs-config --test parse_validation --test generated_types --lib --all-features --locked --quiet
cargo +nightly clippy -p tacacsrs-config --all-targets --all-features --locked -- -D warnings
git diff --check
```

- Generator suite: 26 passed. Clean regeneration passed twice and matched the checked-in artifacts.
- Stable configuration suite: 262 tests and three doctests passed. Rust 1.88 focused suite: 233 passed. Nightly package Clippy passed.
- Artifact hashes match the Astra table: generated Rust `a9ce045b…76a8`, expanded tree `5cf7da89…1420`, generation manifest `1c14fb71…14c3f`, secret-field manifest `223ac537…9fb0`.

Final review status for source `800bd708…de23`: Astra and Claude Opus 5.5 reviews are complete. No further review is required.

- Main's full-workspace build, test, lint, formatting, documentation, and MSRV gates: PENDING.
- Hosted Windows and ARMhf builds and execution: PENDING. No hosted CI result is claimed.
- No branch, commit, push, PR, subagent, or other worktree edit occurred. Main retains publication ownership.

#### Coordinator Iteration 02 Final Gate Receipt

The initial final-gate sequence was interrupted after Clippy and is not counted as a complete passing run.
The coordinator reran the complete sequence successfully after moving tracking documents out of implementation worktrees.
The validated implementation fingerprint remains `800bd7089f910d1a8d485dbdb70b515b610ac0ba87eebe3ec347acfdeb56de23`.
Its calculation excludes all three tracking-document paths.

Executed gates used `/home/vscode/.cache/tacacs-rs-02-yang-choices`:

```bash
cargo +nightly fmt --all -- --check
cargo +nightly clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo +stable doc --workspace --no-deps --all-features --document-private-items --locked --quiet
cargo +stable build --workspace --locked --quiet
cargo +stable test --workspace --all-features --locked --quiet
cargo +1.88.0 check --workspace --all-targets --all-features --locked --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s libraries/tacacsrs_config/yang -p 'test_*.py' -q
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider -q .github/steps/cargo-metadata .github/steps/check-architecture .github/steps/compute-versions .github/steps/inject-versions .github/steps/release-manifest
git diff --check
```

All gates passed, followed by the `ALL_ITERATION_02_GATES_PASSED` marker.
The Rust suite had no failures and ten existing ignored tests.
All 26 generator tests and 256 selected delivery tests passed.
Prior clean double-regeneration and secret-annotation evidence remains unchanged.
Hosted checks for iteration 02 are not yet claimed. Privileged or external-service early returns are not execution evidence.

### 03: Endpoint Addresses

Status: implemented; both named reviews cover the final source. Final common workspace gates passed. Scope: R4 and R11.
Worktree: `/home/vscode/tacacs-rs-03-endpoint-addresses`; branch: `refactor/general-iterations/03-endpoint-addresses`.
Published as [PR #280](https://github.com/AuthScaffold/tacacs-rs/pull/280) against `main`, initially at `1ed047f79f40a93c788f125b7728eb4108f2ce0b`.
The reviewed Windows repair is now published at `02d2bbc82f8fec4a49800856bb842d7642ca6d40`.
The parent is predecessor squash `7d60ee481554ed98234b51a18d99475cf76939f7`.
The complete retargeted tree equals tested checkpoint `a387c4313aa7f594368cc19dc9e5a4d7e1abeac7`.
The PR has 41 implementation/product-documentation paths and no tracking documents.
GitHub Copilot review `5568266591` reported no open issues but requested closer security/platform confirmation.
Workflow `39216146715` failed Windows job `117942656258` in the new repeated-connection guard test.
The failure is under repair through the established model-review and fresh-CI procedure below; iteration 04 publication remains paused until this predecessor is clear.
Final reviewed source-diff SHA-256: `3efcef8fbdb4aa5a629e169512bc0123510ab59b86313a81f98ebc5bc4780c01`.
The fingerprint excludes all three tracking-document paths, which remain absent from the implementation worktree.

#### Implementation And Review Receipt

The implementation consumes one prepared transport when constructing an immutable endpoint.
It removes the old TCP constructor and all five endpoint security/evidence setters.
`ServerAddress` preserves DNS/IP and a nonzero outbound port without parse-time I/O.
Connections retain fresh resolution, destination checks, and connected-peer checks.
Bare IPv6 remains a whole host. Explicit IPv6 ports require brackets; scoped addresses and outbound port zero are rejected.
DNS spelling, YANG-permitted underscores, and optional trailing dots remain supported.
Canonical source, credential roles, SNI/peer-identity separation, and certificate/evidence lifetime distinctions remain intact.

The required reviews ran sequentially through the accepted model routes:

1. `GPT-6 Astra (copilot)` reviewed input `6cef536b7fe7e1a4b1420158abe6ff12eb722ad6b52f6f2304a03e1966a9d3a5`.
	It fixed noncanonical numeric hosts being accepted as DNS names and moved validated SNI into prepared PSK ownership.
	Its output was `c73db3e51c16615fc5131e201699176d2550590769c59f87d69c506405dd2b33`.
2. `Claude Opus 5.5 (copilot)` reviewed that output.
	It fixed rejection of schema-valid underscore names and added redacted `Debug` for newly public prepared types.
	Its output was `350236200e651b154ee95f2c8bc0ab872e0c88259f3150506d319b969554beb0`.
3. Astra reviewed those revisions and the coordinator's public-API concern about a positional verification-disable Boolean.
	It introduced `CertificateVerification::{Required, DisabledForDevelopment}` without a compatibility Boolean overload.
	It also rejected malformed certificate peer/SNI names during preparation.
	Its output was `3efcef8fbdb4aa5a629e169512bc0123510ab59b86313a81f98ebc5bc4780c01`.
4. Opus accepted that final source with no further edits, including policy defaults, native verify-mode mapping, evidence compatibility, and redacted diagnostics.

Failed-before regressions covered TLS re-selection dropping staple policy, outbound port zero, legacy numeric hosts, invalid PSK SNI, underscore names, Boolean API compilation, and malformed certificate names.
The coordinator independently reran the numeric-host, SNI, underscore, redacted-PSK, and compile-contract checks after the corresponding revisions.

All Cargo invocations used `/home/vscode/.cache/tacacs-rs-03-endpoint-addresses`, with isolated consumer-profile subdirectories.
The implementation and reviewers reported these passing scoped gates on their recorded output trees:

- Rust 1.88 all-target/all-feature affected-consumer checks.
- Networking/configuration all-feature tests and compile-fail doctests.
- Agent 198 tests, daemon 72 unit tests, 48 native prepared-source cases, nine process tests, and `tacon` 66 tests.
- Nine executed independent TACACS+ peer scenarios, including certificate, PSK, and DHE modes.
- Three CI consumer selections and Linux/Windows architecture metadata checks.
- Nightly formatting, strict newer-toolchain Clippy, warning-free private docs, and whitespace checks.

One unchanged timed-probe test failed in an earlier parallel networking run, then passed alone and in the final serial reviewer suite.
It remains enabled and was not modified to hide the result.
Rust 1.88 Clippy reports the pre-existing newer `unused_async_trait_impl` lint as unknown; required MSRV compilation and newer strict Clippy are separate gates.
Stable's Clippy component was absent; installed nightly and Rust 1.99.0 Clippy supplied the scoped strict-lint evidence.
Final full-workspace gates passed in the coordinator run below. Hosted Windows/ARMhf checks for this iteration are not yet claimed as passed.
No dependencies, lockfiles, operator systems, release policies, or tracking documents changed in the implementation worktree.

#### Coordinator Final Gate Receipt

The final reviewed fingerprint remained `3efcef8fbdb4aa5a629e169512bc0123510ab59b86313a81f98ebc5bc4780c01` throughout verification.
Every Cargo command used `/home/vscode/.cache/tacacs-rs-03-endpoint-addresses`.
The following complete sequence passed and emitted `ALL_ITERATION_03_GATES_PASSED`:

```bash
cargo +nightly fmt --all -- --check
cargo +nightly clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo +stable doc --workspace --no-deps --all-features --document-private-items --locked --quiet
cargo +stable build --workspace --locked --quiet
cargo +stable test --workspace --all-features --locked --quiet
cargo +1.88.0 check --workspace --all-targets --all-features --locked --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider -q .github/steps/cargo-metadata .github/steps/check-architecture .github/steps/compute-versions .github/steps/inject-versions .github/steps/release-manifest
git diff --check
```

There were no Rust test failures. Ten existing tests remained ignored.
The final parallel workspace run also passed the unchanged timed-probe test noted above.
All 256 selected Python delivery tests passed.
Native prepared-source, process, compile-fail, and affected consumer checks remained enabled.
Existing privileged and external-service early returns are not claimed as execution coverage.

#### Windows CI Repair Receipt

The Windows log showed `Elapsed` at the outer two-second guard-test deadline, without a host-specific diagnostic.
The fixture originally provided only IPv4 acceptance for `localhost` and waited for acceptance even after a connection error.
The repair serves `127.0.0.1` and `::1` on the same port for that case and uses error-aware joining with host-specific diagnostics.
It keeps every host, both repetitions, and the two-second deadline. No case is skipped and no timeout is relaxed.

GPT-6 Astra also identified a source-backed Windows client-socket risk for mapped IPv4 destinations.
Resolved mapped IPv6 addresses now become native IPv4 before guards and connect.
Configured host/display values remain unchanged; ordinary IPv6 flow and scope, resolver order, and duplicates remain intact.
The fully qualified mapped-address regression failed before the fix and passed afterward.
An earlier unqualified exact-name command selected zero tests and was not counted as evidence.

Both accepted model routes reviewed the full repair sequentially:

- `GPT-6 Astra (copilot)` accepted the runtime correction and added mixed-address/IPv6-metadata, mapped-exclusion, and peer-identity coverage.
- `Claude Opus 5.5 (copilot)` accepted that final repair without source revisions, including cancellation-safe dual-listener acceptance and guard alias semantics.

The complete repair diff SHA-256 against initial head `1ed047f79f40a93c788f125b7728eb4108f2ce0b` is `2f28efd87e009f9c6de05a8a038d977d02190c2b89a1d1a9880db29cb1413f11`.
The destination source-file SHA-256 is separately `ab787dba600b70865444a4ee79f9f26364a54d7f0cde3390da350041e9045dc0`.
These identify different objects and are not interchangeable fingerprints.

Twelve destination tests and three production loop-guard tests passed; Opus also ran thirty passing Linux repetitions of the previously failing test.
The full coordinator gate sequence then passed again: formatting, strict nightly Clippy, private docs, stable workspace build/all-feature tests, MSRV all-target checks, 256 delivery tests, and whitespace checks.
It emitted `ALL_ITERATION_03_WINDOWS_REPAIR_GATES_PASSED`, with no Rust failures and ten existing ignored tests.
The exact Windows timeout cause remains unproven locally. Fresh hosted Windows CI and Copilot re-review on the repaired head remain required before merge.
Fresh Windows testing job `117965858744` passed on repair head `02d2bbc82f8fec4a49800856bb842d7642ca6d40`.
Copilot re-review `5568863719` reported no open issues and requested final security/platform confirmation.
Aggregate workflow `39223264314` subsequently passed on the repaired head.
After confirming unchanged head, no open Copilot issues or inline comments, and clean mergeability, PR #280 was squash-merged as `3dc393aa8dfc71d9406bdbf9dca6fb83207d548b`.
The merge used an expected-head guard and a description covering the API refactor, Windows repair, reviews, and verification limits.

#### Planned Acceptance Criteria

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

Status: implemented; both named reviews accepted the same source without revisions. Final common workspace gates passed.
Scope: R5 and small provider-contract clarifications.
Worktree: `/home/vscode/tacacs-rs-04-credential-targets`; branch: `refactor/general-iterations/04-credential-targets`.
Published as [PR #281](https://github.com/AuthScaffold/tacacs-rs/pull/281) against `main` at head `35d9924a089beb818c65937eee6e4e319b486e41`.
Its base is squash `3dc393aa8dfc71d9406bdbf9dca6fb83207d548b`, and its complete tree equals tested checkpoint `df5e02f1ec4721e4ff7d345b98ea9eb5ff0e9b30`.
The PR contains 18 implementation/product-documentation files and no tracking documents.
Copilot recommended approval; the separately reviewed test-only CodeQL finding is resolved. Required aggregate CI remains pending.
The parent fast-forwarded from initial PR #280 head to repair head `02d2bbc82f8fec4a49800856bb842d7642ca6d40` without changing the iteration's diff.
Reviewed source-diff SHA-256: `603203cb887170eb8b3442dee0088cec84d1af32953331c3dfc92bc29f23a19a`, excluding all three tracking-document paths.

#### Implementation And Review Receipt

Configuration now owns `ServerResolutionPlan`, containing the neutral plan and a private plan-local slot-to-usage map.
Its public `neutral_plan()` accessor exposes only a shared borrow.
The existing neutral constructor assigns slots in input order without dropping or reordering requests.
Materialization associates validated results by slot and matches typed usage/material pairs before target mutation.
Diagnostic field paths no longer select installation behavior, and the CA/EE Boolean is removed.
Both bag destinations reuse one converter while retaining distinct usage and result variants.
Validity intersection, unresolved-reference rejection, final validation, and canonical-source immutability remain intact.

Combined provider types are named `HttpEvidenceResolver` and `EvidenceFetchLimits`.
CRL and OCSP source types, CLI flags, retrieval authorization, and registered-failure/no-fallback behavior remain unchanged.
All in-tree consumers, examples, fixtures, and product guides migrate directly without compatibility aliases.
Change-stream documentation distinguishes worker ownership and notification recovery from cancellation of arbitrary I/O.
No manifests, lockfiles, or dependencies changed, and the neutral crate acquires no schema or runtime edge.

Both required accepted routes reviewed the complete 18-file diff sequentially:

- `GPT-6 Astra (copilot)` accepted input/output hash `603203cb887170eb8b3442dee0088cec84d1af32953331c3dfc92bc29f23a19a` without revisions.
- `Claude Opus 5.5 (copilot)` accepted the same unchanged hash without revisions; no further Astra follow-up was required.

The first typed installer probe failed against the old string-based signature with two expected compile errors, then passed after implementation.
Checks covered all six destinations in direct and local-bundle configurations, wrong-kind rejection, immutable source/siblings, staged failure, and reordered neutral slots.
The coordinator independently reran both typed bag tests after propagating the repaired parent.

Scoped evidence used `/home/vscode/.cache/tacacs-rs-04-credential-targets` and included:

- Configuration materialization 9 tests, resolution 7, typed bag installation 2, and five configuration doctests.
- Neutral contracts 11 tests; HTTP provider 9 tests and one doctest.
- Agent materialization 15 and configuration supervision 46 tests.
- SONiC provider and watcher suites, with privileged-owner requirements explicitly excluded or reported as early returns where applicable.
- Daemon provider composition 3 tests and the downloaded-CRL native-verification case.
- The central-resolution example, Rust 1.88 affected all-target checks, strict private Rust 1.99 Clippy, private docs, formatting, and architecture guards.

No hosted Windows or ARMhf execution for this iteration is claimed.
Final workspace gates, parent aggregate CI, publication, GitHub Copilot review, and merge remain coordinator-owned.
Opus noted pre-existing guide text describing some HTTP evidence features as unimplemented; that unchanged wording is deferred rather than expanding this typed-target implementation.

#### Coordinator Final Gate Receipt

The full final sequence passed on the unchanged reviewed diff `603203cb887170eb8b3442dee0088cec84d1af32953331c3dfc92bc29f23a19a`.
Every Cargo command used `/home/vscode/.cache/tacacs-rs-04-credential-targets`.

```bash
cargo +nightly fmt --all -- --check
cargo +nightly clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo +stable doc --workspace --no-deps --all-features --document-private-items --locked --quiet
cargo +stable build --workspace --locked --quiet
cargo +stable test --workspace --all-features --locked --quiet
cargo +1.88.0 check --workspace --all-targets --all-features --locked --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider -q .github/steps/cargo-metadata .github/steps/check-architecture .github/steps/compute-versions .github/steps/inject-versions .github/steps/release-manifest
git diff --check
```

The sequence emitted `ALL_ITERATION_04_GATES_PASSED`.
No Rust tests failed; ten existing tests remained ignored. All 256 selected Python delivery tests passed.
Privileged or external-service early returns are not execution claims.
The predecessor subsequently passed required CI and merged; publication now proceeds from its squash-equivalent base.
GitHub Copilot review and hosted checks for iteration 04 remain required on the published head.

#### GitHub Security Comment Disposition

Copilot review `5569430728` recommended approval with no open issues on head `35d9924a089beb818c65937eee6e4e319b486e41`.
CodeQL comment `4312241168` separately raised alert `203` at the test helper `trust_server`.
Both required model routes independently traced the exact head and agreed that the reported sink is test-only.
It parses fixed JSON containing opaque references and no secret fields; its callers are only adjacent unit tests.
The flagged validators check presence or emptiness, and production materialization discards their inner errors.
The coordinator posted evidence reply `4312302950`, dismissed only alert `203` as `used in tests`, and verified that the corresponding thread is resolved.
The current alert state is dismissed; its instance endpoint can retain the historical open observation.
The PR-scoped open-alert query returned no findings. No source suppression or production change was made.
Required workflow `39229336104` subsequently passed on head `35d9924a089beb818c65937eee6e4e319b486e41`.
After verifying resolved conversations, no open PR-scoped alerts, and clean mergeability, PR #281 was squash-merged as `6602e12ff23065abeb3815b29b38be307e008d3c`.
The merge used an exact reviewed-head guard and a description covering typed installation, provider contracts, validation, and the test-only alert disposition.

#### Planned Acceptance Criteria

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

Status: implemented; both named reviews cover the final complete content manifest. Final common local gates passed.
Scope: R14 admission and configuration-material phase.
Iteration 10 completes R14 through prepared-runtime accounting and native preparation lock ownership.
Do not close R14 after this iteration alone.

#### Implementation And Review Receipt

Worktree: `/home/vscode/tacacs-rs-05-candidate-budgets`; branch: `refactor/general-iterations/05-candidate-budgets`.
Published as [PR #282](https://github.com/AuthScaffold/tacacs-rs/pull/282) against `main` at head `a9dfba8b5e427b11b9d9f87265cb65074dbd8c78`.
The predecessor is squash `6602e12ff23065abeb3815b29b38be307e008d3c`; the complete retargeted tree equals tested checkpoint `7f5b3dd4a1fdffe2bda229bb97bd87a734ad8b4e`.
Git records 45 implementation files, including the YANG rename, and no tracking documents.
The initial PR workflow was `39252965825`; later review fixes are published at `e3f60473f6ad8a8b4f03bfaa332acbc68e43debf`.
Required workflow `39258678652` failed ARMhf in two HTTP test peers. Review `5572195730` confirmed the first two lifecycle findings resolved and raised a payload-disposal ownership finding.
The next repair passes both named reviews and all final local gates. Fresh current-head Copilot review and required CI remain necessary before merge.
Iteration 06 implementation is complete locally; its reviews and publication wait for the parent repair.
The review inventory includes 46 changed/new/deleted paths: 42 tracked paths plus four initially untracked files.
The complete content manifest hashes sorted changed/new paths, a NUL, each current file's SHA-256 or `<deleted>`, and a newline.
It excludes only the three tracking-document paths. A tracked diff alone does not cover the new implementation files.

Implementation provides canonical generated candidate limits, checked configuration payload accounting, absolute admissions, bounded preparation ownership, registered provider work, and a final precommit fence.
`WorkScope` is scheduler-independent and opaque. Only `register()` creates another lease while open; cancellation sealing prevents new registration.
SONiC retains leases through actual queued/running blocking work and queued results, with payload disposal before capacity release.
HTTP fallback receives the same scope. Unobservable SDK/filter/OS DNS work remains outside the registered-work guarantee.
Candidates use canonical server order, preflight every selected slot before provider entry, and reject oversized handoffs before accumulating further results.
The final tighter-policy fence precedes retirement cutoffs, snapshot, health, and bookkeeping changes. Postcommit retirement cannot erase `Published`.

Required accepted model reviews ran sequentially:

1. `GPT-6 Astra (copilot)` reviewed complete manifest `d4eff9bc04bff36b96645d0748a6f840e6bab2e15cdad5f31fa796cfbbd802df`.
	It fixed candidates starting filters or provider work after closure while waiting for capacity.
	Its output was `b743da63c5f20c8a70eac6072a6a3bcb46b4e6c5c2209a42dbde7693be6c5711`.
2. `Claude Opus 5.5 (copilot)` fixed installation rejection caused by unrelated state-lock contention, using the revision watch for the private installation fence.
	It also removed unrestricted scope cloning, making registration/sealing enforceable through the public API.
	Its output was `46625b0dc49070763ee3c3f5a6b1194b4bf30a0e65faeb606f1d815308e0418b`.
3. Astra reviewed those material revisions and accepted the same unchanged final complete manifest.

The final tracked-patch hash is separately `ece90178669d6fc5d886e482557c96f9545c4cc966fb066d5380e8fbf9f1d5e0`.
The coordinator independently reran closure-after-wait, unrelated-lock installation, and sealed-scope doctest checks and verified all changed/new contents.

Failed-before evidence includes complete request preflight/canonical ordering, SONiC queued-payload disposal, closed-service admissions, and false rejection under an unrelated state lock.
Tests cover exact/plus-one limits, inline/bundle/retained payload, provider handoff, deadline nonrenewal, tighter policy, lock waits, postcommit success, cancellation barriers, and 1,000-event bursts.
The three-loop stress test reported exactly three bounded waiters; no unbounded expanded candidate queue is introduced.

Real pinned clean regeneration ran twice with matching artifacts:

- Generated Rust: `0ccbca284f2cca1a08ee96e738730a44773a03137afe1e909f2bd1210823bed9`.
- Expanded tree: `40c655f4be4b2dc964a99e33d075b4aef9827ae3233780c773cc1f51b6393361`.
- Generation manifest: `5a8b1c4cd75b73d060a617af11bf5e3049ada2d3445fcaca3b08f0d29ddb5a1c`.
- Unchanged secret annotations: `223ac5374a618666581a11bf8bc2c15acec7ef41b0b64b5ee97b80adb11b9fb0`.

The project YANG revision advances to 2026-10-19. Generated Rust was not edited manually.
Scoped evidence also includes two neutral-work Miri tests, 48 native prepared-source cases, and nine independent TACACS+ peer scenarios.
Root-dependent and Redis early returns are not execution claims.

#### Coordinator Final Gate Receipt

The complete final sequence used `/home/vscode/.cache/tacacs-rs-05-candidate-budgets` and emitted `ALL_ITERATION_05_GATES_PASSED`:

```bash
cargo +nightly fmt --all -- --check
cargo +nightly clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo +stable doc --workspace --no-deps --all-features --document-private-items --locked --quiet
cargo +stable build --workspace --locked --quiet
cargo +stable test --workspace --all-features --locked --quiet
cargo +1.88.0 check --workspace --all-targets --all-features --locked --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s libraries/tacacsrs_config/yang -p 'test_*.py' -q
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider -q .github/steps/cargo-metadata .github/steps/check-architecture .github/steps/compute-versions .github/steps/inject-versions .github/steps/release-manifest
git diff --check
```

There were no Rust failures and ten existing ignored tests. All 26 generator and 256 selected delivery tests passed.
Hosted Windows/ARMhf checks, publication, and GitHub Copilot review remain required on the published head.
No dependency versions, Cargo manifests, Cargo.lock, operator systems, or implementation tracking documents changed.

#### GitHub Copilot Lifecycle Repair Receipt

HIGH comment `4313925389` identified credential notification loss retaining an unpolled candidate that could own coordinator state while waiting for publication.
MEDIUM comment `4313925476` identified projection-acceptance deadline failure bypassing revision-fenced source rejection.

`GPT-6 Astra (copilot)` directly fixed both findings and added four deterministic regressions:

- Unavailable and EOF drop the pending candidate before awaiting coordinator notification-loss bookkeeping.
- Both cases prove health, coordinator updates, and host stop proceed while publication remains locked.
- Projection acceptance timeout follows the same fenced rejection path as filtering errors, marking the current source stale and permitting eventual withdrawal.
- A superseded timeout returns `Superseded` without rejecting a newer source or altering its health.

Each two-test command failed before the corresponding fix and passed afterward:

```bash
cargo +stable test -p tacacsrs-agent --all-features --locked candidate_notification_ -- --nocapture
cargo +stable test -p tacacsrs-agent --all-features --locked candidate_acceptance_timeout_ -- --nocapture
```

`Claude Opus 5.5 (copilot)` accepted the exact unchanged repair, independently reproduced all four old-source failures, and confirmed adjacent candidate branches already cancel before conflicting state updates.
The coordinator independently reran both passing two-test groups.
Repair-only diff SHA-256 against initial published head `a9dfba8b5e427b11b9d9f87265cb65074dbd8c78`: `dbbaaef2ddda328fde7c344b72235c792900366412e36abe363f0b6f35bc4710`.
Full PR-diff SHA-256 against squash predecessor `6602e12ff23065abeb3815b29b38be307e008d3c`: `cab87b923ea8febde464c165914d9da36155f083ecf2c68e30e91757cd99e008`.

The reviewer detected stale artifacts after replaying old source through the active cache, removed affected iteration-owned package artifacts, and reran the passing suite.
The coordinator then reran every final gate on the repaired tree with its assigned cache: formatting, strict nightly workspace Clippy, private docs, stable build/all-feature tests, MSRV all-target checks, 256 delivery tests, and whitespace validation.
The run emitted `ALL_ITERATION_05_COPILOT_REPAIR_GATES_PASSED`, with no Rust failures and ten existing ignored tests.
The repair changes only observation handling, supervisor regressions, and a scoped test-only lock helper.
Registered work ownership, YANG artifacts, payload accounting, and iteration 10 exclusions are unchanged.
Publishing the repair, evidence replies, conversation resolution, fresh Copilot review, and required hosted checks remain necessary before merge.
The repair was published as `e3f60473f6ad8a8b4f03bfaa332acbc68e43debf`.
Evidence replies `4314255320` and `4314255584` were posted; both addressed lifecycle threads were explicitly resolved.
CodeQL alerts `204` and `205` separately flagged coordinator fixture calls in a test-only module.
Both model routes independently verified identical test-file blobs across alert and repaired commits, fixed keystore-reference JSON, and a test-only parser `expect` sink.
Replies `4314317907` and `4314318314` record that evidence. Only those alerts were dismissed as `used in tests`; their conversations are resolved.
The PR-scoped open-alert query returned no findings. No source suppression or unrelated native-error safety claim was made.

#### Publication Ownership And ARM Fixture Repair Receipt

Copilot HIGH comment `4314332435` identified premature capacity release during cancellation at both publication-lock waits.
Async function argument disposal released preparation before server, proxy, and commit-closure payload owners.
`GPT-6 Astra (copilot)` added internal `PublicationCandidate<Commit>` and migrated the coordinator, service, and manager calls.
The ordered owner retains candidate servers, proxy policy, prepared server references, and commit captures before the preparation lease.
It stays intact across waits. Successful atomic commit still releases capacity before postcommit retirement.
Strengthened regressions failed at both actual lock waits before the repair, observing a surviving server owner after lease release.
Six focused tests passed afterward. Coverage includes unpolled cancellation, admission and outer timeouts, prepared-client suspension, native failure, final fencing, and retained provider work.

ARMhf job `118080434561` failed two HTTP/OCSP process fixtures at first-read assertions; 46 other native cases passed.
Single TCP reads do not guarantee a complete request. Cancellation can close a connection before it sends a complete request.
Astra added bounded known-client request parsing, exact body consumption, and pending-read barriers in the existing fixture module.
The tests retain their original deadlines, fail-closed and recovery checks, source equality checks, and shutdown assertions.
Deterministic empty-connection and one-byte-fragment regressions both failed before the fix.
Executed requests showed a 108-byte GET header and a 169-byte POST header with all 115 body bytes consumed.
Both process tests verified pending I/O before termination and EOF afterward.

`Claude Opus 5.5 (copilot)` accepted the ownership repair and fixed malformed partial requests that the fixture could otherwise discard silently.
Its new six-case regression failed before that change. Seven reader tests and all 55 native cases passed on stable and Rust 1.88.
Astra reviewed the material revision without retained edits. A temporary probe tested every byte boundary of four valid requests.
The final ten-file repair diff against `e3f60473f6ad8a8b4f03bfaa332acbc68e43debf` is `cb216d0c3071abb58d2a83cc565802659d9290305ef951b51f0463ef5a90ac06`.
The complete changed-content manifest is `ba27c472d3ae1c6c5384e8f4d361acdaa996ef8345da62a175120e90f50d0b70`.
The fixture SHA-256 is `7426af326cad3586936c05a9309441b529008ee2cb9d286486c3081664703492`.

The coordinator reran the full final sequence and received `ALL_ITERATION_05_OWNERSHIP_ARM_FIXTURE_GATES_PASSED`.
Formatting, strict workspace Clippy, private docs, build, all-feature workspace tests, and MSRV all-target checks passed.
The run included 232 agent tests, 55 native prepared-source tests, 26 YANG tests, and 256 delivery tests.
Ten existing ignored Rust tests remain excluded. The existing optional `console-subscriber` manifest advisory did not fail Clippy.
No dependency, schema, or generated-artifact change belongs to this repair.
Fresh hosted ARMhf success remains required; local evidence does not establish the complete cause of the earlier ARM failure.
Prepared-runtime accounting, native allocator limits, RSS, and preparation/expiry-lock independence remain iteration 10 work.
The repair is published as `8e0bdc9dbc329acab018ce5e92bb72e50fe88049`; evidence reply `4315616938` and thread resolution are recorded.
Current-head Copilot review `5573894855` reports no open issues and confirms the disposal-order finding resolved.
Its generic final-review reminder is not a human approval claim. Both named direct reviews and the coordinator's local gates are recorded above.
Required workflow `39277505296` remains queued at the last reliable observation. Job-list requests then returned a transport error and HTTP 502.
GitHub reported Actions, Pages, and Webhooks incident `8tzbpcnl75jp`, updated at 2026-10-19 15:54 UTC.
That incident is consistent with current service trouble, but does not prove the cause of the initial queue delay.
The PR remains unmerged. No required-check bypass or unsupported hosted-platform success claim is authorized.

#### Canonical Contract

The detailed source reviews accepted a non-presence `runtime-policy/candidate-preparation` container with three positive `uint32` leaves:

| Leaf | Default | Unit |
| --- | --- | --- |
| `timeout-seconds` | 30 | Seconds |
| `max-resolution-requests` | 256 | Resolver-slot attempts |
| `max-retained-material-bytes` | 67108864 | Decoded payload bytes, extended through prepared-runtime Rust payload in 10 |

Generated defaults are authoritative. Preserve absent-container semantics and validate JSON plus programmatically constructed values.
Do not duplicate these defaults as handwritten Rust constants. Use the existing `uint32 { range "1..max"; }` leaf style.
Use checked `u64` size accounting, checked request totals, and checked monotonic deadline construction.
Add no dependency. The neutral resolver crate receives no YANG policy types.
These finite defaults are admission policy, not measured capacity or process-memory guarantees.

#### Admission And Pending Work

Capture policy and one admission instant before filtering or capacity waiting.
No successful substep, internal retry, duplicate notification, or policy relaxation renews that admission.
A later independent observation or scheduled retry creates a new admission, not an extension of the old attempt.
Admit at most one preparation work scope per coordinator, including cancelled work that still owns a registered lease.

Use these finite bounds with the existing source, credential-notification, and periodic-refresh loops:

- Retain at most three pending records, one unexpanded record per loop. Retain at most one waiter future per loop.
- A record contains revision identity, admission time, captured limits, and trigger metadata. It contains no plans, expanded servers, or provider results.
- Source records share at most one latest raw observation owner. Credential records coalesce to an unknown/all-references marker when necessary.
- Do not accumulate reference sets, source snapshots, channels, or spawned waiter tasks per notification.
- A stricter shared pending record is acceptable. An actor rewrite is not required.
- Drop a superseded record promptly. Repeated refresh ticks for the same pending work neither advance its revision nor renew its deadline.
- Keep observation handling pollable while preparation waits. Coalesce notifications in owned futures, without spawning a preparation per event.

Advance source identity when accepting or rejecting an observation, before filtering and before the capacity wait.
Advance credential identity when admitting a relevant invalidation or a new refresh, before waiting.
Coalesced duplicates of that pending refresh do not create another admission.
A rejected newer source invalidates older work even if the newer source never publishes.
Credential invalidation during filtering must survive until the current source projection is ready.
Then select against the latest credential revision. Use full refresh when dependencies or the applied revision are uncertain.

After capacity acquisition, recheck source and credential revisions, expiry, closure, and the original deadline before filtering or expansion.
Recheck the relevant identity after filtering and before each resolver call, result installation, and publication.
A pending record never authorizes its stale captured server selection.
Discard superseded results and errors without overwriting newer rejection or expiry state.
Keep policy revision separate. Rejected policy candidates do not become applied limits.

#### Registered Provider Work

Add a public, opaque registered-work scope to the neutral resolver contract and propagate it through every resolver and fallback.
The HTTP resolver passes the same scope to its fallback resolver. It does not create a second scope.
The new API uses standard-library ownership and synchronization types only, with no Tokio, YANG, or concrete provider types.
Agent scheduling remains outside the neutral crate.
Expose public construction, lease registration, sealing, and quiet observation without exposing counters or scheduler permits.
Keep sealing authority separate from provider work leases. Add a cross-crate construction test with no Tokio runtime or YANG values.
Permit a completion callback or an opaque held owner, provided both designs meet these requirements:

- The coordinator holds a root lease throughout preparation. Register provider-owned work before it can start or enter a blocking queue.
- Cancellation seals admission to new work. It drops the root only after candidate ownership is released or transferred.
- Quiet means the root and all registered work/result leases are released. Dropping a future, abort handle, or join handle does not prove quiet.
- Scope release returns capacity exactly once. No public force-complete operation can bypass outstanding leases.
- Completion callbacks and held-owner destructors must not block, panic, reenter coordinator state, or require a live Tokio context.
- Avoid an ownership cycle between the completion observer, scope, and permit. The observer must not itself prevent quiet.
- SONiC carries a lease through queued work, running closure, and queued result. Transfer or discard the result before releasing its lease.
- Test cancellation before worker start, during execution, and after completion but before result consumption, including errors and unwind.

Permanently stuck registered work retains its slot. This proves non-overlap, not eventual termination or hard cancellation.
Opaque OS/SDK work, including unregistered filter/reqwest DNS internals, is outside the registered-work guarantee.
This exclusion does not cover provider-owned blocking jobs or returned configuration payloads.
Expiry and host-stop futures never acquire or await the preparation slot, and never await provider quiet.
New admission, pending-record, and ledger locks are never held across filtering, provider waits, or native preparation.
This phase guarantees their independence from provider waits, not from existing synchronous native preparation.

#### Configuration-Material Accounting

Iterate servers in canonical source order and slots in plan order. A selected-name set provides membership, not execution order.
Reuse iteration 04's `ServerResolutionPlan` and plan-local typed slots. Do not add global slot IDs.
Build all selected plans and reject an excessive complete request count before the first resolver call.
Resolve sequentially. Repeated references count separately, without deduplication.
A resolver slot is not an HTTP URL request. Provider fan-out and response limits remain independent.
Count attempted slots monotonically, including failures. Internal retries cannot reset the count.

Use one payload-size definition for decoded keys, shared secrets, public/private key fields, certificates/intermediates, trust bags, CRLs, and OCSP responses.
Include downstream proxy secret payloads. Exclude field names, opaque references, collection metadata, and allocator slack from this decoded-payload measure.

The byte charge is `L + E`, using checked arithmetic:

- `L` counts the complete candidate's logical configuration payload, once per destination occurrence, even when destinations share storage.
- Include inline material, expanded bundles, proxy credentials, and retained servers borrowed from the active catalog during partial refresh.
- Reserve all known logical payload before expansion. Increase the reservation at each individual provider-result handoff for previously unknown payload.
- `E` counts additional retained configuration-payload allocations beyond the destination owners already covered by `L`.
- Reserve known copy sizes before cloning. Moves transfer charges, and shared ownership of the same allocation adds no duplicate allocation charge.
- A moved provider result reserved for its destination counts once. Concurrent staging or installation copies add to `E` until released.
- Check each provider return before buffering or installation. Reject and drop an oversized return immediately, before another resolver call.
- Track live charge and its high-water mark. Never reduce the logical full-candidate charge merely because an unchanged server is borrowed.
- Consume changed materialized servers into publication. Do not retain dead candidates while cloning their payloads into the committed set.

Compute known expansion sizes from borrowed source before `enumerate_server` or any equivalent payload clone.
The raw-input boundary is the immutable observation snapshot supplied by the datastore before candidate processing.
Sharing or moving that existing owner creates no extra allocation charge. Its resulting destination payload still contributes to `L`.
Every new payload allocation made for filtering, expansion, staging, or publication belongs to candidate accounting, regardless of its type name.
An owned filtered projection contributes to `E` while retained alongside destination owners.
If the filter reuses the raw owner without copying, prove that ownership transfer or sharing instead of assuming it from equal contents.
Retained filtered projections keep their accounting classification across admissions. Reusing an `Arc` cannot relabel them as raw input.
Filter-created payload must be charged at return before coordinator retention, enumeration, or provider calls.
Known filter copies require reservation before cloning. An opaque filter's unknown result is checked at handoff, like a provider result.

The handoff check cannot prevent an opaque producer's earlier allocation. It prevents retaining that output or making further candidate copies.
Raw datastore ingestion, opaque provider/SDK internals, active/retiring catalogs, and process RSS are not collectively bounded by this policy.
Borrowing an active server excludes its existing allocation from `E`, not its logical destination contribution to `L`.
Prepared-runtime Rust payload copies are deferred to iteration 10, with no claim that they are configuration-input exclusions.
Iteration 10 extends this same ledger and limit. Native allocator internals remain outside the decoded-payload claim.

#### Deadline And Final Fence

Bound cooperative filtering, provider waits, and publication-lock waits with the captured absolute deadline.
The deadline ends at commit. Do not wrap the postcommit `retire_replaced` await in it.
An outer timeout or cancellation after commit still reports `PublicationOutcome::Published`.
The effective final limits are the componentwise minima of captured limits and currently applied limits.
Compute the deadline from the original admission instant. Reject at or after that deadline, including after synchronous native preparation returns.
Under publication serialization, check the complete planned slot count, accumulated attempts, complete-candidate charge, and byte high-water mark.
Keep policy changes serialized through that check and the commit so a tighter policy cannot pass between them.

Put every fallible check before retirement cutoffs, active snapshot replacement, applied health, and coordinator commit bookkeeping.
In the current manager, the fence must precede `previous.retire_replaced_until`, not run inside the existing commit callback.
Keep the commit callback infallible and non-awaiting. Do not turn a failed fence into a successful no-op commit.
Precommit rejection leaves active routing, generation, applied metadata, and existing retirement cutoffs unchanged.
Only a current revision can publish the separate candidate-rejection health outcome.
Postcommit retirement uses its separate cleanup budget. Its timeout or cancellation cannot become candidate rejection or undo publication success.

At source HEAD `35d9924a089beb818c65937eee6e4e319b486e41`, coordinator state stays locked across native preparation and manager publication waits.
Iteration 05 adds admission, ownership accounting, and the final fence without claiming to remove that coupling.
Do not extend this phase into the full R7 prepared-catalog rewrite.
Iteration 10 must remove native preparation from coordinator and publication lock ownership before R14 can close.

Apply this contract to startup, full reload, partial refresh, and inline-only supervised preparation.
Keep scheduling outside the neutral crate. Do not hold coordinator/publication locks during provider I/O.
The direct Opus written-plan review of this refined contract is recorded in the receipt below.

#### First Check And Acceptance

First add a counting resolver regression beside the coordinator materialization tests.
Use two servers in source order `z-first`, then `a-second`, with the same EPSK reference and one slot each.
With request limit one, require rejection and exactly zero resolver calls.
With limit two, require exactly two calls in source order, each installed into its own typed target.
Use one known test key and unbounded validity. No native endpoint preparation or external provider is needed for this first check.
Introduce only the policy/test seam needed to compile the regression before changing admission enforcement.
Run that exact test before enforcement changes and immediately after the first fix.
Compilation failure or zero selected tests is not behavioral failure evidence.
Record the actual failure and passing evidence, including the selected test count.

Acceptance:

- Exact-limit and limit-plus-one cases cover request counts, inline material, expanded bundles, provider results, and merged partial refreshes.
- Omitted container, empty container, omitted leaves, explicit defaults, JSON round-trips, and programmatic construction all preserve 30/256/67108864 defaults.
- Each leaf accepts `1` and `4294967295`. Zero, out-of-range JSON integers, overflow, and unrepresentable deadlines fail without panic.
- Ownership tests distinguish shared raw input from an equal owned filter copy, reused filtered projections, moved provider output, and simultaneous staging copies.
- Tests prove pre-clone reservation and immediate oversized-result disposal before any later resolver call.
- Several slow successful requests cannot renew the whole-candidate deadline.
- Oversized or expired candidates never publish partially.
- Cancellation releases HTTP capacity and staged material.
- Expiry monitors and host shutdown progress while providers stall, without waiting for scope quiet.
- Burst tests assert one active work scope, at most three unexpanded pending records, and at most three owned waiter futures.
- A barrier holds cancelled registered work while source, credential, and refresh events arrive. No replacement provider starts before quiet.
- The burst ends with a rejected newest source. Older success and failure must not publish or alter that rejection.
- Separate cases cover credential invalidation during filtering, expired pending admission, coalesced periodic ticks, and current-source recovery after quiet.
- Observed failure order is deterministic, and diagnostics are sanitized.
- Tighter timeout, slot, and byte limits each fail at the final fence before any retirement cutoff or applied-state change.
- A deadline that expires during native preparation rejects afterward. This test proves a fence, not native preemption or expiry-lock independence.
- A retirement timeout after commit does not erase publication success or report a candidate budget failure.

Checks: canonical policy/default tests, actual YANG regeneration, paused-time and native cancellation tests, common gates, and platform/native integration.

### 06: Prepared Operations

Status: published as staged PR #283; both named reviews and coordinator final gates passed.
The PR targets iteration 05 while required hosted checks remain pending, as permitted by the common procedure.
Scope: R6 and the consuming-IPC/Bash-builder portions of R15.

#### Initial Implementation Receipt

Worktree: `/home/vscode/tacacs-rs-06-prepared-operations`; branch: `refactor/general-iterations/06-prepared-operations`.
The implementation has 36 tracked modified files, no new files, and no tracking-document changes.
`FixedExchange: Send + Sync` borrows protected prepared bodies and requires `Reply: Send`.
Fallible concrete constructors encode once. Captured request deadlines cover preparation and admission; allowed attempts borrow the same exchange.
Networking retains packet headers, fresh session IDs, obfuscation, reply validation, and transport ownership.
IPC consumes owned requests. Bash uses its existing builder while preserving exact mandatory metadata and argument order.
The invalid fixed-request regression ran one test and failed before preparation moved ahead of connection creation.
The passing form observes zero connections, messages, and sessions. Serialization characterization observed one encoding across two fresh session IDs.

Initial affected-package tests passed on Rust 1.88 and stable: protocol 83, networking 257, agent 228, IPC 39, CLI 66, and Bash 8.
The independent peer runner passed nine cases. Native prepared-source tests passed 48 cases before the parent fixture additions.
Nine pure exchange Miri tests and four 30-second existing fuzz targets passed with private writable corpora.
The Rust 1.88 generic connector fixture compiled; the monomorphic fixture failed with the expected Send generality diagnostic.
An initial unwritable compiler-output location was corrected; that environmental failure is not counted as verification.
Affected formatting, strict Clippy, private docs, architecture checks, and three isolated Linux consumer profiles passed.
Windows, ARMhf, coverage, both named reviews, and coordinator final gates are not claimed complete.

Initial complete changed-content manifest: `862a9d14937effbefe143db5db9da9623757a56ca5e4ec6d247bec0ad27af6c8`.
Initial tracked patch SHA-256: `3adb5c3e3307b340a3b8ba2356a277f65740be0137d546e51ae321fe0cef8d29`.

#### Named Review Receipt

The parent fast-forward from `e3f60473` to `8e0bdc9` preserved the complete iteration 06 patch byte for byte.
`GPT-6 Astra (copilot)` reviewed all 36 changed paths and accepted the unchanged implementation without source edits.
It reran affected Rust 1.88 tests: protocol 83, networking 257, agent 235, IPC 39, CLI 66, Bash 8, and configuration 269.
It also passed connector boundaries, 23 doctests, all 55 native prepared-source cases, and nine independent peer cases.
The generic connector fixture compiled; its monomorphic counterpart failed with the expected Send generality diagnostic.
Affected strict Clippy, private docs, formatting, architecture, and whitespace checks passed.

`Claude Opus 5.5 (copilot)` found no behavior, security, or contract defect.
It corrected two stale rustdoc sentences that still described execution-time request encoding.
The focused warning-free networking docs check ran immediately after that docs-only edit.
Affected tests, networking doctests, strict Clippy, and formatting passed afterward.
The coordinator accepted that nonmaterial documentation correction; Astra's behavior review remains applicable.
Neither reviewer claims current Windows, ARMhf, coverage, or full-workspace execution.

The coordinator recomputed the complete final manifest using the specified NUL-delimited recipe:
`9b7a84ba66f96d0494e41e8f347383f7d0215e898d9e0a3b91f51739b919a520`.
The final tracked binary patch SHA-256 is `87c51c14664c1b336d15135cc2d6911c47118f2f7302cf3dad16228285a843c4`.
The Opus report used space-delimited manifest records; its aggregate is not this canonical complete-content fingerprint.
#### Coordinator Final Gate Receipt

The complete workspace gate sequence used `/home/vscode/.cache/tacacs-rs-06-prepared-operations` and emitted `ALL_ITERATION_06_GATES_PASSED`.
Formatting, strict nightly Clippy, warning-free private docs, stable build, all-feature tests, and Rust 1.88 all-target checks passed.
All 26 YANG generator tests and 256 selected delivery tests passed. Whitespace validation passed.
The run included 235 agent tests, 257 passing networking unit tests, 83 protocol tests, and all 55 native prepared-source cases.
Eight manual-peer tests and two existing networking benchmarks remain ignored; the separate nine-case peer run supplies executed interop evidence.
No source bytes changed during the gate run. The final patch hash still matches the reviewed value above.
The existing optional `console-subscriber` manifest advisory did not fail Clippy. No validation process remains active.
The clean local checkpoint is `572652e3c41936fbad46a4c961e2be7f52560a30`, with tree `9d04f8c7cb54d2c80aff65bce44000ef3a385688`.
Hosted Windows and ARMhf success is not claimed. Merge remains gated on the predecessor's merge and current-head required checks.

#### Publication Receipt

[PR #283](https://github.com/AuthScaffold/tacacs-rs/pull/283) targets `refactor/general-iterations/05-candidate-budgets` at predecessor `8e0bdc9dbc329acab018ce5e92bb72e50fe88049`.
Its published head is `572652e3c41936fbad46a4c961e2be7f52560a30`; its tree equals the tested checkpoint above.
The remote PR reports exactly 36 changed files and the `skip-release` label. No tracking documents occur in its diff.
Copilot review was requested on that head. Required workflow `39282835429` started in queued state during the reported Actions incident.
An empty initial comment list or pending workflow is not merge clearance.
After predecessor merge, update this published branch through a normal forward merge of updated `main`, then retarget and verify the complete tree.
Do not rewrite or force-push its published history. Rerun affected checks and require current-head review and CI before merge.

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

Status: planned. Scope: R7 and R14 prepared-runtime completion, built on iterations 05 and 09.

Carry source metadata, prepared endpoint identity, validity, budgets, and admitted revisions in one derived candidate.
Move native preparation outside coordinator state and publication locks while keeping preparation concurrency explicitly bounded.
Use at most one active preparation per coordinator initially, including cancelled-but-running blocking work.
Cancel superseded cooperative work. Do not release its capacity before owned work actually exits.
Recheck revisions, closure, validity, budgets, retained identities, and merged-catalog invariants before committing.
Resolve endpoint reuse against the current committed state, not a stale preparation-time assumption.
Retain urgent revocation retirement and earlier conservative validity bounds.
Extend the iteration 05 ledger through prepared-runtime Rust payload copies and owned native preparation boundaries.
Reserve known Rust-owned payload copies before preparation, or eliminate those copies through shared/moved ownership.
Include endpoint configuration, TLS/PSK key owners, revocation evidence, and comparison copies wherever they retain Rust-owned payload.
Audit every prepared owner, including rejected candidates and queued native results. Do not exempt Rust payload because its owner wraps native state.
Reuse iteration 05's limit, high-water accounting, registered-work ownership, pending bounds, and final fence before retirement cutoffs.
Keep native allocator internals and total RSS explicitly outside any decoded-payload accounting claim.
Do not mark R14 complete until this extension and native preparation/expiry-lock independence are verified.
Document unchecked server builders, validated roots, materialized values, and prepared candidates as distinct stages.
Keep schema acceptance, runtime capability checks, and native verification explicit rather than deleting them as duplicate validation.

Acceptance:

- Barrier tests cover newer source, credential change, expiry, policy update, host stop, and revocation change during preparation.
- Rejected/precommit-cancelled work never changes the active generation.
- Postcommit cancellation leaves routing, health, and coordinator bookkeeping coherent.
- Unchanged endpoints retain identities and counter epochs only when final reuse checks still hold.
- Replacement bursts cannot accumulate background native preparations beyond the bound.
- Expiry and shutdown remain independent of preparation locks. Document non-preemptible native-work limitations rather than promising hard cancellation.
- Exact-limit and limit-plus-one tests count configuration and prepared Rust payload together, including partial refresh, reuse, queued results, and cancellation.
- Native-work barriers prove expiry and shutdown can progress while preparation remains blocked, without releasing its capacity early.
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
| R14 | 05, 10 |
| R15 | 06, 12, 13 |

R14 remains open after 05. Closure requires 10's prepared-runtime Rust payload accounting and native preparation/expiry-lock independence.

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

### Iteration 05 Detailed Contract Follow-Up

Date: 2026-10-19. Status: direct written follow-up complete; Opus review pending.
Caller-specified reviewer route: `GPT-6 Astra (copilot)`. No substitute reviewer or subagent was invoked.
The caller supplies the accepted route. This session provides no independent routing metadata to verify it.
Input document blob: `e187072cb07abae2b0110625135b7375446f35c6` from `git hash-object docs/refactor-delivery-plan.md`, without `-w`.
Source input: clean `/home/vscode/tacacs-rs-04-credential-targets` at `35d9924a089beb818c65937eee6e4e319b486e41`.
Inputs include current 05/10, the caller's prior source conclusions, coordinator admission/publication, manager publication, supervisor loop composition, and SONiC result ownership.

Findings and dispositions:

- Accepted 30 seconds, 256 slots, and 67108864 bytes. Added explicit generated-default and overflow cases without changing their policy meaning.
- Pending work lacked a numeric bound. Defined three unexpanded records and three owned waiters, with coalescing and revision admission before waits.
- Raw-input ownership could hide filtered copies. Defined `L + E`, the datastore boundary, retained projection charges, and mandatory ownership tests.
- Registered-work quiet could be confused with future completion. Required root/work/result lease release and public construction without runtime dependencies.
- Kept callback versus opaque held-owner construction open. Both must meet exactly-once, nonblocking release and no-premature-quiet requirements.
- Final-fence placement required a concrete boundary. Required validation before `retire_replaced_until`, with serialized current policy and no fallible commit callback.
- Existing native lock coupling remains real. Kept its removal and all prepared-runtime Rust payload accounting in 10 before R14 closure.
- Specified the first counting-resolver regression and barrier cases. These are required future tests, not executed implementation evidence.

Actual document validation:

- Immediately after the first edit, the read-only Python structural validator exited successfully.
- All 18 iteration headings occur once in order. R1-R15 coverage matches the stack table, including R14 mapped to 05 and 10.
- All eight local relative links resolve. No trailing whitespace or conflict markers exist.
- Assertions preserve the native lock-coupling disclosure and iteration 10's prepared-runtime accounting and lock-independence requirements.
- Assertions also check finite pending work, the first zero-call regression, payload accounting, defaults, and the pre-retirement fence.
- `get_errors` reported no errors for this document.
- No Rust tests, generated-default tests, YANG regeneration, native tests, or hosted checks ran during this document-only review.

Only this plan's 05/10 sections, related tables/coverage text, and this appended receipt changed in this follow-up.
No production edits, other file edits, Git writes, branch changes, pushes, or subagents form part of this review.
The output document blob will be reported outside this file after validation.
Material contract revisions require the direct `Claude Opus 5.5 (copilot)` written-plan review, which remains pending.
The earlier completed sequence-review receipts do not satisfy that new review gate.

### Iteration 05/10 Opus Written-Contract Review

Date: 2026-10-19. Status: direct written review complete.
Caller-specified reviewer route: `Claude Opus 5.5 (copilot)`. No substitute reviewer or subagent was invoked.
This session provides no independent routing metadata to verify that route.
Input document blob: `4f71c9118037e94fd699003d52a27e5f7a0fc311` from `git hash-object`, without `-w`.
Source input: `/home/vscode/tacacs-rs-04-credential-targets` at `35d9924a089beb818c65937eee6e4e319b486e41`.
Source read: `publication.rs`, `materialization_coordinator.rs`, the HTTP resolver fallback, SONiC provider blocking work, and the runtime-policy YANG module.

Confirmed without change:

- Pending work is finite: three unexpanded records, three owned waiters, and no expanded plans or provider results in records.
- One admission instant and absolute deadline are captured before filtering and capacity waits. Successful substeps do not renew them.
- `L + E` charges logical destinations, filter-owned copies, partial retained servers, inline material, and provider results.
- Reservations precede known clones. Each provider return is checked before buffering or another resolver call.
- Phase limits are admission policy. Raw ingestion, opaque SDK internals, native allocators, and RSS stay outside the claim.
- Registered work uses standard-library types only. SONiC leases cover queued work, running closure, and queued result.
- A stuck registered job keeps its slot. Opaque OS/SDK work exclusions do not cover provider-owned blocking jobs.
- The fence precedes `retire_replaced_until`. Source confirms that call precedes the infallible `publish_runtime` callback.
- The current manager prepares native endpoints under `catalog_reload_lock`. Iteration 05 discloses this coupling and defers removal to 10.
- Iteration 10 extends the same ledger to prepared Rust payload and native locks. R14 stays open after 05.

Clarifying edits, with no policy change:

- Defaults come from generated YANG only, with the existing `1..max` leaf style. Added `1` and `4294967295` acceptance cases.
- Stated no new dependency and no YANG policy types in the neutral resolver crate.
- The HTTP resolver passes the same work scope to its fallback. Source shows a direct `fallback.resolve` delegation.
- Expiry and host stop never acquire or await the slot or provider quiet. New locks are never held across long waits.
- Reuse iteration 04's `ServerResolutionPlan` and plan-local typed slots, without global slot IDs.
- The candidate deadline ends at commit. An outer timeout around postcommit `retire_replaced` cannot change `Published`.

No material change was made. No Astra follow-up is necessary for these clarifications.
No outstanding written-plan blocker remains for 05 or 10. No user decision is required.

Validation: a read-only Python check ran immediately after the edits and passed.
All 18 iteration headings occur once in order. R1-R15 coverage is complete, with R14 mapped to 05 and 10.
All eight local links resolve. No trailing whitespace or conflict markers exist.
Assertions confirmed the R14 non-closure text in 05 and 10 and each new clarification.
No code, tests, YANG regeneration, native checks, or hosted checks ran. This review claims no implementation.
Only this plan changed. No Git writes, branch changes, pushes, or other file edits occurred.
The output document blob is reported outside this file.
No outstanding plan blocker remains from this follow-up. Implementation and its required evidence remain pending.