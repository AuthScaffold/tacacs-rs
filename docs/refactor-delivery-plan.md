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

### WSL Resumption, 2026-10-20

The user renewed authority to finish iteration 10 and continue through iterations 11 through 18 autonomously.
This authority includes commits, pushes, pull requests, and squash merges after every review and verification gate passes.
Required tool approvals still apply.

Implementation runs through `GPT 6.1 Sol` subagents.
Sequential direct reviews run through `GPT 6 Astra`, then `Claude Opus 5.5`.
Reviewers can make necessary direct revisions.
Material revisions return to each reviewer whose earlier conclusion they invalidate.
An unavailable named model blocks its gate rather than permitting a silent substitution.

The tracking checkout is `/home/ubuntu/tacacs-rs`.
Restored implementation worktrees are `/home/ubuntu/tacacs-rs-10-prepared-publication` and `/home/ubuntu/tacacs-rs-11-embedding-api`.
Each implementation uses its separate `$HOME/.cache/tacacs-rs-<slug>` target directory.
The restored iteration 11 binary patch matches SHA-256 `e43aab42a4db5e210a9fac137d9d2b3963da0ead82cb973c598a21184768eb7f`.
Its 15 modified files remain protected while iteration 10 review repairs finish.

The original chat archive passed its recorded checksum.
All 319 restored files match the archive, and the restored chat index passes SQLite integrity checks.
Recovery used a separate directory, without replacing live VS Code session databases.
This recovery restores context, not a guarantee of native chat import.

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

Status: squash-merged as `efdc20d60b4d756a37e99c5b13c0c3580781b9fc`; both named reviews and final local and hosted gates passed.
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

#### Merge Receipt

Required current-head workflow `39277505296` subsequently completed successfully on `8e0bdc9dbc329acab018ce5e92bb72e50fe88049`.
ARMhf job `118145680649`, Windows testing job `118149258839`, and both CI-success gates passed.
Copilot review `5573894855` had no open issues, all review threads were resolved, and the PR-scoped open-alert query was empty.
The final mergeability check was clean. The guarded REST squash request specified that exact reviewed head.
GitHub returned `merged: true` and squash `efdc20d60b4d756a37e99c5b13c0c3580781b9fc`.
Fetched `origin/main` and the reviewed topic head have identical tree `717dcc9a01be9ff38f684d615cbf6ee0b13b51d3`.
The published iteration 06 branch integrated this squash through a normal merge, without rewriting history.
Its complete tested tree stayed unchanged, as did the uncommitted iteration 07 patch after its parent fast-forward.
After preserving this receipt, the clean idle iteration 05 worktree was removed without force.
Its exact owned 18 GiB cache and six completed PR/reply/squash-description temporary files were removed.
Branch history and GitHub evidence remain intact. Active iterations 06 and 07 and the diagnostics checkout were preserved.

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

Status: squash-merged as `ab347c178906b7ebef9918a3153d366712d01595`; both named reviews and final local and hosted gates passed.
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
Initial Copilot review `5574390116` on `572652e3c41936fbad46a4c961e2be7f52560a30` reported no open issues; no threads were unresolved.
After predecessor squash, normal merge `f8a59ac9fef6700d310d0f796c488462e361ceef` retains tested tree `9d04f8c7cb54d2c80aff65bce44000ef3a385688` exactly.
Focused Rust 1.88 reruns passed 235 agent, 257 networking, and 83 protocol tests; two existing networking benchmarks remained ignored.
The final head was pushed normally and PR #283 now targets `main`, with exactly 36 implementation files and no tracking documents.
Fresh Copilot review `5574629008` on `f8a59ac9fef6700d310d0f796c488462e361ceef` reports no open issues; all threads are resolved.
Retargeting superseded workflow `39285678964`; its cancellation is not a source failure or a passing gate.
Replacement workflow `39285889531` runs on the same final head. ARMhf, Windows tests, MSRV, and all consumer profiles passed at the latest observation.
Remaining build and aggregate checks are still in progress. No merge clearance is claimed.

#### Merge Receipt

Replacement required workflow `39285889531` subsequently completed successfully on final head `f8a59ac9fef6700d310d0f796c488462e361ceef`.
ARMhf job `118172693794`, Windows testing job `118176104969`, and both CI-success gates passed.
Copilot review `5574629008` had no open issues. All threads were resolved, the PR-scoped open-alert query was empty, and mergeability was clean.
The guarded squash request specified that exact reviewed head. GitHub returned `merged: true` and squash `ab347c178906b7ebef9918a3153d366712d01595`.
Fetched `origin/main` equals the complete tested tree `9d04f8c7cb54d2c80aff65bce44000ef3a385688`.
Iteration 07 integrated the squash through normal merge `d01637e9f78a0c46254820196a51f5d25ea7bdc4`, preserving its complete tested tree.
All 237 agent tests passed again. Iteration 08 fast-forwarded its parent without changing its complete changed-content fingerprint, including the new file.
After preserving this receipt, the clean idle iteration 06 worktree was removed without force.
Its exact owned 22 GiB cache and completed PR/squash-description temporary files were removed.
Branches, review history, active iterations 07 and 08, and the diagnostics checkout remain intact.

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

Status: squash-merged as `f1e65c15e76b1d58fe56682e3ea814e33818fb41`; both named reviews and final local and hosted gates passed.
Coordinator final workspace gates passed. Scope: R10.

#### Implementation And Review Receipt

Worktree: `/home/vscode/tacacs-rs-07-binding-outcomes`; branch: `refactor/general-iterations/07-binding-outcomes`.
Eight tracked files are modified, with no new or deleted files and no tracking-document changes.
Lease-only admission moved from manager methods to `RoutingLease::{reserve, admit_reserved, admit}`.
`RequestRouting` calls its lease directly and retains manager ownership only for binding and availability publication.
`BoundServer::{note_success, note_failure}` replace behavior-free router and manager outcome forwarders.
Typed attempts and raw managed conversations no longer retain a router solely for recording outcomes.
Guard scopes, disarm conditions, absolute deadlines, delivery classifications, retry decisions, raw pinning, session mapping, and reply acknowledgement remain unchanged.

The first focused compile exposed seven test consumers of the removed admission API. Those consumers were migrated before further changes.
Structural characterization checks then passed: captured retry across reload, cancellation releasing capacity, and two cases where leases or bindings outlive their former manager/router.
Rust 1.88 package checks passed 237 agent, 257 networking, four connector, and 11 networking doctests.
Two existing networking benchmarks remain ignored. Agent tests had no ignored cases.
The standalone generic connector fixture compiled. The monomorphic fixture failed with the expected Send generality diagnostic.
An unwritable initial output location was corrected and is not counted as verification.
Strict agent Clippy, private docs, nightly formatting, 35 architecture checks, diagnostics, and whitespace checks passed.

Focused coverage ran with the existing LLVM tools and all 237 agent tests:

```bash
CARGO_TARGET_DIR=/home/vscode/.cache/tacacs-rs-07-binding-outcomes cargo +1.88.0 llvm-cov test -p tacacsrs-agent --lib --all-features --locked --lcov --output-path /home/vscode/.cache/tacacs-rs-07-binding-outcomes/agent-ownership.lcov
```

Covered lines were 217/221 in the lease/binding file, 64/73 in typed routing, and 212/290 in raw sessions.
These figures are focused evidence, not a complete coverage claim.

`GPT-6 Astra (copilot)` accepted the source without edits and independently passed 112 selected behavior tests.
Those selections covered manager behavior, typed routing, raw bridging, networking routes, admission, retry, and connector boundaries.
It also passed the compiler fixture, strict Clippy, formatting, 35 architecture tests, and whitespace checks.
`Claude Opus 5.5 (copilot)` accepted the same unchanged source and passed 82 manager/router/bridge tests, with no ignored cases.
Both reviews confirmed explicit shutdown still closes admission and generation fencing remains owned by the networking binding.
Cleanup still depends on connectors honoring their close/join contracts; no new hard-cancellation guarantee is introduced.

Both reviewers cover complete changed-content manifest `f43a267645340a9b92a0e74f749cf580290d8b2057a021ca57fc0d9e159582c5`.
The separate tracked binary patch SHA-256 is `d0c2c4b5b2d04bd163f1e0472b0a88a73f4d962ce9b7ade9763525a5b9abec77`.
Parent integration preserved that patch byte for byte.
No parser, schema, dependency, or unsafe changes require fuzz, compatibility, audit, or new Miri checks.
Independent native prepared-source and peer suites were not rerun for this structural iteration.
#### Coordinator Final Gate Receipt

The complete final sequence used `/home/vscode/.cache/tacacs-rs-07-binding-outcomes` and emitted `ALL_ITERATION_07_GATES_PASSED`.
Formatting, strict nightly workspace Clippy, warning-free private docs, stable build, all-feature tests, and Rust 1.88 all-target checks passed.
All 26 YANG tests and 256 selected delivery tests passed. Whitespace checks passed and the reviewed patch hash is unchanged.
The final run included 237 agent tests, 257 passing networking unit tests, 83 protocol tests, and 55 native prepared-source cases.
Ten existing ignored Rust tests remain excluded; the independent peer runner was not rerun for this structural iteration.
The existing optional `console-subscriber` manifest advisory did not fail Clippy. No local validation process remains active.
Windows and ARMhf remain current-head hosted gates, not executed local evidence.

#### Publication Receipt

[PR #284](https://github.com/AuthScaffold/tacacs-rs/pull/284) targets `refactor/general-iterations/06-prepared-operations`.
Published head `ded01e643f27d1847ca7e847bc154464433db5bb` has tested tree `9c03e697aa8a65e10d750145048f4998d6fbfe0c`.
The remote PR reports exactly eight implementation files, no tracking documents, and the `skip-release` label.
Copilot review was requested on that head. Required workflow `39290252584` started and is in progress.
The predecessor remains subject to its replacement required workflow `39285889531`; pending checks are not merge clearance.
No iteration 07 worktree or cache is eligible for cleanup before merge and preservation of its receipts.
Copilot review `5574977456` on the original published head reported no open issues and recommended approval.
After predecessor merge, integration head `d01637e9f78a0c46254820196a51f5d25ea7bdc4` retains tested tree `9c03e697aa8a65e10d750145048f4998d6fbfe0c` exactly.
All 237 agent tests passed again. The head was published normally and PR #284 now targets `main`, retaining exactly eight implementation files.
Copilot review `5575347114` on `d01637e9f78a0c46254820196a51f5d25ea7bdc4` reports no open issues and recommends approval; all threads are resolved.
Retargeting superseded workflow `39295100283`. Replacement current-head workflow `39295100962` is in progress, not merge clearance.

#### Merge Receipt

Current-head required workflow `39295100962` subsequently succeeded on `d01637e9f78a0c46254820196a51f5d25ea7bdc4`.
ARMhf job `118205572861`, Windows testing job `118208781178`, and both CI-success gates passed.
Copilot review `5575347114` had no open issues. All threads were resolved, the PR-scoped open-alert query was empty, and mergeability was clean.
The guarded squash specified that exact reviewed head. GitHub returned `merged: true` and squash `f1e65c15e76b1d58fe56682e3ea814e33818fb41`.
Fetched `origin/main` equals tested tree `9c03e697aa8a65e10d750145048f4998d6fbfe0c`.
Iteration 08 integrated the squash through normal merge `e0d1ccb183b2e0bf43f3fb80841fc7d5ecd1a263`, preserving its tested tree exactly.
All 49 observer source tests passed again. Iteration 09 fast-forwarded its parent without changing its patch.
After preserving this receipt, the clean idle iteration 07 worktree was removed without force.
Its exact owned 12 GiB cache and completed PR/squash-description temporary files were removed.
Branches, review history, active iterations 08 and 09, and the diagnostics checkout remain intact.

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

Status: squash-merged as `47d74aa00aba3bc0d2ced4473767ac8c22a4fbe9`; both named reviews and final local and hosted gates passed.
Coordinator final workspace gates passed.
Scope: R13.

Read-only preflight confirms two owners in the current predecessor: private `source/file.rs::FileObservation` and public `source/policy.rs::FilePolicyObservation`.
Their common mechanism owns pending invalidation, debounce state, a retained read task, watcher failures, and platform directory checks.
Keep the public policy wrapper and both parsing/event contracts separate from the private shared mechanism.
Configuration can have a finite baseline without a native watcher; that mode must still return its baseline and then end.
Keep separate invalidation and failure receivers so failure checks cannot consume changes received during an active read.
Configuration alone owns previous-snapshot delta history. Do not introduce policy snapshot history into the observer.
Started operating-system reads can finish after drop, but must not publish into a dropped observation. Preserve that limitation without claiming hard I/O cancellation.
#### Initial Implementation Receipt

Worktree: `/home/vscode/tacacs-rs-08-file-observation`; branch: `refactor/general-iterations/08-file-observation`.
The implementation modifies three tracked source files and adds private `source/file_observation.rs`; no files are deleted.
One private `FileObservationState<T>` owns debounce, retained reads, separate receivers, failure priority, and cleanup.
Configuration and policy wrappers retain lazy loaders, parsing, warnings, and distinct events. Only configuration retains parsed-candidate delta history.
Public APIs remain unchanged. No compatibility aliases or dependencies are added.

The first focused existing cancelled-read test selected one case and passed without ignores.
Configuration migration then passed 15 tests; policy migration passed eight tests.
Final source checks passed 49 cases, including 13 new characterizations. Full configuration tests passed 282 runtime cases and five doctests.
Consumer checks passed 65 supervisor, nine daemon-process, and 66 CLI cases.
MSRV all-target/all-feature checks and Rust 1.99 minimal/all-feature consumer checks passed.
Strict configuration Clippy, private docs, formatting, architecture validation, 35 architecture tests, and diagnostics passed.
Focused coverage reran all 49 source cases: shared owner 93.71%, configuration 96.76%, and policy 97.77% line coverage, including tests.
These are characterization results, not failed-before evidence of a pre-existing defect.
Windows and ARM execution remain unverified. Started blocking reads can finish after drop without publishing.

The complete changed-content manifest, including the new file, is `17bf56dea10a17f1cf66024aaaa6ddea86c775fd2637fc50c56b3f5ddc2b030b`.
Tracked-only patch SHA-256 is separately `0235432412174d41522d480b4fef67ac95f35de8cc7a9a5645f1d79603885c3d` and is not a complete review identity.
Parent integration preserved the complete content manifest and tracked patch byte for byte.
Both named direct reviews and full final workspace gates remain pending. No local validation process remains active.

#### Named Review Receipt

`GPT-6 Astra (copilot)` reviewed all four paths, including the untracked shared implementation, wrapper tests, and `DirectoryWatch`.
It found no actionable issue and made no edits. All 49 source tests and Rust 1.88 configuration all-target/all-feature checks passed.
`Claude Opus 5.5 (copilot)` reviewed the same unchanged source and found no actionable issue.
It independently passed 49 source tests, strict configuration Clippy, formatting, and the MSRV check.
Both reviews confirmed separate receivers, retained read/debounce state, failure priority, finite baselines, lazy loaders, and unchanged wrapper contracts.
Both cover complete content manifest `17bf56dea10a17f1cf66024aaaa6ddea86c775fd2637fc50c56b3f5ddc2b030b`, including the new file.
The tracked-only patch remains `0235432412174d41522d480b4fef67ac95f35de8cc7a9a5645f1d79603885c3d`.
The complete patch, formed from the tracked diff followed by the new-file no-index diff, is `4dc3f805a0859d715ab5c6c0957120369aa02d055020287e7ead058b20166768`.
Neither reviewer executed Windows or ARM. Abstract Windows helper tests are not native watcher execution evidence.
#### Coordinator Final Gate Receipt

The complete sequence used `/home/vscode/.cache/tacacs-rs-08-file-observation` and emitted `ALL_ITERATION_08_GATES_PASSED`.
Formatting, strict nightly workspace Clippy, warning-free private docs, stable build, all-feature tests, and Rust 1.88 all-target checks passed.
All 26 YANG tests and 256 selected delivery tests passed. Whitespace checks passed.
The run included 127 configuration unit tests, 237 agent tests, 257 passing networking unit tests, and all 55 native prepared-source cases.
Ten existing ignored Rust tests remain excluded. No new source edits occurred during final verification.
The existing optional `console-subscriber` manifest advisory did not fail Clippy. No local validation process remains active.
The complete reviewed identity still includes the new shared-observer file. Current-head hosted Windows and ARMhf checks remain required.

#### Publication Receipt

[PR #285](https://github.com/AuthScaffold/tacacs-rs/pull/285) targets `refactor/general-iterations/07-binding-outcomes`.
Published head `e2e39c19bf81f9b720ee9bb7e09160287061de1e` has complete tested tree `4c6eac3601670343a020ae21b252b2f404b201ef`.
All four reviewed files, including the new shared observer, are committed. The remote PR has the `skip-release` label and no tracking documents.
Copilot review was requested on that head. Required workflow `39299324444` is in progress.
Pending predecessor checks and an initial empty comment list do not establish merge readiness.
Initial Copilot review `5575691546` on `e2e39c19bf81f9b720ee9bb7e09160287061de1e` reported no open issues, with platform validation still required.
After predecessor merge, normal integration head `e0d1ccb183b2e0bf43f3fb80841fc7d5ecd1a263` retains complete tested tree `4c6eac3601670343a020ae21b252b2f404b201ef` exactly.
All 49 source tests passed again. The normal integration head was published and PR #285 now targets `main`, with exactly four implementation files.
Fresh Copilot review `5575934709` on `e0d1ccb183b2e0bf43f3fb80841fc7d5ecd1a263` reports no open issues and recommends approval; all threads are resolved.
Current-head required workflow `39302494582` is in progress. Hosted Windows and ARMhf remain merge gates, not assumed results.

#### Merge Receipt

Current-head required workflow `39302494582` subsequently succeeded on `e0d1ccb183b2e0bf43f3fb80841fc7d5ecd1a263`.
ARMhf job `118231498136` and Windows testing job `118234023765` passed.
The Windows log directly confirms shared-state, configuration, and policy watcher tests, including cancellation, failure priority, replacement, directory loss/rename, and stalled-read interruption.
Copilot review `5575934709` had no open issues. All threads were resolved, the PR-scoped open-alert query was empty, and mergeability was clean.
The guarded squash specified that exact reviewed head. GitHub returned `merged: true` and squash `47d74aa00aba3bc0d2ced4473767ac8c22a4fbe9`.
Fetched `origin/main` equals tested tree `4c6eac3601670343a020ae21b252b2f404b201ef`.
Iteration 09 integrated the squash through normal merge `49055f56925e0215a9120d36044cd1900a730b0c`, preserving its tested tree exactly.
All 32 coordinator tests passed again with the pinned normal rustup home. The new iteration 10 worktree fast-forwarded cleanly before implementation.
After preserving this receipt, the clean idle iteration 08 worktree was removed without force.
Its exact owned 15 GiB cache and completed PR/squash-description temporary files were removed.
Branches, platform logs, active iterations 09 and 10, and the diagnostics checkout remain intact.

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

Status: squash-merged as `b09c15b3242c7c633138ff3c5018ba338ccdc7bc`; both named reviews and final local and hosted gates passed.
Coordinator final workspace gates passed.
Scope: R8. This iteration does not move preparation across locks.

Local preflight confirms dependency knowledge currently uses `Option<BTreeMap<...>>`: `None` is unknown and `Some(empty)` is known-empty.
Known-empty does not fall through to an all-server selection. Preserve scheduled-refresh suppression and unknown-source invalidation behavior.
Applied empty catalogs have an active revision. Withdrawn state clears that active revision and retains a separate withdrawn revision.
Use existing dependency-index, independent-revision, partial-refresh, and expiry tests as the first discriminating checks.
Keep existing behavior assertions unchanged; adapt private fixture access only when the state representation requires it.

#### Initial Implementation Receipt

Worktree: `/home/vscode/tacacs-rs-09-coordinator-state`; branch: `refactor/general-iterations/09-coordinator-state`.
Only the coordinator implementation and its existing test module are modified. No files are added or deleted.
`DesiredRuntime::{Unfiltered, Filtered}` groups runtime projection, proxy policy, and dependency knowledge.
`DependencyKnowledge::{Unknown, Known}` preserves known-empty maps without nested optional maps.
`PublishedMaterial` distinguishes never-published, applied, and withdrawn state. Applied empty catalogs retain their revision.
Applied material groups servers, lifetimes, revision, and reference knowledge; withdrawn material retains its revision, expiry flags, and reference knowledge.
Raw source, admission, freshness, and pending-refresh state keep their existing independent meanings.
The types exclude split source/policy presence and simultaneous applied/withdrawn state. Server/lifetime key coherence remains a transition invariant.
Rejection still retains raw source; unavailability retains the projection. Expiry still reads validity from health.
Publication bookkeeping remains in the existing non-awaiting atomic callback. Preparation awaits, locks, revision fences, selection, notifications, budgets, and ordered payload ownership are unchanged.

The first edit immediately passed the exact dependency-index test: one selected case.
Subsequent coordinator checks passed 27, 27, and then 32 cases as the type-only migration progressed.
Five characterization tests were added. Two existing assertions received mechanical projection-access changes; expected values, timing assertions, and skips are unchanged.
The final agent suite passed 242 cases without ignores. A focused coverage rerun also passed all 242 cases.
Connector tests passed four cases. The generic compiler fixture passed; its monomorphic counterpart failed with the expected Send generality diagnostic.
Strict agent Clippy, private docs, MSRV checks, formatting, 35 architecture tests, diagnostics, and whitespace validation passed.
Coordinator line coverage was 765/790, or 96.84%. This is focused coverage, not a complete state-proof claim.
No Miri, fuzz, or YANG generation check was needed for this safe type-only change. Windows and ARM execution are not claimed.

The complete changed-content manifest is `63b323c37b132f14509172e76a0f34e0c738759b1ee47bd4efb2bc41d1a91c40`.
The separate tracked binary patch SHA-256 is `fcae0f2bac55b006f9e2f70a2842e8a5a47bd2f93b6778393e79d021185cc0e2`.
Parent fast-forward preserved that patch byte for byte. Both named reviews and full final workspace gates remain pending.

#### Named Review Receipt

`GPT-6 Astra (copilot)` reviewed both files and the old-to-new transition mapping without finding an actionable issue or making edits.
It independently passed all 32 coordinator tests and 242 agent tests, with no failures or ignores.
`Claude Opus 5.5 (copilot)` reviewed the same unchanged source and also found no actionable issue.
It passed the same 32 coordinator and 242 agent tests, strict agent Clippy, formatting, and whitespace checks.
Both reviews cover complete content manifest `63b323c37b132f14509172e76a0f34e0c738759b1ee47bd4efb2bc41d1a91c40`.
The separate binary patch remains `fcae0f2bac55b006f9e2f70a2842e8a5a47bd2f93b6778393e79d021185cc0e2`.
Both confirmed unchanged default, rejection, unavailability, dependency selection, refresh coalescing, publication, and expiry behavior.
Preparation still holds the existing locks. Callback and ordered payload/lease disposal behavior remain unchanged.
The types remove split source/policy presence, simultaneous applied/withdrawn state, and active servers or lifetimes after withdrawal.
Server/lifetime key coherence, withdrawn expiry validity, and reference-flag consistency remain transition invariants, not complete type-level guarantees.
No new raw-source logging or secret-bearing Debug derivation was added.
#### Coordinator Final Gate Receipt

The complete sequence used `/home/vscode/.cache/tacacs-rs-09-coordinator-state` and emitted `ALL_ITERATION_09_GATES_PASSED`.
Formatting, strict nightly workspace Clippy, warning-free private docs, stable build, all-feature tests, and Rust 1.88 all-target checks passed.
All 26 YANG tests and 256 selected delivery tests passed. Whitespace checks passed and the reviewed patch hash is unchanged.
The run included 242 agent tests, 127 configuration unit tests, 257 passing networking unit tests, and all 55 native prepared-source cases.
Ten existing ignored Rust tests remain excluded. No validation process remains active.
The inherited private rustup home automatically installed stable 1.99.1 and Rust 1.88.0 during the run; both required checks completed successfully.
The normal rustup home was restored afterward. Future normal gate commands pin it explicitly; private Clippy selection stays command-scoped.
No product MSRV or dependency changed. Current-head hosted Windows and ARMhf checks remain required.

#### Publication Receipt

[PR #286](https://github.com/AuthScaffold/tacacs-rs/pull/286) targets `refactor/general-iterations/08-file-observation`.
Published head `902f42c5394997f27ed629d3c04a4ec21deca0cb` has tested tree `954ffdc1d3c79379d8e8a1076acd919d32934a44`.
The remote PR reports exactly two implementation files, the `skip-release` label, and no tracking documents.
Copilot review was requested on that head. Required workflow `39307226464` is in progress.
The predecessor's current-head ARMhf job `118231498136` and Windows testing job `118234023765` passed; its full workflow still needs final success.
Neither those partial results nor an initial empty comment list establish merge readiness for this PR.
After predecessor merge, normal integration head `49055f56925e0215a9120d36044cd1900a730b0c` retains complete tested tree `954ffdc1d3c79379d8e8a1076acd919d32934a44` exactly.
All 32 coordinator tests passed again. The integration head was published normally and PR #286 now targets `main`, with exactly two implementation files.
Fresh Copilot review `5576388900` on `49055f56925e0215a9120d36044cd1900a730b0c` reports no open issues; all threads are resolved.
Required workflow `39308010437` failed ARMhf job `118250811176` because the runner shut down while downloading Docker base layers.
The log shows a shutdown signal, cancelled build context, and exit 143 before build or test execution. This is not source-regression evidence.
A failed-jobs rerun was accepted on the same unchanged head and is queued. Required success remains pending; no merge bypass or source change was made.
Attempt 2 subsequently completed successfully, including ARMhf job `118276795438`, Windows testing job `118276801812`, and required `CI Success` job `118281781562`.
The required check uses GitHub Actions app `15368`, as branch protection requires. The rollup is successful, all threads are resolved, and the PR-scoped alert query is empty.
Strict base comparison reports zero commits behind, and no additional branch rules were returned.
GitHub still reports a blocked merge state at the latest observation. The PR remains unmerged; no requirement was disabled or bypassed.
A single content-preserving CI refresh commit, `49e49162f5fc3cb2f5591202854082059337910c`, now triggers fresh checks and review without changing tested tree `954ffdc1d3c79379d8e8a1076acd919d32934a44`.
Its current Copilot review `5577982340` reports no open issues. Required workflow `39327284920` is in progress; earlier-head success does not clear this head.
Iteration 10 fast-forwarded that metadata-only parent change, and its complete source fingerprint stayed unchanged.

#### Merge Receipt

Fresh current-head workflow `39327284920` succeeded on `49e49162f5fc3cb2f5591202854082059337910c` and GitHub reported a clean merge state.
ARMhf job `118316352728`, Windows testing job `118319083698`, and both CI-success gates passed.
Copilot review `5577982340` had no open issues. All threads were resolved and the PR-scoped open-alert query was empty.
The guarded squash specified that exact cleared head. GitHub returned `merged: true` and squash `b09c15b3242c7c633138ff3c5018ba338ccdc7bc`.
Fetched `origin/main` equals unchanged tested tree `954ffdc1d3c79379d8e8a1076acd919d32934a44`.
Iteration 10 integrated the squash through normal merge `15052b7ec93cb795ecaabbd611427267077058e5` without changing its complete 30-file fingerprint.
Its eight focused native ownership cases and four disposal cases passed again with Rust 1.88.
After preserving this receipt, the clean idle iteration 09 worktree was removed without force.
Its exact owned 13 GiB cache, completed PR/squash drafts, and known reviewer test-diff scratch file were removed.
Branch history, the active iteration 10 resources, and the diagnostics checkout remain intact. No branch protection or required check was bypassed.

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

Status: PR #287 merged as `782c73ecf91554703284f6be2b689722a3fd6e03` after both named reviews and all current-head gates passed.
Reviewed repair head: `e90b0732b51cb1410c85fd5462da50f030806005`.
R14's prepared-runtime phase is complete under the documented accounting and cancellation limits.
Worktree: `/home/ubuntu/tacacs-rs-10-prepared-publication`; branch: `refactor/general-iterations/10-prepared-publication`.
Scope: R7 and R14 prepared-runtime completion, built on iterations 05 and 09.

Local preflight anchor: `PreparedServer::new` calls `prepare_endpoint` synchronously inside catalog reload while service and coordinator publication locks are also held.
Use the existing native-preparation pause barrier for the first failed-before check: expiry or shutdown must progress while preparation remains paused.
Cancellation must retain the preparation slot through actual worker completion and queued payload disposal.
`Preparation` currently owns its ledger directly and seals work registration on final owner drop. Preserve prompt sealing when native work retains capacity.
Do not solve worker lifetime by accidentally retaining an unsealed admission owner or detaching unaccounted payloads.
An initial implementation pass modified 25 tracked files and added networking `preparation_payload.rs`.
Focused native fence, cancellation, queued-result, and combined-budget checks passed during that pass, as did networking and configuration tests.
The full 55-case native prepared-source suite subsequently passed, including unchanged-certificate reuse and HTTP/OCSP refresh.
The initial handoff remained incomplete: strict gates, two newly unused manager methods, owner inventory, final hashes, and both named reviews still need completion.
No iteration 10 commit or PR exists. R14 is not marked complete, and the implementation is not publication-ready.

#### Complete Implementation Handoff

The finishing pass has 29 modified tracked files and one new networking module, `preparation_payload.rs`; no files are deleted.
Native endpoint and speculative catalog preparation now precede coordinator, service publication, catalog reload, and snapshot-write locks.
Registered native work shares the ledger without retaining the full preparation owner, so cancellation seals registration promptly while capacity survives work and result disposal.
Final fences precede retirement cutoffs and visible publication. They recheck revisions, source expiry, closure, validity, tighter limits, and current-catalog reuse.
Historical endpoint metadata remains shared only while its networking lifecycle is unfinished; identity tokens do not retain endpoint payload.
Speculative idle lifecycle registrations are disposed with their final unused catalog owner, before candidate capacity returns.
Two newly unused manager helpers became test-only; no warning suppression was added.

Prepared Rust accounting covers endpoint names and address text, packet-key copies, PSK callback bytes and settings, TLS identity/SNI, trust callback DER, fetched OCSP bytes, and live certificate/CRL comparison buffers.
The complete candidate includes retained and reused endpoints. Shared owners avoid repeated payload copies; known-size copies reserve before allocation.
Queued inputs, partial outputs, success/error results, callback captures, and lifecycle names retain accounting until disposal.
High-water accounting does not decrease when temporary buffers drop. Conservative enclosing-DER forecasts can reject before retained bytes reach the limit.
The measure excludes fixed-layout metadata, collection headers, reference counts, allocator slack, native allocator internals, connection execution, raw ingestion, opaque SDK/filter DNS, and RSS.
Direct helpers without a supplied ledger remain explicitly unmanaged. No process-wide memory or eventual native-work termination guarantee is introduced.

The first delegate's original execution chronology is unavailable. A later isolated predecessor replay selected one source-expiry test and failed with `source expiry blocked behind native preparation`.
That replay used its own extracted source and target. The active-source case passes; no active-cache replay contamination occurred.
Historical revocation and speculative lifecycle tests also failed before their corresponding repairs and passed afterward; preliminary fixture errors are not counted as defect evidence.
Barrier tests cover newer or rejected sources and credentials, both expiry orders, policy tightening, host stop, catalog ABA, and revocation replacement.
Thirty-two replacement admissions cannot exceed one native job. Cancelled and queued results retain payload, ledger charges, and capacity through disposal.
Combined exact-limit/one-byte-over tests cover new, reused, full, and partial candidates in eight combinations.

Scoped validation passed 813 tests with two existing manual benchmarks ignored: 250 agent tests, configuration tests, 260 passing networking unit tests, connector tests, and doctests.
All 55 native prepared-source cases and nine independent peer scenarios passed, including expired-certificate reuse.
Strict Clippy, private docs, formatting, MSRV checks, architecture validation, and three isolated consumer profiles passed.
Two pure-ledger Miri cases passed. Focused coverage includes publication/worker 685/689 lines, payload owner 156/162, and lifecycle 493/527, including test code.
The standalone generic connector fixture compiled; the monomorphic fixture failed with the expected Send generality diagnostic.
No local test, build, compiler, or owned peer listener remains active.

Complete changed-content manifest: `73bce56e175ae07c3e7587802151f0eb87ee3bdaa526adad2bffd4cc76e18ee2`.
Separate tracked binary patch SHA-256: `2255d05b268f2f45354be5972d913475ca7047f8b9107c385dbd95db7c3b27af`.
The new file is included in the complete manifest, not the tracked-only patch.
Both named reviews, final full-workspace checks, and current-head hosted gates remain pending. R14 remains open until those results and ownership claims are verified.

#### Named Reviews And Concurrent Disposal Repair

`GPT-6 Astra (copilot)` reviewed all 30 paths, including the new payload module, and accepted the initial implementation without edits.
It independently passed 37 coordinator tests, 813 scoped tests, connector proofs, strict Clippy, formatting, and whitespace checks.
`Claude Opus 5.5 (copilot)` identified a new concurrent-disposal race: reference-count checks could miss cleanup when final catalog or slot owners dropped together.
The current agent path avoided that interleaving, but the public cloned-client contract did not. A deterministic test-only synchronization hook was permitted.

Astra added two regressions that force both old cleanup checks before either owner releases its fields.
Both cases failed before the repair and passed afterward with `the final slot owner must unregister its unused lifecycle` as the original failure.
Cleanup now runs from the actual final `EndpointSlot::drop` through a weak runtime reference, not an observed strong count.
Shared active catalogs and cached connections remain registered. Runtime-before-slot disposal is safe and creates no ownership cycle.
Registry removal cannot destroy the lifecycle under the registry lock because the slot still owns it. Endpoint payload and names still precede their accounting guards in disposal order.
Only routed catalog, client, and lifecycle files changed during this repair; the other 27 reviewed paths remain byte-identical.

Postrepair scoped suites passed 817 cases with two existing manual benchmarks ignored. All 55 native cases and nine independent peer scenarios passed again.
Four pure disposal Miri tests passed with isolation disabled for existing counter clock access; no native FFI interpretation is claimed.
Strict Clippy, MSRV checks, private docs, formatting, and focused coverage passed.
Covered routed lines, including tests, were catalog 91/92, client 1045/1064, and lifecycle 569/609.
Opus directly reviewed the material repair without further edits and passed 24 routed tests plus ten repetitions of the four disposal cases.
It confirmed final-slot cleanup, pointer identity, lock order, accounting retention, and unchanged active/setup/cleanup/retirement behavior.

An existing public-client limitation remains: callers that drop active catalogs without retirement can retain unfinished lifecycle registrations until explicit close/join.
This behavior predates the change and does not occur for unpublished supervised candidates. It is not silently treated as a new automatic-retirement guarantee.
The ledger's replacing charges still precede all incremental native reservations; no new concurrent setter contract is claimed.
Concurrent unmanaged reloads can now reject stale catalog preparation rather than serialize all preparation. That visible, safe behavior is within the accepted breaking-change scope.

Both reviews remain valid for final complete content manifest `2a2d6a6154c15ece3442b8410f59d6f9612fde5033992518f57f37fc59e7b650`.
The final tracked binary patch SHA-256 is `0b38e9bc7cd0b0387d677001dc0d848bd0831fd0650603b7b539a48fd1a40fb9`.
The new payload file remains part of the complete manifest. It must be included in the eventual implementation commit.
#### Coordinator Final Gate Receipt

The complete sequence used `/home/vscode/.cache/tacacs-rs-10-prepared-publication` with pinned `RUSTUP_HOME=/usr/local/rustup` and emitted `ALL_ITERATION_10_GATES_PASSED`.
Formatting, strict nightly workspace Clippy, warning-free private docs, stable build, all-feature tests, and Rust 1.88 all-target checks passed.
All 26 YANG tests and 256 selected delivery tests passed. Whitespace checks passed.
The run included 250 agent tests, 128 configuration unit tests, 264 passing networking unit tests, and all 55 native prepared-source cases.
Ten existing ignored Rust tests remain excluded. The existing optional `console-subscriber` manifest advisory did not fail Clippy.
No local validation process remains active. The full content fingerprint stayed unchanged through final gates and predecessor integration.
Current integration head is `15052b7ec93cb795ecaabbd611427267077058e5`; the complete implementation is still uncommitted.
Current-head GitHub review, hosted Windows/ARMhf and required CI, and final merge remain pending. R14 is not yet marked closed.

#### Publication Receipt

[PR #287](https://github.com/AuthScaffold/tacacs-rs/pull/287) targets `main` after predecessor squash `b09c15b3242c7c633138ff3c5018ba338ccdc7bc`.
Published head `b35fc958350e71521ca75179c2a1cab49ae597d1` has complete tested tree `aaea8dc4256493fefa093c5307a5d8c28f7badc1`.
All 30 reviewed implementation files, including the new payload module, are committed. The PR has `skip-release` and no tracking documents.
Copilot review was requested on that head. Required workflow `39334465618` is in progress.
Hosted requirements, completed review, findings disposition, and clean mergeability remain necessary before merging or closing R14.

#### WSL Review-Repair Handoff

PR #287 remained open at head `b35fc958350e71521ca75179c2a1cab49ae597d1` after recovery.
Both primary CI success gates passed, but the CodeQL aggregate failed.
Two Copilot findings remained unresolved: inconsistent proxy-policy/catalog snapshots and quadratic certificate duplicate detection.
CodeQL alert 206 also required investigation before disposition.

`GPT 6.1 Sol` repaired both defects in eight tracked files, without dependencies, unsafe code, or new files.
Upstream-only reload now captures the implicit proxy policy and preparation base from one snapshot.
The existing publication fence rejects that snapshot after a concurrent secret rotation.
Native preparation remains outside publication and coordinator locks.
Certificate deduplication now uses accounted `PayloadBytes` keys in a `BTreeSet`.

Both regressions failed before repair and passed afterward.
Distinct-chain comparison counts fell from 2,016/32,640 to 696/4,146 for 64/256 certificates.
Exact-limit, one-byte-over, and reservation-release assertions passed.
Scoped suites passed 819 tests, with two existing manual benchmarks ignored.
All 55 native prepared-source cases and nine independent peer scenarios passed.
The focused coverage run passed 516 tests, with two benchmarks ignored.
Targeted private docs, MSRV checks, nightly formatting, and nightly strict Clippy passed.
Existing unknown-lint diagnostics prevent stable strict Clippy from serving as the local lint gate.

The delegate traced alert 206 to `cert_chain.remove(0)`, not a logging operation.
Its recommended disposition is false positive, pending named review and coordinator disposition.
No alert suppression or GitHub change belongs to this implementation handoff.

Complete repair-content manifest SHA-256: `cfc153ab4a009d27bb363a8c8cddf0b4acff95abea70a9ed33222ea5d277f74a`.
Tracked repair patch SHA-256: `157331d0ebf08d3e0f48b61c9d37b278c33e3bd6de5b1bec6200e25f1a6c6765`.
Both named repair reviews, final whole-workspace gates, publication, current-head hosted review, and merge remain pending.
R14 remains open.

`GPT 6 Astra` subsequently approved the repair tree without revisions.
Its focused checks produced 19 passes across 18 distinct tests, with no failures or skips.
It independently classified alert 206 as false positive at the inspected callsite.
The repair manifest and patch remain unchanged.
The complete 31-path iteration manifest is `b8ec7ce92cf4885441f9551d6b4002a1aa2dd37430e7b8ab64cc30687fb5adb3`.
The complete base-to-tree patch is `3c9bbd221eaf2243cb5d5b89dad45460c2ba8eb07d7c5f522d6c095bc9a41d28`.
Opus review and every later gate remain pending.

`Claude Opus 5.5` approved both production repairs and added one test-only duplicate-rejection assertion.
An isolated replay without duplicate detection passes the earlier test but fails this assertion.
The test also checks the duplicate's peak charge and complete reservation release.
No production code changed during this review.
Opus passed 251 agent tests, 25 extra proxy regressions, ten repetitions of eight native cases, and seven networking cases.
Nightly formatting, strict targeted Clippy, and networking MSRV checks passed.
The final eight-file repair manifest is `95ff95298fd8d8987333095f116d3958ec497f9443b96b021d039119e3e64897`.
Its repair patch is `538521a8465d945d5862e3590bed5eb704cd3779387ec30fe23fedad8aa375ae`.
The complete 31-path iteration manifest is `1fbeae2eabee1989042f48bad3b4831fd1ad5560c173fad7fe2b981723ace927`.
The complete base-to-tree patch is `58e017ff5412afe8b44fce55f95cf4572764a53a210edb365f905050bf3ca32d`.
Astra's focused final-tree follow-up and the final common gates remain pending.

Both reviewers independently confirmed that alert 206 reports a non-logging vector operation.
The coordinator dismissed it as false positive on 2026-10-20, without code suppression.
Current-head hosted verification remains necessary after publication.

`GPT 6 Astra` subsequently reviewed Opus's test-only addition and retained approval without further edits.
The enhanced duplicate regression passed once more, with comparison counts 696/4,146.
Both named reviews now cover the final repair tree identified above.
The coordinator recorded the alert disposition on PR #287 and resolved its CodeQL review thread.
Final whole-workspace gates are in progress; the implementation remains uncommitted pending those results.

#### WSL Repair Publication

Final common gates passed on 2026-10-20.
They include nightly formatting, strict nightly workspace Clippy, stable private docs, stable build, and stable all-feature tests.
The tests passed 1,320 cases across 46 suites, with ten existing ignored cases.
Rust 1.88 all-target/all-feature checks and Linux/Windows metadata architecture checks also passed.
The Windows metadata check does not replace hosted Windows compilation or execution.

The exact reviewed repair tree was committed and pushed normally as `e90b0732b51cb1410c85fd5462da50f030806005`.
Both actionable Copilot threads now contain repair evidence and are resolved.
A fresh Copilot review was requested on that head.
Pull-request workflow `39360179146` and CodeQL workflow `39360175760` started on the repaired head.
Their completion and final merge remain pending.
The current receipt is also recorded in [the PR discussion](https://github.com/AuthScaffold/tacacs-rs/pull/287#issuecomment-6282075479).

Fresh Copilot review `5580191567` on the repaired head reports no open issues and confirms both defects resolved.
All primary current-head CI checks subsequently passed, including Windows, ARMhf, container build, and both CI success gates.
The CodeQL analysis workflow also passed, but its aggregate check reports a new alert, 207.
This alert identifies test code at TLS builder line 348, not alert 206's earlier vector operation.
Its disposition requires separate evidence and review.
Merge remains paused until that investigation completes.

The delegate traced alert 207 to a failure-only assertion inside a test.
Its reported paths carry a static error, encoded length, or OpenSSL error stack rather than certificate bytes.
The fixture contains one certificate and returns before those later paths.
`GPT 6 Astra` independently confirmed the false-positive classification without source changes.
Opus's independent disposition review remains pending.

Opus independently confirmed alert 207 as false positive, including the other reachable error paths.
The coordinator dismissed it with that rationale and without source suppression.
Every current-head check then passed, mergeability was clean, and no unresolved review threads remained.
PR #287 was squash-merged as `782c73ecf91554703284f6be2b689722a3fd6e03` at 2026-10-20 03:21 UTC.
No protection bypass, release, or tag was used.
The merged worktree and cache await the documented clean/idle ownership check and receipt preservation before cleanup.

The reviewed repair tree exactly matches the squash-merged source tree.
Tracking commit `b4f01b7` preserved the receipts before cleanup.
The clean merged worktree had no active process using its directory.
The coordinator removed it without force and removed its exact 26 GiB cache.
Branch history, recovery archives, the restored conversation, and iteration 11's recovery stash remain retained.
The active tracking and iteration 11 worktrees remain intact.

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

Status: PR #288 merged as `9cf3109a756381c6bd4fc5031e28e3201bdcda00` after both named reviews and all current-head gates passed.
Scope: R9.

The original 15-file work remains preserved in the recovery patch and stash `b2b4f0e9dc638d8fce9c1fd70f5e58b541412d82`.
The WSL worktree advanced from `b35fc958350e71521ca75179c2a1cab49ae597d1` to reviewed parent repair `e90b0732b51cb1410c85fd5462da50f030806005`.
Restoration merged fourteen paths and produced one engine conflict.
The implementation delegate owns its resolution and must preserve both the embedding redesign and atomic parent snapshot fence.
The stash remains retained; no restored work was discarded.
Publication remains blocked until predecessor hosted review and required checks pass.

#### WSL Implementation Handoff

`GPT 6.1 Sol` resolved the engine source conflict while preserving the parent snapshot capture and publication fence.
The original secret-rotation regression retains every assertion and fails when its fence is removed.
The coordinator marked the resolved engine index entry without changing source content.
Sixteen tracked paths now differ from parent `e90b0732b51cb1410c85fd5462da50f030806005`; no new source files are present.
The additional publication-module change makes the obsolete implicit reload helper test-only.

The public service now has one empty-runtime `new` constructor.
Canonical configuration enters through `ConfigDatastore` and the retained `ConfigSupervisor`.
Canonical policy updates enter through `apply_policy_candidate`.
The populated/waiting constructor pair, `ServiceConfig::tacacs_plus`, and public direct reload variants are removed.
Private test fixtures retain only the lower-level operations needed for regressions.
No compatibility aliases or extra builders remain.
The daemon retains its existing `PreparedService` ownership topology.

Scoped checks passed 956 tests across 19 suites, with ten existing ignored cases.
These include 251 agent, 72 daemon unit, 55 prepared-source, and nine process-lifecycle cases.
The public embedding example compiles as a doctest.
Nine independent peer executions cover eight distinct cases across all five fixture modes.
Separate consumer profiles passed 92 protocol, 568 direct-toolkit, and 42 IPC cases.
Architecture and metadata Python checks passed 52 cases; both platform metadata guards passed.
Connector checks passed four MSRV cases and the generic fixture.
The monomorphic fixture failed with the expected Send-generality diagnostic.
Targeted strict nightly Clippy, private docs, build, MSRV, and nightly formatting passed.
Focused coverage passed 251 instrumented agent tests and covers the facade, engine, supervisors, and publication owner.
These file-level coverage results do not prove every concurrency interleaving.

Complete 16-path content manifest: `d739bbe0521d861e5a5fff7fc2d1804f45bda59ccdfab1e29efe987b72be7de8`.
Full-index parent-to-tree patch: `80c6a1de4a81e5d688034a2f5404e70de3b4dbfa592f99a05fd3b228a6026db9`.
Both named reviews and final whole-workspace gates remain pending.

`GPT 6 Astra` reviewed the complete staged and unstaged implementation and approved it without revisions.
It independently passed 339 selected tests, including the public embedding doctest, daemon lifecycle, and five native expiry/revocation cases.
Strict targeted nightly Clippy, nightly formatting, and whitespace checks passed.
The input and output manifest and patch remain identical.
Opus review and final whole-workspace gates remain pending.

`Claude Opus 5.5` approved the API redesign with four narrow revisions.
The public example now derives the filter from service listener controls and validation options from the datastore.
It also joins the service after initialization failure.
This example change prevents the default filter from replacing a configured downstream secret with unobfuscated mode.
Related constructor rustdoc states the same ownership contracts.
A redundant test-only attribute was removed without changing compiled production behavior.
Stable and MSRV doctests, 251 agent tests, strict targeted Clippy, private docs, MSRV checks, and formatting passed.
The secret-rotation regression again failed with the parent fence removed and passed after restoration.

The existing API still requires the host to retain one supervisor and pass the service's health publisher.
These are documented caller obligations, not new enforced uniqueness or identity guarantees.
Astra's final-tree follow-up will assess the revised example and these residual contracts.
The 16-path output manifest is `36f4dd7ae0570d296253702deeec86b5f66395d922a268902fd2b84eef872566`.
The full-index output patch is `dab6c7cc7d703fbc6bea1aaa649eeaf49df993bec56d1e4033ca7968e15e97a8`.
Final whole-workspace gates remain pending.

`GPT 6 Astra` reviewed the final example and rustdoc revisions and retained approval without further edits.
The public doctest, nightly formatting, and whitespace checks passed.
Both named reviews now cover the final manifest and patch above.
The documented supervisor, health-publisher, and filter-input obligations are not new regressions or R9 blockers.
Final common workspace gates are in progress.

#### Publication And Parent Integration

Final whole-workspace formatting, strict nightly Clippy, private docs, stable build, and stable all-feature tests passed.
The tests passed 1,321 cases across 46 suites, with ten existing ignored cases.
Rust 1.88 all-target/all-feature checks and both platform metadata architecture guards passed.
The exact reviewed tree was committed as `c76262c`.

The merged parent tree exactly equals predecessor `e90b0732b51cb1410c85fd5462da50f030806005`.
Integrating its squash history produced six conflicts despite that source equivalence.
The coordinator resolved those paths to the exact tested implementation commit, without inventing source changes.
Integration commit `7cd8321ad43023ec2ccbe0f3e77ee53011dc8b5f` retains tested tree `ef740f7fdf25e8f2deb90e2856e35389ed81c704`.
All 251 agent, 72 daemon, 55 prepared-source, nine lifecycle, and one public doctest cases passed again afterward.
Eight opt-in interoperability cases remain ignored in that selection; independent peer evidence is recorded above.

[PR #288](https://github.com/AuthScaffold/tacacs-rs/pull/288) targets `main` and contains exactly the 16 implementation paths.
It has `skip-release`, no tracking documents, and a fresh Copilot review request.
Required workflow `39365582578` and CodeQL workflow `39365579900` started on its published head.
Completed hosted review, actionable findings disposition, current-head checks, and clean mergeability remain necessary before merge.

Fresh Copilot review `5580516988` on `7cd8321ad43023ec2ccbe0f3e77ee53011dc8b5f` reports no open issues.
No unresolved review threads remain.
Current-head hosted verification is still in progress; merge remains gated on its completion.

#### Merge Receipt

Every current-head hosted check subsequently passed, including Windows, ARMhf, CodeQL, and container build.
The final recheck found clean mergeability, the expected reviewed head, and no unresolved threads.
PR #288 was squash-merged as `9cf3109a756381c6bd4fc5031e28e3201bdcda00` at 2026-10-20 04:14 UTC.
No protection bypass, release, or tag was used.
The merged source tree exactly matches reviewed integration head `7cd8321ad43023ec2ccbe0f3e77ee53011dc8b5f`.

The merged worktree is clean, with no active process using its directory or dedicated cache.
Its 35 GiB cache and worktree await receipt preservation before removal.
The original recovery archive, patch, and stash remain retained.

Tracking commit `beb9a7b` preserved these receipts before cleanup.
The coordinator removed the clean merged worktree without force, its exact cache, and its path-specific Rust override.
The active scheduler worktree and original recovery stash remain intact.

Local preflight confirms that daemon startup builds a waiting `TacacsClientService`; private `PreparedService::run` then composes configuration and policy supervisors.
The public service also exposes populated/waiting constructors and several direct reload variants. The latter bypass supervised materialization bookkeeping by contract.
Prefer reusing the existing supervisor and prepared-service ownership rather than adding another builder layer.
The first discriminating checks are supervised embedding construction, independent source/policy updates, and daemon startup/shutdown tests.

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

Status: PR #289 merged as `724d7f11227dc4610af514cd95e3806f8b7451dd` after both named reviews and all current-head gates passed.
Scope: the scheduler portion of R15.
Worktree: `/home/ubuntu/tacacs-rs-12-load-scheduler`; branch: `refactor/general-iterations/12-load-scheduler`.
Predecessor: `7cd8321ad43023ec2ccbe0f3e77ee53011dc8b5f`, the reviewed iteration 11 publication head.
Publication remains blocked until predecessor review findings and required checks clear.

#### Implementation Handoff

`GPT 6.1 Sol` removed the workload-sized Boolean vector and duplicate success recount.
The bounded stream drains through `for_each`, and the result builder uses the existing `completed_count()`.
No replacement history, compatibility alias, dependency, or unsafe code was added.
The only changed paths are the tacon README and `batch/executor/common.rs`.

Eleven deterministic characterization tests passed before and after the production change.
They cover bounded success waves, concurrent failures, successful in-flight completion after failure, and cancellation disposal.
The concurrency-one failure case also has stronger assertions.
All 71 tacon tests passed, without failures or ignored cases.
Targeted build, strict nightly Clippy, private docs, Rust 1.88 checks, nightly formatting, and whitespace checks passed.
Eleven instrumented scheduler tests passed.
Focused file coverage includes unrelated lines and does not establish complete branch coverage.
No measured memory improvement is claimed.

Complete two-path content manifest: `e262fe71a9e9fe7cd04a92cf654718f93a019b9832aba2d51c525d009e5d9ce5`.
Full-index parent-to-tree patch: `3bf2c651a59457dfc441db938e4045da18d4f2046b47dca6ff3443f1ad508228`.
Both named reviews and final common gates remain pending.

`GPT 6 Astra` approved the complete two-file change without revisions.
It independently passed all eleven scheduler cases with four test threads.
Bounded polling, first-failure retention, cancellation, and complete in-flight draining remain unchanged.
The input and output content hashes remain identical.
Opus review and final common gates remain pending.

`Claude Opus 5.5` approved the unchanged implementation.
It passed all 71 tacon tests, fourteen load-test selections, and thirty focused repetitions.
The unchanged predecessor scheduler also passed the eleven characterization cases.
Five deliberate mutations failed their expected tests: excess concurrency, last-failure replacement, missed later successes, queued work after failure, and early draining termination.
Targeted strict nightly Clippy, private docs, MSRV checks, formatting, and whitespace checks passed.
Restoring preserved timestamps briefly reused a mutant build artifact; a forced rebuild then passed.
Final validation uses the restored source content and refreshed artifacts.
Both review manifests and patches remain identical to the implementation handoff.
The existing cancelled-run progress-task lifetime remains unchanged and outside this iteration.
Final common workspace gates are in progress.

#### Publication Receipt

All final common workspace gates passed on 2026-10-20.
Stable all-feature tests passed 1,326 cases across 46 suites, with ten existing ignored cases.
Nightly formatting, strict nightly Clippy, stable private docs/build, Rust 1.88 checks, and both metadata architecture guards passed.
Implementation commit `fbef6d9` contains the exact reviewed two-file change.

The iteration 11 squash tree exactly matches the recorded predecessor tree.
Integration commit `db09b0270954b8b7c9ed77de010a38d28cebd6d1` preserves tested tree `11fc3192316c86e6dc70979b3fc28108a4314b53`.
All 71 tacon cases passed again after integration.
[PR #289](https://github.com/AuthScaffold/tacacs-rs/pull/289) targets `main` with exactly two paths and `skip-release`.
Fresh Copilot review was requested on that head.
Required workflow `39368894279` and CodeQL workflow `39368891229` started.
Completed review, findings disposition, current-head required checks, and clean mergeability remain necessary before merge.

Fresh Copilot review `5580724669` on the published head recommends approval and reports no open issues.
Current-head hosted verification remains in progress.

#### Merge Receipt

Every current-head hosted check subsequently passed, including supported platform builds and execution.
The final recheck found the expected reviewed head, clean mergeability, and no unresolved review threads.
PR #289 was squash-merged as `724d7f11227dc4610af514cd95e3806f8b7451dd` at 2026-10-20 04:54 UTC.
No protection bypass, release, or tag was used.
The merged source tree exactly matches reviewed head `db09b0270954b8b7c9ed77de010a38d28cebd6d1`.
The clean worktree and its 17 GiB cache have no active directory users.
Their cleanup awaits preservation of this receipt.

Tracking commit `b80eaa4` preserved the receipt before cleanup.
The coordinator removed the clean merged worktree without force, its exact 17 GiB cache, and its path-specific Rust override.
Branch history, recovery backups, and the active emulator worktree remain intact.

Remove the workload-sized Boolean result vector and duplicate success recount.
Drain in-flight work and derive completion from the existing counter.
Do not add per-request history merely to replace deleted state.

Acceptance: zero requests, concurrency one, concurrent failures, first failure, cancellation, and successful in-flight completion preserve their contracts.
Checks: focused scheduler tests, complete CLI tests, and common Rust gates.
Do not claim a measured memory improvement without a measurement.

### 13: Emulator Cleanup

Status: PR #290 merged as `63e290190ae68ffb336a765420b57c54ddd58074` after both named reviews and all current-head gates passed.
Scope: the emulator connector and compilation portions of R15.
Worktree: `/home/ubuntu/tacacs-rs-13-emulator-cleanup`; branch: `refactor/general-iterations/13-emulator-cleanup`.
Predecessor: `db09b0270954b8b7c9ed77de010a38d28cebd6d1`, the reviewed iteration 12 publication head.
The implementation delegate can create the two required coherent local commits after focused checks, but cannot publish or rewrite history.
Both named reviews will cover the complete predecessor-to-final change.
Publication remains blocked until predecessor review findings and required checks clear.

#### Implementation Handoff

`GPT 6.1 Sol` created connector commit `cda07f3c3947a97497ef4250f89007f2e2bf198a` and compilation commit `b80ea680d5336ff02b52e888cdf64193091424b0`.
Both contain the required co-author trailer; the worktree is clean.
The complete change covers twenty paths, including six new test and fixture files.

`IpcEndpoint::connect_channel()` now owns shared Unix/TCP setup for service, controller, health, and diagnostics clients.
Repeated client/controller calls and service clones use two accepted reusable connections in the regression.
Endpoint identity and underlying error causes remain visible.
The emulator no longer directly depends on `http`, `hyper-util`, or `tower`.
The lockfile removes only those three edges, without package version or transitive package changes.

File loading now reads source and decodes JSON separately from compilation.
Startup compiles the completed policy before listener setup.
Per-policy test instrumentation measured startup counts changing from 2/3 to 1/1 without/with data.
File-based TCP/Unix startup counts changed from 2/2 to 1/1.
Corrected pre-change regression cases reproduced those extra compilations before the production repair.
Failed replacements retain the active engine and captures; successful replacements still clear captures.
Raw status errors, malformed-request projection, and shutdown-based transport faults remain available.
Documentation separates normal domain fidelity from production request validation and deliberate faults.

Focused tests passed 71 cases without ignored tests, including emulator, IPC, and daemon process coverage.
Strict targeted nightly Clippy, private docs, stable build, MSRV checks, formatting, and whitespace checks passed.
Architecture tests passed 35 cases, and Linux/Windows metadata guards passed.
The isolated IPC consumer passed 42 cases.
Audit passed with the configured yanked `chacha20 0.10.1` warning.
Selected unused-dependency checks passed with the action's `--cfg tokio_unstable` flag.
The reporting-only freshness check completed and reported available updates.

Complete twenty-path content manifest: `7e8e94d391ef89b029a4e8937979e2d62d014ece06293a11706e95dea22b3f34`.
Full-index predecessor-to-tree patch: `ff09d71edc832a05373ba0af506f19774f1096367e724e612bdda6522959628f`.
Both named reviews and final common workspace gates remain pending.

`GPT 6 Astra` reviewed all twenty paths, including every new fixture, and approved without revisions.
It independently passed 71 focused tests, 42 isolated IPC cases, and 35 architecture tests.
Targeted formatting, Clippy, docs, build, MSRV, unused-dependency checks, and both metadata guards passed.
Its cached audit excluded yanked checks; the earlier online audit and freshness evidence remain applicable.
Input and output hashes are unchanged.
Opus review and final common workspace gates remain pending.

`Claude Opus 5.5` approved the production design and repaired two material test-evidence gaps.
The per-value compilation counter missed compilation of a separate policy copy.
A test-only thread-local compiler counter now observes that boundary without changing the policy type's test-build equality or synchronization traits.
The separate-copy mutant now fails with counts 2/2; predecessor loaders reproduce counts 2/3 and 2/2.
The replacement regression now proves both failure retention and successful capture clearing.
Removing successful capture clearing makes that regression fail.
All changes affect test code only.

Opus passed 71 focused cases, five emulator/daemon repetitions, and public-future Send probes.
Formatting, targeted strict Clippy, private docs, build, and MSRV checks passed.
Earlier production and dependency-check evidence remains applicable, but the instrumentation requires Astra's explicit follow-up.
`state.rs` now matches the predecessor, so the complete iteration diff has nineteen paths.
Final nineteen-path manifest: `56f9663d3e065d151cbb3698c02d1e262b32fdc5c5265473eccc11b56b4d2c3e`.
Full-index predecessor patch: `0e37f95d4a6ff6a48859628c66e7d63f4429797f38cc2c105a376146bbcec544`.
Astra's final-tree confirmation and all final common workspace gates remain pending.

`GPT 6 Astra` independently reviewed the repaired instrumentation and replacement regression and retained approval.
The three-package suite passed 71 cases before and after isolated mutation replay.
The combined extra-copy and missing-clear mutants produced the expected three failures.
The restored isolated emulator suite passed all 26 cases.
Targeted formatting, strict Clippy, private docs, build, MSRV, and whitespace checks passed.
Both reviewers now cover the final nineteen-path manifest and predecessor patch above.
The thread-local counter measures the current synchronous compilation path, not hypothetical off-thread work.
Final common workspace and audit gates are in progress.

#### Publication Receipt

All final common workspace and audit gates passed on 2026-10-20.
Stable all-feature tests passed 1,342 cases across 47 suites, with ten existing ignored cases.
Nightly formatting, strict nightly Clippy, private docs/build, Rust 1.88 checks, and both metadata architecture guards passed.
Review-test commit `44f13fd` preserves the strengthened compiler and replacement evidence after the two implementation commits.

The iteration 12 squash tree equals predecessor `db09b0270954b8b7c9ed77de010a38d28cebd6d1`.
Integration commit `6add7c19dd3dfdfe9143d167598bf3fc240e14dc` preserves exact tested tree `d688acdf01aa36f0ee71e1b20e8eefef9a55ee6d`.
All 71 focused cases passed again after integration.
[PR #290](https://github.com/AuthScaffold/tacacs-rs/pull/290) targets `main`, contains nineteen paths, and has `skip-release`.
Fresh Copilot review was requested.
Required workflow `39374579452` and CodeQL workflow `39374577383` started on its published head.
Completed review, actionable findings disposition, successful current-head checks, and clean mergeability remain necessary before merge.

Fresh Copilot review `5581082561` on the published head recommends approval and reports no open issues.
Current-head hosted verification remains in progress.

#### Merge Receipt

Every current-head hosted check subsequently passed, including Windows, ARMhf, CodeQL, and container build.
The final recheck found the expected reviewed head, clean mergeability, and no unresolved review threads.
PR #290 was squash-merged as `63e290190ae68ffb336a765420b57c54ddd58074` at 2026-10-20 06:00 UTC.
No protection bypass, release, or tag was used.
The merged source tree exactly matches reviewed head `6add7c19dd3dfdfe9143d167598bf3fc240e14dc`.
The clean worktree and its 21 GiB cache have no active directory users.
Cleanup awaits preservation of this receipt.

Tracking commit `1ec8f57` preserved the receipt before cleanup.
The coordinator removed the clean merged emulator worktree without force, its exact 21 GiB cache, and its path-specific Rust override.
Branch history, recovery backups, and the active registry worktree remain intact.

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

Status: PR #291 merged as `a6942e2011c1f8b6647774ebb192e5b38accdd83` after both named reviews and every repaired-head gate passed.
Scope: R12.
Worktree: `/home/ubuntu/tacacs-rs-14-product-registry`; branch: `refactor/general-iterations/14-product-registry`.
Predecessor: `6add7c19dd3dfdfe9143d167598bf3fc240e14dc`, the reviewed iteration 13 publication head.
Product/platform policy changes, releases, tags, and hosting remain outside this iteration.
Publication remains blocked until predecessor review findings and required checks clear.

#### Implementation Handoff

`GPT 6.1 Sol` added `.github/products.json` as the canonical registry.
The existing Cargo metadata tooling validates records, and a composite action supplies the reusable workflow's required registry job.
Official build matrices and architecture checks consume that job's output.
Both workflow callers no longer contain their own inventories or overrides.
Linux rehearsal invokes the same validator from the exported revision before hydration.
Four production inventories with nineteen record copies became one five-record registry.
Independent literal policy goldens remain.

The registry retains four Linux GNU products and Windows direct-mode `tacon`.
Asset names, package roots, features, artifact kinds, packaging, SBOM modes, and platform behavior are unchanged.
Default features remain enabled, and every explicit feature string remains empty.
Semantic comparisons preserve existing build steps, publication conditions, ARMhf execution, and aggregate gates.
Version computation, hydration, provenance, append-only release behavior, and tags remain unchanged.

Validation rejects incomplete records, stale packages/paths, incorrect targets/kinds, unknown or missing required features, duplicates, unsupported packaging, and empty selections.
Initial characterization/schema checks produced thirteen expected failures before implementation.
All fourteen registry cases passed after implementation.
The complete required delivery suites passed 311 tests without skips.
The no-publish fixture rehearsal exercised real registry, hydration, staging, archive, provenance, checksum, and rollback paths.
Compilation, SBOM generation, export, and native inspection in that rehearsal use fixtures.
Actionlint 1.7.7 passed, and 39 GitHub YAML documents parsed as mappings.
Real Linux/Windows Cargo graphs produced the exact four/one policy selections without architecture errors.
The action emitted exactly one JSON output line with five nine-field records matching the independent golden.

No Rust source, interfaces, manifests, or dependencies changed.
Unrelated Rust workspace and API-classifier rebuilds are not claimed.
Complete fourteen-path content manifest: `2db52dc7fd3b6aa5708e0dc8cb21fdfdab453743e68b8d03f3e6dee166062e02`.
Complete patch, including all four new files: `4522311930cfe40e6e567ff0ca45f4fbd3a6ffa0ebd417f7a88298c65a3ef1a9`.
Both named reviews and final delivery-tooling gates remain pending.

`GPT 6 Astra` reviewed all fourteen paths, including the four new files, and approved without revisions.
It independently passed all 311 delivery tests after isolating legacy Cargo fixtures from the enclosing workspace.
Actionlint, YAML mappings, exact action output, and both real platform architecture-consumer paths passed.
Twenty-three Cargo-backed invalid-input probes rejected invalid registries without matrix output.
Cross-revision selection passed, and missing, empty, or stale-platform registries stopped rehearsal before hydration or builds.
The complete input and output hashes are unchanged.
Opus review and final delivery-tooling gates remain pending.

`Claude Opus 5.5` approved the registry and workflow design with three narrow revisions.
Rehearsal now reports the exact missing exported registry-tool path, consistent with other exported tools.
The invalid-output test no longer confuses missing-tool and returned-output errors.
A new missing-tool regression fails before that repair and passes afterward.
The Cargo metadata README now runs its complete test directory and identifies the independent policy goldens.

The full delivery suite passed 311 cases before these revisions and 312 afterward, without skips.
Focused rehearsal, fixture rehearsal, README tests, Actionlint, YAML parsing, and real Cargo output checks passed.
Cargo 1.88, 1.91, and 1.96 produced the same registry output.
All nineteen removed record copies and all unchanged workflow conditions/gates match their predecessor semantics.
No current product uses dependency-feature syntax; the validator does not claim support for it.
Pre-registry revisions remain explicitly unsupported by the documented rehearsal contract.

Opus's fourteen-path output manifest is `47b5a2ef057e07a1435b429fcded2f1eb0b098dcc19a1542230438da0beccca3`.
Its complete patch, including new files, is `d82bf298353dc5a0dfd6e05099301f9b38a1743952babe7bb3d2f2cb3b574995`.
Astra's final-tree follow-up includes a scope check of unrelated example-output path changes.
Final delivery-tooling and hosted gates remain pending.

#### Final Reviews And Publication

Astra approved Opus's three revisions and restored only the two unrelated example output paths.
The registry documentation remains intact.
Opus confirmed those documentation restorations and retained final approval without further edits.
Both named reviews cover manifest `b317b5f5ded3a0804afcf73723832adabcef35b567d9598121a5926c4ceb2e76`.
The complete pre-staging patch is `5fa24ffd8bfa2cd9c2feb67c6d13a5934b462ceff096716ef9c12ac15dac8473`.

Final delivery validation passed all 312 tests without skips.
Actionlint passed the three changed workflows.
Exact real-Cargo checks retained five total products, four Linux products, one Windows product, nine fields, and one GitHub output line.
All 39 GitHub YAML documents parsed as mappings: 38 workflows/actions and Dependabot configuration.
Fixture scratch stayed outside the source tree and was removed after validation.
No unrelated Rust checks are claimed for this tooling-only change.

Implementation commit `00b015f` contains the exact reviewed fourteen-file change, including all four new files.
The parent squash tree equals predecessor `6add7c19dd3dfdfe9143d167598bf3fc240e14dc`.
Integration commit `4d1ce5321dd7f95ba2e9abf4f4e742c45637e419` preserves tested tree `58fa427383588a5c0cf803938e12fe969c55011c`.
Post-integration metadata/rehearsal tests passed 115 cases, and workflow lint passed again.
[PR #291](https://github.com/AuthScaffold/tacacs-rs/pull/291) targets `main`, contains fourteen paths, and has `skip-release`.
Fresh Copilot review was requested.
Required workflow `39379187536` and CodeQL workflow `39379185235` started on its published head.
Completed review, findings disposition, current-head hosted checks, and clean mergeability remain necessary before merge.

Fresh Copilot review `5581411316` on the published head reports no open issues.
It explicitly retains hosted workflow execution as a required gate.
Current-head hosted verification remains in progress.

Four later CodeQL quality comments identify mixed `import` and `from` forms for `products` in the new registry tests.
The coordinator paused descendant review and assigned the smallest consistent-import repair to the original implementer.
Registry, workflow, and product policy must remain unchanged.
Both named reviews and current-head hosted verification will cover any resulting repair before merge.

The implementer changed only `test_products.py` to one module import with consistently qualified references.
Monkeypatch targets remain the same module attributes.
Normalized AST comparison retains all 36 assertions and sixteen test functions.
All 63 metadata tests and all 312 delivery tests passed without skips.
The input file hash is `12312dc17f4b6a4a4abd784a2d1ad84917314aff3ef615e4b1aa059c98bd588c`.
The repair output hash is `70cb2ce6227464e1e2889401be12179da4ed81d33d9ef8bdadfc1ceda991b66a`.
Old-head hosted checks passed, but merge remains paused for repair reviews and fresh-head verification.

Both named reviewers subsequently approved the unchanged import repair.
Their independent AST checks retain all assertions, test/helper functions, parametrization, expected errors, and five monkeypatch targets.
The final complete delivery suite passed 312 cases without skips.
Exact repair patch: `cceb936b2579e3b780f07ca7e459db35950316cd6004ed41c2448e573d440a37`.
The coordinator committed and pushed repair head `e025b0d2b7d40530c876bab8ff323918ba877815`.
Complete repaired fourteen-path manifest: `4bc20606abd2fe5fecd31ef446855d692e5b6c859d351524c522feb5319520c1`.

All four quality threads now contain repair evidence and are resolved.
Fresh Copilot review `5581716726` on the repaired head reports no open issues.
Required workflow `39383183825` and CodeQL workflow `39383178850` started on that head.
Prior successful hosted checks do not substitute for the repaired head's required verification.
Merge remains pending until its current-head gates pass.

#### Repaired-Head Merge Receipt

Every hosted check on `e025b0d2b7d40530c876bab8ff323918ba877815` subsequently passed.
This includes actual registry-job output, all five product/platform builds, Windows/ARMhf execution, CodeQL, and aggregate CI.
The final recheck found the expected reviewed head, clean mergeability, and no unresolved threads.
PR #291 was squash-merged as `a6942e2011c1f8b6647774ebb192e5b38accdd83` at 2026-10-20 07:31 UTC.
No protection bypass, release, or tag was used.
The merged source tree exactly matches the reviewed repair head.
The clean worktree and its dedicated cache have no active directory users.
Cleanup awaits preservation of this receipt.

Tracking commit `4181ae7` preserved the receipt before cleanup.
The coordinator removed the clean merged registry worktree without force, its exact cache, and its path-specific Rust override.
Global Actionlint remains installed, and both TOML worktrees remain intact.

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

Status: PR #292 merged as `b93b0a83141a61912006c660902653e6236e2dac` after both final reviews and all current-head gates passed.
Prototype: `/home/ubuntu/tacacs-rs-15-toml-editing-prototype`, branch `refactor/general-prototypes/15-toml-editing`.
Integration: `/home/ubuntu/tacacs-rs-15-toml-editing`, branch `refactor/general-iterations/15-toml-editing`.
Both start from reviewed predecessor `4d1ce5321dd7f95ba2e9abf4f4e742c45637e419` and use separate caches.
Prototype analysis, implementation, and focused checks have a 45-minute budget.
Evaluation stops earlier if a required capability fails or no concrete deletion remains.
Only accepted source can enter integration; rejection or blocked adoption produces a reproducible documentation-only decision.
Publication remains blocked until predecessor review findings and required checks clear.

#### Evaluation Handoff

`GPT 6.1 Sol` completed the prototype in nine minutes and three seconds and proposed adoption.
TOML Kit 0.15.2 uses MIT licensing, requires Python 3.9 or later, and adds no transitive runtime dependencies.
Version-specific PyPI, wheel, and source metadata agree; downloaded archive hashes match supplier metadata.
The project's existing Python 3.11 minimum and Rust 1.88 MSRV remain unchanged.
The Rust `toml_edit` route was not selected because the existing Rust tool owns API classification, not hydration.

The proposed editor removes three parser regexes, `lock_package_name`, offset slicing, block reconstruction, and lock cursor assembly.
The initial candidate had sixteen fewer production lines before later review repairs.
It introduced no second parser or alternate member-discovery path.
Cargo metadata remains authoritative for member discovery.
Exact source-free lock references update by name and old version; source-qualified external identities remain unchanged.
Comments, alternate valid formatting, unknown fields, line endings, idempotence, dependency association, and same-name external packages have comparison coverage.
All seventeen real member manifests and the actual lockfile match predecessor semantic and unaffected-content expectations.
Quote changes are allowed only for intentionally edited literals, not unrelated content.

The prototype passed 138 focused cases and a fixture rehearsal.
The integration candidate passed 333 delivery tests, nineteen bootstrap tests, pin contracts, fixture rehearsal, and workflow lint.
Canonical Python requirements pin TOML Kit in the composite action, delivery tests, development image, and local instructions.
Separate prototype/integration virtual environments contain the candidate dependency.
An attempted global install lacked write permission; no successful global dependency change occurred.
No Rust source, manifests, or lockfiles changed.
The full development image and native release artifacts were not rebuilt.

Integration content manifest: `707824871066e959cb99740565c1bc71c59e59c5499bc29582f83178b6ca854a`.
Complete integration patch: `2f43a6f80c17f1df31db9d0fb7ac97d7d404f134033026a2d55fb32a09a5284c`.
Prototype content manifest: `0d107a6e69b1079c3a44f04df0d3d68faec9dca6ffa8a00536ae932195929d35`.
Complete prototype patch: `f4b0f4b37ea3d6119a5c32668a91f1e7dfa5e3d204632f3c8956a86a84b2de23`.
Experimental-only patch: `8c5bfe1e9d418f41daa6dd70380cc59625f2628df8ac30989a1dd59d6a20e302`.
Both named integration reviews and every publication gate remain pending.

The coordinator preserved the complete measured prototype in local commit `40daab0`.
That experimental branch is not an integration predecessor and must not be merged wholesale.
The integration candidate remains a separate ten-file change.
The structured handoff is retained outside the disposable caches for provenance.

After both iteration 14 repair reviews passed, integration advanced to `e025b0d2b7d40530c876bab8ff323918ba877815`.
Only the predecessor's test-import repair changed during that fast-forward.
All ten TOML candidate file hashes and its complete patch remain unchanged.
Canonical source-only integration manifest: `4db4a41f0628d10c36dce13e6b02d9c074f165e95f28c5f61f42234bae3910c4`.
Canonical source-only prototype manifest: `45be3a371419dda67fa9f1b43d2652085747ba66bac0d55cb01180d38cde1683`.
These differ from the earlier metadata-rich manifest digests by format, not source content.
Both named integration reviews and final environment/tooling gates remain pending.

#### First Direct Review And Identity Repairs

`GPT 6 Astra` recommends adoption after two direct correctness repairs.
A changed source-free version can collide with a same-name registry or Git package version.
The initial candidate then produced ambiguous version-qualified references and failed real offline Cargo resolution.
The repair adds an external source qualifier only when the changed local identity creates that ambiguity.
Existing source-qualified and unqualified references remain unchanged otherwise.
Exact registry/Git cases and four real offline Cargo transitions cover the repaired behavior.

Malformed package names, sources, and dependency-array fields now produce contextual `HydrationError` diagnostics rather than incidental type errors or acceptance.
Rejected lockfiles retain their input bytes.
Nine new regressions failed before the repairs.
The final combined delivery/bootstrap suite passed 368 cases without skips.
Fixture and pin checks passed five additional selected cases.
All seventeen actual manifests and the actual lockfile still match predecessor goldens in semantics and complete bytes.

Astra's reviewed production delta was 67 additions and 62 deletions, not a net line reduction.
The custom section/block parser, offset slicing, reconstruction, and lock cursor machinery remain removed.
Cargo metadata remains the only workspace-member authority.
Canonical ten-path review output manifest: `25fdbc6d2f613550928e38d528a281f46d6be92fe43eeec0f6d288e23720155e`.
Complete output patch: `188624c65990eeaf1b7fce79c0e3a361e97ae5a7ea6e6040088869ad9c3b0eac`.
Opus review and final environment/tooling gates remain pending.

The coordinator queried OSV and GitHub advisories for pinned PyPI package `tomlkit 0.15.2`.
Neither source returned a published advisory at the time of the check.
This result, supplier hashes, and `pip check` do not establish absence of vulnerabilities.

#### Second Direct Review And Canonical Cargo References

`Claude Opus 5.5` recommends adoption after two material reference corrections and a related guide update.
Git qualifiers must omit the precise revision; the official unlocked build otherwise rewrites the hydrated reference.
Reverse collisions must also remove an external qualifier when the changed local version no longer needs it.
The new `lock_references` helper computes minimal Cargo references before and after mutation and replaces only changed references.
Version qualification distinguishes multiple versions; source qualification distinguishes remaining identical name/version identities.
Selected external entries without a version now raise `HydrationError`.
The development-container guide now lists the new Python dependency.

Thirteen real Cargo transitions cover registry, Git, mixed sources, and both change directions.
Six added regressions fail the prior review input.
The revised output matches canonical reference bytes in eleven transitions.
Two remaining differences concern package/dependency ordering, a documented predecessor limitation.
No universal Cargo-byte-canonical claim is made for arbitrary same-name package graphs.
All eighteen real project outputs still match predecessor bytes and TOML values and remain idempotent.

The combined final delivery/bootstrap selection passed 373 cases without skips.
Focused hydration/version tests passed 147 cases, and fixture/pin selections passed five.
Workflow lint, dependency consistency, local links, whitespace, and reverse-patch checks passed.
Opus's reviewed production delta was 82 additions and 66 deletions, with no line-reduction claim.
The structural benefit remains removal of the custom parser plus explicit Cargo identity handling and validation.
The accepted diff now contains eleven paths, including `docs/dev-container.md`.

Opus's output manifest: `07a21822d2ba680f18a06ce613e3e7aa1c7b83fc6522b63b2645d2ec2f48549d`.
Complete output patch: `69c2b208586f25b252d98977e7c71b18a7c70ff0896ab83a1c59cb898533244a`.
Astra's explicit final-tree review and global pin provisioning remain pending.
The coordinator validated the image's actual base and apt/Python provisioning blocks.
The resulting Python 3.11.2 environment imported the exact four image package pins, including TOML Kit 0.15.2, and passed dependency checks.
The smoke container ran read-only without a network, and its temporary image was removed.
This limited check does not rebuild the unchanged Rust/Cargo/TACACS image layers.

#### Accepted Reference Forms And Unaffected Text

Astra's final-tree follow-up found two remaining defects and repaired them.
Cargo accepts explicit qualifiers and some unqualified local references beyond its minimal serialized spellings.
The previous map could leave a qualified local reference at its old version or retain an unnecessary Git revision.
The repair generates accepted spellings from structured package identities and maps only affected references to their new minimal form.
Five new real Cargo cases validate accepted inputs before hydration and resolution afterward.

The previous map also rewrote unchanged dependency literals and changed their quotes.
Unchanged identities and reference strings are now excluded from replacements, preserving their exact text.
Six new regressions failed the prior output before the fixes.
Focused tests passed 155 cases, and the combined delivery/bootstrap suite passed 381 without skips.
Fixture and pin selections passed five cases.
The thirteen-transition identity probe still preserves semantics in every case and retains the documented two ordering-only differences.

The current production delta is 100 additions and 65 deletions, not a line reduction.
The custom parser remains removed; the additional code handles Cargo identities, accepted reference forms, and validation.
Astra recommends adoption of this revised tree, subject to Opus confirmation.
Current eleven-path manifest: `7293d5599b7d71f79cb8e9f7d3c6ed7ee067b5bd736c50552ee17dea4c77991b`.
Complete current patch: `c1bc56a650af41e53a0c8e5ab5ab12cade1e8c5eae7b7721fedac667b5255233`.
Global provisioning and final local/hosted gates remain pending.

#### Final Runtime Approval And Global Validation

Opus approved Astra's revised runtime without edits.
Seven layouts produced 42 reference-spelling trials: 25 accepted by Cargo and seventeen rejected.
The generated accepted-spelling sets matched Cargo without differences.
All 25 accepted spellings passed hydration to both target versions, giving fifty successful checks and idempotent output.
The prior Opus hydrator failed six final regressions, confirming the defects and repaired coverage.
Both named reviewers approve the same runtime code.

The coordinator installed TOML Kit 0.15.2 into `/opt/tacacs-python` from the unchanged canonical requirements.
Global dependency checks and an import/parse smoke check passed.
The final global-environment delivery/bootstrap suite passed 381 tests without skips.
`RUSTUP_TOOLCHAIN=1.88.0` explicitly selected Cargo 1.88 for child processes.
An additional private-Cargo-home spelling probe passed 42 trials and fifty hydrations with zero mismatches or failures.
Python 3.11 grammar, all 39 GitHub YAML mappings, workflow lint, whitespace, and protected-file checks passed.

Opus clarified the README's Cargo-home and offline/no-dependency distinctions without changing runtime code, tests, or pins.
Registry/Git resolution fixtures use private homes and local sources; unique-local commands use the active home offline.
Member discovery uses `cargo metadata --no-deps`, not an `--offline` claim.
The documentation-only output manifest is `5ea03e184f5052db3255e1c97ec85c08ee9ea8a3733fdd7b5ee5c785bdfda2f6`.
Its complete patch is `4ea17e6b2b25cf2b2b024e288176266c46425bf996becd9695c6c4106eb421be`.
Astra's narrow final documentation confirmation remains pending.

#### Final Confirmation And Publication

Astra confirmed the documentation-only output and retained adoption approval without further edits.
Both named reviewers cover final eleven-path manifest `5ea03e184f5052db3255e1c97ec85c08ee9ea8a3733fdd7b5ee5c785bdfda2f6`.
The complete pre-staging patch is `4ea17e6b2b25cf2b2b024e288176266c46425bf996becd9695c6c4106eb421be`.
Implementation commit `6d03694` contains exactly those eleven paths, including the four new files.

The iteration 14 squash tree equals predecessor `e025b0d2b7d40530c876bab8ff323918ba877815`.
Integration commit `680b6f3c8c813e6f3c803673975a4bd73208c433` preserves exact validated tree `22a71317133784a89a5e71d12259fedd430352ff`.
All 381 global-environment tests and workflow lint passed again after integration.
[PR #292](https://github.com/AuthScaffold/tacacs-rs/pull/292) targets `main`, contains no experimental files, and has `skip-release`.
Fresh Copilot review was requested.
Required workflow `39391294960` and CodeQL workflow `39391292213` started on its published head.
Completed review, actionable findings disposition, current-head hosted checks, and clean mergeability remain necessary before merge.

Fresh Copilot review `5582436859` on the published head reports no open issues.
It retains current-head hosted platform execution as a required release-tooling gate.
Hosted verification remains in progress.

#### Merge Receipt

Every current-head hosted check on `680b6f3c8c813e6f3c803673975a4bd73208c433` subsequently passed.
This includes Linux, Windows, ARMhf, tool installation, container execution, and aggregate CI.
The final recheck found the reviewed head, clean mergeability, and no unresolved review threads.
PR #292 was squash-merged as `b93b0a83141a61912006c660902653e6236e2dac` at 2026-10-20 08:45 UTC.
No protection bypass, release, or tag was used.
The merged source exactly matches the reviewed integration tree.

Both completed TOML worktrees are clean and have no active directory users.
Their dedicated caches occupy approximately 58 MiB and 39 MiB.
Cleanup awaits preservation of this receipt.
The accepted global TOML Kit pin and isolated remote prototype history remain retained.

Tracking commit `55bdd59` preserved the receipt before cleanup.
The coordinator removed both clean completed TOML worktrees without force, their exact caches, and both path-specific Rust overrides.
Retained review receipts, replay probes, logs, backups, remote prototype history, and global tooling remain available.
Active and unrelated worktrees were left untouched.

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

Status: PR #293 merged as `3080e9de3974cde6c088caf72f4c0a932245521b` after both named reviews and all current-head gates passed.
Prototype: `/home/ubuntu/tacacs-rs-16-systemd-notifications-prototype`, branch `refactor/general-prototypes/16-systemd-notifications`.
Integration: `/home/ubuntu/tacacs-rs-16-systemd-notifications`, branch `refactor/general-iterations/16-systemd-notifications`.
Both start from reviewed predecessor `680b6f3c8c813e6f3c803673975a4bd73208c433` and use separate caches.
Prototype analysis, implementation, and focused checks have a 45-minute budget, with at most two credible library candidates.
Required capability failure or lack of concrete deletion ends the prototype early.
Only private sockets and owned processes are permitted; real host service notifications and configuration changes are excluded.
Rejected or blocked adoption produces a reproducible documentation-only integration decision.
Publication remains blocked until predecessor review findings and required checks clear.

#### Evaluation Handoff

`GPT 6.1 Sol` rejected the two tested direct APIs after a valid pressure result within three minutes and forty seconds.
Final focused checks completed within seven minutes and fourteen seconds.
The integration contains only `docs/systemd-notification-evaluation.md`.
No rejected dependency or production code enters integration.

The evaluated APIs are `sd-notify 0.5.0` and `libsystemd 0.7.2`, both under permissive dual licenses.
Their Linux dependency closures contain two and 32 packages respectively, including each candidate.
Neither requires a systemd development package or the libsystemd C library.
The selected `sd-notify` closure passes Rust 1.88 checks.
The combined experimental lockfile fails because selected `uuid 1.28.0` requires Rust 1.89.
That prototype-only result does not change the workspace MSRV, lockfile, or either package's declared minimum.

Three normal private-socket cases delivered `READY=1` with the owned child's PID/UID/GID.
The tested `sd-notify` API failed Linux abstract addressing.
Three non-draining receiver cases blocked past a 750ms process deadline and required exact-child termination and reaping.
Fresh nonblocking senders returned `EAGAIN` before candidate calls, confirming receiver pressure rather than a full sender buffer.
All filler sockets stayed open, and no receiver read occurred before termination.
Seven characterization cases passed as expected observations, including four required-acceptance failures.
This is rejection evidence, not seven successful adoption cases.

The unchanged owner passed ten host tests, fifteen supervision tests, and one native stalled-helper shutdown regression.
Prototype formatting, strict Clippy, and private docs passed.
No live service manager, host unit, shared notification environment, or operator VM changed.
Kernel credential observations do not prove real service-manager `NotifyAccess` policy.
No rejected-dependency audit or unrelated integration Rust rebuild is claimed.

The frozen four-file prototype is preserved as `3a759ba3cf9c2cf3654d5bf739e578eb2c4a14de`.
Its isolated prototype ref is pushed for durable replay, not opened as a PR or merged into integration.
TOML prototype `40daab01a3b9ae042de87da6dff3b48b94e5f30e` is likewise preserved on its isolated remote ref.
Notification prototype changed-source manifest: `b1696a991049878d6d8f1db2612ae3f63cfbe42d3d656c43b3f0c477a41c0e87`.
Complete prototype patch: `0457f6f764a3da6ce49a595f8ad106cdc867aa3c595ab7b99042ce36d355a718`.
Initial one-document integration manifest: `89edd4804f1a0f0dae9bfd25e834196045875e269c301d22c6b5119d254bf59c`.
Complete initial integration patch: `2048c9450759307df7bc000b1e41fcd509422e6681f0e4d131f8d8b1c88f5292`.
Both named decision reviews and final document checks remain pending.

Astra independently reproduced all seven characterization cases, including the four acceptance failures.
The receiver-saturation guards, blocked kernel waits, exact-child termination, and reaping all reproduced.
Ten host tests, fifteen supervision tests, and the native stalled-helper shutdown regression passed again.
Package source/checksum, feature, dependency-closure, native-prerequisite, and declared/resolved-MSRV facts were independently verified.
Prototype formatting, strict Clippy, documentation, and link checks passed.

Astra added exact remote prototype provenance and conditional recovery instructions to the integration document.
Nine links, shell syntax, and prose checks passed.
The frozen prototype remains unchanged.
Current document hash: `a6f65098b9727b7aaf2950ada1e3aebe3cf4e0f5f22f08a3e79386853ca57f4b`.
Canonical changed-source manifest: `b4a210312e235b04f2cdc0c0da2b3ead74b0fd2d002dd05729590869b2ac592b`.
Complete one-document patch: `5d091f889792391097a122205509c69bce31aa548982b8d2dcfbf88b2aa9dcff`.
Opus review and final document gates remain pending.

#### Final Decision Reviews And Publication

Opus independently supported rejection and reproduced every normal, abstract-address, pressure, and unchanged-owner result.
Its precision edits clarified the timing, disabled feature name, normal/build closure counts, queue-fill distribution, retry semantics, and replay commands.
Two filler sockets queued 278 plus 235 datagrams; the third fresh sender returned `EAGAIN`.
No implementation, dependency, or rejection decision changed.
Nine links, four Bash blocks, prose, and table checks passed.
Astra read the final 191-line document and retained approval without further edits.

Final document hash: `04fe2ebd282d076fda25c0bb18c82c973d4eeb360a03fb89c5387e80d8ccd73f`.
Canonical changed-source manifest: `52e9a5e22707a63bc634e89f9f1facbb586b5284fb60faad04a47cc05d6a0301`.
Complete new-file patch: `b55b78716e2bc8e7f5c68b861e431024dd225136964e85199b5fe2b3b19400a0`.
The coordinator validated those identities, all local links, all four Bash blocks, and the exact remote prototype ref.
All 935 baseline files remain unchanged.

Decision commit `d94d63a` contains only the new document.
The iteration 15 squash tree equals predecessor `680b6f3c8c813e6f3c803673975a4bd73208c433`.
Integration commit `0518d4753e24292da9866a3c4f71233f232353fb` preserves exact validated tree `c7b910f5e382ac5f46bfd7649fa753218348a149`.
[PR #293](https://github.com/AuthScaffold/tacacs-rs/pull/293) targets `main`, contains only the decision, and has `skip-release`.
Fresh Copilot review was requested.
Required workflow `39398669418` and CodeQL workflow `39398667218` started.
Completed review, findings disposition, current-head required checks, and clean mergeability remain necessary before merge.

Fresh Copilot review `5583141997` recommends approval and reports no open issues.
Current-head hosted verification remains in progress.

#### Merge Receipt

Every current-head hosted check subsequently passed.
The final recheck found reviewed head `0518d4753e24292da9866a3c4f71233f232353fb`, clean mergeability, and no unresolved threads.
PR #293 was squash-merged as `3080e9de3974cde6c088caf72f4c0a932245521b` at 2026-10-20 09:52 UTC.
No protection bypass, release, or tag was used.
No rejected source or dependency entered `main`.
Completed integration/prototype cleanup awaits receipt preservation and clean/idle ownership checks.

Tracking commit `3fbd39f` preserved the receipt before cleanup.
The coordinator removed both clean completed notification worktrees without force, their exact caches, and both path-specific Rust overrides.
The remote prototype, retained handoff, accepted global tooling, active codec worktrees, and unrelated worktrees remain intact.

Compare direct notification APIs with the subprocess owner.
Test pathname and abstract sockets, sender attribution, auto/strict selection, retries, and one-shot ready/stopping behavior.
Prove bounded behavior when the receiver does not drain its socket.
`spawn_blocking` alone is not evidence of bounded shutdown.

Adopt only if helper discovery/execution code disappears without weakening lifetime bounds or introducing native setup costs that exceed the benefit.
Keep process-manager integration daemon-owned.
Checks: private Unix datagram tests, process lifecycle/timeout cases, dependency/MSRV/audit checks, and hosted platform builds.

### 17: Codec Evaluation

Status: both final reviews and document gates are complete; documentation-only decision published as PR #294 against `main`.
Prototype: `/home/ubuntu/tacacs-rs-17-codec-evaluation-prototype`, branch `refactor/general-prototypes/17-codec-evaluation`.
Integration: `/home/ubuntu/tacacs-rs-17-codec-evaluation`, branch `refactor/general-iterations/17-codec-evaluation`.
Both start from reviewed predecessor `0518d4753e24292da9866a3c4f71233f232353fb` and use separate caches.
The prototype has a 45-minute analysis/implementation/focused-check budget.
Required capability failure or lack of concrete buffering deletion ends evaluation early.
Only accepted implementation or a reproducible documentation-only decision can enter integration.
Publication remains blocked until predecessor review findings and required checks clear.

#### Evaluation Handoff

`GPT 6.1 Sol` rejected the tested route after eleven minutes and 58 seconds.
Final prototype checks completed within nineteen minutes and 27 seconds.
The integration contains only `docs/tokio-util-framing-evaluation.md`.
No rejected code, feature, or dependency edge enters integration.

The evaluated Tokio-util 0.7.19 package already exists in the workspace and uses MIT licensing with declared Rust 1.71.
Supplier archive/source checksums match the predecessor lockfile.
The prototype adds three direct dependency edges but no package identities, versions, native prerequisites, or tools.
Its initial proxy adapter removed eleven unformatted production lines but increased read-ahead and body-copy costs.
A working small adapter restored cancellation state, deadlines, EOF/error context, coalesced packets, key ownership, and controlled read windows.
The formatted proxy then grew from 231 to 252 production lines.
It adds custom allocation handoff and tail-copy machinery, so no simplification is adopted.
This result concerns the tested route, not every possible Tokio-util design.

Fourteen networking probes and six new proxy probes characterize the evaluated APIs.
The complete networking unit suite passed 279 cases with two existing manual benchmarks ignored.
All 31 proxy cases passed, including the 25 pre-existing cases.
Prototype formatting, strict Clippy, private docs, and Rust 1.88 checks passed.
Existing unknown-lint messages remain documented.
No interoperability, streaming-target fuzz, global allocation instrumentation, dependency audit, or unrelated integration Rust rebuild is claimed.

The simple route read 65,548 bytes before the next invalid header instead of the existing 8,192-byte window.
Shared frame ownership plus body conversion held 131,084 byte-owner capacity in the controlled large-frame case.
The repair transferred the large allocation and retained an 8,192-byte read window.
These are capacities and pointer-ownership observations, not allocator or RSS measurements.
Cancellation at zero/five/sixteen written bytes retained sixteen/eleven/zero queued bytes.
Completed writes and pending flushes differ, so successful sink futures do not preserve the existing `messages_sent` counter.
No `NotSent` conversion or wire-byte counter is invented.

The exact six-file prototype is preserved remotely as `4f60508ceea1c8789a2d9ab7acfc555e6bf7f282`.
Generated `.iteration17-evidence` scratch is excluded from that commit.
Prototype changed-source manifest: `e16abdee6cc55287601b88ce1594ae9543d0b4922c72d34fa2c71d98f625b793`.
Complete prototype patch: `682c47e803f9aec2bbc22848712cb255a44c02267e9d8da11e55474223e15f40`.
Initial decision manifest: `4bfd47472e100668794b44cd5d7617fd4831802e2b0da9488e5a08e467fc6e8b`.
Complete initial decision patch: `2701bdf96c86dbf82060199ccaf0f63c7cc34c666cc31098912bee2acc12f422`.
Both named decision reviews and final document gates remain pending.

Astra independently supports the documentation-only rejection and found no prototype proof blocker.
It clarified that bespoke buffering policies remain split across three adapters.
The 21-line increase supports that structural assessment but does not define it.
It also corrected the allocation interpretation: reused allocation ownership does not mean zero body-byte copying.
`Vec::from(BytesMut)` still shifts body bytes with `ptr::copy`.

All seven prototype validation commands passed again.
Fourteen networking probes, 279 networking cases, and 31 proxy cases passed; two existing manual benchmarks remain ignored.
Formatting, strict Clippy, private docs, and Rust 1.88 checks passed.
Astra added exact remote prototype provenance, conditional detached recovery, `$HOME` replay paths, and self-contained source checks.
Five local links, two Bash blocks, tables, and prose checks passed.
The six frozen prototype source hashes and all 936 baseline integration files remain unchanged.

Current document hash: `0e630a26500442b34c7a032d263f5b8a6d65130fecb33db2383004c373c18f2d`.
Canonical changed-source manifest: `374bf534763b9f8889780260da55693d3809c7388d7489a3cabb1d41c844821f`.
Complete 220-line new-document patch: `db1be12d41c2ac23ba3f7852d0c83033acc85d32f97b5e0c92d6326462483526`.
Opus review and final document gates remain pending.

#### Final Decision Reviews And Publication

Opus supports rejecting the bounded route on structural grounds.
It independently replayed every command both in the cached prototype and in a clean archive with a separate full rebuild.
All observed counts reproduced without the generated evidence directory.
Networking probes passed fourteen cases; networking passed 279 with two existing manual benchmarks ignored; proxy passed 31.
Formatting, strict Clippy, private docs, and Rust 1.88 checks passed.

Opus corrected the dependency scope: the agent `bytes` edge is production, while the networking additions are test-only.
It also documented that the committed large-frame coalescing test leaves zero tail bytes.
The committed probe therefore does not exercise its non-empty-tail copy branch.
A separate review-only model produced 784 non-empty tails, but does not establish committed-prototype conformance.
Those coverage limits remain explicit and no rejected code is integrated.
Astra confirmed the final precision edits without further changes.

Final 233-line document hash: `5d80daf516fe2329c378cf3a5b54c0904b3822bebbcf89b51a8e09e1eb47d957`.
Canonical changed-source manifest: `11c35733422a989d3cc8df0a85e17780ee709217ea9b321fbf334ad907a64d6b`.
Complete new-file patch: `9b3bddc83853a536f828c78952d98d1ee81fb0f5705da43d0bc9a5816415f71d`.
The coordinator validated exact identities, five local links, both Bash blocks, and the durable remote prototype ref.
All 936 baseline integration files remain unchanged.

Decision commit `d11f6ed` contains only the evaluation document.
The iteration 16 squash source equals predecessor `0518d4753e24292da9866a3c4f71233f232353fb`.
Integration commit `d3629b2ee0f78c862e7a4d8fb7558622c6f6591a` preserves exact validated tree `0fd0de2e57287b1611a1889b2354eae5e735f900`.
[PR #294](https://github.com/AuthScaffold/tacacs-rs/pull/294) targets `main`, contains one file, and has `skip-release`.
Fresh Copilot review was requested.
Required workflow `39409754281` and CodeQL workflow `39409751847` started.
Completed review, findings disposition, current-head required checks, and clean mergeability remain necessary before merge.

Fresh Copilot review `5584006093` on the published head reports no open issues.
Current-head hosted verification remains in progress.

Evaluate Tokio-util only for framing and buffering.
Keep packet semantics, session routing, delivery facts, obfuscation, and counters in their owning layers.
Test oversized headers before allocation, fragmented reads, partial writes, cancellation, and contiguous packet behavior.
Do not translate a cancelled `send()` into `NotSent`.

Adopt only if bespoke buffering disappears and all ownership/delivery contracts remain explicit.
Checks: networking/proxy native tests, relevant fuzz and allocation-bound checks, interop, and common gates.
Reject the prototype if custom adapters reproduce the deleted machinery without a clear reduction.

### 18: Packaging Evaluation

Status: bounded evaluation started through `GPT 6.1 Sol`.
Prototype: `/home/ubuntu/tacacs-rs-18-packaging-evaluation-prototype`, branch `refactor/general-prototypes/18-packaging-evaluation`.
Integration: `/home/ubuntu/tacacs-rs-18-packaging-evaluation`, branch `refactor/general-iterations/18-packaging-evaluation`.
Both start from reviewed predecessor `d3629b2ee0f78c862e7a4d8fb7558622c6f6591a` and use separate caches.
The prototype has a 45-minute analysis/configuration/implementation/focused-check budget.
Only local planning/builds are permitted; hosting, publication, Git tags, generated release workflows, deployment, and policy changes are excluded.
Required artifact/provenance/platform failure or lack of concrete deletion ends evaluation early.
Only accepted implementation or a reproducible documentation-only non-adoption decision can enter integration.
Publication remains blocked until predecessor review findings and required checks clear.

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