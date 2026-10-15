# Stage 6: Delivery and Architecture Gates

## Status

Stage 6 started on 2026-10-15 from `35910ca` after the revised versioning decision.
The user authorizes autonomous implementation, breaking internal changes, and incremental local commits.
No push, release publication, tag mutation, crates.io publication, or live deployment change is authorized.
Unrelated worktree files remain untouched.

The local Linux delivery work passed. Stage 6 remains open because automatic API
classification cannot yet analyze external trait definitions in the real protocol package.
This is a correctness blocker, not a missing local tool or a hosted-platform limitation.

## Reviewed Plan

Claude Opus 4.8 reviewed this plan before code changes.
Computed library SemVer, executable CalVer, dependency-aware propagation, version hydration, and the generated release branch remain supported.
The no-release CI path is the release rehearsal. A second release pipeline is unnecessary.

- [x] S6-01: Cargo metadata now owns release discovery, hydration membership, and CI inventory. Tests cover aliases, inherited and target-specific dependencies, build/dev kinds, and excluded nonmembers.
- [x] S6-02: The resolved production allowlist passes on Linux and Windows graphs, with 43 and 40 workspace edges respectively. Eight external guards and explicit product validation remain enforced.
- [ ] S6-03: The typed analyzer passes its fixtures but rejects the real protocol package because external trait definitions are absent. Resolve this completeness blocker before automatic classification is ready.
- [x] S6-04: CI defines isolated protocol, direct-client, IPC, and full Linux selections. Local selections pass. Dedicated authentication/authorization fuzz targets and pinned YANG verification pass.
- [x] S6-05: The existing no-release path computes and hydrates versions without changing publication guards. Schema-v2 manifests record source, versions, schema hashes, artifact hashes, and build-runner provenance.
- [x] S6-06: The four-product Linux rehearsal passed from `4e4c6ad`, with computed versions, JSON/XML SBOMs, symbols, provenance, checksums, linkage, plugin exports, and scratch-directory rollback.
- [ ] S6-07: Run focused tests, independent final review, and relevant gates. Remove only superseded discovery or validation machinery and record remaining environment limits.

## Design Constraints

Cargo is the package authority. Directory names and regular expressions must not decide workspace membership or dependency identity.
Normal and build dependencies can affect computed versions. Development-only edges do not trigger version propagation.
Architecture rules use resolved production edges for each supported target. Test dependencies remain a separate concern.
The release product list remains an explicit supported-product decision, checked against Cargo rather than generated from every member.

An API-analysis failure must not silently become a major bump or a compatible result.
Breaking changes and additive API changes are different classifications. A boolean compatibility result cannot prove a minor increment is needed.
The implementation will verify tool capabilities and document any unsupported classification rather than use source-text heuristics.

Pinned YANG hashes provide an offline consistency gate. Deterministic regeneration uses pinned source and generator versions.
Canonical YANG and the supported field-to-behavior tests remain authoritative.

## Verification

Inventory tests cover renamed, inherited, target-specific, build, and development dependencies, plus excluded nonmembers.
Architecture tests inject forbidden edges and check the actual supported-target graphs.
Version tests cover unchanged, patch, additive, breaking, pre-1.0, dependency propagation, and indeterminate analysis.
No-release tests verify computed version inputs and publication guards. Archive names alone do not prove that hydration occurred.
A release manifest records the source commit, computed versions, YANG/protobuf identities, and artifact checksums.
The rehearsal must not invoke the release job's remote writes or container publication.

The final checkpoint records actual local evidence separately from unexecuted hosted-CI or platform checks.

## Implementation Progress

Commit `af6611b` records the reviewed plan. Commit `fc2857d` implements the Cargo-derived delivery contracts and shared rehearsal operations.
Commit `f3c8096` fixes a defect discovered by the first real artifact rehearsal: health-probe help and version output incorrectly returned invocation-error status.
The failed-before regression now passes, alongside the existing health exit-code tests.

The release model remains computed per-package SemVer and executable CalVer, including dependency propagation and the generated release-source branch.
The CI-only API adapter has its own workspace and lockfile. It is not a product or a release-library member.
It pins `cargo-semver-checks` 0.47.0, `public-api` 0.52.0, and `nightly-2025-11-23` to rustdoc JSON format 57.
The tool requires Rust 1.91. The product workspace still requires Rust 1.88.
Both analyzers use all features and distinguish tool failure from API change.
Unexplained changed or removed public items receive a conservative breaking classification rather than a patch.
Incomplete public surfaces fail closed. New public feature labels count as additions.
Before 1.0, breaking changes increment the minor position, while compatible additions increment the patch position under the retained Rust compatibility policy.

Root manifest, lockfile, and Cargo configuration changes participate in release selection.
Unchanged executables retain their released versions in the hydration map without new tags.
Normal dependencies with incompatible computed bumps impose a conservative breaking floor on dependents, because public type identity can change without textual signature changes.
This can over-bump a private dependency. Build-only dependencies trigger analysis without that automatic floor.
Git failures and analysis failures never become successful unchanged or initial-release results.

Final reviews found and corrected metadata fail-open cases, missing automation gates, inaccurate build provenance, and weaker rehearsal SBOM checks.
CI now runs the Python automation tests and the API tool's real Git fixtures.
The rehearsal shares binary staging, symbol extraction, archive creation, and structured SBOM sanitation with CI.
Linux symbols are extracted before stripping and linked back to the staged binary.
Per-product provenance comes from the build runner. Manifest assembly-tool versions are recorded separately.
Rehearsal output must be new or empty. Stale archives cannot enter a new manifest.
Commit `4e4c6ad` accepts SBOM component names from Cargo package and target identities, without guessed name substitutions.
Commit `52ca5c9` prevents a reusable Cargo cache from overlapping source and release directories.
Commit `f57c6a9` updates the analyzer dependencies, adds its CI audit, and records the incomplete-trait regression.

## Local Verification

- All 244 delivery automation tests pass, including workflow contracts and Cargo identity tests.
- All 12 real Git fixtures for the analyzer pass, including the negative completeness cases.
- Full workspace tests, strict Clippy, warnings-as-errors private rustdoc, and nightly formatting pass.
- Separate protocol/secrets, configuration/networking, and IPC selections pass with all features and the Linux target.
- Authentication and authorization fuzz targets each pass a 30-second sanitizer run, with 2,236,542 and 2,628,733 executions respectively.
- All 19 YANG verification tests pass. Full pinned regeneration runs twice and matches the checked-in files and hashes.
- Product and analyzer audits report no vulnerabilities across 324 and 407 dependencies respectively.
- The analyzer also passes strict Clippy, private rustdoc, formatting, and unused-dependency checks.

The analyzer upgrade fixes RUSTSEC-2025-0140 in transitive `gix-date` and removes `atty`.
The audit fetched its advisory database successfully. A crates.io index refresh emitted a cache-lock warning.
The local consumer selections do not prove the absence of native packages from this development container.
The CI matrix preserves that installation distinction.

## Successful Rehearsal

Source: `4e4c6ad1a73357582b732e843c8f1888e8393fa9`.
Output: `/tmp/tacacsrs-stage6-rehearsal-verified.TU2TjC`.
Log: `target/tmp/stage6-rehearsal-verified.log`.
Target: `x86_64-unknown-linux-gnu`, release profile, Rust 1.88.0, OpenSSL 3.0.20.

The computed map assigns `0.1.0` to 12 libraries and `2026.1015.0` to `tacon`, `tacacsrs-agentd`, and `tacacsrs-agent-health`.
These are initial-release versions. This rehearsal does not prove successful API classification against an existing release tag.

Archive SHA-256 values:

```text
0fd76b2e0db180d2f2aa55b1662c1d6f8366143f004f214f577709bf8f7291f1  tacon-linux-gnu-x86_64.tar.gz
90a31881186428590d1ed926145603e6cc1a08ac6deecbb5462f8dc44086c27c  tacacsrs-agentd-linux-gnu-x86_64.tar.gz
78f6a05e14c6bdd216c9c36deeb84193fc3fc612fb9b9062ce6c2bb8182d1e15  tacacsrs-agent-health-linux-gnu-x86_64.tar.gz
5ef1a58c13990454577837b928c2713865117cda55c58119497547e8cf8e0bcd  tacacsrs-bash-plugin-linux-gnu-x86_64.tar.gz
```

The release directory includes four provenance files, `release-manifest.json`, and `checksums-sha256.txt`.
The manifest digest is `d782778c70cd5515a1b2c3718108d24cff0ddbe4914626fdd8ebee7c61030390`.
The rehearsal verified archived payloads against embedded and separate provenance records, then verified all artifact digests offline.
Rollback only extracted and executed the CLI in a scratch directory.
No source manifest, live service, tag, remote branch, or publication endpoint changed.

## Remaining Work

S6-03 remains blocked at `.github/tools/api-classifier/src/additive.rs`.
The real protocol comparison against `35910ca` exits with an error and no JSON result.
Its 1,134 missing lookups reference 49 external trait definitions, not omitted implementation records.
Private-item output does not supply these definitions.
A regression proves that an inherited method can change its return type from `u8` to `u16` without a rendered diff.
Ignoring unresolved IDs would therefore permit an incorrect patch classification.

The classifier must resolve external trait definitions and validate cross-crate identities before it can classify this surface automatically.
An alternative analyzer needs the same regression evidence. The implementation must not silently downgrade incomplete analysis or infer a bump from tool failure.
A manual release decision needs explicit review. The existing fast-patch bypass is not a validated replacement.

S6-07 remains open until the real-package classification passes and the final release path receives its remaining platform verification.
Hosted CI, Windows artifacts, and container builds did not run locally. No push or publication was authorized.