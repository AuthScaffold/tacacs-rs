# Stage 6: Delivery and Architecture Gates

## Status

Stage 6 started on 2026-10-15 from `35910ca` after the revised versioning decision.
The user authorizes autonomous implementation, breaking internal changes, and incremental local commits.
No push, release publication, tag mutation, crates.io publication, or live deployment change is authorized.
Unrelated worktree files remain untouched.

## Reviewed Plan

Claude Opus 4.8 reviewed this plan before code changes.
Computed library SemVer, executable CalVer, dependency-aware propagation, version hydration, and the generated release branch remain supported.
The no-release CI path is the release rehearsal. A second release pipeline is unnecessary.

- [ ] S6-01: Use one Cargo-derived package inventory for release discovery, hydration, and CI reporting. Preserve dependency kind, platform conditions, aliases, and workspace membership.
- [ ] S6-02: Enforce the production dependency allowlist from resolved, platform-filtered metadata. Preserve existing external dependency restrictions and verify the declared product matrix.
- [ ] S6-03: Keep computed versions and distinguish API-analysis errors from compatibility results. Add tested major/minor/patch classification where supported by verified tooling.
- [ ] S6-04: Run isolated protocol, direct-client, IPC, and full Linux selections in CI. Add dedicated authentication/authorization fuzz targets and pinned YANG verification.
- [ ] S6-05: Compute and hydrate candidate versions on the existing no-release path. Record source, versions, schema identities, and artifact hashes without enabling publication.
- [ ] S6-06: Rehearse artifact production in an isolated source export using the existing packaging operations. Verify embedded versions, SBOMs, checksums, native dependencies, and rollback instructions.
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