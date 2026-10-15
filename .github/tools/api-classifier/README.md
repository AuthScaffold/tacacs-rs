# api-classifier

A CI-only typed adapter that classifies a crate's public-API change as
`patch`, `minor`, or `major`. The release pipeline uses it to decide the next
SemVer version for each library crate.

This crate is intentionally **its own Cargo workspace**. It never joins the
product workspace, the product `Cargo.lock`, or the release member set. It is
not published.

## Why a typed adapter

The `cargo-semver-checks` command-line tool exits with code `1` for both a
breaking change and an internal error, and it prints no machine-readable
result. A boolean exit code therefore cannot tell "the API broke" apart from
"the tool failed". That ambiguity turned every tool error into a wrong major
bump.

This adapter uses the `cargo-semver-checks` and `public-api` **library** APIs
instead of parsing text. It prints one JSON object and uses the process exit
code only to signal a hard failure:

```json
{"package":"tacacsrs-protocol","bump":"minor","breaking_analysis":"cargo-semver-checks","minor_analysis":"public-api","reason":"public-api found an added public item"}
```

## Classification

Three signals produce the verdict. Each one can only raise the bump, never
lower it, and each one fails closed on error.

1. **Breaking analysis — `cargo-semver-checks`.** It is authoritative for the
   breaking changes it detects. `Report.crate_reports()[pkg].required_bump()`
   returns `Some(Major)`, `Some(Minor)`, or `None`, and `check_release` returns
   `Err` on a tool failure. An `Err` here fails closed: the process exits
   non-zero with **no JSON on standard output**, so the caller never mistakes a
   tool failure for a compatibility result. A required major short-circuits the
   rest of the analysis.
2. **Surface analysis — `public-api`.** It renders the public API at the
   current checkout and at the baseline and diffs them. It covers two gaps the
   pinned `cargo-semver-checks` leaves:
   - An **added** item it does not flag is a minor change.
   - A **removed or changed** item it misses — for example a changed
     free-function parameter type, such as `fn accept(x: u8)` becoming
     `fn accept(x: u16)` — is a surface-contract change. Because this analysis
     runs only after the breaking engine found no major change, such a delta is
     breaking the engine missed, so it becomes a **conservative major** with an
     explicit reason, never a silent patch.

   It also fails closed on an **incomplete surface**. When `public-api` reports
   a referenced item missing from the rustdoc JSON — for example a
   `pub use other_crate::some_module` re-export of a foreign module, whose items
   rustdoc cannot inline — the diff cannot see changes inside that re-export, so
   the adapter refuses to classify rather than risk a too-low bump.
3. **Feature analysis — Cargo metadata.** It compares the declared feature set
   of the package at the current checkout and at the baseline. An **added**
   feature is a minor change; a **removed** feature is a major change. Cargo is
   the authority: the metadata feature map includes both explicit `[features]`
   entries and the implicit features Cargo derives from optional dependencies.

Every analysis fails closed. An analysis error exits the process non-zero with
no JSON on standard output. The adapter never downgrades an unknown result to a
silent `patch`, because a missed change would publish without the bump it needs.

## Baseline

`--baseline-rev` must be the **hydrated release tag**, not the source commit it
was generated from. The tag carries the released version and public API. The
baseline for `public-api` is rendered from a detached Git worktree, so the
working tree is never modified.

## Usage

```bash
api-classifier \
  --package tacacsrs-protocol \
  --baseline-rev tacacsrs-protocol-v0.3.0 \
  --manifest-path /path/to/workspace/Cargo.toml \
  --toolchain nightly-2025-11-23
```

## Toolchain and rustdoc format

Both engines read rustdoc JSON. The format version must match what the pinned
analysis libraries understand:

| Component | Version | rustdoc JSON format |
| --- | --- | --- |
| `cargo-semver-checks` | `0.47.0` | supports 56, 57 |
| `public-api` | `0.52.0` (via `rustdoc-types` 0.57.4) | 57 |

`nightly-2025-11-23` emits rustdoc JSON **format 57**, which both engines
accept, so one toolchain serves both. The adapter sets `RUSTUP_TOOLCHAIN` for
its subprocesses, so `cargo-semver-checks` and the rustdoc build both use
`--toolchain`.

Install it with:

```bash
rustup toolchain install nightly-2025-11-23 --profile minimal
```

The adapter binary requires Rust **1.91**. The product workspace still requires
Rust **1.88**. The separate tool lockfile uses MSRV-aware resolution for Rust 1.91.

`cargo-semver-checks` 0.44 and 0.45 depend on vulnerable `gix-date` 0.10.
Version 0.46 depends on vulnerable `gix-date` 0.11.
Version 0.47 requires Rust 1.91 and resolves to fixed `gix-date` 0.13.0.
This upgrade fixes RUSTSEC-2025-0140 and removes the transitive `atty` dependency.
It also removes JSON 55 support, so callers must use the new nightly pin.

The exact `public-api` pin matters: version 0.52.2 reads JSON 59, not JSON 57.
The minimum-nightly constant in version 0.52.0 is stale. Use the verified pin above.

## Validation

Run these commands from the repository root:

```bash
rustup toolchain install 1.91.0 --profile minimal --component clippy
env -u CARGO_TARGET_DIR cargo +1.91.0 test --manifest-path .github/tools/api-classifier/Cargo.toml --locked
cargo audit --file .github/tools/api-classifier/Cargo.lock
cargo +nightly fmt --manifest-path .github/tools/api-classifier/Cargo.toml -- --check
cargo +1.91.0 clippy --manifest-path .github/tools/api-classifier/Cargo.toml --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo +1.91.0 doc --manifest-path .github/tools/api-classifier/Cargo.toml --no-deps --all-features --document-private-items --locked
```

The twelve integration fixtures use temporary Git repositories and real compiler output.
They fail when the pinned nightly is missing. Most fixtures exercise the CLI default;
the missing-baseline fixture also exercises an explicit `--toolchain`.
Do not export `CARGO_TARGET_DIR` for these tests. Child builds can inherit it and collide.

## Limitations

- Automatic classification is not ready for the product workspace. The real
  protocol package fails closed because rustdoc omits external trait definitions.
  Its 1,134 unresolved lookups refer to 49 external traits. Private-item output
  does not resolve them. A regression proves that an inherited default method
  can change its return type without a rendered diff. The completeness guard
  must remain until an analyzer resolves these definitions and cross-crate
  identities. A manual release decision needs explicit review.
- Both API engines analyze every feature. `cargo-semver-checks` runs with
  `--all-features`, and the surface (`public-api`) check renders its rustdoc
  JSON with `--all-features` too, so an addition behind a non-default feature is
  detected as a minor change rather than missed.
- The surface analysis is conservative. It treats any removed or changed item
  the breaking engine missed as a major change, even in the rare case where
  `public-api` reports a change that is benign (for example an explicit return
  type rewritten to an identical `Self`). This can over-bump, but it never
  under-bumps a breaking change to a patch.
- A crate that cannot be built on the analysis toolchain, or a baseline
  revision that cannot be checked out, makes the analysis fail closed.
