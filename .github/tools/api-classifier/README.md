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
  --toolchain nightly-2025-08-02
```

## Toolchain and rustdoc format

Both engines read rustdoc JSON. The format version must match what the pinned
analysis libraries understand:

| Component | Version | rustdoc JSON format |
| --- | --- | --- |
| `cargo-semver-checks` | `0.44.0` | supports 45, 53, 55, 56 |
| `public-api` | `0.50.1` (via `rustdoc-types` 0.55.0) | 55 (min nightly `nightly-2025-08-02`) |

`nightly-2025-08-02` emits rustdoc JSON **format 55**, which both engines
accept, so one toolchain serves both. The adapter sets `RUSTUP_TOOLCHAIN` for
its subprocesses, so `cargo-semver-checks` and the rustdoc build both use
`--toolchain`.

Install it with:

```bash
rustup toolchain install nightly-2025-08-02 --profile minimal
```

The adapter binary itself builds on the workspace toolchain (`1.88`). The pinned
`Cargo.lock` uses MSRV-aware resolution to keep every dependency buildable on
`1.88`.

## Limitations

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
