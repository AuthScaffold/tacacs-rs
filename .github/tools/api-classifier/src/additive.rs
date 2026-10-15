//! Surface-change detection through `public-api`.
//!
//! `cargo-semver-checks` is authoritative for breaking changes, but this pinned
//! version has gaps. It does not flag a purely additive change (a new public
//! function) as a minor bump, and it does not flag a changed free-function
//! parameter type (for example `fn accept(x: u8)` becoming `fn accept(x: u16)`)
//! as breaking. This module fills both gaps by diffing the rendered public API:
//!
//! - An added item, with nothing removed or changed, is an additive (minor)
//!   change.
//! - A removed or changed item is a surface-contract change. This module runs
//!   only after the breaking engine found no major change, so such a delta is a
//!   breaking change that engine missed. It is reported as a conservative
//!   breaking result, never a silent patch.
//!
//! It fails closed on an incomplete surface. If the rendered API references
//! items that are missing from the rustdoc JSON (for example a re-export of a
//! foreign module), the diff cannot be trusted, so the analysis returns an
//! error instead of a possibly wrong verdict.

use std::path::Path;

use anyhow::{bail, Context, Result};
use public_api::diff::PublicApiDiff;
use public_api::{Builder, PublicApi};

/// The public-API delta the surface analysis found, relative to the baseline.
///
/// This is the delta the breaking-change engine did not already classify as a
/// major bump, because this analysis runs only when that engine found no major
/// change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceDelta {
    /// No item was added, removed, or changed.
    Unchanged,
    /// At least one item was added, and none were removed or changed.
    Additive,
    /// At least one item was removed or changed. Because the breaking engine
    /// found no major change, this is a breaking change it missed.
    Breaking,
}

/// Diff the current public API against the baseline and return the delta.
///
/// `current_manifest` is the workspace root manifest at the current checkout.
/// `baseline_manifest` is the same manifest inside a detached baseline
/// worktree. `toolchain` renders the rustdoc JSON for both and must emit a
/// format that `public-api` can read.
///
/// # Errors
///
/// Returns an error when either public API cannot be rendered, or when a
/// rendered surface is incomplete (see the module docs). An incomplete surface
/// fails closed rather than producing a possibly wrong verdict.
pub fn surface_delta(
    current_manifest: &Path,
    baseline_manifest: &Path,
    package: &str,
    toolchain: &str,
) -> Result<SurfaceDelta> {
    let current_api = render_public_api(current_manifest, package, toolchain)
        .context("rendering the current public API")?;
    let baseline_api = render_public_api(baseline_manifest, package, toolchain)
        .context("rendering the baseline public API")?;

    let diff = PublicApiDiff::between(baseline_api, current_api);

    // Order matters: a removal or change is the strongest signal and outranks a
    // concurrent addition. A pure addition is a minor change. Anything else is
    // unchanged at the public-API level.
    if !diff.removed.is_empty() || !diff.changed.is_empty() {
        Ok(SurfaceDelta::Breaking)
    } else if !diff.added.is_empty() {
        Ok(SurfaceDelta::Additive)
    } else {
        Ok(SurfaceDelta::Unchanged)
    }
}

/// Render the public API of one package into an owned [`PublicApi`].
///
/// The rustdoc JSON is generated into an owned temporary target directory that
/// is removed once this function returns, after the API has been parsed out of
/// it. All features are enabled so the analyzed surface matches the
/// breaking-change engine, which also runs with `--all-features`; an addition
/// behind a non-default feature is therefore detected here as well.
fn render_public_api(manifest_path: &Path, package: &str, toolchain: &str) -> Result<PublicApi> {
    let target_dir = tempfile::Builder::new()
        .prefix("api-classifier-rustdoc-")
        .tempdir()
        .context("creating a temporary rustdoc target directory")?;

    // Capture the `cargo rustdoc` output instead of inheriting this process's
    // standard output, so the only thing on our stdout stays the JSON result.
    let mut build_stderr = Vec::new();
    let build = rustdoc_json::Builder::default()
        .toolchain(toolchain.to_string())
        .manifest_path(manifest_path)
        .package(package)
        .all_features(true)
        .target_dir(target_dir.path())
        .build_with_captured_output(std::io::sink(), &mut build_stderr);
    let json_path = build.with_context(|| {
        format!(
            "rustdoc JSON build failed for `{package}`: {}",
            String::from_utf8_lossy(&build_stderr).trim()
        )
    })?;

    // Parse the API before `target_dir` drops and removes the JSON file.
    let api = Builder::from_rustdoc_json(&json_path)
        .build()
        .with_context(|| format!("parsing the public API for `{package}`"))?;

    reject_incomplete_surface(&api, package)?;
    Ok(api)
}

/// Fail closed when a rendered public API is incomplete.
///
/// `public-api` records the rustdoc JSON IDs of items that are referenced from
/// the public API but missing from the JSON. This happens for re-exports of
/// foreign modules (cargo-public-api issue 103): rustdoc records the re-export
/// but cannot inline the foreign module's items, so they are referenced yet
/// absent. When that happens, the diff cannot see additions, removals, or
/// changes inside the re-exported module, so an additive-or-patch verdict would
/// be unsound. This analysis therefore refuses to classify an incomplete
/// surface rather than risk a wrong, silently-too-low bump.
///
/// This is deliberately specific. It keys off `missing_item_ids`, which is
/// populated only when a referenced item is genuinely absent from the JSON. A
/// complete surface, including one that re-exports individual foreign items that
/// rustdoc does inline, reports no missing IDs and classifies normally.
fn reject_incomplete_surface(api: &PublicApi, package: &str) -> Result<()> {
    let missing: Vec<u32> = api.missing_item_ids().copied().collect();
    if !missing.is_empty() {
        bail!(
            "the public API of `{package}` is incomplete: `public-api` could not \
             resolve {count} referenced item(s) in the rustdoc JSON. This happens \
             when the crate re-exports a foreign module (`pub use other_crate::some_module`), \
             whose items rustdoc cannot inline. The surface diff cannot see changes \
             inside such a re-export, so this adapter refuses to classify it rather \
             than risk a too-low bump. Re-export the specific items instead of the \
             whole foreign module. Unresolved rustdoc IDs: {missing:?}",
            count = missing.len(),
        );
    }
    Ok(())
}
