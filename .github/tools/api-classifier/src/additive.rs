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
//! Missing external definitions produce a warning, not a release failure.
//! The diff covers the rendered API. Inherited methods and foreign re-exports
//! can need review because rustdoc does not include every external definition.
//! Build and parsing failures still return errors.

use std::path::Path;

use anyhow::{Context, Result};
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
/// Returns an error when either public API cannot be built or parsed.
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

    if baseline_api.missing_item_ids().next().is_some()
        || current_api.missing_item_ids().next().is_some()
    {
        eprintln!(
            "api-classifier: warning: the baseline or current public API for `{package}` \
             omits external definitions. Inherited methods and foreign re-exports \
             can need review; the classification covers detected changes only."
        );
    }

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
    Builder::from_rustdoc_json(&json_path)
        .build()
        .with_context(|| format!("parsing the public API for `{package}`"))
}
