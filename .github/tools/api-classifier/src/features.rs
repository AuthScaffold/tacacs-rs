//! Feature-label change detection through Cargo metadata.
//!
//! `cargo-semver-checks` flags a removed feature as a major change through its
//! `feature_missing` lint, but it does not flag an added feature as a minor
//! change, and it does not uniformly catch the implicit features Cargo derives
//! from optional dependencies. This module compares the declared feature set of
//! the package at the current checkout and at the baseline, read from
//! `cargo metadata`:
//!
//! - A feature present at the baseline but absent now is a major change.
//! - A feature present now but absent at the baseline is a minor change.
//!
//! Cargo is the authority on the feature set. The metadata feature map includes
//! both explicit `[features]` entries and the implicit features Cargo derives
//! from optional dependencies, so comparing the map keys captures the real
//! feature surface, not a hand-parsed manifest.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// The feature-label delta between the baseline and the current checkout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureDelta {
    /// The feature set is identical.
    Unchanged,
    /// A feature was added, and none were removed.
    Added,
    /// At least one feature was removed. Removing a feature is breaking.
    Removed,
}

/// Compare the declared feature set of `package` across the two manifests.
///
/// `current_manifest` is the workspace manifest at the current checkout.
/// `baseline_manifest` is the same manifest inside a detached baseline
/// worktree. Both are read with `cargo metadata --no-deps`, which needs no
/// native build or network access.
///
/// # Errors
///
/// Returns an error when `cargo metadata` fails for either manifest, or when a
/// manifest does not contain `package`. A metadata failure fails closed rather
/// than guessing a delta.
pub fn feature_delta(
    current_manifest: &Path,
    baseline_manifest: &Path,
    package: &str,
) -> Result<FeatureDelta> {
    let current = feature_names(current_manifest, package)
        .with_context(|| format!("reading current features of `{package}`"))?;
    let baseline = feature_names(baseline_manifest, package)
        .with_context(|| format!("reading baseline features of `{package}`"))?;

    // A removal is the strongest signal and outranks a concurrent addition,
    // mirroring the surface analysis: a removed feature is breaking.
    if baseline.difference(&current).next().is_some() {
        Ok(FeatureDelta::Removed)
    } else if current.difference(&baseline).next().is_some() {
        Ok(FeatureDelta::Added)
    } else {
        Ok(FeatureDelta::Unchanged)
    }
}

/// The `cargo metadata` fields this module reads.
#[derive(Deserialize)]
struct Metadata {
    packages: Vec<MetadataPackage>,
}

#[derive(Deserialize)]
struct MetadataPackage {
    name: String,
    /// Cargo renders the feature table as a map of feature name to the list of
    /// features or dependencies it enables. Only the keys matter here.
    features: std::collections::BTreeMap<String, Vec<String>>,
}

/// Return the declared feature names of `package` from one manifest.
fn feature_names(manifest_path: &Path, package: &str) -> Result<BTreeSet<String>> {
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()
        .context("running `cargo metadata`")?;
    if !output.status.success() {
        bail!("`cargo metadata` failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }

    let metadata: Metadata =
        serde_json::from_slice(&output.stdout).context("parsing `cargo metadata` JSON")?;
    let package_metadata = metadata
        .packages
        .into_iter()
        .find(|candidate| candidate.name == package)
        .with_context(|| format!("`cargo metadata` has no package named `{package}`"))?;

    Ok(package_metadata.features.into_keys().collect())
}
