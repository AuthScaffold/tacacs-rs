//! Breaking-change analysis through the `cargo-semver-checks` library API.
//!
//! This module never parses `cargo-semver-checks` text output. It uses the
//! typed library surface so a tool error is distinguishable from a verdict:
//! an error returns `Err`, while a verdict returns `Ok(Option<ReleaseType>)`.

use std::path::Path;

use anyhow::{Context, Result};
use cargo_semver_checks::{Check, GlobalConfig, ReleaseType, Rustdoc};

/// Return the minimum bump the public API requires, or `Err` on tool failure.
///
/// The result is:
///
/// - `Ok(Some(ReleaseType::Major))` for a breaking change,
/// - `Ok(Some(ReleaseType::Minor))` for a change a lint flags as minor,
/// - `Ok(None)` when no bump beyond patch is required by the lints, and
/// - `Err(_)` when the analysis itself could not complete.
///
/// The baseline rustdoc is generated from `baseline_rev`, and the current
/// rustdoc from `project_root`. The current manifest version is irrelevant:
/// [`cargo_semver_checks::CrateReport::required_bump`] reads lint hits, not the
/// detected version delta, so a `0.0.0-dev` current version is fine.
pub fn required_bump(
    project_root: &Path,
    package: &str,
    baseline_rev: &str,
) -> Result<Option<ReleaseType>> {
    let current = Rustdoc::from_root(project_root);
    let baseline = Rustdoc::from_git_revision(project_root, baseline_rev.to_string());

    let mut check = Check::new(current);
    check.set_packages(vec![package.to_string()]);
    check.set_baseline(baseline);
    // A declared patch release runs every major and minor lint, so the report
    // reflects the true minimum required bump.
    check.set_release_type(ReleaseType::Patch);
    check.with_all_features();

    let mut config = GlobalConfig::new();
    config.set_log_level(None);
    // Keep the adapter's own standard output clean for the JSON result.
    config.set_stdout(Box::new(std::io::sink()));
    config.set_stderr(Box::new(std::io::sink()));

    let report = check
        .check_release(&mut config)
        .context("cargo-semver-checks check_release returned an error")?;

    let crate_report = report
        .crate_reports()
        .get(package)
        .with_context(|| format!("cargo-semver-checks produced no report for `{package}`"))?;

    // Deliberately avoid `CrateReport::success`: it asserts invariants about the
    // detected version delta that do not hold for a `0.0.0-dev` current crate.
    Ok(crate_report.required_bump())
}
