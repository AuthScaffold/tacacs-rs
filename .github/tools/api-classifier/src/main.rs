//! CI-only typed adapter that classifies a crate's public-API change.
//!
//! The adapter compares a package at the current checkout against a baseline
//! Git revision and prints a single JSON object to standard output:
//!
//! ```json
//! {"package":"my-crate","bump":"minor","breaking_analysis":"cargo-semver-checks","minor_analysis":"public-api","reason":"..."}
//! ```
//!
//! Three signals produce the verdict, and each one can only raise the bump:
//!
//! - [`cargo_semver_checks`] is authoritative for the breaking changes it
//!   detects. A tool error here is never silently turned into a bump: the
//!   process exits non-zero with no JSON on standard output, so the caller
//!   fails closed. A required major bump short-circuits the rest.
//! - [`public_api`] diffs the rendered public API. It detects additive items
//!   that `cargo-semver-checks` does not flag (a minor change), and it detects
//!   removed or changed items that this pinned `cargo-semver-checks` misses (a
//!   changed free-function parameter type, for example). A removal or change
//!   the breaking engine did not already flag becomes a conservative major with
//!   an explicit reason, never a silent patch. It fails closed on an incomplete
//!   surface rather than risk a too-low bump.
//! - Cargo metadata compares the declared feature set. An added feature is a
//!   minor change; a removed feature is a major change. It also fails closed.

mod additive;
mod features;
mod semver_checks;
mod worktree;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use cargo_semver_checks::ReleaseType;
use clap::Parser;
use serde::Serialize;

use additive::SurfaceDelta;
use features::FeatureDelta;

/// Classify a crate's public-API change as `patch`, `minor`, or `major`.
#[derive(Parser, Debug)]
#[command(
    name = "api-classifier",
    about = "Classify a crate's public-API change as patch, minor, or major."
)]
struct Args {
    /// Package (crate) name to analyze, as declared in `Cargo.toml`.
    #[arg(long)]
    package: String,

    /// Baseline Git revision to compare against.
    ///
    /// Use the hydrated release tag so the baseline carries the released
    /// version and public API, not the `0.0.0-dev` development manifest.
    #[arg(long)]
    baseline_rev: String,

    /// Path to the workspace root `Cargo.toml` that contains the package.
    #[arg(long)]
    manifest_path: PathBuf,

    /// Toolchain used to render rustdoc JSON for both engines. It must emit a
    /// rustdoc JSON format that the pinned analysis libraries understand.
    #[arg(long, default_value = "nightly-2025-11-23")]
    toolchain: String,
}

/// The classified minimum bump the public-API change requires.
#[derive(Debug, Clone, Copy)]
enum Bump {
    Patch,
    Minor,
    Major,
}

impl Bump {
    fn as_str(self) -> &'static str {
        match self {
            Bump::Patch => "patch",
            Bump::Minor => "minor",
            Bump::Major => "major",
        }
    }
}

/// How the additive (`minor`) refinement was resolved.
#[derive(Debug, Clone, Copy)]
enum MinorAnalysis {
    /// The additive engine ran and produced the result.
    PublicApi,
    /// The additive engine was not needed (semver-checks already decided).
    NotRun,
}

impl MinorAnalysis {
    fn as_str(self) -> &'static str {
        match self {
            MinorAnalysis::PublicApi => "public-api",
            MinorAnalysis::NotRun => "not-run",
        }
    }
}

/// The JSON document written to standard output on success.
#[derive(Debug, Serialize)]
struct Classification {
    package: String,
    bump: String,
    breaking_analysis: String,
    minor_analysis: String,
    /// A short human-readable explanation of the verdict. The release pipeline
    /// does not parse this field; it aids humans reading CI logs.
    reason: String,
}

fn main() -> ExitCode {
    let args = Args::parse();
    // Pin the toolchain used to render rustdoc JSON for both engines, so the
    // format is deterministic and matches the pinned analysis libraries.
    // cargo-semver-checks has no toolchain option, so it reads this variable
    // when it spawns cargo. This runs before any threads or subprocesses.
    std::env::set_var("RUSTUP_TOOLCHAIN", &args.toolchain);
    match run(&args) {
        Ok(classification) => {
            // Standard output carries only this one JSON line. Every other
            // engine writes to standard error, so the caller can parse stdout.
            let line =
                serde_json::to_string(&classification).expect("classification serializes to JSON");
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            // Fail closed: a breaking-change analysis error must never be
            // reported as a bump. No JSON is printed to standard output.
            eprintln!("api-classifier: public-API analysis failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<Classification> {
    // Canonicalize the manifest path so a relative `--manifest-path` resolves to
    // an absolute, symlink-free location. The project root, the Git-relative
    // manifest path, and the baseline worktree comparison all derive from it.
    let manifest_path = args
        .manifest_path
        .canonicalize()
        .with_context(|| format!("resolving --manifest-path `{}`", args.manifest_path.display()))?;
    let project_root = manifest_path
        .parent()
        .context("--manifest-path has no parent directory")?
        .to_path_buf();

    // The breaking-change engine is authoritative and fails closed.
    let required = semver_checks::required_bump(&project_root, &args.package, &args.baseline_rev)
        .with_context(|| {
        format!(
            "cargo-semver-checks could not analyze `{}` against `{}`",
            args.package, args.baseline_rev
        )
    })?;

    match required {
        // A required major bump is the top of the scale. No surface or feature
        // signal can raise it, and the additive engine does not run.
        Some(ReleaseType::Major) => {
            return Ok(classification(
                &args.package,
                Bump::Major,
                "cargo-semver-checks",
                MinorAnalysis::NotRun,
                "cargo-semver-checks requires a major (breaking) bump",
            ));
        }
        // No required bump, an explicit patch, or a minor may still hide a
        // surface removal/change or a feature-label change that
        // cargo-semver-checks does not flag, so the extra analyses run below.
        None | Some(ReleaseType::Minor) | Some(ReleaseType::Patch) => {}
        // `ReleaseType` is non-exhaustive. An unrecognized future verdict is not
        // a known-safe patch, so fail closed rather than guess a bump.
        Some(other) => bail!(
            "cargo-semver-checks reported an unrecognized required bump ({other:?}); \
             this adapter cannot classify it"
        ),
    }

    // Check out the baseline once; the surface and feature analyses share it, so
    // the baseline is rendered a single time and the working tree is untouched.
    let repo_root = worktree::git_toplevel(&project_root)?;
    let relative_manifest = manifest_path
        .strip_prefix(&repo_root)
        .context("manifest path is not inside the Git repository")?
        .to_path_buf();
    let baseline = worktree::TempWorktree::add(&repo_root, &args.baseline_rev)?;
    let baseline_manifest = baseline.path().join(&relative_manifest);

    // The surface analysis fills the breaking engine's gaps: it detects removed
    // or changed items it misses and additive items it does not flag. Its errors
    // propagate and fail closed; they are never downgraded to a silent patch.
    let surface =
        additive::surface_delta(&manifest_path, &baseline_manifest, &args.package, &args.toolchain)
            .context("public-api surface analysis")?;

    // The feature analysis detects feature-label additions (minor) and removals
    // (major) through Cargo metadata. It also fails closed.
    let features = features::feature_delta(&manifest_path, &baseline_manifest, &args.package)
        .context("cargo-metadata feature analysis")?;

    Ok(classify(&args.package, required, surface, features))
}

/// Combine the breaking, surface, and feature signals into one classification.
///
/// Each signal can only raise the bump, never lower it. A removed or changed
/// item, or a removed feature, is a breaking change `cargo-semver-checks`
/// missed, so it becomes a conservative major with an explicit reason. An added
/// item or an added feature is a minor change. Otherwise the result is a patch.
fn classify(
    package: &str,
    required: Option<ReleaseType>,
    surface: SurfaceDelta,
    features: FeatureDelta,
) -> Classification {
    // A surface removal/change outranks everything else below a semver-checks
    // major: the breaking engine missed a contract change, so bump major.
    if surface == SurfaceDelta::Breaking {
        return classification(
            package,
            Bump::Major,
            "public-api",
            MinorAnalysis::PublicApi,
            "public-api found a removed or changed public item that \
             cargo-semver-checks did not flag",
        );
    }
    // A removed feature is breaking. cargo-semver-checks has a lint for this, but
    // reading the feature set from Cargo metadata also covers the implicit
    // features it does not uniformly catch.
    if features == FeatureDelta::Removed {
        return classification(
            package,
            Bump::Major,
            "cargo-metadata",
            MinorAnalysis::PublicApi,
            "a Cargo feature was removed, which is a breaking change",
        );
    }
    if matches!(required, Some(ReleaseType::Minor)) {
        return classification(
            package,
            Bump::Minor,
            "cargo-semver-checks",
            MinorAnalysis::PublicApi,
            "cargo-semver-checks requires a minor bump",
        );
    }
    if surface == SurfaceDelta::Additive {
        return classification(
            package,
            Bump::Minor,
            "cargo-semver-checks",
            MinorAnalysis::PublicApi,
            "public-api found an added public item",
        );
    }
    if features == FeatureDelta::Added {
        return classification(
            package,
            Bump::Minor,
            "cargo-semver-checks",
            MinorAnalysis::PublicApi,
            "a Cargo feature was added",
        );
    }
    classification(
        package,
        Bump::Patch,
        "cargo-semver-checks",
        MinorAnalysis::PublicApi,
        "no public-API or feature change beyond patch",
    )
}

/// Build a [`Classification`] from its parts.
fn classification(
    package: &str,
    bump: Bump,
    breaking_analysis: &str,
    minor_analysis: MinorAnalysis,
    reason: &str,
) -> Classification {
    Classification {
        package: package.to_string(),
        bump: bump.as_str().to_string(),
        breaking_analysis: breaking_analysis.to_string(),
        minor_analysis: minor_analysis.as_str().to_string(),
        reason: reason.to_string(),
    }
}
