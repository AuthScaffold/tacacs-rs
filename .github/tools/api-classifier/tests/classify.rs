//! End-to-end tests for the `api-classifier` binary.
//!
//! Each test builds a throwaway crate inside a temporary Git repository, tags a
//! baseline, changes the public API, and runs the compiled binary. The tests
//! assert the printed classification and the fail-closed behavior.
//!
//! The tests need the pinned rustdoc toolchain. They do not skip when it is
//! missing: they fail with a clear prerequisite message instead, because a
//! silent skip would hide a real regression. The compute-versions GitHub Action
//! installs the toolchain before it runs the classifier.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const TOOLCHAIN: &str = "nightly-2025-08-02";
const BASELINE_TAG: &str = "fixture-lib-v1.0.0";

fn toolchain_available() -> bool {
    Command::new("rustup")
        .args(["run", TOOLCHAIN, "rustc", "--version"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Fail the test with an actionable prerequisite when the toolchain is missing.
///
/// The suite must never silently skip: a skipped classifier test would pass CI
/// while hiding a regression. CI installs the toolchain, so a failure here means
/// a genuinely missing prerequisite.
fn require_toolchain() {
    assert!(
        toolchain_available(),
        "prerequisite missing: the pinned rustdoc toolchain `{TOOLCHAIN}` is not \
         installed. Install it with `rustup toolchain install {TOOLCHAIN} --profile \
         minimal`. CI's compute-versions action installs it automatically.",
    );
}

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn unique() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// A temporary directory removed on drop.
struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "api-classifier-it-{}-{}",
            std::process::id(),
            unique()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Build a repository whose baseline tag holds `baseline_lib` and whose HEAD
/// holds `current_lib`.
fn setup(baseline_lib: &str, current_lib: &str) -> TempRepo {
    setup_with_features(baseline_lib, current_lib, "")
}

/// Like [`setup`], but appends raw `[features]` manifest text, for example
/// `"\n[features]\nextra = []\n"`.
fn setup_with_features(baseline_lib: &str, current_lib: &str, features: &str) -> TempRepo {
    let repo = TempRepo::new();
    let root = &repo.path;

    write(
        &root.join("Cargo.toml"),
        &format!(
            "[workspace]\n\n[package]\nname = \"fixture-lib\"\nversion = \"1.0.0\"\nedition = \"2021\"\n{features}"
        ),
    );
    write(&root.join("src/lib.rs"), baseline_lib);

    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "baseline"]);
    git(root, &["tag", BASELINE_TAG]);

    if current_lib != baseline_lib {
        write(&root.join("src/lib.rs"), current_lib);
        git(root, &["add", "-A"]);
        git(root, &["commit", "-qm", "change"]);
    }

    repo
}

/// Build a repository whose baseline and current share identical source and
/// differ only in the manifest `[features]` text. Each argument is raw manifest
/// text appended after the package table, for example
/// `"\n[features]\nextra = []\n"`. The manifest always changes, so the current
/// state is committed unconditionally.
fn setup_feature_change(baseline_features: &str, current_features: &str) -> TempRepo {
    let repo = TempRepo::new();
    let root = &repo.path;
    let lib = "pub fn alpha() {}\n";
    let manifest = |features: &str| {
        format!(
            "[workspace]\n\n[package]\nname = \"fixture-lib\"\nversion = \"1.0.0\"\nedition = \"2021\"\n{features}"
        )
    };

    write(&root.join("Cargo.toml"), &manifest(baseline_features));
    write(&root.join("src/lib.rs"), lib);
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "baseline"]);
    git(root, &["tag", BASELINE_TAG]);

    write(&root.join("Cargo.toml"), &manifest(current_features));
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "change"]);

    repo
}

/// Build a workspace where `fixture-lib` re-exports a whole foreign module from
/// a path dependency. rustdoc cannot inline the foreign module, so `public-api`
/// reports a missing item ID and the adapter must fail closed.
fn setup_foreign_module_reexport() -> TempRepo {
    let repo = TempRepo::new();
    let root = &repo.path;

    write(
        &root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"dep\", \"fixture-lib\"]\nresolver = \"2\"\n",
    );
    write(
        &root.join("dep/Cargo.toml"),
        "[package]\nname = \"dep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
    );
    write(&root.join("dep/src/lib.rs"), "pub mod inner {\n    pub fn helper() {}\n}\n");
    write(
        &root.join("fixture-lib/Cargo.toml"),
        "[package]\nname = \"fixture-lib\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n[dependencies]\ndep = { path = \"../dep\" }\n",
    );
    write(&root.join("fixture-lib/src/lib.rs"), "pub use dep::inner;\n");

    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "baseline"]);
    git(root, &["tag", BASELINE_TAG]);

    // Add an item so there is a current-vs-baseline diff to classify.
    write(&root.join("fixture-lib/src/lib.rs"), "pub use dep::inner;\npub fn extra() {}\n");
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "change"]);

    repo
}

fn run_tool(repo: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_api-classifier"))
        .args(["--package", "fixture-lib", "--baseline-rev", BASELINE_TAG])
        .arg("--manifest-path")
        .arg(repo.join("Cargo.toml"))
        .args(["--toolchain", TOOLCHAIN])
        .current_dir(repo)
        .output()
        .expect("run api-classifier")
}

fn bump_of(output: &Output) -> String {
    assert!(
        output.status.success(),
        "api-classifier failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().last().expect("a JSON line on stdout");
    let value: serde_json::Value = serde_json::from_str(line).expect("stdout is valid JSON");
    value["bump"]
        .as_str()
        .expect("bump field is a string")
        .to_string()
}

#[test]
fn unchanged_api_is_patch() {
    require_toolchain();
    let lib = "pub fn alpha() {}\n";
    let repo = setup(lib, lib);
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "patch");
}

#[test]
fn new_public_function_is_minor() {
    require_toolchain();
    let repo = setup("pub fn alpha() {}\n", "pub fn alpha() {}\npub fn beta() {}\n");
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "minor");
}

#[test]
fn removed_public_function_is_major() {
    require_toolchain();
    let repo = setup("pub fn alpha() {}\npub fn beta() {}\n", "pub fn alpha() {}\n");
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "major");
}

#[test]
fn broken_current_build_fails_closed() {
    require_toolchain();
    // The current source does not compile, so the breaking-change engine cannot
    // complete. The tool must exit non-zero and print no JSON to standard
    // output, so the caller never mistakes the failure for a bump.
    let repo = setup("pub fn alpha() {}\n", "pub fn alpha( {\n");
    let output = run_tool(&repo.path);
    assert!(!output.status.success(), "expected a non-zero exit for a broken build");
    assert!(
        output.stdout.is_empty(),
        "expected no JSON on stdout, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn addition_behind_non_default_feature_is_minor() {
    require_toolchain();
    // The new function is gated behind a non-default feature. Because both
    // engines analyze all features, the new item is part of the analyzed
    // surface and the change is a minor bump, not a patch.
    let repo = setup_with_features(
        "pub fn alpha() {}\n",
        "pub fn alpha() {}\n#[cfg(feature = \"extra\")]\npub fn beta() {}\n",
        "\n[features]\nextra = []\n",
    );
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "minor");
}

#[test]
fn missing_baseline_revision_fails_closed() {
    require_toolchain();
    // The baseline tag does not exist, so the breaking-change engine cannot
    // render the baseline API. The tool must exit non-zero and print no JSON, so
    // the caller never mistakes the failure for a bump.
    let lib = "pub fn alpha() {}\n";
    let repo = setup(lib, lib);
    let output = Command::new(env!("CARGO_BIN_EXE_api-classifier"))
        .args(["--package", "fixture-lib", "--baseline-rev", "no-such-tag"])
        .arg("--manifest-path")
        .arg(repo.path.join("Cargo.toml"))
        .args(["--toolchain", TOOLCHAIN])
        .current_dir(&repo.path)
        .output()
        .expect("run api-classifier");
    assert!(!output.status.success(), "expected a non-zero exit for a missing baseline");
    assert!(
        output.stdout.is_empty(),
        "expected no JSON on stdout, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn changed_parameter_type_is_major() {
    require_toolchain();
    // This pinned `cargo-semver-checks` has no lint for a changed free-function
    // parameter type, so it reports no required bump. `public-api` sees the
    // function as changed (same path, different signature), which is a breaking
    // surface change. The adapter must report major, not a silent patch.
    let repo = setup("pub fn accept(_x: u8) {}\n", "pub fn accept(_x: u16) {}\n");
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "major");
}

#[test]
fn added_feature_is_minor() {
    require_toolchain();
    // Only a feature label is added; no Rust item changes. `cargo-semver-checks`
    // does not flag an added feature, so the Cargo-metadata feature analysis
    // must raise the result to minor.
    let repo = setup_feature_change("", "\n[features]\nextra = []\n");
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "minor");
}

#[test]
fn removed_feature_is_major() {
    require_toolchain();
    // Removing a feature is a breaking change. The result must be major.
    let repo = setup_feature_change("\n[features]\nextra = []\n", "");
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "major");
}

#[test]
fn foreign_module_reexport_fails_closed() {
    require_toolchain();
    // Re-exporting a whole foreign module leaves referenced items missing from
    // the rustdoc JSON, so the surface diff is incomplete. The adapter must fail
    // closed with no JSON on standard output rather than risk a too-low bump.
    let repo = setup_foreign_module_reexport();
    let output = run_tool(&repo.path);
    assert!(!output.status.success(), "expected a non-zero exit for an incomplete surface");
    assert!(
        output.stdout.is_empty(),
        "expected no JSON on stdout, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("incomplete"), "expected an incomplete-surface message, got: {stderr}");
}
