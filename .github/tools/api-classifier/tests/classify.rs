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

const TOOLCHAIN: &str = "nightly-2025-11-23";
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
/// reports a missing item ID and the adapter emits a coverage warning.
fn setup_foreign_module_reexport() -> TempRepo {
    setup_with_dependency(
        "pub mod inner {\n    pub fn helper() {}\n}\n",
        "pub use dep::inner;\n",
        "pub use dep::inner;\npub fn extra() {}\n",
    )
}

fn setup_with_dependency(dependency: &str, baseline_lib: &str, current_lib: &str) -> TempRepo {
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
    write(&root.join("dep/src/lib.rs"), dependency);
    write(
        &root.join("fixture-lib/Cargo.toml"),
        "[package]\nname = \"fixture-lib\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n[dependencies]\ndep = { path = \"../dep\" }\n",
    );
    write(&root.join("fixture-lib/src/lib.rs"), baseline_lib);

    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "baseline"]);
    git(root, &["tag", BASELINE_TAG]);

    if baseline_lib != current_lib {
        write(&root.join("fixture-lib/src/lib.rs"), current_lib);
        git(root, &["add", "-A"]);
        git(root, &["commit", "-qm", "change"]);
    }

    repo
}

fn render_api(
    repo: &Path,
    document_private_items: bool,
) -> (public_api::PublicApi, serde_json::Value) {
    let target = tempfile::tempdir().unwrap();
    let mut stderr = Vec::new();
    let json_path = rustdoc_json::Builder::default()
        .toolchain(TOOLCHAIN.to_owned())
        .manifest_path(repo.join("Cargo.toml"))
        .package("fixture-lib")
        .all_features(true)
        .document_private_items(document_private_items)
        .target_dir(target.path())
        .build_with_captured_output(std::io::sink(), &mut stderr)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&stderr)));
    let api = public_api::Builder::from_rustdoc_json(&json_path)
        .build()
        .unwrap();
    let json = serde_json::from_reader(std::fs::File::open(json_path).unwrap()).unwrap();
    (api, json)
}

fn assert_external_default_is_missing(api: &public_api::PublicApi, json: &serde_json::Value) {
    let (trait_id, _) = json["paths"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, path)| path["path"] == serde_json::json!(["dep", "Wire"]))
        .expect("external trait has a path summary");
    let trait_id: u32 = trait_id.parse().unwrap();
    assert!(json["index"][trait_id.to_string()].is_null());
    assert!(api.missing_item_ids().any(|id| *id == trait_id));
    let implementation = json["index"]
        .as_object()
        .unwrap()
        .values()
        .map(|item| &item["inner"]["impl"])
        .find(|implementation| implementation["trait"]["id"] == trait_id)
        .expect("implementation is present even though its trait definition is absent");
    assert_eq!(implementation["provided_trait_methods"], serde_json::json!(["sequence"]));
    assert_eq!(implementation["items"], serde_json::json!([]));
}

fn tool_command(repo: &Path, baseline_rev: &str) -> Command {
    assert!(repo.is_absolute(), "fixture repository path must be absolute");
    let mut command = Command::new(env!("CARGO_BIN_EXE_api-classifier"));
    command
        .args(["--package", "fixture-lib", "--baseline-rev", baseline_rev])
        .arg("--manifest-path")
        .arg(repo.join("Cargo.toml"))
        .args(["--toolchain", TOOLCHAIN])
        .env("CARGO_TARGET_DIR", repo.join("target"))
        .current_dir(repo);
    command
}

fn run_tool(repo: &Path) -> Output {
    tool_command(repo, BASELINE_TAG)
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
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is one JSON object");
    assert_eq!(value["package"], "fixture-lib");
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
    assert!(!String::from_utf8_lossy(&output.stderr).contains("api-classifier: warning:"));
}

#[test]
fn tool_commands_use_distinct_fixture_targets() {
    let first = TempRepo::new();
    let second = TempRepo::new();
    let target = |command: &Command| {
        command
            .get_envs()
            .find_map(|(key, value)| {
                (key == "CARGO_TARGET_DIR").then(|| PathBuf::from(value.unwrap()))
            })
            .expect("classifier command has a target directory")
    };

    let first_target = target(&tool_command(&first.path, BASELINE_TAG));
    let second_target = target(&tool_command(&second.path, BASELINE_TAG));
    assert_eq!(first_target, first.path.join("target"));
    assert_eq!(second_target, second.path.join("target"));
    assert!(first_target.is_absolute());
    assert_ne!(first_target, second_target);
}

#[test]
fn internal_only_changes_are_patch() {
    require_toolchain();
    let repo = setup(
        "pub fn alpha() -> u8 { internal() }\nfn internal() -> u8 { 1 }\n",
        "pub fn alpha() -> u8 { replacement() }\nfn replacement() -> u8 { 2 }\n",
    );
    assert_eq!(bump_of(&run_tool(&repo.path)), "patch");
}

#[test]
fn new_public_function_is_minor() {
    require_toolchain();
    let repo = setup("pub fn alpha() {}\n", "pub fn alpha() {}\npub fn beta() {}\n");
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "minor");
}

#[test]
fn protocol_style_derived_trait_api_is_patch_with_warning() {
    require_toolchain();
    let lib = r#"
use bitflags::bitflags;
use num_enum::TryFromPrimitive;

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum PacketType { Authentication = 1, Authorization = 2 }

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Flags: u8 { const SINGLE_CONNECT = 4; }
}

pub trait Body {
    fn bytes(&self) -> Vec<u8>;
    fn length(&self) -> usize { self.bytes().len() }
}

#[derive(Debug, Clone)]
pub struct Header { pub packet_type: PacketType, pub flags: Flags, pub sequence: u8 }

impl Body for Header {
    fn bytes(&self) -> Vec<u8> { vec![self.sequence] }
}
"#;
    let repo = setup_with_features(
        lib,
        lib,
        "\n[dependencies]\nbitflags = \"=2.13.2\"\nnum_enum = \"=0.7.6\"\n",
    );
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "patch");
    assert_partial_warning(&output);
}

#[test]
fn external_definitions_only_in_current_do_not_block_an_addition() {
    require_toolchain();
    let repo =
        setup("pub fn alpha() {}\n", "pub fn alpha() {}\n#[derive(Debug)] pub struct Header;\n");
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "minor");
    assert_partial_warning(&output);
}

#[test]
fn external_definitions_only_in_baseline_do_not_override_a_detected_break() {
    require_toolchain();
    let repo =
        setup("pub fn alpha() {}\n#[derive(Debug)] pub struct Header;\n", "pub fn alpha() {}\n");
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "major");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["minor_analysis"], "not-run");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("api-classifier: warning:"));
}

#[test]
fn removed_public_function_is_major() {
    require_toolchain();
    let repo = setup("pub fn alpha() {}\npub fn beta() {}\n", "pub fn alpha() {}\n");
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "major");
}

#[test]
fn external_default_method_change_documents_the_analyzer_limit() {
    require_toolchain();
    let lib = "pub struct Header;\nimpl dep::Wire for Header {}\n";
    let repo =
        setup_with_dependency("pub trait Wire { fn sequence(&self) -> u8 { 0 } }\n", lib, lib);
    let baselines: Vec<_> = [false, true]
        .into_iter()
        .map(|private| {
            let (api, json) = render_api(&repo.path, private);
            assert_eq!(json["includes_private"], private);
            assert_external_default_is_missing(&api, &json);
            (private, api)
        })
        .collect();

    write(
        &repo.path.join("dep/src/lib.rs"),
        "pub trait Wire { fn sequence(&self) -> u16 { 0 } }\n",
    );
    git(&repo.path, &["add", "-A"]);
    git(&repo.path, &["commit", "-qm", "change inherited return type"]);

    for (private, baseline) in baselines {
        let (current, json) = render_api(&repo.path, private);
        assert_external_default_is_missing(&current, &json);
        let diff = public_api::diff::PublicApiDiff::between(baseline, current);
        assert!(diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty());
    }
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "patch");
    assert_partial_warning(&output);
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
    let output = tool_command(&repo.path, "no-such-tag")
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
fn external_definitions_do_not_hide_a_detected_signature_change() {
    require_toolchain();
    let repo = setup_with_dependency(
        "pub mod inner { pub fn helper() {} }\n",
        "pub use dep::inner;\npub fn accept(_value: u8) {}\n",
        "pub use dep::inner;\npub fn accept(_value: u16) {}\n",
    );
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "major");
    assert_partial_warning(&output);
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
fn foreign_module_reexport_does_not_hide_a_detected_addition() {
    require_toolchain();
    let repo = setup_foreign_module_reexport();
    let output = run_tool(&repo.path);
    assert_eq!(bump_of(&output), "minor");
    assert_partial_warning(&output);
}

fn assert_partial_warning(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.matches("api-classifier: warning:").count(), 1, "{stderr}");
    assert!(stderr.contains("`fixture-lib`"), "{stderr}");
    assert!(stderr.contains("omits external definitions"), "{stderr}");
}
