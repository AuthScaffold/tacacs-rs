//! A detached Git worktree for rendering the baseline.
//!
//! The surface analysis and the feature analysis both compare the current
//! checkout against the baseline revision. They share one detached worktree so
//! the baseline is checked out exactly once per classification, and the working
//! tree is never modified.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tempfile::TempDir;

/// Return the top-level directory of the Git repository holding `path`.
pub fn git_toplevel(path: &Path) -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(path)
        .output()
        .context("running `git rev-parse --show-toplevel`")?;
    if !output.status.success() {
        bail!(
            "`git rev-parse --show-toplevel` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let top = String::from_utf8(output.stdout)
        .context("git top-level path is not valid UTF-8")?
        .trim()
        .to_string();
    Ok(PathBuf::from(top))
}

/// A detached Git worktree created inside an owned temporary directory.
///
/// The worktree is a nonexistent child of a freshly created temporary
/// directory, so `git worktree add` creates it and this type never deletes a
/// pre-existing path it did not create. On drop it deregisters the worktree,
/// then the owned temporary directory removes the files.
pub struct TempWorktree {
    repo_root: PathBuf,
    path: PathBuf,
    _dir: TempDir,
}

impl TempWorktree {
    /// Check out `revision` into a fresh detached worktree.
    pub fn add(repo_root: &Path, revision: &str) -> Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("api-classifier-worktree-")
            .tempdir()
            .context("creating a temporary worktree directory")?;
        // `git worktree add` requires a path that does not yet exist, so target
        // a child of the owned temporary directory. The tool therefore never
        // removes a pre-existing directory it did not create.
        let path = dir.path().join("baseline");
        let output = Command::new("git")
            .args(["worktree", "add", "--detach"])
            .arg(&path)
            .arg(revision)
            .current_dir(repo_root)
            .output()
            .context("running `git worktree add`")?;
        if !output.status.success() {
            bail!(
                "`git worktree add {revision}` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(Self {
            repo_root: repo_root.to_path_buf(),
            path,
            _dir: dir,
        })
    }

    /// The checked-out worktree root.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempWorktree {
    fn drop(&mut self) {
        // Deregister the worktree. The owned temporary directory removes the
        // files when `_dir` drops immediately after this.
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force"])
            .arg(&self.path)
            .current_dir(&self.repo_root)
            .output();
    }
}
