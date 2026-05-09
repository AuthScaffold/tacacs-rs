//! Fast-path exec authorization via a local allowlist.
//!
//! # Why an allowlist?
//!
//! Every `execve`/`execveat` system call in the wrapped session triggers a
//! seccomp user notification that pauses the target process until the supervisor
//! responds. For commands that are definitively safe (shells, basic utilities
//! bash invokes internally), waiting for a round-trip to the TACACS+ agent adds
//! latency without meaningful security benefit.
//!
//! The allowlist provides an O(1) short-circuit: if the executable path is in
//! the set, the supervisor immediately responds with "continue" and never
//! contacts the agent.
//!
//! # Security scope
//!
//! The allowlist is a **trust-by-path** mechanism. It does **not** verify file
//! integrity (no hash checking). Entries should be limited to paths that:
//!
//! 1. Are owned by root and not writable by the session user.
//! 2. Are utilities so fundamental that denying them would break basic shell
//!    operation (e.g. `/bin/bash` when bash is the configured shell).
//!
//! # File format
//!
//! The optional user-supplied config file contains one absolute path per line.
//! Blank lines and lines beginning with `#` are ignored.
//!
//! ```text
//! # Allow additional vendor utilities
//! /opt/vendor/bin/helper
//! /opt/vendor/bin/status
//! ```
//!
//! Built-in defaults are always active and cannot be removed via the config
//! file.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

/// Paths that are always permitted to execute, regardless of TACACS+ policy.
///
/// These entries exist because bash (and compatible shells) `exec` these
/// binaries as part of ordinary shell operation — for example, to check the
/// current user identity, resolve command paths, or launch sub-shells. Denying
/// them would make an interactive session unusable before any real command runs.
///
/// Keep this list **minimal**. Every entry is a potential bypass if the binary
/// at that path can be manipulated.
const BUILTIN_PATHS: &[&str] = &[
    // The shell itself. Without this, `bash` forking a sub-shell would trigger
    // an authorization round-trip for every subshell invocation.
    "/bin/bash",
    // POSIX-mandated `sh` location, often a symlink to bash or dash.
    "/bin/sh",
    // bash uses env(1) for the `env` builtin and for shebang lines like
    // `#!/usr/bin/env python3`.
    "/usr/bin/env",
    // Shells check user/group identity at startup (PS1 construction, etc.).
    "/usr/bin/id",
    "/usr/bin/groups",
    // Common `sh` locations on Debian/Ubuntu (dash is the default /bin/sh).
    "/usr/bin/dash",
    "/bin/dash",
    // bash completion and prompts commonly run `uname` for PS1 decoration.
    "/bin/uname",
    "/usr/bin/uname",
    // Needed for `type`, `command -v`, and shebang resolution.
    "/usr/bin/which",
    // tty/stty are checked by interactive login shells.
    "/usr/bin/tty",
    "/bin/stty",
    "/usr/bin/stty",
];

/// Fast-path lookup table for exec authorization.
///
/// Backed by a [`HashSet`] for O(1) average-case membership tests. The set
/// is built once at startup and treated as immutable for the lifetime of the
/// session.
///
/// # Construction
///
/// Use [`Allowlist::default_only`] when no config file is provided, or
/// [`Allowlist::load`] to merge a user-supplied file with the built-in
/// defaults.
#[derive(Debug)]
pub(crate) struct Allowlist {
    /// Union of built-in paths and any user-supplied paths.
    paths: HashSet<String>,
}

impl Allowlist {
    /// Builds an allowlist containing only the built-in default paths.
    ///
    /// This is the fallback when the operator has not supplied a config file.
    pub(crate) fn default_only() -> Self {
        let paths = BUILTIN_PATHS.iter().map(|&s| s.to_owned()).collect();
        Self { paths }
    }

    /// Builds an allowlist by merging the built-in defaults with paths read
    /// from `config_path`.
    ///
    /// # File format
    ///
    /// Each line is an absolute path. Lines beginning with `#` and blank lines
    /// are ignored. Paths are not validated — if an entry does not match an
    /// actual file, it is simply never matched.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read. Individual malformed lines
    /// are silently skipped (they are non-absolute paths after trimming).
    pub(crate) fn load(config_path: &Path) -> Result<Self> {
        let mut allowlist = Self::default_only();

        let content = fs::read_to_string(config_path)
            .with_context(|| format!("failed to read allowlist from {}", config_path.display()))?;

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip blank lines and comment lines.
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Only accept absolute paths to prevent relative-path confusion.
            if !trimmed.starts_with('/') {
                log::warn!(
                    "allowlist: skipping non-absolute path: {trimmed:?} (from {})",
                    config_path.display()
                );
                continue;
            }

            allowlist.paths.insert(trimmed.to_owned());
        }

        log::debug!(
            "allowlist loaded {} entries from {} (including {} built-in defaults)",
            allowlist.paths.len(),
            config_path.display(),
            BUILTIN_PATHS.len(),
        );

        Ok(allowlist)
    }

    /// Returns `true` if `path` is on the allowlist and should be permitted
    /// to execute without a TACACS+ authorization round-trip.
    ///
    /// The lookup is O(1) average-case (hash table). The path is matched
    /// exactly — no glob expansion, no symlink resolution.
    pub(crate) fn is_allowed(&self, path: &str) -> bool {
        self.paths.contains(path)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::{Allowlist, BUILTIN_PATHS};

    // ── default_only ────────────────────────────────────────────────────────

    #[test]
    fn default_only_contains_all_builtin_paths() {
        let al = Allowlist::default_only();
        for path in BUILTIN_PATHS {
            assert!(
                al.is_allowed(path),
                "built-in path {path:?} should be in the default allowlist"
            );
        }
    }

    #[test]
    fn default_only_rejects_arbitrary_path() {
        let al = Allowlist::default_only();
        assert!(!al.is_allowed("/usr/bin/vim"), "arbitrary path should not match");
        assert!(!al.is_allowed(""), "empty string should not match");
        assert!(!al.is_allowed("/"), "root should not match");
    }

    // ── load ────────────────────────────────────────────────────────────────

    #[test]
    fn load_adds_paths_from_file() {
        let mut tmp = NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "/usr/local/bin/my-tool").expect("write");
        writeln!(tmp, "/opt/vendor/helper").expect("write");

        let al = Allowlist::load(tmp.path()).expect("load should succeed");

        assert!(al.is_allowed("/usr/local/bin/my-tool"), "user entry should match");
        assert!(al.is_allowed("/opt/vendor/helper"), "second user entry should match");
    }

    #[test]
    fn load_preserves_builtin_defaults() {
        let mut tmp = NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "/custom/path").expect("write");

        let al = Allowlist::load(tmp.path()).expect("load should succeed");

        for path in BUILTIN_PATHS {
            assert!(al.is_allowed(path), "builtin {path:?} must survive loading a config file");
        }
    }

    #[test]
    fn load_ignores_comments_and_blank_lines() {
        let mut tmp = NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "# This is a comment").expect("write");
        writeln!(tmp).expect("write");
        writeln!(tmp, "   ").expect("write");
        writeln!(tmp, "/valid/path").expect("write");
        writeln!(tmp, "# another comment").expect("write");

        let al = Allowlist::load(tmp.path()).expect("load should succeed");

        assert!(al.is_allowed("/valid/path"), "valid path should be allowed");
        assert!(!al.is_allowed("# This is a comment"), "comment line must not be a path entry");
    }

    #[test]
    fn load_skips_relative_paths() {
        let mut tmp = NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "relative/path").expect("write");
        writeln!(tmp, "./also-relative").expect("write");
        writeln!(tmp, "/absolute/path").expect("write");

        let al = Allowlist::load(tmp.path()).expect("load should succeed");

        assert!(!al.is_allowed("relative/path"), "relative path must be skipped");
        assert!(!al.is_allowed("./also-relative"), "dot-relative path must be skipped");
        assert!(al.is_allowed("/absolute/path"), "absolute path must be allowed");
    }

    #[test]
    fn load_returns_error_for_missing_file() {
        let result = Allowlist::load(std::path::Path::new("/nonexistent/path/to/allowlist"));
        assert!(result.is_err(), "missing file should return an error");
    }

    // ── is_allowed ──────────────────────────────────────────────────────────

    #[test]
    fn is_allowed_is_case_sensitive() {
        let al = Allowlist::default_only();
        // Built-in paths are all lowercase; capitalized variant must not match.
        assert!(!al.is_allowed("/Bin/Bash"), "lookup must be case-sensitive");
    }

    #[test]
    fn is_allowed_requires_exact_match() {
        let al = Allowlist::default_only();
        // Prefix and suffix must not match.
        assert!(!al.is_allowed("/bin/bash "), "trailing space must not match");
        assert!(!al.is_allowed("/bin/bash/extra"), "sub-path must not match");
        assert!(!al.is_allowed("/bin"), "parent directory must not match");
    }
}
