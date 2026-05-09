//! Noop platform backend for non-Linux targets.
//!
//! This keeps the crate present in the workspace on macOS/Windows without
//! pretending that seccomp-based session mediation is available there.
use std::process::ExitCode;

/// Returns success on platforms where the real wrapper is not compiled.
pub(crate) fn run() -> ExitCode {
    ExitCode::SUCCESS
}
