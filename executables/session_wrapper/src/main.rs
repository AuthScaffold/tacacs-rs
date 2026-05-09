//! Platform selector for `session-wrapper`.
//!
//! The real implementation currently depends on Linux `x86_64` seccomp user
//! notifications. Other platforms compile a noop entrypoint so the workspace
//! can still build and test cross-platform while the Linux-only wrapper evolves.
#[cfg_attr(all(target_os = "linux", target_arch = "x86_64"), path = "linux.rs")]
#[cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), path = "noop.rs")]
mod platform;

/// Dispatches to the platform-specific `session-wrapper` entrypoint.
fn main() -> std::process::ExitCode {
    platform::run()
}
