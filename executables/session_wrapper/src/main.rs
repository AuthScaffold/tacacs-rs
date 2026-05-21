//! Entry point for `session-wrapper`.
//!
//! Portable CLI, policy, and authorization logic is compiled on every target.
//! The process mediation backend is selected through the platform abstraction
//! layer in [`pal`]: Linux `x86_64` uses seccomp user notifications, while
//! unsupported platforms use an explicit mock backend for developer workflows.
#[cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(dead_code))]
mod allowlist;
mod app;
#[cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(dead_code))]
mod authorization;
mod cli;
#[cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(dead_code))]
mod deny;
mod pal;

/// Dispatches to the `session-wrapper` application entrypoint.
fn main() -> std::process::ExitCode {
    app::run()
}
