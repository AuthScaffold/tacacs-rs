#[cfg(not(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64")))]
compile_error!("session-wrapper supports Linux GNU x86-64 only");

#[cfg(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64"))]
#[path = "linux.rs"]
mod platform;

/// Runs the Linux `session-wrapper` entrypoint.
#[cfg(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64"))]
fn main() -> std::process::ExitCode {
    platform::run()
}

#[cfg(not(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64")))]
fn main() {}
