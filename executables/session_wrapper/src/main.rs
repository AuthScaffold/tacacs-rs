#[cfg_attr(all(target_os = "linux", target_arch = "x86_64"), path = "linux.rs")]
#[cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), path = "noop.rs")]
mod platform;

fn main() -> std::process::ExitCode {
    platform::run()
}
