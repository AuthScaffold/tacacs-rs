#![doc = include_str!("../README.md")]

#[cfg(not(all(target_os = "linux", any(target_env = "gnu", target_env = "musl"))))]
compile_error!("tacacsrs-unix-socket supports Linux GNU or musl only");

mod listener;

pub use listener::{prepare_unix_listener, UnixSocketCleanupGuard};
