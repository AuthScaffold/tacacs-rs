#![doc = include_str!("../README.md")]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-unix-socket supports Linux GNU only");

mod listener;

pub use listener::{prepare_unix_listener, UnixSocketCleanupGuard};
