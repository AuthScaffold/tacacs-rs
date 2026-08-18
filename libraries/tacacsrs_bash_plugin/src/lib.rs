#![doc = include_str!("../README.md")]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-bash-plugin supports Linux GNU only");

mod authorization;
mod c_strings;
mod config;
mod ffi;
mod logging;
mod runtime;
mod session;

pub use ffi::{on_shell_execve, plugin_init, plugin_uninit};
