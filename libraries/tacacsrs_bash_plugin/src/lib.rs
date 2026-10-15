#![doc = include_str!("../README.md")]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-bash-plugin supports Linux GNU only");

mod authorization;
#[allow(unsafe_code)]
mod c_strings;
mod config;
#[allow(unsafe_code)]
mod ffi;
#[allow(unsafe_code)]
mod logging;
mod runtime;
#[allow(unsafe_code)]
mod session;

pub use ffi::{on_shell_execve, plugin_init, plugin_uninit};
