#![doc = include_str!("../README.md")]
#![allow(clippy::missing_safety_doc)]

mod authorization;
mod c_strings;
mod config;
mod ffi;
mod logging;
mod runtime;
mod session;

pub use ffi::{on_shell_execve, plugin_init, plugin_uninit};
