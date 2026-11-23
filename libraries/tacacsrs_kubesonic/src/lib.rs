#![doc = include_str!("../README.md")]

#[cfg(not(all(target_os = "linux", any(target_env = "gnu", target_env = "musl"))))]
compile_error!("tacacsrs-kubesonic supports Linux GNU or musl only");

pub mod environment;
pub mod datastore;
pub mod credentials;
pub mod registration;
mod source;

pub use source::{components, KubeSonicSource, RegistrationComponent};
