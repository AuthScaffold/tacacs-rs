#![doc = include_str!("../README.md")]

mod companion;
mod credentials;
mod source;

pub use companion::{Companion, CompanionContext};
pub use credentials::CredentialProvider;
pub use source::SourceBundle;
