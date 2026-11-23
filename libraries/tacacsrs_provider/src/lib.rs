#![doc = include_str!("../README.md")]

mod credentials;
mod source;

pub use credentials::CredentialProvider;
pub use source::{SourceBundle, SourceDatastore};
