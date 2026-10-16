//! Normalizes parsed CLI inputs and credential files into canonical YANG snapshots.
//!
//! This module has no clap dependency. It converts raw executable inputs
//! ([`CliDatastoreInput`]) and credential files into a validated
//! [`crate::TacacsPlus`] snapshot through the canonical builders and validation
//! rules. These inputs are adapters into the canonical model, not a second
//! desired-configuration schema.
//!
//! The normalized snapshot then flows through the rest of the crate:
//!
//! ```text
//! input (normalize)  ->  parse / enumerate  ->  resolve  ->  materialize  ->  prepare
//! ```
//!
//! The file-backed observation backend that watches these inputs lives in
//! [`crate::source::CliFileDatastore`], not here.
#![allow(clippy::doc_markdown)]

mod address;
mod builder;
mod files;
mod model;

pub use address::parse_host_port;
pub use builder::{tacacs_plus_from_cli_input, tacacs_plus_from_file, tacacs_plus_from_str};
pub use files::{
    load_client_certificate, load_client_private_key, normalize_cli_certificate_data,
    ClientCertificateChain, normalize_cli_private_key_data,
};
pub use model::{
    CertKeyIdentity, CliConfigSource, CliDatastoreInput, CliSecurity, CliSecurityInputs,
    CliSecurityMode, CliServerInput, PskKeyExchangeMode, PskKeyMaterial, TlsServerName,
};
pub use model::CliPskInputs;
