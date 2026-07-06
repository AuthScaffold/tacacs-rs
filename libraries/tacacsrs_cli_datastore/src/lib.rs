#![doc = include_str!("../README.md")]
#![allow(clippy::doc_markdown)]

mod address;
mod builder;
mod datastore;
mod files;
mod model;

pub use address::parse_host_port;
pub use builder::{tacacs_plus_from_cli_input, tacacs_plus_from_file, tacacs_plus_from_str};
pub use datastore::CliFileDatastore;
pub use files::{
    load_client_certificate, load_client_private_key, normalize_cli_certificate_data,
    normalize_cli_private_key_data,
};
pub use model::{
    CertKeyIdentity, CliConfigSource, CliDatastoreInput, CliSecurity, CliSecurityInputs,
    CliSecurityMode, CliServerInput, PskKeyExchangeMode, PskKeyMaterial, TlsServerName,
};
pub use model::CliPskInputs;
