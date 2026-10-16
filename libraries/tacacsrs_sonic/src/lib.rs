#![doc = include_str!("../README.md")]
#![allow(clippy::doc_markdown, clippy::ignored_unit_patterns)]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-sonic supports Linux GNU only");

mod datastore;
pub mod mapping;
mod provider;
pub mod store;

pub use datastore::SonicConfigDb;
pub use mapping::{
    SonicForwarderSettings, SonicHash, SonicTacacsTables, map_sonic_tables_to_tacacs_plus,
    sonic_server_name,
};
pub use provider::{
    SonicCredentialInitializationError, SonicCredentialPolicy, SonicCredentialResolver,
    SonicCredentialRoots,
};
pub use store::{
    DEFAULT_REDIS_URL, SonicConnection, TACPLUS_FORWARDER_TABLE, TACPLUS_GLOBAL_TABLE,
    SonicCredentialChangeSource, TACPLUS_SERVER_TABLE, TACPLUS_SERVER_TLS_TABLE,
    read_tacacs_tables, watch_credential_changes,
};
