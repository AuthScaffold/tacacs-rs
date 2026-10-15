//! Canonical YANG configuration toolkit for TACACS+.
//!
//! This crate owns the authoritative configuration model for the
//! `ietf-system-tacacs-plus` YANG module and the derived preparation pipeline.
//! A derived value never becomes a second source of truth. Configuration flows
//! in one direction:
//!
//! ```text
//! canonical  ->  enumerate  ->  resolve  ->  materialize  ->  prepare
//! ```
//!
//! - Parse RFC 7951 JSON into the validated canonical [`TacacsPlus`] model with
//!   [`parse_yang_json`]. [`parse_root_json`] returns the raw model without
//!   validation for round trips and reports.
//! - [`enumerate_servers`] inlines shared credential bundles onto each server.
//! - A credential resolver resolves central references at the provider boundary,
//!   for example the `SONiC` or HTTP adapter crates.
//! - [`prepare`] materializes a closed plan and projects native endpoints.
//!
//! # Module map
//!
//! - [`generated`]: RFC 7951 / YANG generated types. Do not edit by hand.
//! - [`input`]: normalize raw CLI flags and credential files into canonical snapshots.
//! - [`source`]: observation contracts and their backends (static, file, host adapters).
//! - [`prepare`]: derive native runtime endpoints from canonical configuration.
//! - [`validation`], [`builders`], [`extensions`]: validate and construct canonical values.
//! - [`policy`], [`local_services`], [`proxy_policy`]: parse and prepare the runtime-policy,
//!   local-service, and proxy resources.
//!
//! Most callers use the curated crate-root exports. The grouped modules remain
//! available for advanced integrations.

pub mod generated;
pub mod source;
pub mod input;
mod central_references;
pub mod extensions;
pub mod builders;
pub mod validation;
pub mod prepare;
pub mod policy;
pub mod local_services;
pub mod proxy_policy;
mod enumeration;
mod parse;
pub(crate) mod serde_helpers;
mod statistics;

pub use parse::{
    parse_root_json, parse_root_json_file, parse_yang_json, parse_yang_json_file,
    parse_yang_json_file_with_options, parse_yang_json_with_options,
};
pub use enumeration::{enumerate_server, enumerate_servers, validate_credential_references};
pub use central_references::{
    CentralCredentialReference, CentralCredentialSlot, CentralCredentialUsage,
    EnumerationRequiredError, UnexpandedCredentialField, inspect_central_references,
};
pub use validation::{ValidationOptions, ValidationRelaxation};

// Re-export the main generated types.
pub use generated::tacacs_plus::{
    ClientCredentials, ClientIdentityCertificate, EpskSupportedHash, ServerAuthenticationCaCerts,
    ServerCredentials, TacacsPlus, TacacsPlusServer, TacacsPlusServerType, Tls13Epsk,
    TlsClientClientIdentity, TlsClientServerAuthentication,
};
pub use builders::{TacacsPlusBuilder, TacacsPlusServerBuilder};
pub use extensions::TacacsPlusServerExt;
pub use generated::truststore;
pub use generated::tacacsrs;
pub use generated::tacacsrs::PskDheKeSupportedGroup;
pub use generated::{crypto_types, keystore, YangConfigRoot};

pub use statistics::{ServerStatistics, ServerOperationalStatistics, OperationalStatistics};
pub use serde_helpers::YangEmpty;
