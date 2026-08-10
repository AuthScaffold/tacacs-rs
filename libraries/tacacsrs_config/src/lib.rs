pub mod generated;
mod central_references;
pub mod extensions;
pub mod builders;
pub mod validation;
mod enumeration;
mod mapping;
pub(crate) mod serde_helpers;
mod statistics;

pub use enumeration::{enumerate_server, enumerate_servers, validate_credential_references};
pub use central_references::{
    CentralCredentialReference, CentralCredentialSlot, CentralCredentialUsage,
    EnumerationRequiredError, UnexpandedCredentialField, inspect_central_references,
};
pub use validation::{ValidationOptions, ValidationRelaxation};

// Re-export key types from generated module for convenience
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

pub use statistics::ServerStatistics;

/// Model-oriented API: YANG-generated types and related namespaces.
pub mod model {
    pub use crate::builders::{TacacsPlusBuilder, TacacsPlusServerBuilder};
    pub use crate::extensions::TacacsPlusServerExt;
    pub use crate::generated;
    pub use crate::generated::tacacs_plus::{
        ClientCredentials, ClientIdentityCertificate, EpskSupportedHash,
        ServerAuthenticationCaCerts, ServerCredentials, TacacsPlus, TacacsPlusServer,
        TacacsPlusServerType, Tls13Epsk, TlsClientClientIdentity, TlsClientServerAuthentication,
    };
    pub use crate::generated::{crypto_types, keystore, tacacsrs, truststore, YangConfigRoot};
    pub use crate::generated::tacacsrs::PskDheKeSupportedGroup;
    pub use crate::validation::{ValidationOptions, ValidationRelaxation};
}

/// Step-by-step processing API for custom parse/validate flows.
pub mod pipeline {
    use std::collections::BTreeSet;
    use std::path::Path;

    use anyhow::bail;

    use crate::generated::YangConfigRoot;

    /// Parse RFC 7951 JSON into the root generated model without applying
    /// credential resolution or validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or does not match the model.
    pub fn parse_root_json(json: &str) -> anyhow::Result<YangConfigRoot> {
        let mut deserializer = serde_json::Deserializer::from_str(json);
        let mut ignored_paths = BTreeSet::new();

        let root = serde_ignored::deserialize(&mut deserializer, |path| {
            ignored_paths.insert(path.to_string());
        })
        .map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;

        if !ignored_paths.is_empty() {
            let paths = ignored_paths.into_iter().collect::<Vec<_>>().join(", ");
            bail!("failed to parse config: unknown field(s): {paths}");
        }

        Ok(root)
    }

    /// Read and parse RFC 7951 JSON from a file into the root generated model
    /// without applying credential resolution or validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, or if the JSON is malformed
    /// or does not match the model.
    pub fn parse_root_json_file(path: &Path) -> anyhow::Result<YangConfigRoot> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config file {}: {e}", path.display()))?;

        parse_root_json(&contents)
    }
}

/// Per-server enumeration API used before credential materialization.
pub mod runtime {
    pub use crate::central_references::{
        CentralCredentialReference, CentralCredentialSlot, CentralCredentialUsage,
        EnumerationRequiredError, UnexpandedCredentialField, inspect_central_references,
    };
    pub use crate::enumeration::{enumerate_server, enumerate_servers};
    pub use crate::builders::{TacacsPlusBuilder, TacacsPlusServerBuilder};
    pub use crate::extensions::TacacsPlusServerExt;
}

/// Runtime statistics types.
pub mod stats {
    pub use crate::statistics::ServerStatistics;
}

/// Parse a YANG JSON configuration string and validate it.
///
/// This is the standard API for loading YANG config. The config is parsed, validated
/// for schema constraints, and returned without any mutations. The returned config
/// preserves the exact submitted structure, including any credential references.
/// This enables round-tripping, reporting, and safe credential resolution.
///
/// Validation checks include:
/// - At least one server is configured
/// - Server addresses and ports are unique
/// - SNI-enabled servers have domain names
/// - Security configuration is present and valid
/// - Credential bundle references have matching definitions
///
/// The returned config preserves the submitted structure, including any
/// credential references.
/// To inline shared `client-credentials` / `server-credentials` bundles for
/// per-server processing, call [`enumerate_servers`] or [`enumerate_server`].
///
/// # Errors
///
/// Returns an error if:
/// - The JSON is malformed or does not match the YANG schema
/// - Validation constraints are violated
pub fn parse_yang_json(json: &str) -> anyhow::Result<TacacsPlus> {
    parse_yang_json_with_options(json, &ValidationOptions::default())
}

/// Parse a YANG JSON configuration string with the supplied validation options.
///
/// Behaves identically to [`parse_yang_json`] except that the supplied
/// [`ValidationOptions`] are applied during validation, allowing callers to
/// opt into specific [`ValidationRelaxation`]s.
///
/// # Errors
///
/// Returns an error if:
/// - The JSON is malformed or does not match the YANG schema
/// - Validation constraints are violated (subject to `options`)
pub fn parse_yang_json_with_options(
    json: &str,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlus> {
    let root: YangConfigRoot = pipeline::parse_root_json(json)?;

    let config = root.tacacs_plus;
    validation::validate_config_with_options(&config, options)?;

    Ok(config)
}

/// Parse a YANG JSON config file using the same non-mutating flow as `parse_yang_json`.
///
/// This is a first-class entry point for file-based callers. The file contents
/// are parsed and validated with the same behavior as `parse_yang_json`: the
/// returned config preserves the exact submitted structure, including any
/// credential references.
///
/// Validation checks include:
/// - At least one server is configured
/// - Server addresses and ports are unique
/// - SNI-enabled servers have domain names
/// - Security configuration is present and valid
/// - Credential bundle references have matching definitions
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The JSON is malformed or does not match the YANG schema
/// - Validation constraints are violated
pub fn parse_yang_json_file(path: &std::path::Path) -> anyhow::Result<TacacsPlus> {
    parse_yang_json_file_with_options(path, &ValidationOptions::default())
}

/// Parse a YANG JSON config file with the supplied validation options.
///
/// Behaves identically to [`parse_yang_json_file`] except that the supplied
/// [`ValidationOptions`] are applied during validation, allowing callers to
/// opt into specific [`ValidationRelaxation`]s.
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The JSON is malformed or does not match the YANG schema
/// - Validation constraints are violated (subject to `options`)
pub fn parse_yang_json_file_with_options(
    path: &std::path::Path,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlus> {
    let root: YangConfigRoot = pipeline::parse_root_json_file(path)?;

    let config = root.tacacs_plus;
    validation::validate_config_with_options(&config, options)?;

    Ok(config)
}
