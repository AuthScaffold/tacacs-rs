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

pub use statistics::ServerStatistics;

/// Provides YANG-generated types and related namespaces.
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

/// Provides separate parsing steps for custom processing flows.
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
        .map_err(|e| anyhow::anyhow!("failed to parse configuration: {e}"))?;

        if !ignored_paths.is_empty() {
            let paths = ignored_paths.into_iter().collect::<Vec<_>>().join(", ");
            bail!("failed to parse configuration: unknown field(s): {paths}");
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
        let contents = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("failed to read configuration file {}: {e}", path.display())
        })?;

        parse_root_json(&contents)
    }
}

/// Provides per-server enumeration before credential materialization.
pub mod runtime {
    pub use crate::central_references::{
        CentralCredentialReference, CentralCredentialSlot, CentralCredentialUsage,
        EnumerationRequiredError, UnexpandedCredentialField, inspect_central_references,
    };
    pub use crate::enumeration::{enumerate_server, enumerate_servers};
    pub use crate::builders::{TacacsPlusBuilder, TacacsPlusServerBuilder};
    pub use crate::extensions::TacacsPlusServerExt;
}

/// Provides runtime statistics types.
pub mod stats {
    pub use crate::statistics::ServerStatistics;
}

/// Parse a YANG JSON configuration string and validate it.
///
/// This is the standard API for loading YANG configuration. It parses and
/// validates the configuration without changing it. The result preserves the
/// submitted structure and all credential references. Callers can safely use
/// the result for round trips, reports, and credential resolution.
///
/// Validation makes sure that:
/// - At least one server is configured
/// - Server addresses and ports are unique
/// - SNI-enabled servers have domain names
/// - Security configuration is present and valid
/// - Credential bundle references have matching definitions
///
/// To inline shared `client-credentials` / `server-credentials` bundles for
/// per-server processing, call [`enumerate_servers`] or [`enumerate_server`].
///
/// # Errors
///
/// Returns an error if the JSON is malformed, does not match the YANG schema,
/// or does not satisfy a validation constraint.
pub fn parse_yang_json(json: &str) -> anyhow::Result<TacacsPlus> {
    parse_yang_json_with_options(json, &ValidationOptions::default())
}

/// Parse a YANG JSON configuration string with the supplied validation options.
///
/// This function applies the supplied [`ValidationOptions`] during validation.
/// It otherwise behaves like [`parse_yang_json`].
///
/// # Errors
///
/// Returns an error if the JSON is malformed, does not match the YANG schema,
/// or does not satisfy a constraint enabled by `options`.
pub fn parse_yang_json_with_options(
    json: &str,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlus> {
    let root: YangConfigRoot = pipeline::parse_root_json(json)?;

    let config = root.tacacs_plus;
    validation::validate_config_with_options(&config, options)?;

    Ok(config)
}

/// Parse and validate a YANG JSON configuration file without changing its data.
///
/// This function behaves like [`parse_yang_json`]. The result preserves the
/// submitted structure and all credential references.
///
/// Validation makes sure that:
/// - At least one server is configured
/// - Server addresses and ports are unique
/// - SNI-enabled servers have domain names
/// - Security configuration is present and valid
/// - Credential bundle references have matching definitions
///
/// # Errors
///
/// Returns an error if the file cannot be read, the JSON is malformed, the
/// JSON does not match the YANG schema, or validation fails.
pub fn parse_yang_json_file(path: &std::path::Path) -> anyhow::Result<TacacsPlus> {
    parse_yang_json_file_with_options(path, &ValidationOptions::default())
}

/// Parse a YANG JSON configuration file with the supplied validation options.
///
/// This function applies the supplied [`ValidationOptions`] during validation.
/// It otherwise behaves like [`parse_yang_json_file`].
///
/// # Errors
///
/// Returns an error if the file cannot be read or the JSON is malformed. It
/// also returns an error if the JSON or `options` do not pass validation.
pub fn parse_yang_json_file_with_options(
    path: &std::path::Path,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlus> {
    let root: YangConfigRoot = pipeline::parse_root_json_file(path)?;

    let config = root.tacacs_plus;
    validation::validate_config_with_options(&config, options)?;

    Ok(config)
}
