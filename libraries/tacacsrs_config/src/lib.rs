pub mod generated;
mod enumeration;
mod mapping;
mod statistics;
mod validation;

pub use enumeration::{enumerate_server, enumerate_servers, validate_credential_references};

// Re-export key types from generated module for convenience
pub use generated::tacacs_plus::{
    ClientCredentials, ClientIdentityCertificate, EpskSupportedHash, RawPrivateKey,
    ServerAuthenticationCaCerts, ServerAuthenticationRawPublicKeys, ServerCredentials, TacacsPlus,
    TacacsPlusServer, TacacsPlusServerType, Tls13Epsk, TlsClientClientIdentity,
    TlsClientHelloParams, TlsClientServerAuthentication,
};
pub use generated::truststore;
pub use generated::{crypto_types, keystore, tls_common, YangConfigRoot};

pub use statistics::ServerStatistics;

/// Model-oriented API: YANG-generated types and related namespaces.
pub mod model {
    pub use crate::generated;
    pub use crate::generated::tacacs_plus::{
        ClientCredentials, ClientIdentityCertificate, EpskSupportedHash, RawPrivateKey,
        ServerAuthenticationCaCerts, ServerAuthenticationRawPublicKeys, ServerCredentials,
        TacacsPlus, TacacsPlusServer, TacacsPlusServerType, Tls13Epsk, TlsClientClientIdentity,
        TlsClientHelloParams, TlsClientServerAuthentication,
    };
    pub use crate::generated::{crypto_types, keystore, tls_common, truststore, YangConfigRoot};
}

/// Step-by-step processing API for custom parse/validate flows.
pub mod pipeline {
    use std::path::Path;

    use crate::generated::YangConfigRoot;

    /// Parse RFC 7951 JSON into the root generated model without applying
    /// credential resolution or validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or does not match the model.
    pub fn parse_root_json(json: &str) -> anyhow::Result<YangConfigRoot> {
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))
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

/// Runtime projection API used by networking/client code.
pub mod runtime {
    pub use crate::enumeration::{enumerate_server, enumerate_servers};
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
/// `central-keystore-reference` and `central-truststore-reference` values.
/// To inline shared `client-credentials` / `server-credentials` bundles for
/// per-server processing, call [`enumerate_servers`] or [`enumerate_server`].
///
/// # Errors
///
/// Returns an error if:
/// - The JSON is malformed or does not match the YANG schema
/// - Validation constraints are violated
pub fn parse_yang_json(json: &str) -> anyhow::Result<TacacsPlus> {
    let root: YangConfigRoot = pipeline::parse_root_json(json)?;

    let config = root.tacacs_plus;
    validation::validate_config(&config)?;

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
    let root: YangConfigRoot = pipeline::parse_root_json_file(path)?;

    let config = root.tacacs_plus;
    validation::validate_config(&config)?;

    Ok(config)
}
