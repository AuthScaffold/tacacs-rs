pub mod generated;
mod credential_refs;
mod mapping;
mod statistics;
mod validation;

// Re-export key types from generated module for convenience
pub use generated::tacacs_plus::{
    ClientCredentials, ClientIdentityCertificate, EpskSupportedHash, RawPrivateKey,
    ServerAuthenticationCaCerts, ServerAuthenticationRawPublicKeys, ServerCredentials, TacacsPlus,
    TacacsPlusServer, TacacsPlusServerType, Tls13Epsk, TlsClientClientIdentity,
    TlsClientHelloParams, TlsClientServerAuthentication,
};
pub use generated::truststore;
pub use generated::{crypto_types, keystore, tls_common, YangConfigRoot};

pub use credential_refs::resolve_credential_references;
pub use mapping::{to_connection_configs, ResolvedSecurity, ServerConnectionConfig};
pub use statistics::ServerStatistics;
pub use validation::validate_config;

/// Parse a YANG JSON configuration string into a validated config.
///
/// # Errors
///
/// Returns an error if the JSON is malformed, doesn't match the expected
/// YANG schema structure, or fails validation constraints.
pub fn parse_yang_json(json: &str) -> anyhow::Result<TacacsPlus> {
    let root: YangConfigRoot =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;

    let mut config = root.tacacs_plus;
    credential_refs::resolve_credential_references(&mut config)?;
    validation::validate_config(&config)?;

    Ok(config)
}

/// Parse a YANG JSON configuration file into a validated config.
///
/// # Errors
///
/// Returns an error if the file cannot be read, the JSON is malformed,
/// or validation fails.
pub fn parse_yang_json_file(path: &std::path::Path) -> anyhow::Result<TacacsPlus> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config file {}: {e}", path.display()))?;
    parse_yang_json(&contents)
}

#[cfg(test)]
mod tests;
