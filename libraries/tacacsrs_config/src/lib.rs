mod credential_refs;
mod mapping;
mod server;
mod serde_helpers;
mod statistics;
mod tls;
mod validation;

pub use credential_refs::{ClientCredentials, ServerCredentials};
pub use mapping::{to_connection_configs, ResolvedSecurity, ServerConnectionConfig};
pub use server::{Security, ServerEntry, ServerType, SourceType, TacacsPlusConfig};
pub use statistics::ServerStatistics;
pub use tls::{CertificateIdentity, ClientIdentity, HelloParams, ServerAuthentication, TlsClientConfig};
pub use validation::validate_config;

use serde::Deserialize;

/// Top-level wrapper matching the YANG JSON encoding root key.
///
/// The RFC 7951 JSON encoding uses the module-prefixed key
/// `ietf-system-tacacs-plus:tacacs-plus` at the document root.
#[derive(Debug, Clone, Deserialize)]
pub struct YangConfigRoot {
    #[serde(rename = "ietf-system-tacacs-plus:tacacs-plus")]
    pub tacacs_plus: TacacsPlusConfig,
}

/// Parse a YANG JSON configuration string into a validated config.
///
/// # Errors
///
/// Returns an error if the JSON is malformed, doesn't match the expected
/// YANG schema structure, or fails validation constraints.
pub fn parse_yang_json(json: &str) -> anyhow::Result<TacacsPlusConfig> {
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
pub fn parse_yang_json_file(path: &std::path::Path) -> anyhow::Result<TacacsPlusConfig> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config file {}: {e}", path.display()))?;
    parse_yang_json(&contents)
}

#[cfg(test)]
mod tests;
