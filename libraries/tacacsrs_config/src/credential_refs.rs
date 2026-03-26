use serde::Deserialize;

use crate::server::{Security, ServerEntry, TacacsPlusConfig};
use crate::tls::{ClientIdentity, ServerAuthentication};

/// A reusable client credentials bundle.
///
/// Maps to the YANG `list client-credentials` keyed by `id`.
/// These can be referenced by server entries via `credentials-reference`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientCredentials {
    /// Unique identifier for this credential bundle.
    pub id: String,

    /// The client identity contained in this bundle.
    #[serde(flatten)]
    pub identity: Option<ClientIdentity>,
}

/// A reusable server credentials bundle.
///
/// Maps to the YANG `list server-credentials` keyed by `id`.
/// These can be referenced by server entries via `credentials-reference`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentials {
    /// Unique identifier for this credential bundle.
    pub id: String,

    /// The server authentication config contained in this bundle.
    #[serde(flatten)]
    pub authentication: Option<ServerAuthentication>,
}

/// Resolve credential references in server entries to inline values.
///
/// For each server using TLS with a `credentials-reference` in its
/// client-identity or server-authentication, look up the referenced
/// bundle from the top-level lists and copy the concrete values inline.
///
/// # Errors
///
/// Returns an error if a referenced credential ID does not exist.
pub fn resolve_credential_references(config: &mut TacacsPlusConfig) -> anyhow::Result<()> {
    let client_creds: std::collections::HashMap<&str, &ClientCredentials> = config
        .client_credentials
        .iter()
        .map(|c| (c.id.as_str(), c))
        .collect();

    let server_creds: std::collections::HashMap<&str, &ServerCredentials> = config
        .server_credentials
        .iter()
        .map(|c| (c.id.as_str(), c))
        .collect();

    for server in &mut config.server {
        resolve_server_credentials(server, &client_creds, &server_creds)?;
    }

    Ok(())
}

fn resolve_server_credentials(
    server: &mut ServerEntry,
    client_creds: &std::collections::HashMap<&str, &ClientCredentials>,
    server_creds: &std::collections::HashMap<&str, &ServerCredentials>,
) -> anyhow::Result<()> {
    let Security::Tls(ref mut tls) = server.security else {
        return Ok(());
    };

    // Resolve client identity reference.
    if let Some(ref mut ci) = tls.client_identity {
        if let Some(ref cref) = ci.credentials_reference {
            let bundle = client_creds.get(cref.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "server '{}': client-credentials reference '{}' not found",
                    server.name,
                    cref,
                )
            })?;
            ci.inline = bundle.identity.clone();
            ci.credentials_reference = None;
        }
    }

    // Resolve server authentication reference.
    if let Some(ref cref) = tls.server_authentication.credentials_reference {
        let bundle = server_creds.get(cref.as_str()).ok_or_else(|| {
            anyhow::anyhow!(
                "server '{}': server-credentials reference '{}' not found",
                server.name,
                cref,
            )
        })?;
        tls.server_authentication
            .inline
            .clone_from(&bundle.authentication);
        tls.server_authentication.credentials_reference = None;
    }

    Ok(())
}
