use serde::Deserialize;

use crate::server::{Security, ServerEntry, TacacsPlusConfig};
use crate::tls::{ClientAuthType, ServerAuthentication};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientCredentials {
    pub id: String,
    #[serde(flatten)]
    pub auth_type: Option<ClientAuthType>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentials {
    pub id: String,
    #[serde(flatten)]
    pub authentication: Option<ServerAuthentication>,
}

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
            ci.auth_type.clone_from(&bundle.auth_type);
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
