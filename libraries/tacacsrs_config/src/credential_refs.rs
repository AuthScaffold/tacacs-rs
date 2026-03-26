use std::collections::HashMap;

use crate::generated::tacacs_plus::{
    ClientCredentials, ServerCredentials, TacacsPlus, TacacsPlusServer,
};

/// Resolve credential references in server entries to inline values.
///
/// # Errors
///
/// Returns an error if a referenced credential ID is not found.
pub fn resolve_credential_references(config: &mut TacacsPlus) -> anyhow::Result<()> {
    let client_creds: HashMap<&str, &ClientCredentials> = config
        .client_credentials
        .iter()
        .map(|c| (c.id.as_str(), c))
        .collect();

    let server_creds: HashMap<&str, &ServerCredentials> = config
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
    server: &mut TacacsPlusServer,
    client_creds: &HashMap<&str, &ClientCredentials>,
    server_creds: &HashMap<&str, &ServerCredentials>,
) -> anyhow::Result<()> {
    // Resolve client identity reference
    if let Some(ref mut ci) = server.client_identity {
        if let Some(ref cref) = ci.credentials_reference {
            let bundle = client_creds.get(cref.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "server '{}': client-credentials reference '{}' not found",
                    server.name,
                    cref,
                )
            })?;
            ci.certificate.clone_from(&bundle.certificate);
            ci.raw_private_key.clone_from(&bundle.raw_private_key);
            ci.tls13_epsk.clone_from(&bundle.tls13_epsk);
            ci.credentials_reference = None;
        }
    }

    // Resolve server authentication reference
    if let Some(ref mut sa) = server.server_authentication {
        if let Some(ref cref) = sa.credentials_reference {
            let bundle = server_creds.get(cref.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "server '{}': server-credentials reference '{}' not found",
                    server.name,
                    cref,
                )
            })?;
            sa.ca_certs.clone_from(&bundle.ca_certs);
            sa.ee_certs.clone_from(&bundle.ee_certs);
            sa.raw_public_keys.clone_from(&bundle.raw_public_keys);
            sa.tls13_epsks = bundle.tls13_epsks;
            sa.credentials_reference = None;
        }
    }

    Ok(())
}
