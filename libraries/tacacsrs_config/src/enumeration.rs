use anyhow::{Context, Result};

use crate::{TacacsPlus, TacacsPlusServer};

/// Enumerate each server and inline its shared credential bundles.
///
/// This operation copies `client-credentials` and `server-credentials` bundle
/// contents into each server entry. It clears the related
/// `credentials-reference` fields. It preserves external
/// `central-keystore-reference` and `central-truststore-reference` values.
///
/// # Errors
///
/// Returns an error if any referenced client or server credential bundle is
/// missing from the configuration.
pub fn enumerate_servers(config: &TacacsPlus) -> Result<Vec<TacacsPlusServer>> {
    config
        .server
        .iter()
        .map(|server| {
            let mut enumerated = server.clone();
            enumerate_server_credentials(&mut enumerated, config).with_context(|| {
                format!("failed to enumerate credentials for server '{}'", server.name)
            })?;
            Ok(enumerated)
        })
        .collect()
}

/// Enumerate one server by name and inline its shared credential bundles.
///
/// # Errors
///
/// Returns an error if the server does not exist or if it references a missing
/// client or server credential bundle.
pub fn enumerate_server(config: &TacacsPlus, server_name: &str) -> Result<TacacsPlusServer> {
    let server = config
        .server
        .iter()
        .find(|candidate| candidate.name == server_name)
        .ok_or_else(|| anyhow::anyhow!("server '{server_name}' not found"))?;

    let mut enumerated = server.clone();
    enumerate_server_credentials(&mut enumerated, config)
        .with_context(|| format!("failed to enumerate credentials for server '{server_name}'"))?;
    Ok(enumerated)
}

/// Make sure that all local credential bundle references are defined.
///
/// This function covers only `credentials-reference` links into the
/// configuration's `client-credentials` and `server-credentials` lists. It
/// does not validate external keystore or truststore references.
///
/// # Errors
///
/// Returns one error that lists all missing credential bundles.
pub fn validate_credential_references(config: &TacacsPlus) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();

    for server in &config.server {
        if let Some(ref ci) = server.client_identity {
            if let Some(ref cred_ref) = ci.credentials_reference {
                if !config
                    .client_credentials
                    .iter()
                    .any(|credentials| credentials.id == *cred_ref)
                {
                    errors.push(format!(
                        "server '{}': client-identity credentials-reference '{}' not found in client-credentials",
                        server.name, cred_ref,
                    ));
                }
            }
        }

        if let Some(ref sa) = server.server_authentication {
            if let Some(ref cred_ref) = sa.credentials_reference {
                if !config
                    .server_credentials
                    .iter()
                    .any(|credentials| credentials.id == *cred_ref)
                {
                    errors.push(format!(
                        "server '{}': server-authentication credentials-reference '{}' not found in server-credentials",
                        server.name, cred_ref,
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "credential reference validation failed:\n  - {}",
            errors.join("\n  - ")
        ))
    }
}

fn enumerate_server_credentials(server: &mut TacacsPlusServer, config: &TacacsPlus) -> Result<()> {
    if let Some(ref mut ci) = server.client_identity {
        if let Some(ref cred_ref) = ci.credentials_reference {
            let bundle = config
                .client_credentials
                .iter()
                .find(|credentials| credentials.id == *cred_ref)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "client-identity credentials-reference '{cred_ref}' not found in client-credentials"
                    )
                })?;

            ci.certificate = bundle.certificate.clone();
            ci.tls13_epsk = bundle.tls13_epsk.clone();
            ci.credentials_reference = None;
        }
    }

    if let Some(ref mut sa) = server.server_authentication {
        if let Some(ref cred_ref) = sa.credentials_reference {
            let bundle = config
                .server_credentials
                .iter()
                .find(|credentials| credentials.id == *cred_ref)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "server-authentication credentials-reference '{cred_ref}' not found in server-credentials"
                    )
                })?;

            sa.ca_certs = bundle.ca_certs.clone();
            sa.ee_certs = bundle.ee_certs.clone();
            sa.tls13_epsks = bundle.tls13_epsks;
            sa.credentials_reference = None;
        }
    }

    Ok(())
}
