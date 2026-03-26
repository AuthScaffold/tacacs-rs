use std::collections::HashSet;

use crate::generated::tacacs_plus::TacacsPlus;

/// Validate a parsed TACACS+ configuration against YANG model constraints.
///
/// # Errors
///
/// Returns an error describing the first constraint violation found.
pub fn validate_config(config: &TacacsPlus) -> anyhow::Result<()> {
    if config.server.is_empty() {
        anyhow::bail!("server list must contain at least one entry");
    }

    let mut seen_endpoints = HashSet::new();
    for server in &config.server {
        let key = (server.address.clone(), server.port);
        if !seen_endpoints.insert(key) {
            anyhow::bail!("duplicate server address+port: {}:{}", server.address, server.port,);
        }

        if server.sni_enabled == Some(true) && server.domain_name.is_none() {
            anyhow::bail!("server '{}': sni-enabled requires domain-name to be set", server.name,);
        }

        // Validate choice: security is mandatory — either TLS fields or shared-secret must be set
        let has_tls = server.client_identity.is_some()
            || server.server_authentication.is_some()
            || server.hello_params.is_some();
        let has_obfuscation = server.shared_secret.is_some();
        if !has_tls && !has_obfuscation {
            anyhow::bail!(
                "server '{}': security choice is mandatory — set TLS fields or shared-secret",
                server.name,
            );
        }
        if has_tls && has_obfuscation {
            anyhow::bail!(
                "server '{}': cannot use both TLS and shared-secret obfuscation",
                server.name,
            );
        }

        if let Some(ref hp) = server.hello_params {
            validate_tls_versions(hp, &server.name)?;
        }
    }

    validate_unique_ids(
        config.client_credentials.iter().map(|c| c.id.as_str()),
        "client-credentials",
    )?;
    validate_unique_ids(
        config.server_credentials.iter().map(|c| c.id.as_str()),
        "server-credentials",
    )?;

    Ok(())
}

fn validate_tls_versions(
    hp: &crate::generated::tacacs_plus::TlsClientHelloParams,
    server_name: &str,
) -> anyhow::Result<()> {
    if let Some(ref versions) = hp.tls_versions {
        if let Some(ref min) = versions.min {
            if is_below_tls13(min) {
                anyhow::bail!(
                    "server '{server_name}': minimum TLS version must be >= 1.3, got '{min}'",
                );
            }
        }
        if let Some(ref max) = versions.max {
            if is_below_tls13(max) {
                anyhow::bail!(
                    "server '{server_name}': maximum TLS version must be >= 1.3, got '{max}'",
                );
            }
        }
    }
    Ok(())
}

fn is_below_tls13(version: &str) -> bool {
    matches!(version, "tls10" | "tls11" | "tls12")
}

fn validate_unique_ids<'a>(
    ids: impl Iterator<Item = &'a str>,
    list_name: &str,
) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for id in ids {
        if !seen.insert(id) {
            anyhow::bail!("duplicate {list_name} id: '{id}'");
        }
    }
    Ok(())
}
