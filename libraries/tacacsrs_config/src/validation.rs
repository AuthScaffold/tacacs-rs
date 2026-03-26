use std::collections::HashSet;

use crate::server::{Security, TacacsPlusConfig};

/// Validate a parsed TACACS+ configuration against YANG model constraints.
///
/// Checks:
/// - Server list is non-empty
/// - Each server's `address` + `port` pair is unique (YANG `unique` constraint)
/// - `sni-enabled` requires `domain-name` to be set
/// - TLS version constraints are >= 1.3 when specified
///
/// # Errors
///
/// Returns an error describing the first constraint violation found.
pub fn validate_config(config: &TacacsPlusConfig) -> anyhow::Result<()> {
    if config.server.is_empty() {
        anyhow::bail!("server list must contain at least one entry");
    }

    // YANG: unique "address port"
    let mut seen_endpoints = HashSet::new();
    for server in &config.server {
        let key = (server.address.clone(), server.port);
        if !seen_endpoints.insert(key) {
            anyhow::bail!("duplicate server address+port: {}:{}", server.address, server.port,);
        }

        // YANG: sni-enabled must have ../domain-name
        if server.sni_enabled == Some(true) && server.domain_name.is_none() {
            anyhow::bail!("server '{}': sni-enabled requires domain-name to be set", server.name,);
        }

        // Validate TLS-specific constraints.
        if let Security::Tls(ref tls) = server.security {
            if let Some(ref hello) = tls.hello_params {
                validate_tls_versions(hello, &server.name)?;
            }
        }
    }

    // Validate unique credential IDs.
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

fn validate_tls_versions(hello: &crate::tls::HelloParams, server_name: &str) -> anyhow::Result<()> {
    if let Some(ref versions) = hello.tls_versions {
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
