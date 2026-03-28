use std::collections::HashSet;

use crate::generated::tacacs_plus::{
    ClientIdentityCertificate, RawPrivateKey, ServerAuthenticationCaCerts,
    ServerAuthenticationRawPublicKeys, TacacsPlus, Tls13Epsk,
};

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
        validate_server(server, &mut seen_endpoints)?;
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

fn validate_server(
    server: &crate::generated::tacacs_plus::TacacsPlusServer,
    seen_endpoints: &mut HashSet<(String, u16)>,
) -> anyhow::Result<()> {
    let key = (server.address.clone(), server.port);
    if !seen_endpoints.insert(key) {
        anyhow::bail!("duplicate server address+port: {}:{}", server.address, server.port,);
    }

    if server.sni_enabled == Some(true) && server.domain_name.is_none() {
        anyhow::bail!("server '{}': sni-enabled requires domain-name to be set", server.name,);
    }

    validate_security_choice(server)?;
    validate_client_identity(server)?;
    validate_server_authentication(server)?;

    if let Some(ref hp) = server.hello_params {
        validate_tls_versions(hp, &server.name)?;
    }

    Ok(())
}

fn validate_security_choice(
    server: &crate::generated::tacacs_plus::TacacsPlusServer,
) -> anyhow::Result<()> {
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
    Ok(())
}

fn validate_client_identity(
    server: &crate::generated::tacacs_plus::TacacsPlusServer,
) -> anyhow::Result<()> {
    let Some(ref client_identity) = server.client_identity else {
        return Ok(());
    };

    if let Some(ref certificate) = client_identity.certificate {
        validate_mandatory_choice(
            &server.name,
            "client-identity/certificate",
            ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE,
            ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[
                certificate.inline_definition.is_some(),
                certificate.central_keystore_reference.is_some(),
            ],
        )?;
    }

    if let Some(ref raw_private_key) = client_identity.raw_private_key {
        validate_mandatory_choice(
            &server.name,
            "client-identity/raw-private-key",
            RawPrivateKey::CHOICE_INLINE_OR_KEYSTORE,
            RawPrivateKey::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[
                raw_private_key.inline_definition.is_some(),
                raw_private_key.central_keystore_reference.is_some(),
            ],
        )?;
    }

    if let Some(ref tls13_epsk) = client_identity.tls13_epsk {
        validate_mandatory_choice(
            &server.name,
            "client-identity/tls13-epsk",
            Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE,
            Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[
                tls13_epsk.inline_definition.is_some(),
                tls13_epsk.central_keystore_reference.is_some(),
            ],
        )?;

        #[cfg(not(feature = "psk"))]
        anyhow::bail!("server '{}': TLS 1.3 PSK requires the 'psk' feature flag", server.name,);
    }

    Ok(())
}

fn validate_server_authentication(
    server: &crate::generated::tacacs_plus::TacacsPlusServer,
) -> anyhow::Result<()> {
    let Some(ref server_authentication) = server.server_authentication else {
        return Ok(());
    };

    if let Some(ref ca_certs) = server_authentication.ca_certs {
        validate_mandatory_choice(
            &server.name,
            "server-authentication/ca-certs",
            ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE,
            ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY,
            &[
                ca_certs.inline_definition.is_some(),
                ca_certs.central_truststore_reference.is_some(),
            ],
        )?;
    }

    if let Some(ref raw_public_keys) = server_authentication.raw_public_keys {
        validate_mandatory_choice(
            &server.name,
            "server-authentication/raw-public-keys",
            ServerAuthenticationRawPublicKeys::CHOICE_INLINE_OR_TRUSTSTORE,
            ServerAuthenticationRawPublicKeys::CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY,
            &[
                raw_public_keys.inline_definition.is_some(),
                raw_public_keys.central_truststore_reference.is_some(),
            ],
        )?;
    }

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

fn validate_mandatory_choice(
    server_name: &str,
    field_path: &str,
    choice_cases: &[(&str, &[&str])],
    mandatory: bool,
    case_presence: &[bool],
) -> anyhow::Result<()> {
    let selected_cases = case_presence.iter().filter(|present| **present).count();
    if mandatory && selected_cases == 0 {
        anyhow::bail!(
            "server '{server_name}': {field_path} requires one of [{}]",
            choice_case_names(choice_cases),
        );
    }
    if selected_cases > 1 {
        anyhow::bail!(
            "server '{server_name}': {field_path} allows only one of [{}]",
            choice_case_names(choice_cases),
        );
    }
    Ok(())
}

fn choice_case_names(choice_cases: &[(&str, &[&str])]) -> String {
    choice_cases
        .iter()
        .map(|(case_name, _)| *case_name)
        .collect::<Vec<_>>()
        .join(", ")
}
