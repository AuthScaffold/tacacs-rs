use std::collections::HashSet;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::generated::crypto_types::{PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat};
use crate::generated::tacacs_plus::{
    ClientCredentials, ClientIdentityCertificate, RawPrivateKey, ServerAuthenticationCaCerts,
    ServerAuthenticationRawPublicKeys, TacacsPlus, TacacsPlusServer, Tls13Epsk,
    TlsClientClientIdentity, TlsClientServerAuthentication,
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

    for credentials in &config.client_credentials {
        validate_client_credentials(credentials)?;
        reject_unsupported_credentials_features(&credentials.id, credentials)?;
    }

    crate::enumeration::validate_credential_references(config)?;

    validate_key_formats(config)?;

    Ok(())
}

fn validate_server(
    server: &crate::generated::tacacs_plus::TacacsPlusServer,
    seen_endpoints: &mut HashSet<(String, u16)>,
) -> anyhow::Result<()> {
    validate_choice(
        &server.name,
        "source-type",
        TacacsPlusServer::CHOICE_SOURCE_TYPE,
        TacacsPlusServer::CHOICE_SOURCE_TYPE_MANDATORY,
        &[
            server.source_ip.is_some(),
            server.source_interface.is_some(),
        ],
    )?;

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

    if let Some(ref ci) = server.client_identity {
        reject_unsupported_inline_features(&server.name, ci)?;
    }

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
    validate_choice(
        &server.name,
        "security",
        TacacsPlusServer::CHOICE_SECURITY,
        TacacsPlusServer::CHOICE_SECURITY_MANDATORY,
        &[has_tls, has_obfuscation],
    )
}

fn validate_client_identity(
    server: &crate::generated::tacacs_plus::TacacsPlusServer,
) -> anyhow::Result<()> {
    let Some(ref client_identity) = server.client_identity else {
        return Ok(());
    };

    validate_choice(
        &server.name,
        "client-identity",
        TlsClientClientIdentity::CHOICE_REF_OR_EXPLICIT,
        TlsClientClientIdentity::CHOICE_REF_OR_EXPLICIT_MANDATORY,
        &[
            client_identity.credentials_reference.is_some(),
            client_identity.certificate.is_some()
                || client_identity.raw_private_key.is_some()
                || client_identity.tls13_epsk.is_some(),
        ],
    )?;

    if let Some(ref certificate) = client_identity.certificate {
        validate_choice(
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
        validate_choice(
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
        validate_choice(
            &server.name,
            "client-identity/tls13-epsk",
            Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE,
            Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[
                tls13_epsk.inline_definition.is_some(),
                tls13_epsk.central_keystore_reference.is_some(),
            ],
        )?;
    }

    Ok(())
}

fn validate_server_authentication(
    server: &crate::generated::tacacs_plus::TacacsPlusServer,
) -> anyhow::Result<()> {
    let Some(ref server_authentication) = server.server_authentication else {
        return Ok(());
    };

    validate_choice(
        &server.name,
        "server-authentication",
        TlsClientServerAuthentication::CHOICE_REF_OR_EXPLICIT,
        TlsClientServerAuthentication::CHOICE_REF_OR_EXPLICIT_MANDATORY,
        &[
            server_authentication.credentials_reference.is_some(),
            server_authentication.ca_certs.is_some()
                || server_authentication.ee_certs.is_some()
                || server_authentication.raw_public_keys.is_some()
                || server_authentication.tls13_epsks.is_some(),
        ],
    )?;

    if let Some(ref ca_certs) = server_authentication.ca_certs {
        validate_choice(
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

    if let Some(ref ee_certs) = server_authentication.ee_certs {
        validate_choice(
            &server.name,
            "server-authentication/ee-certs",
            ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE,
            ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY,
            &[
                ee_certs.inline_definition.is_some(),
                ee_certs.central_truststore_reference.is_some(),
            ],
        )?;
    }

    if let Some(ref raw_public_keys) = server_authentication.raw_public_keys {
        validate_choice(
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

fn validate_client_credentials(credentials: &ClientCredentials) -> anyhow::Result<()> {
    validate_choice(
        &credentials.id,
        "client-credentials/auth-type",
        ClientCredentials::CHOICE_AUTH_TYPE,
        ClientCredentials::CHOICE_AUTH_TYPE_MANDATORY,
        &[
            credentials.certificate.is_some(),
            credentials.raw_private_key.is_some(),
            credentials.tls13_epsk.is_some(),
        ],
    )?;

    if let Some(ref certificate) = credentials.certificate {
        validate_choice(
            &credentials.id,
            "client-credentials/certificate",
            ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE,
            ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[
                certificate.inline_definition.is_some(),
                certificate.central_keystore_reference.is_some(),
            ],
        )?;
    }

    if let Some(ref raw_private_key) = credentials.raw_private_key {
        validate_choice(
            &credentials.id,
            "client-credentials/raw-private-key",
            RawPrivateKey::CHOICE_INLINE_OR_KEYSTORE,
            RawPrivateKey::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[
                raw_private_key.inline_definition.is_some(),
                raw_private_key.central_keystore_reference.is_some(),
            ],
        )?;
    }

    if let Some(ref tls13_epsk) = credentials.tls13_epsk {
        validate_choice(
            &credentials.id,
            "client-credentials/tls13-epsk",
            Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE,
            Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[
                tls13_epsk.inline_definition.is_some(),
                tls13_epsk.central_keystore_reference.is_some(),
            ],
        )?;
    }

    Ok(())
}

fn validate_choice(
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

// ---------------------------------------------------------------------------
// Unsupported feature rejection
// ---------------------------------------------------------------------------

/// Rejects unsupported inline key features that are parsed by the YANG model
/// but not yet handled by the resolver/connection layers.
fn reject_unsupported_inline_features(
    context: &str,
    ci: &TlsClientClientIdentity,
) -> anyhow::Result<()> {
    if let Some(ref cert) = ci.certificate {
        if let Some(ref inline) = cert.inline_definition {
            reject_unsupported_asymmetric_key_type(
                context,
                "client-identity/certificate",
                inline.hidden_private_key,
                inline.encrypted_private_key.is_some(),
            )?;
        }
    }
    if let Some(ref rpk) = ci.raw_private_key {
        if let Some(ref inline) = rpk.inline_definition {
            reject_unsupported_asymmetric_key_type(
                context,
                "client-identity/raw-private-key",
                inline.hidden_private_key,
                inline.encrypted_private_key.is_some(),
            )?;
        }
    }
    if let Some(ref epsk) = ci.tls13_epsk {
        if let Some(ref inline) = epsk.inline_definition {
            reject_unsupported_symmetric_key_type(
                context,
                "client-identity/tls13-epsk",
                inline.hidden_symmetric_key,
                inline.encrypted_symmetric_key.is_some(),
            )?;
        }
        reject_unsupported_epsk_derivation(context, epsk)?;
    }
    Ok(())
}

/// Rejects unsupported inline key features in a client-credentials bundle.
fn reject_unsupported_credentials_features(
    context: &str,
    creds: &ClientCredentials,
) -> anyhow::Result<()> {
    if let Some(ref cert) = creds.certificate {
        if let Some(ref inline) = cert.inline_definition {
            reject_unsupported_asymmetric_key_type(
                context,
                "certificate",
                inline.hidden_private_key,
                inline.encrypted_private_key.is_some(),
            )?;
        }
    }
    if let Some(ref rpk) = creds.raw_private_key {
        if let Some(ref inline) = rpk.inline_definition {
            reject_unsupported_asymmetric_key_type(
                context,
                "raw-private-key",
                inline.hidden_private_key,
                inline.encrypted_private_key.is_some(),
            )?;
        }
    }
    if let Some(ref epsk) = creds.tls13_epsk {
        if let Some(ref inline) = epsk.inline_definition {
            reject_unsupported_symmetric_key_type(
                context,
                "tls13-epsk",
                inline.hidden_symmetric_key,
                inline.encrypted_symmetric_key.is_some(),
            )?;
        }
        reject_unsupported_epsk_derivation(context, epsk)?;
    }
    Ok(())
}

fn reject_unsupported_asymmetric_key_type(
    context: &str,
    path: &str,
    hidden: Option<bool>,
    has_encrypted: bool,
) -> anyhow::Result<()> {
    if hidden == Some(true) {
        anyhow::bail!("'{context}': {path} uses hidden-private-key which is not yet supported");
    }
    if has_encrypted {
        anyhow::bail!("'{context}': {path} uses encrypted-private-key which is not yet supported");
    }
    Ok(())
}

fn reject_unsupported_symmetric_key_type(
    context: &str,
    path: &str,
    hidden: Option<bool>,
    has_encrypted: bool,
) -> anyhow::Result<()> {
    if hidden == Some(true) {
        anyhow::bail!("'{context}': {path} uses hidden-symmetric-key which is not yet supported");
    }
    if has_encrypted {
        anyhow::bail!(
            "'{context}': {path} uses encrypted-symmetric-key which is not yet supported"
        );
    }
    Ok(())
}

fn reject_unsupported_epsk_derivation(context: &str, epsk: &Tls13Epsk) -> anyhow::Result<()> {
    if epsk.context.is_some() {
        anyhow::bail!(
            "'{context}': tls13-epsk 'context' for additional key derivation is not yet supported"
        );
    }
    if epsk.target_protocol.is_some() {
        anyhow::bail!(
            "'{context}': tls13-epsk 'target-protocol' for additional key derivation is not yet supported"
        );
    }
    if epsk.target_kdf.is_some() {
        anyhow::bail!(
            "'{context}': tls13-epsk 'target-kdf' for additional key derivation is not yet supported"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Identityref key-format validation
// ---------------------------------------------------------------------------

fn validate_identityref(
    context: &str,
    field_name: &str,
    value: &str,
    allowed: &[&str],
) -> anyhow::Result<()> {
    if !allowed.contains(&value) {
        anyhow::bail!(
            "{context}: invalid {field_name} '{value}', expected one of [{}]",
            allowed.join(", "),
        );
    }
    Ok(())
}

/// Validate key format identityrefs in all inline definitions across the config.
pub(crate) fn validate_key_formats(config: &TacacsPlus) -> anyhow::Result<()> {
    for server in &config.server {
        let ctx = format!("server '{}'", server.name);

        if let Some(ref ci) = server.client_identity {
            validate_client_identity_key_formats(ci, &ctx)?;
        }
        if let Some(ref sa) = server.server_authentication {
            validate_server_auth_key_formats(sa, &ctx)?;
        }
    }

    for cred in &config.client_credentials {
        let ctx = format!("client-credentials '{}'", cred.id);
        validate_client_credential_key_formats(cred, &ctx)?;
    }

    Ok(())
}

fn validate_asymmetric_key_formats(
    public_key_format: Option<&str>,
    private_key_format: Option<&str>,
    context: &str,
) -> anyhow::Result<()> {
    if let Some(pkf) = public_key_format {
        validate_identityref(context, "public-key-format", pkf, PublicKeyFormat::ALLOWED_VALUES)?;
    }
    if let Some(pkf) = private_key_format {
        validate_identityref(context, "private-key-format", pkf, PrivateKeyFormat::ALLOWED_VALUES)?;
    }
    Ok(())
}

fn validate_client_identity_key_formats(
    ci: &TlsClientClientIdentity,
    context: &str,
) -> anyhow::Result<()> {
    if let Some(ref cert) = ci.certificate {
        if let Some(ref inline) = cert.inline_definition {
            let path = format!("{context}/client-identity/certificate");
            validate_asymmetric_key_formats(
                inline.public_key_format.as_deref(),
                inline.private_key_format.as_deref(),
                &path,
            )?;
            validate_inline_asymmetric_key_material(
                inline.public_key.as_deref(),
                inline.cleartext_private_key.as_deref(),
                inline.cert_data.as_deref(),
                &path,
            )?;
        }
    }
    if let Some(ref rpk) = ci.raw_private_key {
        if let Some(ref inline) = rpk.inline_definition {
            let path = format!("{context}/client-identity/raw-private-key");
            validate_asymmetric_key_formats(
                inline.public_key_format.as_deref(),
                inline.private_key_format.as_deref(),
                &path,
            )?;
            validate_inline_asymmetric_key_material(
                inline.public_key.as_deref(),
                inline.cleartext_private_key.as_deref(),
                None, // no cert-data in asymmetric key definition
                &path,
            )?;
        }
    }
    if let Some(ref epsk) = ci.tls13_epsk {
        if let Some(ref inline) = epsk.inline_definition {
            let path = format!("{context}/client-identity/tls13-epsk");
            if let Some(ref kf) = inline.key_format {
                validate_identityref(&path, "key-format", kf, SymmetricKeyFormat::ALLOWED_VALUES)?;
            }
            if let Some(ref key) = inline.cleartext_symmetric_key {
                validate_binary_data(key, &path, "cleartext-symmetric-key")?;
            }
        }
    }
    Ok(())
}

fn validate_server_auth_key_formats(
    sa: &TlsClientServerAuthentication,
    context: &str,
) -> anyhow::Result<()> {
    if let Some(ref rpk) = sa.raw_public_keys {
        if let Some(ref inline) = rpk.inline_definition {
            for pk in &inline.public_key {
                let path = format!("{context}/server-authentication/raw-public-keys");
                validate_identityref(
                    &path,
                    "public-key-format",
                    &pk.public_key_format,
                    PublicKeyFormat::ALLOWED_VALUES,
                )?;
                validate_binary_data(&pk.public_key, &path, "public-key")?;
            }
        }
    }
    // Validate inline CA and EE certificate data
    if let Some(ref ca) = sa.ca_certs {
        if let Some(ref inline) = ca.inline_definition {
            for cert_entry in &inline.certificate {
                validate_binary_data(
                    &cert_entry.cert_data,
                    &format!("{context}/server-authentication/ca-certs"),
                    &format!("certificate '{}'", cert_entry.name),
                )?;
            }
        }
    }
    if let Some(ref ee) = sa.ee_certs {
        if let Some(ref inline) = ee.inline_definition {
            for cert_entry in &inline.certificate {
                validate_binary_data(
                    &cert_entry.cert_data,
                    &format!("{context}/server-authentication/ee-certs"),
                    &format!("certificate '{}'", cert_entry.name),
                )?;
            }
        }
    }
    Ok(())
}

fn validate_client_credential_key_formats(
    cred: &ClientCredentials,
    context: &str,
) -> anyhow::Result<()> {
    if let Some(ref cert) = cred.certificate {
        if let Some(ref inline) = cert.inline_definition {
            let path = format!("{context}/certificate");
            validate_asymmetric_key_formats(
                inline.public_key_format.as_deref(),
                inline.private_key_format.as_deref(),
                &path,
            )?;
            validate_inline_asymmetric_key_material(
                inline.public_key.as_deref(),
                inline.cleartext_private_key.as_deref(),
                inline.cert_data.as_deref(),
                &path,
            )?;
        }
    }
    if let Some(ref rpk) = cred.raw_private_key {
        if let Some(ref inline) = rpk.inline_definition {
            let path = format!("{context}/raw-private-key");
            validate_asymmetric_key_formats(
                inline.public_key_format.as_deref(),
                inline.private_key_format.as_deref(),
                &path,
            )?;
            validate_inline_asymmetric_key_material(
                inline.public_key.as_deref(),
                inline.cleartext_private_key.as_deref(),
                None,
                &path,
            )?;
        }
    }
    if let Some(ref epsk) = cred.tls13_epsk {
        if let Some(ref inline) = epsk.inline_definition {
            let path = format!("{context}/tls13-epsk");
            if let Some(ref kf) = inline.key_format {
                validate_identityref(&path, "key-format", kf, SymmetricKeyFormat::ALLOWED_VALUES)?;
            }
            if let Some(ref key) = inline.cleartext_symmetric_key {
                validate_binary_data(key, &path, "cleartext-symmetric-key")?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Inline key material validation
// ---------------------------------------------------------------------------

/// Validates that a YANG `binary` field contains decodable data.
///
/// YANG binary values are either base64-encoded DER or PEM with BEGIN/END
/// markers. This accepts both forms and rejects data that cannot be decoded.
fn validate_binary_data(data: &str, context: &str, field: &str) -> anyhow::Result<()> {
    let trimmed = data.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{context}: {field} must not be empty");
    }

    // PEM data is valid if it has proper markers — the base64 payload inside
    // is decoded by PEM parsers, not by us.
    if trimmed.starts_with("-----BEGIN") {
        if !trimmed.contains("-----END") {
            anyhow::bail!("{context}: {field} contains a PEM BEGIN marker but no END marker");
        }
        return Ok(());
    }

    // Raw base64 — validate it decodes.
    BASE64
        .decode(trimmed)
        .map_err(|e| anyhow::anyhow!("{context}: {field} contains invalid base64: {e}"))?;
    Ok(())
}

/// Validates that inline asymmetric key material fields (public-key,
/// cleartext-private-key, cert-data) contain decodable data when present.
fn validate_inline_asymmetric_key_material(
    public_key: Option<&str>,
    cleartext_private_key: Option<&str>,
    cert_data: Option<&str>,
    context: &str,
) -> anyhow::Result<()> {
    if let Some(pk) = public_key {
        validate_binary_data(pk, context, "public-key")?;
    }
    if let Some(key) = cleartext_private_key {
        validate_binary_data(key, context, "cleartext-private-key")?;
    }
    if let Some(cert) = cert_data {
        validate_binary_data(cert, context, "cert-data")?;
    }
    Ok(())
}
