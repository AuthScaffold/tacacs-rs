use std::collections::HashSet;

use crate::generated::tacacs_plus::{
    ClientCredentials, ClientIdentityCertificate, ServerAuthenticationCaCerts, TacacsPlus,
    TacacsPlusServer, Tls13Epsk, TlsClientClientIdentity, TlsClientServerAuthentication,
};

// ---------------------------------------------------------------------------
// Validation options and relaxations
// ---------------------------------------------------------------------------

/// An optional relaxation that loosens a specific YANG validation constraint.
///
/// Relaxations are opt-in; default (strict) validation never applies them.
/// They are designed as a migration aid and should be removed once the
/// underlying configuration is updated to comply with strict YANG constraints.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValidationRelaxation {
    /// Allow TLS and `shared-secret` to coexist on the same server.
    ///
    /// By default the YANG `security` choice is strict: either TLS
    /// (`client-identity` / `server-authentication`) **or** obfuscation
    /// (`shared-secret`) may be configured, but not both.
    ///
    /// This relaxation permits the combination as a temporary migration state
    /// for server implementations that cannot yet cleanly remove
    /// shared-secret handling after enabling TLS.
    AllowTlsWithSharedSecret,

    /// Allow a plain TCP TACACS+ server with neither TLS nor `shared-secret`.
    ///
    /// Strict YANG validation treats the `security` choice as mandatory. This
    /// relaxation permits legacy deployments that intentionally send TACACS+
    /// packets without TLS and without TACACS+ body obfuscation.
    AllowPlainTcpWithoutSharedSecret,
}

impl std::fmt::Display for ValidationRelaxation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllowTlsWithSharedSecret => write!(f, "allow-tls-with-shared-secret"),
            Self::AllowPlainTcpWithoutSharedSecret => {
                write!(f, "allow-plain-tcp-without-shared-secret")
            }
        }
    }
}

impl std::str::FromStr for ValidationRelaxation {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow-tls-with-shared-secret" => Ok(Self::AllowTlsWithSharedSecret),
            "allow-plain-tcp-without-shared-secret" => Ok(Self::AllowPlainTcpWithoutSharedSecret),
            other => anyhow::bail!(
                "unknown validation relaxation '{other}'; valid values: \
                 allow-tls-with-shared-secret, allow-plain-tcp-without-shared-secret"
            ),
        }
    }
}

/// Options that control YANG validation behaviour.
///
/// By default all options are empty, producing the same strict behaviour as
/// the original `validate_config` call. Individual [`ValidationRelaxation`]
/// values can be opted into via [`ValidationOptions::with_relaxation`].
///
/// # Example
///
/// ```rust
/// use tacacsrs_config::validation::{ValidationOptions, ValidationRelaxation};
///
/// let opts = ValidationOptions::new()
///     .with_relaxation(ValidationRelaxation::AllowTlsWithSharedSecret);
/// ```
#[derive(Debug, Clone, Default)]
pub struct ValidationOptions {
    relaxations: HashSet<ValidationRelaxation>,
}

impl ValidationOptions {
    /// Creates a new `ValidationOptions` with no relaxations (strict mode).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a [`ValidationRelaxation`] to this options set.
    #[must_use]
    pub fn with_relaxation(mut self, relaxation: ValidationRelaxation) -> Self {
        self.relaxations.insert(relaxation);
        self
    }

    /// Returns `true` if the given relaxation is active.
    #[must_use]
    pub fn allows(&self, relaxation: &ValidationRelaxation) -> bool {
        self.relaxations.contains(relaxation)
    }
}

// ---------------------------------------------------------------------------
// Config validation entry points
// ---------------------------------------------------------------------------

/// Validate a parsed TACACS+ configuration against YANG model constraints.
///
/// This uses strict (default) validation. To opt into relaxations, call
/// [`validate_config_with_options`] instead.
///
/// # Errors
///
/// Returns an error describing the first constraint violation found.
pub fn validate_config(config: &TacacsPlus) -> anyhow::Result<()> {
    validate_config_with_options(config, &ValidationOptions::default())
}

/// Validate a parsed TACACS+ configuration with the supplied validation options.
///
/// # Errors
///
/// Returns an error describing the first constraint violation found.
pub fn validate_config_with_options(
    config: &TacacsPlus,
    options: &ValidationOptions,
) -> anyhow::Result<()> {
    if config.server.is_empty() {
        anyhow::bail!("server list must contain at least one entry");
    }

    let mut seen_endpoints = HashSet::new();
    for server in &config.server {
        validate_server(server, &mut seen_endpoints, options)?;
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
    options: &ValidationOptions,
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
        anyhow::bail!("duplicate server address+port: {}:{}", server.address, server.port);
    }

    if server.sni_enabled == Some(true) && server.domain_name.is_none() {
        anyhow::bail!("server '{}': sni-enabled requires domain-name to be set", server.name);
    }

    validate_security_choice(server, options)?;
    validate_client_identity(server)?;
    validate_server_authentication(server)?;

    if let Some(ref ci) = server.client_identity {
        reject_unsupported_inline_features(&server.name, ci)?;
    }

    Ok(())
}

fn validate_security_choice(
    server: &crate::generated::tacacs_plus::TacacsPlusServer,
    options: &ValidationOptions,
) -> anyhow::Result<()> {
    let has_tls = server.client_identity.is_some() || server.server_authentication.is_some();
    let has_obfuscation = server.shared_secret.is_some();

    if !has_tls
        && !has_obfuscation
        && options.allows(&ValidationRelaxation::AllowPlainTcpWithoutSharedSecret)
    {
        return Ok(());
    }

    // When AllowTlsWithSharedSecret is active, permit both TLS and shared-secret
    // simultaneously.  We still require at least one security mode.
    if has_tls && has_obfuscation && options.allows(&ValidationRelaxation::AllowTlsWithSharedSecret)
    {
        return Ok(());
    }

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
            client_identity.certificate.is_some() || client_identity.tls13_epsk.is_some(),
        ],
    )?;

    if let Some(ref certificate) = client_identity.certificate {
        validate_choice(
            &server.name,
            "client-identity/certificate",
            ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE,
            ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[certificate.inline_definition.is_some()],
        )?;
    }

    if let Some(ref tls13_epsk) = client_identity.tls13_epsk {
        validate_choice(
            &server.name,
            "client-identity/tls13-epsk",
            Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE,
            Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[tls13_epsk.inline_definition.is_some()],
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
                || server_authentication.tls13_epsks.is_some(),
        ],
    )?;

    if let Some(ref ca_certs) = server_authentication.ca_certs {
        validate_choice(
            &server.name,
            "server-authentication/ca-certs",
            ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE,
            ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY,
            &[ca_certs.inline_definition.is_some()],
        )?;
    }

    if let Some(ref ee_certs) = server_authentication.ee_certs {
        validate_choice(
            &server.name,
            "server-authentication/ee-certs",
            ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE,
            ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY,
            &[ee_certs.inline_definition.is_some()],
        )?;
    }

    Ok(())
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
            credentials.tls13_epsk.is_some(),
        ],
    )?;

    if let Some(ref certificate) = credentials.certificate {
        validate_choice(
            &credentials.id,
            "client-credentials/certificate",
            ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE,
            ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[certificate.inline_definition.is_some()],
        )?;
    }

    if let Some(ref tls13_epsk) = credentials.tls13_epsk {
        validate_choice(
            &credentials.id,
            "client-credentials/tls13-epsk",
            Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE,
            Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
            &[tls13_epsk.inline_definition.is_some()],
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
    if let Some(ref epsk) = ci.tls13_epsk {
        reject_unsupported_epsk_derivation(context, epsk)?;
    }
    Ok(())
}

/// Rejects unsupported inline key features in a client-credentials bundle.
fn reject_unsupported_credentials_features(
    context: &str,
    creds: &ClientCredentials,
) -> anyhow::Result<()> {
    if let Some(ref epsk) = creds.tls13_epsk {
        reject_unsupported_epsk_derivation(context, epsk)?;
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
// Inline key material validation
// ---------------------------------------------------------------------------

/// Validate inline key material in all inline definitions across the config.
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

fn validate_client_identity_key_formats(
    ci: &TlsClientClientIdentity,
    context: &str,
) -> anyhow::Result<()> {
    if let Some(ref cert) = ci.certificate {
        if let Some(ref inline) = cert.inline_definition {
            let path = format!("{context}/client-identity/certificate");
            validate_inline_asymmetric_key_material(
                inline.public_key.as_deref(),
                inline.cleartext_private_key.as_deref(),
                inline.cert_data.as_deref(),
                &path,
            )?;
        }
    }
    if let Some(ref epsk) = ci.tls13_epsk {
        if let Some(ref inline) = epsk.inline_definition {
            let path = format!("{context}/client-identity/tls13-epsk");
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
            validate_inline_asymmetric_key_material(
                inline.public_key.as_deref(),
                inline.cleartext_private_key.as_deref(),
                inline.cert_data.as_deref(),
                &path,
            )?;
        }
    }
    if let Some(ref epsk) = cred.tls13_epsk {
        if let Some(ref inline) = epsk.inline_definition {
            let path = format!("{context}/tls13-epsk");
            if let Some(ref key) = inline.cleartext_symmetric_key {
                validate_binary_data(key, &path, "cleartext-symmetric-key")?;
            }
        }
    }
    Ok(())
}

/// Validates that a parsed YANG `binary` field contains usable data.
///
/// RFC 7951 base64 decoding already happened during deserialization, so the
/// remaining semantic validation here is that the field is not empty.
fn validate_binary_data(data: &[u8], context: &str, field: &str) -> anyhow::Result<()> {
    if data.is_empty() {
        anyhow::bail!("{context}: {field} must not be empty");
    }
    Ok(())
}

/// Validates that inline asymmetric key material fields (public-key,
/// cleartext-private-key, cert-data) contain decodable data when present.
fn validate_inline_asymmetric_key_material(
    public_key: Option<&[u8]>,
    cleartext_private_key: Option<&[u8]>,
    cert_data: Option<&[u8]>,
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
