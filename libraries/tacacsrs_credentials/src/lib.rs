use std::fmt;
use std::ops::Deref;
use std::time::Duration;

use anyhow::{Context, Result};
use tacacsrs_config::crypto_types::{PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat};
use tacacsrs_config::{TacacsPlusServer, TlsClientClientIdentity, TlsClientServerAuthentication};

mod epsk;
mod rpk;
mod tls;

struct NoOpResolver;

impl CredentialResolver for NoOpResolver {
    fn resolve_keystore_certificate(&self, key: &str) -> Result<Option<X509CertificateMaterial>> {
        Err(anyhow::anyhow!(
            "no credential resolver configured; cannot resolve keystore certificate '{key}'"
        ))
    }

    fn resolve_certificate_bag(&self, key: &str) -> Result<Option<Vec<CertificateEntry>>> {
        Err(anyhow::anyhow!(
            "no credential resolver configured; cannot resolve certificate bag '{key}'"
        ))
    }

    fn resolve_asymmetric_key(&self, key: &str) -> Result<Option<AsymmetricKeyMaterial>> {
        Err(anyhow::anyhow!(
            "no credential resolver configured; cannot resolve asymmetric key '{key}'"
        ))
    }

    fn resolve_symmetric_key(&self, key: &str) -> Result<Option<SymmetricKeyMaterial>> {
        Err(anyhow::anyhow!(
            "no credential resolver configured; cannot resolve symmetric key '{key}'"
        ))
    }

    fn resolve_public_key_bag(
        &self,
        key: &str,
    ) -> Result<Option<Vec<TruststorePublicKeyMaterial>>> {
        Err(anyhow::anyhow!(
            "no credential resolver configured; cannot resolve public key bag '{key}'"
        ))
    }

    fn validate_keystore_certificate(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "no credential resolver configured; cannot validate keystore certificate '{key}'"
        ))
    }

    fn validate_asymmetric_key(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "no credential resolver configured; cannot validate asymmetric key '{key}'"
        ))
    }

    fn validate_symmetric_key(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "no credential resolver configured; cannot validate symmetric key '{key}'"
        ))
    }

    fn validate_certificate_bag(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "no credential resolver configured; cannot validate certificate bag '{key}'"
        ))
    }

    fn validate_public_key_bag(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "no credential resolver configured; cannot validate public key bag '{key}'"
        ))
    }
}

fn effective_resolver(resolver: Option<&dyn CredentialResolver>) -> &dyn CredentialResolver {
    static NOOP: NoOpResolver = NoOpResolver;
    resolver.unwrap_or(&NOOP)
}

#[derive(Debug, Clone)]
pub struct X509CertificateMaterial {
    pub cert_data: String,
    pub key_material: AsymmetricKeyMaterial,
}

#[derive(Debug, Clone)]
pub struct CertificateEntry {
    pub name: String,
    pub cert_data: String,
}

#[derive(Debug, Clone)]
pub struct AsymmetricKeyMaterial {
    pub cleartext_private_key: String,
    pub public_key: Option<String>,
    pub private_key_format: Option<PrivateKeyFormat>,
    pub public_key_format: Option<PublicKeyFormat>,
}

#[derive(Debug, Clone)]
pub struct SymmetricKeyMaterial {
    pub cleartext_symmetric_key: String,
    pub key_format: Option<SymmetricKeyFormat>,
}

#[derive(Debug, Clone)]
pub struct TruststorePublicKeyMaterial {
    pub name: String,
    pub public_key: String,
    pub public_key_format: PublicKeyFormat,
}

/// Resolves external keystore and truststore references after config-local
/// `credentials-reference` bundles have already been expanded inline.
///
/// `resolve_server`, `resolve_servers`, and the validation helpers call these
/// methods only for external `central-keystore-reference` and
/// `central-truststore-reference` fields that are still present on the server
/// model.
///
/// The `resolve_*` methods are the materialization phase. They are expected to
/// return the concrete secret or trust material needed to replace an external
/// reference with the corresponding inline definition. Returning `Ok(None)`
/// means the reference was not resolved; the current callers treat that as an
/// unresolved-reference error.
///
/// The `validate_*` methods are the preflight phase used by
/// `validate_external_server_references` and
/// `validate_external_servers_references`. They should check that the supplied
/// reference is known and usable without mutating the server model.
pub trait CredentialResolver: Send + Sync {
    /// Resolve `client-identity.certificate.central-keystore-reference`.
    ///
    /// This is used for the TLS client certificate path. The returned material
    /// populates the certificate inline definition, including the certificate
    /// body and the associated key material.
    ///
    /// The input `key` is the `certificate` member of the central keystore
    /// reference. The config model also carries an optional `asymmetric-key`
    /// member, but the current resolver contract does not pass that value
    /// separately; implementations must supply the matching key material from
    /// whatever lookup strategy they use.
    ///
    /// # Errors
    ///
    /// Returns an error if the backing store cannot be queried or if the
    /// reference cannot be checked reliably.
    fn resolve_keystore_certificate(&self, key: &str) -> Result<Option<X509CertificateMaterial>>;

    /// Resolve `server-authentication.ca-certs.central-truststore-reference`
    /// and `server-authentication.ee-certs.central-truststore-reference`.
    ///
    /// The returned entries are copied into the truststore certificate bag
    /// inline definition.
    ///
    /// # Errors
    ///
    /// Returns an error if the backing store cannot be queried or if the
    /// reference cannot be checked reliably.
    fn resolve_certificate_bag(&self, key: &str) -> Result<Option<Vec<CertificateEntry>>>;

    /// Resolve `client-identity.raw-private-key.central-keystore-reference`.
    ///
    /// The returned material becomes the inline raw private key definition and
    /// may include both private and public key data plus their format
    /// identifiers.
    ///
    /// # Errors
    ///
    /// Returns an error if the backing store cannot be queried or if the
    /// reference cannot be checked reliably.
    fn resolve_asymmetric_key(&self, key: &str) -> Result<Option<AsymmetricKeyMaterial>>;

    /// Resolve `client-identity.tls13-epsk.central-keystore-reference`.
    ///
    /// The returned material becomes the inline TLS 1.3 external PSK
    /// definition.
    ///
    /// # Errors
    ///
    /// Returns an error if the backing store cannot be queried or if the
    /// reference cannot be checked reliably.
    fn resolve_symmetric_key(&self, key: &str) -> Result<Option<SymmetricKeyMaterial>>;

    /// Resolve `server-authentication.raw-public-keys.central-truststore-reference`.
    ///
    /// The returned entries are copied into the inline raw public key bag used
    /// for RPK-based server authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if the backing store cannot be queried or if the
    /// reference cannot be checked reliably.
    fn resolve_public_key_bag(&self, key: &str)
        -> Result<Option<Vec<TruststorePublicKeyMaterial>>>;

    /// Validate `client-identity.certificate.central-keystore-reference`.
    ///
    /// This is the preflight companion to `resolve_keystore_certificate` and is
    /// used when callers want to verify references before materializing secret
    /// data.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is unknown or unusable.
    fn validate_keystore_certificate(&self, key: &str) -> Result<()>;

    /// Validate `client-identity.raw-private-key.central-keystore-reference`.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is unknown or unusable.
    fn validate_asymmetric_key(&self, key: &str) -> Result<()>;

    /// Validate `client-identity.tls13-epsk.central-keystore-reference`.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is unknown or unusable.
    fn validate_symmetric_key(&self, key: &str) -> Result<()>;

    /// Validate `server-authentication.ca-certs.central-truststore-reference`
    /// and `server-authentication.ee-certs.central-truststore-reference`.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is unknown or unusable.
    fn validate_certificate_bag(&self, key: &str) -> Result<()>;

    /// Validate `server-authentication.raw-public-keys.central-truststore-reference`.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is unknown or unusable.
    fn validate_public_key_bag(&self, key: &str) -> Result<()>;
}

#[derive(Clone)]
pub struct ResolvedServer(TacacsPlusServer);

impl ResolvedServer {
    #[must_use]
    fn from_raw(server: TacacsPlusServer) -> Self {
        Self(server)
    }

    #[must_use]
    pub fn into_inner(self) -> TacacsPlusServer {
        self.0
    }

    #[must_use]
    pub fn socket_address(&self) -> String {
        if self.0.address.contains(':') {
            format!("[{}]:{}", self.0.address, self.0.port)
        } else {
            format!("{}:{}", self.0.address, self.0.port)
        }
    }

    #[must_use]
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs(u64::from(self.0.timeout))
    }

    #[must_use]
    pub fn obfuscation_key(&self) -> Option<Vec<u8>> {
        self.0.shared_secret.as_ref().map(|s| s.as_bytes().to_vec())
    }

    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.0.client_identity.is_some()
            || self.0.server_authentication.is_some()
            || self.0.hello_params.is_some()
    }

    #[must_use]
    pub fn is_obfuscation(&self) -> bool {
        !self.is_tls()
    }

    #[must_use]
    pub fn sni_enabled(&self) -> bool {
        self.0.sni_enabled.unwrap_or(false)
    }
}

impl Deref for ResolvedServer {
    type Target = TacacsPlusServer;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for ResolvedServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedServer")
            .field("name", &self.0.name)
            .field("server_type", &self.0.server_type)
            .field("address", &self.0.address)
            .field("port", &self.0.port)
            .field("domain_name", &self.0.domain_name)
            .field("sni_enabled", &self.0.sni_enabled)
            .field("single_connection", &self.0.single_connection)
            .field("timeout", &self.0.timeout)
            .field("client_identity", &"<redacted>")
            .field("server_authentication", &"<redacted>")
            .field("hello_params", &self.0.hello_params)
            .field("shared_secret", &self.0.shared_secret.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Resolve all external keystore and truststore references for one server.
///
/// The input server is expected to already have any config-local
/// `credentials-reference` bundles expanded inline.
///
/// # Errors
///
/// Returns an error if any external reference cannot be validated or resolved.
pub fn resolve_server(
    mut server: TacacsPlusServer,
    credential_resolver: Option<&dyn CredentialResolver>,
) -> Result<ResolvedServer> {
    validate_no_config_credential_references(&server)?;
    let ext_resolver = effective_resolver(credential_resolver);
    resolve_server_external_credentials(&mut server, ext_resolver).with_context(|| {
        format!("failed to resolve external credentials for server '{}'", server.name)
    })?;
    Ok(ResolvedServer::from_raw(server))
}

/// Resolve all external keystore and truststore references for many servers.
///
/// # Errors
///
/// Returns an error if any server contains an external reference that cannot
/// be validated or resolved.
pub fn resolve_servers<I>(
    servers: I,
    credential_resolver: Option<&dyn CredentialResolver>,
) -> Result<Vec<ResolvedServer>>
where
    I: IntoIterator<Item = TacacsPlusServer>,
{
    let ext_resolver = effective_resolver(credential_resolver);
    servers
        .into_iter()
        .map(|mut server| {
            validate_no_config_credential_references(&server)?;
            resolve_server_external_credentials(&mut server, ext_resolver).with_context(|| {
                format!("failed to resolve external credentials for server '{}'", server.name)
            })?;
            Ok(ResolvedServer::from_raw(server))
        })
        .collect()
}

/// Validate external keystore and truststore references for one server.
///
/// # Errors
///
/// Returns an aggregated error if any external reference on the server is not
/// resolvable by the supplied resolver.
pub fn validate_external_server_references(
    server: &TacacsPlusServer,
    resolver: Option<&dyn CredentialResolver>,
) -> Result<()> {
    let resolver = effective_resolver(resolver);
    let mut errors = Vec::new();

    if let Some(ref ci) = server.client_identity {
        validate_client_identity_external_refs(ci, &server.name, resolver, &mut errors);
    }

    if let Some(ref sa) = server.server_authentication {
        validate_server_auth_external_refs(sa, &server.name, resolver, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "external credential reference validation failed:\n  - {}",
            errors.join("\n  - ")
        ))
    }
}

/// Validate external keystore and truststore references for many servers.
///
/// # Errors
///
/// Returns an aggregated error if any external reference across the provided
/// servers is not resolvable by the supplied resolver.
pub fn validate_external_servers_references(
    servers: &[TacacsPlusServer],
    resolver: Option<&dyn CredentialResolver>,
) -> Result<()> {
    let resolver = effective_resolver(resolver);
    let mut errors = Vec::new();

    for server in servers {
        if let Some(ref ci) = server.client_identity {
            validate_client_identity_external_refs(ci, &server.name, resolver, &mut errors);
        }

        if let Some(ref sa) = server.server_authentication {
            validate_server_auth_external_refs(sa, &server.name, resolver, &mut errors);
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "external credential reference validation failed:\n  - {}",
            errors.join("\n  - ")
        ))
    }
}

fn resolve_server_external_credentials(
    server: &mut TacacsPlusServer,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref mut ci) = server.client_identity {
        resolve_client_identity_external_refs(ci, resolver)?;
    }

    if let Some(ref mut sa) = server.server_authentication {
        resolve_server_auth_external_refs(sa, resolver)?;
    }

    Ok(())
}

fn validate_no_config_credential_references(server: &TacacsPlusServer) -> Result<()> {
    let mut errors = Vec::new();

    if let Some(ref client_identity) = server.client_identity {
        if let Some(ref credentials_reference) = client_identity.credentials_reference {
            errors.push(format!(
                "server '{}': client-identity credentials-reference '{}' must be expanded before constructing ResolvedServer",
                server.name, credentials_reference,
            ));
        }
    }

    if let Some(ref server_authentication) = server.server_authentication {
        if let Some(ref credentials_reference) = server_authentication.credentials_reference {
            errors.push(format!(
                "server '{}': server-authentication credentials-reference '{}' must be expanded before constructing ResolvedServer",
                server.name, credentials_reference,
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "resolved server construction requires inline credential bundles:\n  - {}",
            errors.join("\n  - ")
        ))
    }
}

fn resolve_client_identity_external_refs(
    ci: &mut TlsClientClientIdentity,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref mut cert) = ci.certificate {
        tls::resolve_certificate_keystore_ref(cert, resolver)?;
    }
    if let Some(ref mut rpk_key) = ci.raw_private_key {
        rpk::resolve_raw_private_key_keystore_ref(rpk_key, resolver)?;
    }
    if let Some(ref mut epsk_key) = ci.tls13_epsk {
        epsk::resolve_epsk_keystore_ref(epsk_key, resolver)?;
    }
    Ok(())
}

fn resolve_server_auth_external_refs(
    sa: &mut TlsClientServerAuthentication,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref mut ca) = sa.ca_certs {
        tls::resolve_certs_truststore_ref(ca, resolver)?;
    }
    if let Some(ref mut ee) = sa.ee_certs {
        tls::resolve_certs_truststore_ref(ee, resolver)?;
    }
    if let Some(ref mut rpk_key) = sa.raw_public_keys {
        rpk::resolve_raw_public_keys_truststore_ref(rpk_key, resolver)?;
    }
    Ok(())
}

fn validate_client_identity_external_refs(
    ci: &TlsClientClientIdentity,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    tls::validate_certificate_refs(ci, server_name, resolver, errors);
    rpk::validate_rpk_keystore_refs(ci, server_name, resolver, errors);
    epsk::validate_epsk_keystore_refs(ci, server_name, resolver, errors);
}

fn validate_server_auth_external_refs(
    sa: &TlsClientServerAuthentication,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    tls::validate_server_auth_cert_refs(sa, server_name, resolver, errors);
    rpk::validate_rpk_truststore_refs(sa, server_name, resolver, errors);
}
