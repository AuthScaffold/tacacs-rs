use std::fmt;
use std::ops::Deref;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::generated::tacacs_plus::{
    ClientIdentityCertificate, RawPrivateKey, ServerAuthenticationCaCerts,
    ServerAuthenticationRawPublicKeys, TacacsPlus, TacacsPlusServer, Tls13Epsk,
    TlsClientClientIdentity, TlsClientServerAuthentication,
};

/// Internal no-op resolver returned when the caller passes `None`.
struct NoOpResolver;

impl CredentialResolver for NoOpResolver {
    fn resolve(&self, _key: &str, _ref_type: CredentialRefType) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Returns the caller's resolver or a no-op fallback.
fn effective_resolver(resolver: Option<&dyn CredentialResolver>) -> &dyn CredentialResolver {
    // SAFETY layout: this is a local borrow of a zero-sized static-lifetime
    // value, so the returned reference is valid for the duration of the call.
    static NOOP: NoOpResolver = NoOpResolver;
    resolver.unwrap_or(&NOOP)
}

/// Type of credential reference that requires resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRefType {
    /// Reference to a central keystore entry (asymmetric keys, certificates).
    Keystore,
    /// Reference to a central truststore entry (CA certificates, public keys).
    Truststore,
}

/// Trait for resolving external credential references to inline material.
///
/// Implementations handle credentials stored outside the YANG config itself:
/// - Keystore references: fetch from system keystore, filesystem, HSM, vault
/// - Truststore references: fetch from system truststore, filesystem
/// - Environment: retrieve from environment variables
///
/// Bundle references (`credentials-reference` pointing to `client-credentials`
/// or `server-credentials` within the same config) are resolved internally
/// by [`resolve_servers`] and do not go through this trait.
pub trait CredentialResolver: Send + Sync {
    /// Resolve a credential reference key to inline PEM or key material.
    ///
    /// The `ref_type` parameter lets implementations specialize by credential
    /// type (e.g., a keystore resolver only handles [`CredentialRefType::Keystore`]).
    ///
    /// Returns the resolved material (e.g., PEM certificate or key bytes).
    /// Returns `None` if this resolver does not handle this credential type.
    /// Returns an error if the reference is expected to be handled but fails.
    ///
    /// # Errors
    ///
    /// Returns an error if resolution fails or the credential is invalid.
    fn resolve(&self, key: &str, ref_type: CredentialRefType) -> Result<Option<String>>;

    /// Validate that a credential reference can be resolved.
    ///
    /// Called during the validation phase to catch missing credentials early.
    /// The default implementation attempts resolution and checks for errors.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential is invalid or cannot be resolved.
    fn validate(&self, key: &str, ref_type: CredentialRefType) -> Result<()> {
        let _ = self.resolve(key, ref_type)?;
        Ok(())
    }
}

/// A `TacacsPlusServer` with all credential references resolved to inline material.
///
/// This type deliberately does **not** implement `Serialize`, `Deserialize`, or
/// the auto-derived `Debug` from `TacacsPlusServer`. This prevents resolved key
/// material (private keys, PSK secrets, shared secrets) from being accidentally
/// leaked via logging, serialization, or debug formatting.
///
/// Access the full YANG model fields via [`Deref<Target = TacacsPlusServer>`].
/// Use [`into_inner`](ResolvedServer::into_inner) when you genuinely need the
/// raw `TacacsPlusServer` (e.g. for test assertions).
#[derive(Clone)]
pub struct ResolvedServer(TacacsPlusServer);

impl ResolvedServer {
    /// Wraps an already-resolved `TacacsPlusServer`.
    ///
    /// This is intended for callers that construct a `TacacsPlusServer` from
    /// non-YANG sources (e.g. CLI flags) where credential references are not
    /// applicable. No resolution is performed.
    #[must_use]
    pub fn from_raw(server: TacacsPlusServer) -> Self {
        Self(server)
    }

    /// Consumes the wrapper and returns the inner `TacacsPlusServer`.
    ///
    /// Use this when you genuinely need the raw type, such as in test
    /// assertions. The naming makes the intent explicit.
    #[must_use]
    pub fn into_inner(self) -> TacacsPlusServer {
        self.0
    }

    /// Returns the `address:port` socket address string.
    #[must_use]
    pub fn socket_address(&self) -> String {
        format!("{}:{}", self.0.address, self.0.port)
    }

    /// Returns the connection timeout as a [`Duration`].
    #[must_use]
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs(u64::from(self.0.timeout))
    }

    /// Returns the obfuscation key bytes, if a shared secret is configured.
    #[must_use]
    pub fn obfuscation_key(&self) -> Option<Vec<u8>> {
        self.0.shared_secret.as_ref().map(|s| s.as_bytes().to_vec())
    }

    /// Returns `true` if this server uses TLS (certificate or PSK).
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.0.client_identity.is_some()
            || self.0.server_authentication.is_some()
            || self.0.hello_params.is_some()
    }

    /// Returns `true` if this server uses legacy TACACS+ obfuscation.
    #[must_use]
    pub fn is_obfuscation(&self) -> bool {
        !self.is_tls()
    }

    /// Returns `true` if SNI is enabled for this server.
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

/// Resolve all servers in a config, materializing credential references into
/// inline material.
///
/// Resolution happens in two stages:
/// 1. **Bundle references** — `credentials-reference` fields are resolved
///    against the config's own `client-credentials` and `server-credentials`
///    lists. The bundle's inline fields are copied into the server entry and
///    the reference is cleared.
/// 2. **External references** — `central-keystore-reference` and
///    `central-truststore-reference` fields are delegated to the caller's
///    [`CredentialResolver`].
///
/// Inline material (`cleartext-private-key`, `cert-data`, etc.) is kept as-is.
///
/// Pass `None` for `credential_resolver` when no external keystore/truststore
/// references need resolution (bundle references are always handled internally).
///
/// # Errors
///
/// Returns an error if any credential reference cannot be resolved (fail-fast).
pub fn resolve_servers(
    config: &TacacsPlus,
    credential_resolver: Option<&dyn CredentialResolver>,
) -> Result<Vec<ResolvedServer>> {
    let ext_resolver = effective_resolver(credential_resolver);
    config
        .server
        .iter()
        .map(|server| {
            let mut resolved = server.clone();
            resolve_server_credentials(&mut resolved, config, ext_resolver).with_context(|| {
                format!("failed to resolve credentials for server '{}'", server.name)
            })?;
            Ok(ResolvedServer(resolved))
        })
        .collect()
}

/// Resolve a single server by name, materializing credential references into
/// inline material.
///
/// Pass `None` for `credential_resolver` when no external keystore/truststore
/// references need resolution (bundle references are always handled internally).
///
/// # Errors
///
/// Returns an error if the server is not found or credential resolution fails.
pub fn resolve_server(
    config: &TacacsPlus,
    server_name: &str,
    credential_resolver: Option<&dyn CredentialResolver>,
) -> Result<ResolvedServer> {
    let ext_resolver = effective_resolver(credential_resolver);
    let server = config
        .server
        .iter()
        .find(|s| s.name == server_name)
        .ok_or_else(|| anyhow::anyhow!("server '{server_name}' not found"))?;

    let mut resolved = server.clone();
    resolve_server_credentials(&mut resolved, config, ext_resolver)
        .with_context(|| format!("failed to resolve credentials for server '{server_name}'"))?;
    Ok(ResolvedServer(resolved))
}

/// Validate all credential references in a config are resolvable.
///
/// Unlike [`resolve_servers`] which fails on the first error, this function
/// collects all validation errors across all servers and returns them together.
///
/// Pass `None` for `resolver` when no external keystore/truststore references
/// need validation (bundle references are always validated against the config).
///
/// # Errors
///
/// Returns an error containing all validation failures if any credential
/// reference cannot be resolved.
pub fn validate_credential_references(
    config: &TacacsPlus,
    resolver: Option<&dyn CredentialResolver>,
) -> Result<()> {
    let resolver = effective_resolver(resolver);
    let mut errors: Vec<String> = Vec::new();

    for server in &config.server {
        // Check client-identity credentials-reference (bundle)
        if let Some(ref ci) = server.client_identity {
            if let Some(ref cred_ref) = ci.credentials_reference {
                if !config.client_credentials.iter().any(|c| c.id == *cred_ref) {
                    errors.push(format!(
                        "server '{}': client-identity credentials-reference '{}' not found in client-credentials",
                        server.name, cred_ref,
                    ));
                }
            }
            validate_client_identity_external_refs(ci, &server.name, resolver, &mut errors);
        }

        // Check server-authentication credentials-reference (bundle)
        if let Some(ref sa) = server.server_authentication {
            if let Some(ref cred_ref) = sa.credentials_reference {
                if !config.server_credentials.iter().any(|c| c.id == *cred_ref) {
                    errors.push(format!(
                        "server '{}': server-authentication credentials-reference '{}' not found in server-credentials",
                        server.name, cred_ref,
                    ));
                }
            }
            validate_server_auth_external_refs(sa, &server.name, resolver, &mut errors);
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

// ---------------------------------------------------------------------------
// Internal resolution logic
// ---------------------------------------------------------------------------

/// Resolves all credential references in a single server entry, mutating it
/// in place to contain only inline material.
fn resolve_server_credentials(
    server: &mut TacacsPlusServer,
    config: &TacacsPlus,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    // Stage 1: Resolve client-identity bundle reference
    if let Some(ref mut ci) = server.client_identity {
        if let Some(ref cred_ref) = ci.credentials_reference {
            let bundle = config
                .client_credentials
                .iter()
                .find(|c| c.id == *cred_ref)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "client-identity credentials-reference '{cred_ref}' not found in client-credentials"
                    )
                })?;

            // Copy bundle's inline fields into the server's client-identity
            ci.certificate = bundle.certificate.clone();
            ci.raw_private_key = bundle.raw_private_key.clone();
            ci.tls13_epsk = bundle.tls13_epsk.clone();
            ci.credentials_reference = None;
        }

        // Stage 2: Resolve external keystore references within client-identity
        resolve_client_identity_external_refs(ci, resolver)?;
    }

    // Stage 1: Resolve server-authentication bundle reference
    if let Some(ref mut sa) = server.server_authentication {
        if let Some(ref cred_ref) = sa.credentials_reference {
            let bundle = config
                .server_credentials
                .iter()
                .find(|c| c.id == *cred_ref)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "server-authentication credentials-reference '{cred_ref}' not found in server-credentials"
                    )
                })?;

            // Copy bundle's inline fields into the server's server-authentication
            sa.ca_certs = bundle.ca_certs.clone();
            sa.ee_certs = bundle.ee_certs.clone();
            sa.raw_public_keys = bundle.raw_public_keys.clone();
            sa.tls13_epsks = bundle.tls13_epsks;
            sa.credentials_reference = None;
        }

        // Stage 2: Resolve external truststore references within server-authentication
        resolve_server_auth_external_refs(sa, resolver)?;
    }

    Ok(())
}

/// Resolves external keystore references in the client-identity subtree.
fn resolve_client_identity_external_refs(
    ci: &mut TlsClientClientIdentity,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref mut cert) = ci.certificate {
        resolve_certificate_keystore_ref(cert, resolver)?;
    }
    if let Some(ref mut rpk) = ci.raw_private_key {
        resolve_raw_private_key_keystore_ref(rpk, resolver)?;
    }
    if let Some(ref mut epsk) = ci.tls13_epsk {
        resolve_epsk_keystore_ref(epsk, resolver)?;
    }
    Ok(())
}

/// Resolves external truststore references in the server-authentication subtree.
fn resolve_server_auth_external_refs(
    sa: &mut TlsClientServerAuthentication,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref mut ca) = sa.ca_certs {
        resolve_ca_certs_truststore_ref(ca, resolver)?;
    }
    if let Some(ref mut ee) = sa.ee_certs {
        resolve_ca_certs_truststore_ref(ee, resolver)?;
    }
    if let Some(ref mut rpk) = sa.raw_public_keys {
        resolve_raw_public_keys_truststore_ref(rpk, resolver)?;
    }
    Ok(())
}

fn resolve_certificate_keystore_ref(
    cert: &mut ClientIdentityCertificate,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ks_ref) = cert.central_keystore_reference {
        let key = ks_ref.asymmetric_key.as_deref().unwrap_or_default();
        if let Some(material) = resolver
            .resolve(key, CredentialRefType::Keystore)
            .context("failed to resolve central-keystore-reference for certificate")?
        {
            // Store the resolved material as PEM in the inline definition
            cert.inline_definition =
                Some(crate::generated::keystore::EndEntityCertWithKeyInlineDefinition {
                    public_key_format: None,
                    public_key: None,
                    private_key_format: None,
                    cleartext_private_key: Some(material),
                    hidden_private_key: None,
                    encrypted_private_key: None,
                    cert_data: ks_ref.certificate.clone(),
                });
            cert.central_keystore_reference = None;
        }
    }
    Ok(())
}

fn resolve_raw_private_key_keystore_ref(
    rpk: &mut RawPrivateKey,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ks_ref) = rpk.central_keystore_reference {
        if let Some(material) = resolver
            .resolve(ks_ref, CredentialRefType::Keystore)
            .context("failed to resolve central-keystore-reference for raw-private-key")?
        {
            rpk.inline_definition =
                Some(crate::generated::keystore::AsymmetricKeyInlineDefinition {
                    public_key_format: None,
                    public_key: None,
                    private_key_format: None,
                    cleartext_private_key: Some(material),
                    hidden_private_key: None,
                    encrypted_private_key: None,
                });
            rpk.central_keystore_reference = None;
        }
    }
    Ok(())
}

fn resolve_epsk_keystore_ref(
    epsk: &mut Tls13Epsk,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ks_ref) = epsk.central_keystore_reference {
        if let Some(material) = resolver
            .resolve(ks_ref, CredentialRefType::Keystore)
            .context("failed to resolve central-keystore-reference for tls13-epsk")?
        {
            epsk.inline_definition =
                Some(crate::generated::keystore::SymmetricKeyInlineDefinition {
                    key_format: None,
                    cleartext_symmetric_key: Some(material),
                    hidden_symmetric_key: None,
                    encrypted_symmetric_key: None,
                });
            epsk.central_keystore_reference = None;
        }
    }
    Ok(())
}

fn resolve_ca_certs_truststore_ref(
    ca: &mut ServerAuthenticationCaCerts,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ts_ref) = ca.central_truststore_reference {
        if let Some(material) = resolver
            .resolve(ts_ref, CredentialRefType::Truststore)
            .context("failed to resolve central-truststore-reference for ca-certs")?
        {
            ca.inline_definition = Some(crate::generated::truststore::CertsInlineDefinition {
                certificate: vec![crate::generated::truststore::CertsCertificate {
                    name: ts_ref.clone(),
                    cert_data: material,
                }],
            });
            ca.central_truststore_reference = None;
        }
    }
    Ok(())
}

fn resolve_raw_public_keys_truststore_ref(
    rpk: &mut ServerAuthenticationRawPublicKeys,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ts_ref) = rpk.central_truststore_reference {
        if let Some(material) = resolver
            .resolve(ts_ref, CredentialRefType::Truststore)
            .context("failed to resolve central-truststore-reference for raw-public-keys")?
        {
            rpk.inline_definition =
                Some(crate::generated::truststore::PublicKeysInlineDefinition {
                    public_key: vec![crate::generated::truststore::PublicKeysPublicKey {
                        name: ts_ref.clone(),
                        public_key_format: String::new(),
                        public_key: material,
                    }],
                });
            rpk.central_truststore_reference = None;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation helpers (collect-all errors)
// ---------------------------------------------------------------------------

fn validate_client_identity_external_refs(
    ci: &TlsClientClientIdentity,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref cert) = ci.certificate {
        if let Some(ref ks_ref) = cert.central_keystore_reference {
            let key = ks_ref.asymmetric_key.as_deref().unwrap_or_default();
            if let Err(e) = resolver.validate(key, CredentialRefType::Keystore) {
                errors.push(format!(
                    "server '{server_name}': certificate central-keystore-reference: {e}",
                ));
            }
        }
    }
    if let Some(ref rpk) = ci.raw_private_key {
        if let Some(ref ks_ref) = rpk.central_keystore_reference {
            if let Err(e) = resolver.validate(ks_ref, CredentialRefType::Keystore) {
                errors.push(format!(
                    "server '{server_name}': raw-private-key central-keystore-reference: {e}",
                ));
            }
        }
    }
    if let Some(ref epsk) = ci.tls13_epsk {
        if let Some(ref ks_ref) = epsk.central_keystore_reference {
            if let Err(e) = resolver.validate(ks_ref, CredentialRefType::Keystore) {
                errors.push(format!(
                    "server '{server_name}': tls13-epsk central-keystore-reference: {e}",
                ));
            }
        }
    }
}

fn validate_server_auth_external_refs(
    sa: &TlsClientServerAuthentication,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref ca) = sa.ca_certs {
        if let Some(ref ts_ref) = ca.central_truststore_reference {
            if let Err(e) = resolver.validate(ts_ref, CredentialRefType::Truststore) {
                errors.push(format!(
                    "server '{server_name}': ca-certs central-truststore-reference: {e}",
                ));
            }
        }
    }
    if let Some(ref ee) = sa.ee_certs {
        if let Some(ref ts_ref) = ee.central_truststore_reference {
            if let Err(e) = resolver.validate(ts_ref, CredentialRefType::Truststore) {
                errors.push(format!(
                    "server '{server_name}': ee-certs central-truststore-reference: {e}",
                ));
            }
        }
    }
    if let Some(ref rpk) = sa.raw_public_keys {
        if let Some(ref ts_ref) = rpk.central_truststore_reference {
            if let Err(e) = resolver.validate(ts_ref, CredentialRefType::Truststore) {
                errors.push(format!(
                    "server '{server_name}': raw-public-keys central-truststore-reference: {e}",
                ));
            }
        }
    }
}
