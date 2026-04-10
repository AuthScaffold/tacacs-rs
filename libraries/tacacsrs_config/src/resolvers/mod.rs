use std::fmt;
use std::ops::Deref;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::generated::crypto_types::{PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat};
use crate::generated::tacacs_plus::{
    TacacsPlus, TacacsPlusServer, TlsClientClientIdentity, TlsClientServerAuthentication,
};

mod epsk;
mod rpk;
mod tls;

/// Internal no-op resolver returned when the caller passes `None`.
///
/// Returns an error for every reference, indicating that no credential
/// resolver is available. This ensures external references are never
/// silently ignored.
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

/// Returns the caller's resolver or a no-op fallback that rejects all lookups.
fn effective_resolver(resolver: Option<&dyn CredentialResolver>) -> &dyn CredentialResolver {
    // SAFETY layout: this is a local borrow of a zero-sized static-lifetime
    // value, so the returned reference is valid for the duration of the call.
    static NOOP: NoOpResolver = NoOpResolver;
    resolver.unwrap_or(&NOOP)
}

/// Resolved X.509 end-entity certificate with its associated key pair.
///
/// Returned by [`CredentialResolver::resolve_keystore_certificate`]. This
/// represents a single certificate from the central keystore that is paired
/// with an asymmetric key entry.
#[derive(Debug, Clone)]
pub struct X509CertificateMaterial {
    /// The certificate data (e.g. base64-encoded DER or PEM).
    pub cert_data: String,
    /// The asymmetric key material associated with this certificate.
    pub key_material: AsymmetricKeyMaterial,
}

/// A single named certificate entry from a certificate bag.
///
/// Used by [`CredentialResolver::resolve_certificate_bag`] to return one or
/// more trust anchor certificates from a truststore certificate bag.
#[derive(Debug, Clone)]
pub struct CertificateEntry {
    /// An arbitrary name for this certificate.
    pub name: String,
    /// The certificate data (e.g. base64-encoded DER or PEM).
    pub cert_data: String,
}

/// Resolved asymmetric key material from a central keystore entry.
///
/// A single keystore entry for an asymmetric key contains both the public and
/// private halves plus their format identities. This struct carries all fields
/// so that [`resolve_asymmetric_key`](CredentialResolver::resolve_asymmetric_key)
/// can return everything in one call.
#[derive(Debug, Clone)]
pub struct AsymmetricKeyMaterial {
    /// The private key material (e.g. base64-encoded DER or PEM).
    pub cleartext_private_key: String,
    /// The public key material, if available.
    pub public_key: Option<String>,
    /// The private key encoding format.
    pub private_key_format: Option<PrivateKeyFormat>,
    /// The public key encoding format.
    pub public_key_format: Option<PublicKeyFormat>,
}

/// Resolved symmetric key material from a central keystore entry.
///
/// A keystore entry for a symmetric key contains the key material and its
/// format identity. This struct carries both so that
/// [`resolve_symmetric_key`](CredentialResolver::resolve_symmetric_key) can
/// return everything in one call.
#[derive(Debug, Clone)]
pub struct SymmetricKeyMaterial {
    /// The symmetric key material (e.g. base64-encoded octet string).
    pub cleartext_symmetric_key: String,
    /// The symmetric key encoding format.
    pub key_format: Option<SymmetricKeyFormat>,
}

/// Resolved public key material from a central truststore entry.
///
/// A truststore entry for a public key bag contains one or more public keys,
/// each with its format identity. This struct represents a single resolved
/// public key entry.
#[derive(Debug, Clone)]
pub struct TruststorePublicKeyMaterial {
    /// An arbitrary name for this public key.
    pub name: String,
    /// The public key material (e.g. base64-encoded DER).
    pub public_key: String,
    /// The public key encoding format.
    pub public_key_format: PublicKeyFormat,
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
    /// Resolve an end-entity certificate and its key pair from the central
    /// keystore.
    ///
    /// The keystore entry contains a certificate associated with an asymmetric
    /// key. The returned [`X509CertificateMaterial`] carries both the
    /// certificate data and the full key pair with format identities.
    ///
    /// # Errors
    ///
    /// Returns an error if the keystore entry cannot be resolved.
    fn resolve_keystore_certificate(&self, key: &str) -> Result<Option<X509CertificateMaterial>>;

    /// Resolve a certificate bag from the central truststore.
    ///
    /// A truststore certificate bag contains one or more trust anchor
    /// certificates (CA certs or EE certs). This method returns all
    /// certificates in the referenced bag.
    ///
    /// # Errors
    ///
    /// Returns an error if the truststore entry cannot be resolved.
    fn resolve_certificate_bag(&self, key: &str) -> Result<Option<Vec<CertificateEntry>>>;

    /// Resolve an asymmetric key entry from the central keystore.
    ///
    /// Used for `raw-private-key` client identity resolution. For certificate
    /// client identity, prefer [`resolve_keystore_certificate`] which returns
    /// both the certificate and key material in one call.
    ///
    /// # Errors
    ///
    /// Returns an error if the keystore entry cannot be resolved.
    fn resolve_asymmetric_key(&self, key: &str) -> Result<Option<AsymmetricKeyMaterial>>;

    /// Resolve a symmetric key entry from the central keystore.
    ///
    /// Used for `tls13-epsk` client identity resolution.
    ///
    /// # Errors
    ///
    /// Returns an error if the keystore entry cannot be resolved.
    fn resolve_symmetric_key(&self, key: &str) -> Result<Option<SymmetricKeyMaterial>>;

    /// Resolve a public key bag from the central truststore.
    ///
    /// A truststore public key bag contains one or more public keys, each
    /// with its format identity. This method returns all public keys in the
    /// referenced bag. Used for `raw-public-keys` server authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if the truststore entry cannot be resolved.
    fn resolve_public_key_bag(&self, key: &str)
        -> Result<Option<Vec<TruststorePublicKeyMaterial>>>;

    /// Validate that a keystore certificate reference is known.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate is unknown.
    fn validate_keystore_certificate(&self, key: &str) -> Result<()>;

    /// Validate that an asymmetric key reference is known in the keystore.
    ///
    /// # Errors
    ///
    /// Returns an error if the asymmetric key is unknown.
    fn validate_asymmetric_key(&self, key: &str) -> Result<()>;

    /// Validate that a symmetric key reference is known in the keystore.
    ///
    /// # Errors
    ///
    /// Returns an error if the symmetric key is unknown.
    fn validate_symmetric_key(&self, key: &str) -> Result<()>;

    /// Validate that a truststore certificate bag reference is known.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate bag is unknown.
    fn validate_certificate_bag(&self, key: &str) -> Result<()>;

    /// Validate that a truststore public key bag reference is known.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key bag is unknown.
    fn validate_public_key_bag(&self, key: &str) -> Result<()>;
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
    ///
    /// IPv6 addresses are wrapped in brackets to produce a valid socket
    /// address (e.g. `[2001:db8::1]:49`).
    #[must_use]
    pub fn socket_address(&self) -> String {
        if self.0.address.contains(':') {
            format!("[{}]:{}", self.0.address, self.0.port)
        } else {
            format!("{}:{}", self.0.address, self.0.port)
        }
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

/// Resolves external truststore references in the server-authentication subtree.
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

// ---------------------------------------------------------------------------
// Validation helpers (collect-all errors)
// ---------------------------------------------------------------------------

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
