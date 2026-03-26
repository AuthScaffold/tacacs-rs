use serde::Deserialize;

// ============================================================================
// ietf-crypto-types: Key material types
// ============================================================================

/// Inline asymmetric key definition from ietf-keystore.
///
/// Used for both certificate-based and raw-public-key client identity.
/// Maps to the YANG `inline-or-keystore/inline/inline-definition` for
/// asymmetric keys.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AsymmetricKeyInline {
    pub public_key_format: Option<String>,
    /// Base64-encoded public key.
    pub public_key: Option<String>,
    pub private_key_format: Option<String>,
    /// Base64-encoded cleartext private key (PEM or DER).
    pub cleartext_private_key: Option<String>,
    /// Base64-encoded end-entity certificate (CMS/PEM/DER).
    /// Only present for `certificate` auth type, not `raw-public-key`.
    pub cert_data: Option<String>,
}

/// Inline symmetric key definition from ietf-keystore.
///
/// Used for TLS 1.3 EPSK identity.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SymmetricKeyInline {
    pub key_format: Option<String>,
    /// Base64-encoded cleartext symmetric key.
    pub cleartext_symmetric_key: Option<String>,
}

// ============================================================================
// ietf-truststore: Certificate and public key bag types
// ============================================================================

/// A single named certificate entry in a certificate bag.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CertificateBagEntry {
    /// Unique name within the bag.
    pub name: String,
    /// Base64-encoded certificate data (trust-anchor-cert-cms).
    pub cert_data: String,
}

/// A bag of certificates, used for CA certs and EE certs.
///
/// Maps to `inline-or-truststore/inline/inline-definition` for certificates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CertificateBag {
    pub inline_definition: Option<CertificateBagInline>,
}

/// Inline certificate bag content.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CertificateBagInline {
    pub certificate: Vec<CertificateBagEntry>,
}

/// A single named public key entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PublicKeyEntry {
    pub name: String,
    pub public_key_format: String,
    /// Base64-encoded public key.
    pub public_key: String,
}

/// A bag of raw public keys.
///
/// Maps to `inline-or-truststore/inline/inline-definition` for public keys.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PublicKeyBag {
    pub inline_definition: Option<PublicKeyBagInline>,
}

/// Inline public key bag content.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PublicKeyBagInline {
    pub public_key: Vec<PublicKeyEntry>,
}

// ============================================================================
// ietf-tls-client: Client identity types
// ============================================================================

/// Client identity authentication type choice.
///
/// Maps to the YANG `choice auth-type` under client-identity.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientAuthType {
    /// X.509 certificate identity with inline key + cert data.
    Certificate(CertificateClientIdentity),
    /// Raw public key identity.
    RawPublicKey(RawPublicKeyClientIdentity),
    /// TLS 1.3 External Pre-Shared Key.
    Tls13Epsk(Tls13EpskClientIdentity),
}

/// Certificate-based client identity wrapping an asymmetric key with cert.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CertificateClientIdentity {
    pub inline_definition: Option<AsymmetricKeyInline>,
}

/// Raw public key client identity wrapping an asymmetric key without cert.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RawPublicKeyClientIdentity {
    pub inline_definition: Option<AsymmetricKeyInline>,
}

/// TLS 1.3 EPSK client identity.
///
/// Maps to the YANG `tls13-epsk` container under client-identity.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Tls13EpskClientIdentity {
    pub inline_definition: Option<SymmetricKeyInline>,
    pub external_identity: String,
    #[serde(default = "default_epsk_hash")]
    pub hash: String,
    pub context: Option<String>,
    pub target_protocol: Option<u16>,
    pub target_kdf: Option<u16>,
}

fn default_epsk_hash() -> String {
    "sha-256".to_owned()
}

// ============================================================================
// Client identity with ref-or-explicit
// ============================================================================

/// Client identity with optional credential reference.
///
/// Maps to the YANG `client-identity` container with `ref-or-explicit` choice.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientIdentityWithRef {
    /// Reference to a named `client-credentials` entry.
    pub credentials_reference: Option<String>,
    /// Explicit inline auth type (used when no reference is provided).
    #[serde(flatten)]
    pub auth_type: Option<ClientAuthType>,
}

// ============================================================================
// ietf-tls-client: Server authentication types
// ============================================================================

/// Server authentication configuration.
///
/// Maps to `server-authentication` under TLS security. Any combination
/// of CA certs, EE certs, raw public keys, and EPSK is additive.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerAuthentication {
    pub ca_certs: Option<CertificateBag>,
    pub ee_certs: Option<CertificateBag>,
    pub raw_public_keys: Option<PublicKeyBag>,
    pub tls13_epsks: Option<bool>,
}

/// Server authentication with optional credential reference.
///
/// Maps to `server-authentication` with `ref-or-explicit` choice.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerAuthenticationWithRef {
    pub credentials_reference: Option<String>,
    #[serde(flatten)]
    pub inline: Option<ServerAuthentication>,
}

// ============================================================================
// ietf-tls-common: Hello parameters
// ============================================================================

/// TLS hello parameters.
///
/// Constrains TLS versions and cipher suites. Per the YANG model,
/// TLS versions must be >= 1.3.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HelloParams {
    pub tls_versions: Option<TlsVersions>,
    pub cipher_suites: Option<CipherSuites>,
}

/// TLS version range constraints.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlsVersions {
    pub min: Option<String>,
    pub max: Option<String>,
}

/// Cipher suite list.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CipherSuites {
    pub cipher_suite: Vec<String>,
}

// ============================================================================
// Top-level TLS client config
// ============================================================================

/// TLS client configuration matching the YANG `tls` security choice.
///
/// Contains client identity, server authentication, and TLS hello parameters.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlsClientConfig {
    pub client_identity: Option<ClientIdentityWithRef>,
    pub server_authentication: ServerAuthenticationWithRef,
    pub hello_params: Option<HelloParams>,
}
