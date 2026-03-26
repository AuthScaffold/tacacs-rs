use serde::Deserialize;

/// TLS client configuration matching the YANG `grouping tls-client`.
///
/// Contains client identity, server authentication, and TLS hello parameters.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlsClientConfig {
    /// Client identity credentials (certificate, RPK, or EPSK).
    pub client_identity: Option<ClientIdentityWithRef>,
    /// How to authenticate the server's certificate/identity.
    pub server_authentication: ServerAuthenticationWithRef,
    /// TLS hello parameters (version constraints, cipher suites).
    pub hello_params: Option<HelloParams>,
}

/// Client identity with optional credential reference.
///
/// Maps to the YANG `grouping client-identity-with-ref`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientIdentityWithRef {
    /// Reference to a named client-credentials entry.
    pub credentials_reference: Option<String>,

    /// Inline client identity (used when no reference is provided).
    #[serde(flatten)]
    pub inline: Option<ClientIdentity>,
}

/// Client identity authentication type.
///
/// Maps to the YANG `grouping client-identity` choice.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientIdentity {
    /// X.509 certificate-based identity.
    Certificate(CertificateIdentity),
    /// Raw public key identity (future support).
    RawPublicKey(RawPublicKeyIdentity),
    /// TLS 1.3 External Pre-Shared Key identity (future support).
    Tls13Epsk(Tls13EpskIdentity),
}

/// Certificate-based client identity.
///
/// References an end-entity certificate with its private key.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CertificateIdentity {
    /// Path to the certificate file (PEM or DER).
    pub cert_file: Option<String>,
    /// Path to the private key file (PEM or DER).
    pub key_file: Option<String>,
    /// Inline PEM-encoded certificate chain.
    pub cert_data: Option<String>,
    /// Inline PEM-encoded private key.
    pub key_data: Option<String>,
}

/// Raw public key identity (stub for future implementation).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RawPublicKeyIdentity {
    /// Inline public key data.
    pub public_key: Option<String>,
    /// Inline private key data.
    pub private_key: Option<String>,
}

/// TLS 1.3 External Pre-Shared Key identity.
///
/// Maps to the YANG `grouping tls13-epsk`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Tls13EpskIdentity {
    /// The pre-shared key material.
    pub key: Option<String>,
    /// External identity label for the PSK.
    pub external_identity: String,
    /// Hash algorithm (default: sha-256).
    #[serde(default = "default_hash")]
    pub hash: String,
    /// Optional context for EPSK derivation.
    pub context: Option<String>,
    /// Target protocol identifier.
    pub target_protocol: Option<u16>,
    /// Target KDF identifier.
    pub target_kdf: Option<u16>,
}

fn default_hash() -> String {
    "sha-256".to_owned()
}

/// Server authentication with optional credential reference.
///
/// Maps to the YANG `grouping server-authentication-with-ref`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerAuthenticationWithRef {
    /// Reference to a named server-credentials entry.
    pub credentials_reference: Option<String>,

    /// Inline server authentication config.
    #[serde(flatten)]
    pub inline: Option<ServerAuthentication>,
}

/// Server authentication configuration.
///
/// Maps to the YANG `grouping server-authentication`.
/// Any combination of methods is additive and unordered.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerAuthentication {
    /// CA certificates for chain-of-trust validation.
    pub ca_certs: Option<CertificateStore>,
    /// End-entity certificates for exact-match validation.
    pub ee_certs: Option<CertificateStore>,
    /// Raw public keys for exact-match validation (future support).
    pub raw_public_keys: Option<PublicKeyStore>,
    /// Whether TLS 1.3 EPSK server authentication is enabled.
    pub tls13_epsks: Option<bool>,
}

/// A store of certificates (CA or EE).
///
/// Certificates can be provided inline or by file path.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CertificateStore {
    /// Paths to PEM or DER certificate files.
    pub cert_files: Option<Vec<String>>,
    /// Inline PEM-encoded certificates.
    pub cert_data: Option<Vec<String>>,
}

/// A store of raw public keys (stub for future implementation).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PublicKeyStore {
    /// Inline public key data.
    pub keys: Option<Vec<String>>,
}

/// TLS hello parameters matching the YANG `grouping hello-params`.
///
/// Constrains TLS versions and cipher suites. Per the YANG model,
/// TLS versions must be >= 1.3.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HelloParams {
    /// TLS version constraints.
    pub tls_versions: Option<TlsVersions>,
    /// Allowed cipher suites.
    pub cipher_suites: Option<Vec<String>>,
}

/// TLS version range constraints.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlsVersions {
    /// Minimum TLS version (must be >= "tls13").
    pub min: Option<String>,
    /// Maximum TLS version (must be >= "tls13").
    pub max: Option<String>,
}
