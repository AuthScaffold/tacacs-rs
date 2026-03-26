// Auto-generated from YANG modules by yang2rust.py -- DO NOT EDIT

#![allow(dead_code)]

use serde::Deserialize;

// --- Type aliases (from YANG typedefs) ---

pub type TacacsPlusServerType = String;
pub type ClientCredentialsRef = String;
pub type ServerCredentialsRef = String;

// --- Enums (from YANG enumerations) ---

/// For externally established PSKs, the Hash algorithm must be
/// set when the PSK is established or default to SHA-256 if no
/// such algorithm is defined.
#[derive(Debug, Clone, Deserialize)]
pub enum EpskSupportedHash {
    /// The SHA-256 hash.
    #[serde(rename = "sha-256")]
    Sha256,
    /// The SHA-384 hash.
    #[serde(rename = "sha-384")]
    Sha384,
}

// --- Structs (from YANG containers / lists) ---

/// An empty container enabling a reference to the key that
/// encrypted the value to be augmented in.  The referenced
/// key MUST be a symmetric key or an asymmetric key.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientCredentialsCertificateInlineDefinitionEncryptedPrivateKeyEncryptedBy {
}

/// A container for the encrypted asymmetric private key
/// value.  The interpretation of the 'encrypted-value'
/// node is via the 'private-key-format' node
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientCredentialsCertificateInlineDefinitionEncryptedPrivateKey {
    /// An empty container enabling a reference to the key that
    #[serde(rename = "encrypted-by")]
    #[serde(default)]
    pub encrypted_by: Option<ClientCredentialsCertificateInlineDefinitionEncryptedPrivateKeyEncryptedBy>,
    /// Identifies the format of the 'encrypted-value' leaf.
    #[serde(rename = "encrypted-value-format")]
    pub encrypted_value_format: String,
    /// The value, encrypted using the referenced symmetric
    #[serde(rename = "encrypted-value")]
    pub encrypted_value: String,
}

/// A container to hold the local key definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientCredentialsCertificateInlineDefinition {
    /// Identifies the public key's format.  Implementations SHOULD
    #[serde(rename = "public-key-format")]
    #[serde(default)]
    pub public_key_format: Option<String>,
    /// The binary value of the public key.  The interpretation
    #[serde(rename = "public-key")]
    #[serde(default)]
    pub public_key: Option<String>,
    /// Identifies the private key's format.  Implementations SHOULD
    #[serde(rename = "private-key-format")]
    #[serde(default)]
    pub private_key_format: Option<String>,
    /// The value of the binary key.  The key's value is
    #[serde(rename = "cleartext-private-key")]
    #[serde(default)]
    pub cleartext_private_key: Option<String>,
    /// A hidden key.  It is of type 'empty' as its value is
    #[serde(rename = "hidden-private-key")]
    #[serde(default)]
    pub hidden_private_key: Option<bool>,
    /// A container for the encrypted asymmetric private key
    #[serde(rename = "encrypted-private-key")]
    #[serde(default)]
    pub encrypted_private_key: Option<ClientCredentialsCertificateInlineDefinitionEncryptedPrivateKey>,
    /// The binary certificate data for this certificate.
    #[serde(rename = "cert-data")]
    #[serde(default)]
    pub cert_data: Option<String>,
}

/// A reference to a specific certificate associated with
/// an asymmetric key stored in the central keystore.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientCredentialsCertificateCentralKeystoreReference {
    /// A reference to an asymmetric key in the keystore.
    #[serde(rename = "asymmetric-key")]
    #[serde(default)]
    pub asymmetric_key: Option<String>,
    /// A reference to a specific certificate of the
    #[serde(default)]
    pub certificate: Option<String>,
}

/// Specifies the client identity using a certificate.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientCredentialsCertificate {
    /// A container to hold the local key definition.
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<ClientCredentialsCertificateInlineDefinition>,
    /// A reference to a specific certificate associated with
    #[serde(rename = "central-keystore-reference")]
    #[serde(default)]
    pub central_keystore_reference: Option<ClientCredentialsCertificateCentralKeystoreReference>,
}

/// An empty container enabling a reference to the key that
/// encrypted the value to be augmented in.  The referenced
/// key MUST be a symmetric key or an asymmetric key.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RawPrivateKeyInlineDefinitionEncryptedPrivateKeyEncryptedBy {
}

/// A container for the encrypted asymmetric private key
/// value.  The interpretation of the 'encrypted-value'
/// node is via the 'private-key-format' node
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RawPrivateKeyInlineDefinitionEncryptedPrivateKey {
    /// An empty container enabling a reference to the key that
    #[serde(rename = "encrypted-by")]
    #[serde(default)]
    pub encrypted_by: Option<RawPrivateKeyInlineDefinitionEncryptedPrivateKeyEncryptedBy>,
    /// Identifies the format of the 'encrypted-value' leaf.
    #[serde(rename = "encrypted-value-format")]
    pub encrypted_value_format: String,
    /// The value, encrypted using the referenced symmetric
    #[serde(rename = "encrypted-value")]
    pub encrypted_value: String,
}

/// A container to hold the local key definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RawPrivateKeyInlineDefinition {
    /// Identifies the public key's format.  Implementations SHOULD
    #[serde(rename = "public-key-format")]
    #[serde(default)]
    pub public_key_format: Option<String>,
    /// The binary value of the public key.  The interpretation
    #[serde(rename = "public-key")]
    #[serde(default)]
    pub public_key: Option<String>,
    /// Identifies the private key's format.  Implementations SHOULD
    #[serde(rename = "private-key-format")]
    #[serde(default)]
    pub private_key_format: Option<String>,
    /// The value of the binary key.  The key's value is
    #[serde(rename = "cleartext-private-key")]
    #[serde(default)]
    pub cleartext_private_key: Option<String>,
    /// A hidden key.  It is of type 'empty' as its value is
    #[serde(rename = "hidden-private-key")]
    #[serde(default)]
    pub hidden_private_key: Option<bool>,
    /// A container for the encrypted asymmetric private key
    #[serde(rename = "encrypted-private-key")]
    #[serde(default)]
    pub encrypted_private_key: Option<RawPrivateKeyInlineDefinitionEncryptedPrivateKey>,
}

/// Specifies the client identity using RPK.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RawPrivateKey {
    /// A container to hold the local key definition.
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<RawPrivateKeyInlineDefinition>,
    /// A reference to an asymmetric key that exists in
    #[serde(rename = "central-keystore-reference")]
    #[serde(default)]
    pub central_keystore_reference: Option<String>,
}

/// An empty container enabling a reference to the key that
/// encrypted the value to be augmented in.  The referenced
/// key MUST be a symmetric key or an asymmetric key.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Tls13EpskInlineDefinitionEncryptedSymmetricKeyEncryptedBy {
}

/// A container for the encrypted symmetric key value.
/// The interpretation of the 'encrypted-value' node
/// is via the 'key-format' node
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Tls13EpskInlineDefinitionEncryptedSymmetricKey {
    /// An empty container enabling a reference to the key that
    #[serde(rename = "encrypted-by")]
    #[serde(default)]
    pub encrypted_by: Option<Tls13EpskInlineDefinitionEncryptedSymmetricKeyEncryptedBy>,
    /// Identifies the format of the 'encrypted-value' leaf.
    #[serde(rename = "encrypted-value-format")]
    pub encrypted_value_format: String,
    /// The value, encrypted using the referenced symmetric
    #[serde(rename = "encrypted-value")]
    pub encrypted_value: String,
}

/// A container to hold the local key definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Tls13EpskInlineDefinition {
    /// Identifies the symmetric key's format.  Implementations
    #[serde(rename = "key-format")]
    #[serde(default)]
    pub key_format: Option<String>,
    /// The binary value of the key.  The interpretation of
    #[serde(rename = "cleartext-symmetric-key")]
    #[serde(default)]
    pub cleartext_symmetric_key: Option<String>,
    /// A hidden key is not exportable and not extractable;
    #[serde(rename = "hidden-symmetric-key")]
    #[serde(default)]
    pub hidden_symmetric_key: Option<bool>,
    /// A container for the encrypted symmetric key value.
    #[serde(rename = "encrypted-symmetric-key")]
    #[serde(default)]
    pub encrypted_symmetric_key: Option<Tls13EpskInlineDefinitionEncryptedSymmetricKey>,
}

/// An EPSK is established or provisioned out-of-band.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Tls13Epsk {
    /// A container to hold the local key definition.
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<Tls13EpskInlineDefinition>,
    /// A reference to a symmetric key that exists in
    #[serde(rename = "central-keystore-reference")]
    #[serde(default)]
    pub central_keystore_reference: Option<String>,
    /// A sequence of bytes used to identify an EPSK. A label for
    #[serde(rename = "external-identity")]
    pub external_identity: String,
    /// For externally established PSKs, the Hash algorithm must be
    pub hash: EpskSupportedHash,
    /// The context used to determine the EPSK, if any exists. For
    #[serde(default)]
    pub context: Option<String>,
    /// Specifies the protocol for which a PSK is imported for
    #[serde(rename = "target-protocol")]
    #[serde(default)]
    pub target_protocol: Option<u16>,
    /// The KDF for which a PSK is imported for use.
    #[serde(rename = "target-kdf")]
    #[serde(default)]
    pub target_kdf: Option<u16>,
}

/// Identity credentials that a TLS client may present
/// when establishing a connection to a TLS server.
/// A list of client credentials that can be referenced
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClientCredentials {
    /// An identifier that uniquely identifies a client
    pub id: String,
    /// Specifies the client identity using a certificate.
    #[serde(default)]
    pub certificate: Option<ClientCredentialsCertificate>,
    /// Specifies the client identity using RPK.
    #[serde(rename = "raw-private-key")]
    #[serde(default)]
    pub raw_private_key: Option<RawPrivateKey>,
    /// An EPSK is established or provisioned out-of-band.
    #[serde(rename = "tls13-epsk")]
    #[serde(default)]
    pub tls13_epsk: Option<Tls13Epsk>,
}

/// A trust anchor certificate or chain of certificates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentialsCaCertsInlineDefinitionCertificate {
    /// An arbitrary name for this certificate.
    pub name: String,
    /// The binary certificate data for this certificate.
    #[serde(rename = "cert-data")]
    pub cert_data: String,
}

/// A container for locally configured trust anchor
/// certificates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentialsCaCertsInlineDefinition {
    /// A trust anchor certificate or chain of certificates.
    #[serde(default)]
    pub certificate: Vec<ServerCredentialsCaCertsInlineDefinitionCertificate>,
}

/// A set of CA certificates used by the TLS client to
/// authenticate TLS server certificates.
/// A server certificate is authenticated if it has a valid
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentialsCaCerts {
    /// A container for locally configured trust anchor
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<ServerCredentialsCaCertsInlineDefinition>,
    /// A reference to a certificate bag that exists in the
    #[serde(rename = "central-truststore-reference")]
    #[serde(default)]
    pub central_truststore_reference: Option<String>,
}

/// A trust anchor certificate or chain of certificates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentialsEeCertsInlineDefinitionCertificate {
    /// An arbitrary name for this certificate.
    pub name: String,
    /// The binary certificate data for this certificate.
    #[serde(rename = "cert-data")]
    pub cert_data: String,
}

/// A container for locally configured trust anchor
/// certificates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentialsEeCertsInlineDefinition {
    /// A trust anchor certificate or chain of certificates.
    #[serde(default)]
    pub certificate: Vec<ServerCredentialsEeCertsInlineDefinitionCertificate>,
}

/// A set of server certificates (i.e., end entity certificates)
/// used by a TLS client to authenticate certificates
/// presented by TLS servers. A server certificate is
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentialsEeCerts {
    /// A container for locally configured trust anchor
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<ServerCredentialsEeCertsInlineDefinition>,
    /// A reference to a certificate bag that exists in the
    #[serde(rename = "central-truststore-reference")]
    #[serde(default)]
    pub central_truststore_reference: Option<String>,
}

/// A public key definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentialsRawPublicKeysInlineDefinitionPublicKey {
    /// An arbitrary name for this public key.
    pub name: String,
    /// Identifies the public key's format.  Implementations SHOULD
    #[serde(rename = "public-key-format")]
    pub public_key_format: String,
    /// The binary value of the public key.  The interpretation
    #[serde(rename = "public-key")]
    pub public_key: String,
}

/// A container to hold local public key definitions.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentialsRawPublicKeysInlineDefinition {
    /// A public key definition.
    #[serde(rename = "public-key")]
    #[serde(default)]
    pub public_key: Vec<ServerCredentialsRawPublicKeysInlineDefinitionPublicKey>,
}

/// A set of raw public keys used by a TLS client to
/// authenticate raw public keys presented by the TLS server.
/// A raw public key is authenticated if it is an exact match
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentialsRawPublicKeys {
    /// A container to hold local public key definitions.
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<ServerCredentialsRawPublicKeysInlineDefinition>,
    /// A reference to a bag of public keys that exists
    #[serde(rename = "central-truststore-reference")]
    #[serde(default)]
    pub central_truststore_reference: Option<String>,
}

/// Identity credentials that a TLS client may use
/// to authenticate a TLS server.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerCredentials {
    /// An identifier that uniquely identify server
    pub id: String,
    /// A set of CA certificates used by the TLS client to
    #[serde(rename = "ca-certs")]
    #[serde(default)]
    pub ca_certs: Option<ServerCredentialsCaCerts>,
    /// A set of server certificates (i.e., end entity certificates)
    #[serde(rename = "ee-certs")]
    #[serde(default)]
    pub ee_certs: Option<ServerCredentialsEeCerts>,
    /// A set of raw public keys used by a TLS client to
    #[serde(rename = "raw-public-keys")]
    #[serde(default)]
    pub raw_public_keys: Option<ServerCredentialsRawPublicKeys>,
    /// Indicates that a TLS client can authenticate TLS servers
    #[serde(rename = "tls13-epsks")]
    #[serde(default)]
    pub tls13_epsks: Option<bool>,
}

/// An empty container enabling a reference to the key that
/// encrypted the value to be augmented in.  The referenced
/// key MUST be a symmetric key or an asymmetric key.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityCertificateInlineDefinitionEncryptedPrivateKeyEncryptedBy {
}

/// A container for the encrypted asymmetric private key
/// value.  The interpretation of the 'encrypted-value'
/// node is via the 'private-key-format' node
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityCertificateInlineDefinitionEncryptedPrivateKey {
    /// An empty container enabling a reference to the key that
    #[serde(rename = "encrypted-by")]
    #[serde(default)]
    pub encrypted_by: Option<TacacsPlusServerClientIdentityCertificateInlineDefinitionEncryptedPrivateKeyEncryptedBy>,
    /// Identifies the format of the 'encrypted-value' leaf.
    #[serde(rename = "encrypted-value-format")]
    pub encrypted_value_format: String,
    /// The value, encrypted using the referenced symmetric
    #[serde(rename = "encrypted-value")]
    pub encrypted_value: String,
}

/// A container to hold the local key definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityCertificateInlineDefinition {
    /// Identifies the public key's format.  Implementations SHOULD
    #[serde(rename = "public-key-format")]
    #[serde(default)]
    pub public_key_format: Option<String>,
    /// The binary value of the public key.  The interpretation
    #[serde(rename = "public-key")]
    #[serde(default)]
    pub public_key: Option<String>,
    /// Identifies the private key's format.  Implementations SHOULD
    #[serde(rename = "private-key-format")]
    #[serde(default)]
    pub private_key_format: Option<String>,
    /// The value of the binary key.  The key's value is
    #[serde(rename = "cleartext-private-key")]
    #[serde(default)]
    pub cleartext_private_key: Option<String>,
    /// A hidden key.  It is of type 'empty' as its value is
    #[serde(rename = "hidden-private-key")]
    #[serde(default)]
    pub hidden_private_key: Option<bool>,
    /// A container for the encrypted asymmetric private key
    #[serde(rename = "encrypted-private-key")]
    #[serde(default)]
    pub encrypted_private_key: Option<TacacsPlusServerClientIdentityCertificateInlineDefinitionEncryptedPrivateKey>,
    /// The binary certificate data for this certificate.
    #[serde(rename = "cert-data")]
    #[serde(default)]
    pub cert_data: Option<String>,
}

/// A reference to a specific certificate associated with
/// an asymmetric key stored in the central keystore.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityCertificateCentralKeystoreReference {
    /// A reference to an asymmetric key in the keystore.
    #[serde(rename = "asymmetric-key")]
    #[serde(default)]
    pub asymmetric_key: Option<String>,
    /// A reference to a specific certificate of the
    #[serde(default)]
    pub certificate: Option<String>,
}

/// Specifies the client identity using a certificate.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityCertificate {
    /// A container to hold the local key definition.
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<TacacsPlusServerClientIdentityCertificateInlineDefinition>,
    /// A reference to a specific certificate associated with
    #[serde(rename = "central-keystore-reference")]
    #[serde(default)]
    pub central_keystore_reference: Option<TacacsPlusServerClientIdentityCertificateCentralKeystoreReference>,
}

/// An empty container enabling a reference to the key that
/// encrypted the value to be augmented in.  The referenced
/// key MUST be a symmetric key or an asymmetric key.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityRawPrivateKeyInlineDefinitionEncryptedPrivateKeyEncryptedBy {
}

/// A container for the encrypted asymmetric private key
/// value.  The interpretation of the 'encrypted-value'
/// node is via the 'private-key-format' node
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityRawPrivateKeyInlineDefinitionEncryptedPrivateKey {
    /// An empty container enabling a reference to the key that
    #[serde(rename = "encrypted-by")]
    #[serde(default)]
    pub encrypted_by: Option<TacacsPlusServerClientIdentityRawPrivateKeyInlineDefinitionEncryptedPrivateKeyEncryptedBy>,
    /// Identifies the format of the 'encrypted-value' leaf.
    #[serde(rename = "encrypted-value-format")]
    pub encrypted_value_format: String,
    /// The value, encrypted using the referenced symmetric
    #[serde(rename = "encrypted-value")]
    pub encrypted_value: String,
}

/// A container to hold the local key definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityRawPrivateKeyInlineDefinition {
    /// Identifies the public key's format.  Implementations SHOULD
    #[serde(rename = "public-key-format")]
    #[serde(default)]
    pub public_key_format: Option<String>,
    /// The binary value of the public key.  The interpretation
    #[serde(rename = "public-key")]
    #[serde(default)]
    pub public_key: Option<String>,
    /// Identifies the private key's format.  Implementations SHOULD
    #[serde(rename = "private-key-format")]
    #[serde(default)]
    pub private_key_format: Option<String>,
    /// The value of the binary key.  The key's value is
    #[serde(rename = "cleartext-private-key")]
    #[serde(default)]
    pub cleartext_private_key: Option<String>,
    /// A hidden key.  It is of type 'empty' as its value is
    #[serde(rename = "hidden-private-key")]
    #[serde(default)]
    pub hidden_private_key: Option<bool>,
    /// A container for the encrypted asymmetric private key
    #[serde(rename = "encrypted-private-key")]
    #[serde(default)]
    pub encrypted_private_key: Option<TacacsPlusServerClientIdentityRawPrivateKeyInlineDefinitionEncryptedPrivateKey>,
}

/// Specifies the client identity using RPK.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityRawPrivateKey {
    /// A container to hold the local key definition.
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<TacacsPlusServerClientIdentityRawPrivateKeyInlineDefinition>,
    /// A reference to an asymmetric key that exists in
    #[serde(rename = "central-keystore-reference")]
    #[serde(default)]
    pub central_keystore_reference: Option<String>,
}

/// An empty container enabling a reference to the key that
/// encrypted the value to be augmented in.  The referenced
/// key MUST be a symmetric key or an asymmetric key.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityTls13EpskInlineDefinitionEncryptedSymmetricKeyEncryptedBy {
}

/// A container for the encrypted symmetric key value.
/// The interpretation of the 'encrypted-value' node
/// is via the 'key-format' node
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityTls13EpskInlineDefinitionEncryptedSymmetricKey {
    /// An empty container enabling a reference to the key that
    #[serde(rename = "encrypted-by")]
    #[serde(default)]
    pub encrypted_by: Option<TacacsPlusServerClientIdentityTls13EpskInlineDefinitionEncryptedSymmetricKeyEncryptedBy>,
    /// Identifies the format of the 'encrypted-value' leaf.
    #[serde(rename = "encrypted-value-format")]
    pub encrypted_value_format: String,
    /// The value, encrypted using the referenced symmetric
    #[serde(rename = "encrypted-value")]
    pub encrypted_value: String,
}

/// A container to hold the local key definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityTls13EpskInlineDefinition {
    /// Identifies the symmetric key's format.  Implementations
    #[serde(rename = "key-format")]
    #[serde(default)]
    pub key_format: Option<String>,
    /// The binary value of the key.  The interpretation of
    #[serde(rename = "cleartext-symmetric-key")]
    #[serde(default)]
    pub cleartext_symmetric_key: Option<String>,
    /// A hidden key is not exportable and not extractable;
    #[serde(rename = "hidden-symmetric-key")]
    #[serde(default)]
    pub hidden_symmetric_key: Option<bool>,
    /// A container for the encrypted symmetric key value.
    #[serde(rename = "encrypted-symmetric-key")]
    #[serde(default)]
    pub encrypted_symmetric_key: Option<TacacsPlusServerClientIdentityTls13EpskInlineDefinitionEncryptedSymmetricKey>,
}

/// An EPSK is established or provisioned out-of-band.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentityTls13Epsk {
    /// A container to hold the local key definition.
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<TacacsPlusServerClientIdentityTls13EpskInlineDefinition>,
    /// A reference to a symmetric key that exists in
    #[serde(rename = "central-keystore-reference")]
    #[serde(default)]
    pub central_keystore_reference: Option<String>,
    /// A sequence of bytes used to identify an EPSK. A label for
    #[serde(rename = "external-identity")]
    pub external_identity: String,
    /// For externally established PSKs, the Hash algorithm must be
    pub hash: EpskSupportedHash,
    /// The context used to determine the EPSK, if any exists. For
    #[serde(default)]
    pub context: Option<String>,
    /// Specifies the protocol for which a PSK is imported for
    #[serde(rename = "target-protocol")]
    #[serde(default)]
    pub target_protocol: Option<u16>,
    /// The KDF for which a PSK is imported for use.
    #[serde(rename = "target-kdf")]
    #[serde(default)]
    pub target_kdf: Option<u16>,
}

/// Identity credentials that a TLS client may present when
/// establishing a connection to a TLS server.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerClientIdentity {
    /// Specifies the client credentials reference.
    #[serde(rename = "credentials-reference")]
    #[serde(default)]
    pub credentials_reference: Option<String>,
    /// Specifies the client identity using a certificate.
    #[serde(default)]
    pub certificate: Option<TacacsPlusServerClientIdentityCertificate>,
    /// Specifies the client identity using RPK.
    #[serde(rename = "raw-private-key")]
    #[serde(default)]
    pub raw_private_key: Option<TacacsPlusServerClientIdentityRawPrivateKey>,
    /// An EPSK is established or provisioned out-of-band.
    #[serde(rename = "tls13-epsk")]
    #[serde(default)]
    pub tls13_epsk: Option<TacacsPlusServerClientIdentityTls13Epsk>,
}

/// A trust anchor certificate or chain of certificates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerServerAuthenticationCaCertsInlineDefinitionCertificate {
    /// An arbitrary name for this certificate.
    pub name: String,
    /// The binary certificate data for this certificate.
    #[serde(rename = "cert-data")]
    pub cert_data: String,
}

/// A container for locally configured trust anchor
/// certificates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerServerAuthenticationCaCertsInlineDefinition {
    /// A trust anchor certificate or chain of certificates.
    #[serde(default)]
    pub certificate: Vec<TacacsPlusServerServerAuthenticationCaCertsInlineDefinitionCertificate>,
}

/// A set of CA certificates used by the TLS client to
/// authenticate TLS server certificates.
/// A server certificate is authenticated if it has a valid
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerServerAuthenticationCaCerts {
    /// A container for locally configured trust anchor
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<TacacsPlusServerServerAuthenticationCaCertsInlineDefinition>,
    /// A reference to a certificate bag that exists in the
    #[serde(rename = "central-truststore-reference")]
    #[serde(default)]
    pub central_truststore_reference: Option<String>,
}

/// A trust anchor certificate or chain of certificates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerServerAuthenticationEeCertsInlineDefinitionCertificate {
    /// An arbitrary name for this certificate.
    pub name: String,
    /// The binary certificate data for this certificate.
    #[serde(rename = "cert-data")]
    pub cert_data: String,
}

/// A container for locally configured trust anchor
/// certificates.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerServerAuthenticationEeCertsInlineDefinition {
    /// A trust anchor certificate or chain of certificates.
    #[serde(default)]
    pub certificate: Vec<TacacsPlusServerServerAuthenticationEeCertsInlineDefinitionCertificate>,
}

/// A set of server certificates (i.e., end entity certificates)
/// used by a TLS client to authenticate certificates
/// presented by TLS servers. A server certificate is
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerServerAuthenticationEeCerts {
    /// A container for locally configured trust anchor
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<TacacsPlusServerServerAuthenticationEeCertsInlineDefinition>,
    /// A reference to a certificate bag that exists in the
    #[serde(rename = "central-truststore-reference")]
    #[serde(default)]
    pub central_truststore_reference: Option<String>,
}

/// A public key definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerServerAuthenticationRawPublicKeysInlineDefinitionPublicKey {
    /// An arbitrary name for this public key.
    pub name: String,
    /// Identifies the public key's format.  Implementations SHOULD
    #[serde(rename = "public-key-format")]
    pub public_key_format: String,
    /// The binary value of the public key.  The interpretation
    #[serde(rename = "public-key")]
    pub public_key: String,
}

/// A container to hold local public key definitions.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerServerAuthenticationRawPublicKeysInlineDefinition {
    /// A public key definition.
    #[serde(rename = "public-key")]
    #[serde(default)]
    pub public_key: Vec<TacacsPlusServerServerAuthenticationRawPublicKeysInlineDefinitionPublicKey>,
}

/// A set of raw public keys used by a TLS client to
/// authenticate raw public keys presented by the TLS server.
/// A raw public key is authenticated if it is an exact match
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerServerAuthenticationRawPublicKeys {
    /// A container to hold local public key definitions.
    #[serde(rename = "inline-definition")]
    #[serde(default)]
    pub inline_definition: Option<TacacsPlusServerServerAuthenticationRawPublicKeysInlineDefinition>,
    /// A reference to a bag of public keys that exists
    #[serde(rename = "central-truststore-reference")]
    #[serde(default)]
    pub central_truststore_reference: Option<String>,
}

/// Specifies how a TLS client can authenticate TLS servers.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerServerAuthentication {
    /// Specifies the server credentials reference.
    #[serde(rename = "credentials-reference")]
    #[serde(default)]
    pub credentials_reference: Option<String>,
    /// A set of CA certificates used by the TLS client to
    #[serde(rename = "ca-certs")]
    #[serde(default)]
    pub ca_certs: Option<TacacsPlusServerServerAuthenticationCaCerts>,
    /// A set of server certificates (i.e., end entity certificates)
    #[serde(rename = "ee-certs")]
    #[serde(default)]
    pub ee_certs: Option<TacacsPlusServerServerAuthenticationEeCerts>,
    /// A set of raw public keys used by a TLS client to
    #[serde(rename = "raw-public-keys")]
    #[serde(default)]
    pub raw_public_keys: Option<TacacsPlusServerServerAuthenticationRawPublicKeys>,
    /// Indicates that a TLS client can authenticate TLS servers
    #[serde(rename = "tls13-epsks")]
    #[serde(default)]
    pub tls13_epsks: Option<bool>,
}

/// Parameters limiting which TLS versions, amongst
/// those enabled by 'features', are presented during
/// the TLS handshake.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerHelloParamsTlsVersions {
    /// If not specified, then there is no configured
    #[serde(default)]
    pub min: Option<String>,
    /// If not specified, then there is no configured
    #[serde(default)]
    pub max: Option<String>,
}

/// Parameters regarding cipher suites.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerHelloParamsCipherSuites {
    /// Acceptable cipher suites in order of descending
    #[serde(rename = "cipher-suite")]
    #[serde(default)]
    pub cipher_suite: Vec<String>,
}

/// Configurable parameters for the TLS Hello message.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServerHelloParams {
    /// Parameters limiting which TLS versions, amongst
    #[serde(rename = "tls-versions")]
    #[serde(default)]
    pub tls_versions: Option<TacacsPlusServerHelloParamsTlsVersions>,
    /// Parameters regarding cipher suites.
    #[serde(rename = "cipher-suites")]
    #[serde(default)]
    pub cipher_suites: Option<TacacsPlusServerHelloParamsCipherSuites>,
}

/// List of TACACS+ servers used by the device.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusServer {
    /// A name that is used to uniquely identify a TACACS+
    pub name: String,
    /// Server type: authentication/authorization/accounting and
    #[serde(rename = "server-type")]
    pub server_type: String,
    /// Provides a domain name of the TACACS+ server.
    #[serde(rename = "domain-name")]
    #[serde(default)]
    pub domain_name: Option<String>,
    /// Enables the use of SNI, when set to true. Disables the
    #[serde(rename = "sni-enabled")]
    #[serde(default)]
    pub sni_enabled: Option<bool>,
    /// The IP address or name of the TACACS+ server.
    pub address: String,
    /// The port number of TACACS+ server.
    pub port: u16,
    /// Identity credentials that a TLS client may present when
    #[serde(rename = "client-identity")]
    #[serde(default)]
    pub client_identity: Option<TacacsPlusServerClientIdentity>,
    /// Specifies how a TLS client can authenticate TLS servers.
    #[serde(rename = "server-authentication")]
    #[serde(default)]
    pub server_authentication: Option<TacacsPlusServerServerAuthentication>,
    /// Configurable parameters for the TLS Hello message.
    #[serde(rename = "hello-params")]
    #[serde(default)]
    pub hello_params: Option<TacacsPlusServerHelloParams>,
    /// The shared secret, which is known to both the
    #[serde(rename = "shared-secret")]
    #[serde(default)]
    pub shared_secret: Option<String>,
    /// Specifies the source IP address for TACACS+ outbound
    #[serde(rename = "source-ip")]
    #[serde(default)]
    pub source_ip: Option<String>,
    /// Specifies the interface from which the IP address
    #[serde(rename = "source-interface")]
    #[serde(default)]
    pub source_interface: Option<String>,
    /// Specifies the VPN Routing and Forwarding (VRF) instance
    #[serde(rename = "vrf-instance")]
    #[serde(default)]
    pub vrf_instance: Option<String>,
    /// Indicates whether the Single Connection Mode is enabled
    #[serde(rename = "single-connection")]
    pub single_connection: bool,
    /// The number of seconds that the device will wait for a
    pub timeout: u16,
}

/// Container for TACACS+ configurations and operations.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlus {
    /// Identity credentials that a TLS client may present
    #[serde(rename = "client-credentials")]
    #[serde(default)]
    pub client_credentials: Vec<ClientCredentials>,
    /// Identity credentials that a TLS client may use
    #[serde(rename = "server-credentials")]
    #[serde(default)]
    pub server_credentials: Vec<ServerCredentials>,
    /// List of TACACS+ servers used by the device.
    #[serde(default)]
    pub server: Vec<TacacsPlusServer>,
}

