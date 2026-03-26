// Auto-generated from YANG modules by yang2rust.py ù DO NOT EDIT

#![allow(dead_code)]

use serde::Deserialize;

/// Types from `ietf-system-tacacs-plus`.
pub mod tacacs_plus {
    use serde::Deserialize;
    use super::keystore;
    use super::tls_common;
    use super::truststore;

    pub type ClientCredentialsRef = String;
    pub type ServerCredentialsRef = String;

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

    bitflags::bitflags! {
        /// The type can be set to authentication, authorization,
        /// accounting, or any combination of the three types.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct TacacsPlusServerType: u32 {
            /// Indicates that the TACACS+ server is providing
            const AUTHENTICATION = 1 << 0;
            /// Indicates that the TACACS+ server is providing
            const AUTHORIZATION = 1 << 1;
            /// Indicates that the TACACS+ server is providing accounting
            const ACCOUNTING = 1 << 2;
        }
    }

    impl<'de> serde::Deserialize<'de> for TacacsPlusServerType {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let mut bits = Self::empty();
            for token in s.split_whitespace() {
                match token {
                    "authentication" => bits |= Self::AUTHENTICATION,
                    "authorization" => bits |= Self::AUTHORIZATION,
                    "accounting" => bits |= Self::ACCOUNTING,
                    other => {
                        return Err(serde::de::Error::unknown_variant(
                            other,
                            &["authentication", "authorization", "accounting"],
                        ))
                    }
                }
            }
            if bits.is_empty() {
                return Err(serde::de::Error::custom("at least one bit must be set"));
            }
            Ok(bits)
        }
    }

    /// Specifies the client identity using a certificate.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ClientIdentityCertificate {
        /// A container to hold the local key definition.
        #[serde(rename = "inline-definition")]
        #[serde(default)]
        pub inline_definition: Option<keystore::EndEntityCertWithKeyInlineDefinition>,
        /// A reference to a specific certificate associated with
        #[serde(rename = "central-keystore-reference")]
        #[serde(default)]
        pub central_keystore_reference:
            Option<keystore::EndEntityCertWithKeyCentralKeystoreReference>,
    }

    /// Choice constraints for [`ClientIdentityCertificate`].
    impl ClientIdentityCertificate {
        /// YANG choice `inline-or-keystore` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_INLINE_OR_KEYSTORE: &[(&str, &[&str])] = &[
            ("inline", &["inline-definition"]),
            ("central-keystore", &["central-keystore-reference"]),
        ];
        pub const CHOICE_INLINE_OR_KEYSTORE_MANDATORY: bool = true;
    }

    /// Specifies the client identity using RPK.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct RawPrivateKey {
        /// A container to hold the local key definition.
        #[serde(rename = "inline-definition")]
        #[serde(default)]
        pub inline_definition: Option<keystore::AsymmetricKeyInlineDefinition>,
        /// A reference to an asymmetric key that exists in
        #[serde(rename = "central-keystore-reference")]
        #[serde(default)]
        pub central_keystore_reference: Option<String>,
    }

    /// Choice constraints for [`RawPrivateKey`].
    impl RawPrivateKey {
        /// YANG choice `inline-or-keystore` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_INLINE_OR_KEYSTORE: &[(&str, &[&str])] = &[
            ("inline", &["inline-definition"]),
            ("central-keystore", &["central-keystore-reference"]),
        ];
        pub const CHOICE_INLINE_OR_KEYSTORE_MANDATORY: bool = true;
    }

    fn default_tls13_epsk_hash() -> EpskSupportedHash {
        EpskSupportedHash::Sha256
    }

    /// An EPSK is established or provisioned out-of-band.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct Tls13Epsk {
        /// A container to hold the local key definition.
        #[serde(rename = "inline-definition")]
        #[serde(default)]
        pub inline_definition: Option<keystore::SymmetricKeyInlineDefinition>,
        /// A reference to a symmetric key that exists in
        #[serde(rename = "central-keystore-reference")]
        #[serde(default)]
        pub central_keystore_reference: Option<String>,
        /// A sequence of bytes used to identify an EPSK. A label for
        #[serde(rename = "external-identity")]
        pub external_identity: String,
        /// For externally established PSKs, the Hash algorithm must be
        #[serde(default = "default_tls13_epsk_hash")]
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

    /// Choice constraints for [`Tls13Epsk`].
    impl Tls13Epsk {
        /// YANG choice `inline-or-keystore` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_INLINE_OR_KEYSTORE: &[(&str, &[&str])] = &[
            ("inline", &["inline-definition"]),
            ("central-keystore", &["central-keystore-reference"]),
        ];
        pub const CHOICE_INLINE_OR_KEYSTORE_MANDATORY: bool = true;
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
        pub certificate: Option<ClientIdentityCertificate>,
        /// Specifies the client identity using RPK.
        #[serde(rename = "raw-private-key")]
        #[serde(default)]
        pub raw_private_key: Option<RawPrivateKey>,
        /// An EPSK is established or provisioned out-of-band.
        #[serde(rename = "tls13-epsk")]
        #[serde(default)]
        pub tls13_epsk: Option<Tls13Epsk>,
    }

    /// Choice constraints for [`ClientCredentials`].
    impl ClientCredentials {
        /// YANG choice `auth-type` (optional).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_AUTH_TYPE: &[(&str, &[&str])] = &[
            ("certificate", &["certificate"]),
            ("raw-public-key", &["raw-private-key"]),
            ("tls13-epsk", &["tls13-epsk"]),
        ];
        pub const CHOICE_AUTH_TYPE_MANDATORY: bool = false;
    }

    /// A set of CA certificates used by the TLS client to
    /// authenticate TLS server certificates.
    /// A server certificate is authenticated if it has a valid
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ServerAuthenticationCaCerts {
        /// A container for locally configured trust anchor
        #[serde(rename = "inline-definition")]
        #[serde(default)]
        pub inline_definition: Option<truststore::CertsInlineDefinition>,
        /// A reference to a certificate bag that exists in the
        #[serde(rename = "central-truststore-reference")]
        #[serde(default)]
        pub central_truststore_reference: Option<String>,
    }

    /// Choice constraints for [`ServerAuthenticationCaCerts`].
    impl ServerAuthenticationCaCerts {
        /// YANG choice `inline-or-truststore` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_INLINE_OR_TRUSTSTORE: &[(&str, &[&str])] = &[
            ("inline", &["inline-definition"]),
            ("central-truststore", &["central-truststore-reference"]),
        ];
        pub const CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY: bool = true;
    }

    /// A set of raw public keys used by a TLS client to
    /// authenticate raw public keys presented by the TLS server.
    /// A raw public key is authenticated if it is an exact match
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ServerAuthenticationRawPublicKeys {
        /// A container to hold local public key definitions.
        #[serde(rename = "inline-definition")]
        #[serde(default)]
        pub inline_definition: Option<truststore::PublicKeysInlineDefinition>,
        /// A reference to a bag of public keys that exists
        #[serde(rename = "central-truststore-reference")]
        #[serde(default)]
        pub central_truststore_reference: Option<String>,
    }

    /// Choice constraints for [`ServerAuthenticationRawPublicKeys`].
    impl ServerAuthenticationRawPublicKeys {
        /// YANG choice `inline-or-truststore` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_INLINE_OR_TRUSTSTORE: &[(&str, &[&str])] = &[
            ("inline", &["inline-definition"]),
            ("central-truststore", &["central-truststore-reference"]),
        ];
        pub const CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY: bool = true;
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
        pub ca_certs: Option<ServerAuthenticationCaCerts>,
        /// A set of server certificates (i.e., end entity certificates)
        #[serde(rename = "ee-certs")]
        #[serde(default)]
        pub ee_certs: Option<ServerAuthenticationCaCerts>,
        /// A set of raw public keys used by a TLS client to
        #[serde(rename = "raw-public-keys")]
        #[serde(default)]
        pub raw_public_keys: Option<ServerAuthenticationRawPublicKeys>,
        /// Indicates that a TLS client can authenticate TLS servers
        #[serde(rename = "tls13-epsks")]
        #[serde(default)]
        pub tls13_epsks: Option<bool>,
    }

    /// Identity credentials that a TLS client may present when
    /// establishing a connection to a TLS server.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct TlsClientClientIdentity {
        /// Specifies the client credentials reference.
        #[serde(rename = "credentials-reference")]
        #[serde(default)]
        pub credentials_reference: Option<String>,
        /// Specifies the client identity using a certificate.
        #[serde(default)]
        pub certificate: Option<ClientIdentityCertificate>,
        /// Specifies the client identity using RPK.
        #[serde(rename = "raw-private-key")]
        #[serde(default)]
        pub raw_private_key: Option<RawPrivateKey>,
        /// An EPSK is established or provisioned out-of-band.
        #[serde(rename = "tls13-epsk")]
        #[serde(default)]
        pub tls13_epsk: Option<Tls13Epsk>,
    }

    /// Choice constraints for [`TlsClientClientIdentity`].
    impl TlsClientClientIdentity {
        /// YANG choice `ref-or-explicit` (optional).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_REF_OR_EXPLICIT: &[(&str, &[&str])] = &[
            ("ref", &["credentials-reference"]),
            ("explicit/auth-type", &["certificate", "raw-private-key", "tls13-epsk"]),
        ];
        pub const CHOICE_REF_OR_EXPLICIT_MANDATORY: bool = false;
    }

    /// Specifies how a TLS client can authenticate TLS servers.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct TlsClientServerAuthentication {
        /// Specifies the server credentials reference.
        #[serde(rename = "credentials-reference")]
        #[serde(default)]
        pub credentials_reference: Option<String>,
        /// A set of CA certificates used by the TLS client to
        #[serde(rename = "ca-certs")]
        #[serde(default)]
        pub ca_certs: Option<ServerAuthenticationCaCerts>,
        /// A set of server certificates (i.e., end entity certificates)
        #[serde(rename = "ee-certs")]
        #[serde(default)]
        pub ee_certs: Option<ServerAuthenticationCaCerts>,
        /// A set of raw public keys used by a TLS client to
        #[serde(rename = "raw-public-keys")]
        #[serde(default)]
        pub raw_public_keys: Option<ServerAuthenticationRawPublicKeys>,
        /// Indicates that a TLS client can authenticate TLS servers
        #[serde(rename = "tls13-epsks")]
        #[serde(default)]
        pub tls13_epsks: Option<bool>,
    }

    /// Choice constraints for [`TlsClientServerAuthentication`].
    impl TlsClientServerAuthentication {
        /// YANG choice `ref-or-explicit` (optional).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_REF_OR_EXPLICIT: &[(&str, &[&str])] = &[
            ("ref", &["credentials-reference"]),
            ("explicit", &["ca-certs", "ee-certs", "raw-public-keys", "tls13-epsks"]),
        ];
        pub const CHOICE_REF_OR_EXPLICIT_MANDATORY: bool = false;
    }

    /// Configurable parameters for the TLS Hello message.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct TlsClientHelloParams {
        /// Parameters limiting which TLS versions, amongst
        #[serde(rename = "tls-versions")]
        #[serde(default)]
        pub tls_versions: Option<tls_common::HelloParamsTlsVersions>,
        /// Parameters regarding cipher suites.
        #[serde(rename = "cipher-suites")]
        #[serde(default)]
        pub cipher_suites: Option<tls_common::HelloParamsCipherSuites>,
    }

    fn default_tacacs_plus_server_timeout() -> u16 {
        5
    }

    /// List of TACACS+ servers used by the device.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct TacacsPlusServer {
        /// A name that is used to uniquely identify a TACACS+
        pub name: String,
        /// Server type: authentication/authorization/accounting and
        #[serde(rename = "server-type")]
        pub server_type: TacacsPlusServerType,
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
        pub client_identity: Option<TlsClientClientIdentity>,
        /// Specifies how a TLS client can authenticate TLS servers.
        #[serde(rename = "server-authentication")]
        #[serde(default)]
        pub server_authentication: Option<TlsClientServerAuthentication>,
        /// Configurable parameters for the TLS Hello message.
        #[serde(rename = "hello-params")]
        #[serde(default)]
        pub hello_params: Option<TlsClientHelloParams>,
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
        #[serde(default)]
        pub single_connection: bool,
        /// The number of seconds that the device will wait for a
        #[serde(default = "default_tacacs_plus_server_timeout")]
        pub timeout: u16,
    }

    /// Choice constraints for [`TacacsPlusServer`].
    impl TacacsPlusServer {
        /// YANG choice `security` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_SECURITY: &[(&str, &[&str])] = &[
            ("tls", &["client-identity", "server-authentication", "hello-params"]),
            ("obfuscation", &["shared-secret"]),
        ];
        pub const CHOICE_SECURITY_MANDATORY: bool = true;
        /// YANG choice `source-type` (optional).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_SOURCE_TYPE: &[(&str, &[&str])] = &[
            ("source-ip", &["source-ip"]),
            ("source-interface", &["source-interface"]),
        ];
        pub const CHOICE_SOURCE_TYPE_MANDATORY: bool = false;
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
}

/// Types from `ietf-keystore`.
pub mod keystore {
    use serde::Deserialize;
    use super::crypto_types;

    /// A container to hold the local key definition.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct EndEntityCertWithKeyInlineDefinition {
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
        pub encrypted_private_key: Option<crypto_types::PrivateKeyEncryptedPrivateKey>,
        /// The binary certificate data for this certificate.
        #[serde(rename = "cert-data")]
        #[serde(default)]
        pub cert_data: Option<String>,
    }

    /// Choice constraints for [`EndEntityCertWithKeyInlineDefinition`].
    impl EndEntityCertWithKeyInlineDefinition {
        /// YANG choice `private-key-type` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_PRIVATE_KEY_TYPE: &[(&str, &[&str])] = &[
            ("cleartext-private-key", &["cleartext-private-key"]),
            ("hidden-private-key", &["hidden-private-key"]),
            ("encrypted-private-key", &["encrypted-private-key"]),
        ];
        pub const CHOICE_PRIVATE_KEY_TYPE_MANDATORY: bool = true;
    }

    /// A reference to a specific certificate associated with
    /// an asymmetric key stored in the central keystore.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct EndEntityCertWithKeyCentralKeystoreReference {
        /// A reference to an asymmetric key in the keystore.
        #[serde(rename = "asymmetric-key")]
        #[serde(default)]
        pub asymmetric_key: Option<String>,
        /// A reference to a specific certificate of the
        #[serde(default)]
        pub certificate: Option<String>,
    }

    /// A container to hold the local key definition.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct AsymmetricKeyInlineDefinition {
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
        pub encrypted_private_key: Option<crypto_types::PrivateKeyEncryptedPrivateKey>,
    }

    /// Choice constraints for [`AsymmetricKeyInlineDefinition`].
    impl AsymmetricKeyInlineDefinition {
        /// YANG choice `private-key-type` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_PRIVATE_KEY_TYPE: &[(&str, &[&str])] = &[
            ("cleartext-private-key", &["cleartext-private-key"]),
            ("hidden-private-key", &["hidden-private-key"]),
            ("encrypted-private-key", &["encrypted-private-key"]),
        ];
        pub const CHOICE_PRIVATE_KEY_TYPE_MANDATORY: bool = true;
    }

    /// A container to hold the local key definition.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct SymmetricKeyInlineDefinition {
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
        pub encrypted_symmetric_key: Option<crypto_types::PrivateKeyEncryptedPrivateKey>,
    }

    /// Choice constraints for [`SymmetricKeyInlineDefinition`].
    impl SymmetricKeyInlineDefinition {
        /// YANG choice `key-type` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_KEY_TYPE: &[(&str, &[&str])] = &[
            ("cleartext-symmetric-key", &["cleartext-symmetric-key"]),
            ("hidden-symmetric-key", &["hidden-symmetric-key"]),
            ("encrypted-symmetric-key", &["encrypted-symmetric-key"]),
        ];
        pub const CHOICE_KEY_TYPE_MANDATORY: bool = true;
    }
}

/// Types from `ietf-crypto-types`.
pub mod crypto_types {
    use serde::Deserialize;

    /// An empty container enabling a reference to the key that
    /// encrypted the value to be augmented in.  The referenced
    /// key MUST be a symmetric key or an asymmetric key.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct EncryptedValueEncryptedBy {}

    /// A container for the encrypted asymmetric private key
    /// value.  The interpretation of the 'encrypted-value'
    /// node is via the 'private-key-format' node
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct PrivateKeyEncryptedPrivateKey {
        /// An empty container enabling a reference to the key that
        #[serde(rename = "encrypted-by")]
        #[serde(default)]
        pub encrypted_by: Option<EncryptedValueEncryptedBy>,
        /// Identifies the format of the 'encrypted-value' leaf.
        #[serde(rename = "encrypted-value-format")]
        pub encrypted_value_format: String,
        /// The value, encrypted using the referenced symmetric
        #[serde(rename = "encrypted-value")]
        pub encrypted_value: String,
    }
}

/// Types from `ietf-truststore`.
pub mod truststore {
    use serde::Deserialize;

    /// A trust anchor certificate or chain of certificates.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct CertsCertificate {
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
    pub struct CertsInlineDefinition {
        /// A trust anchor certificate or chain of certificates.
        #[serde(default)]
        pub certificate: Vec<CertsCertificate>,
    }

    /// A public key definition.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct PublicKeysPublicKey {
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
    pub struct PublicKeysInlineDefinition {
        /// A public key definition.
        #[serde(rename = "public-key")]
        #[serde(default)]
        pub public_key: Vec<PublicKeysPublicKey>,
    }
}

/// Types from `ietf-tls-common`.
pub mod tls_common {
    use serde::Deserialize;

    /// Parameters limiting which TLS versions, amongst
    /// those enabled by 'features', are presented during
    /// the TLS handshake.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct HelloParamsTlsVersions {
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
    pub struct HelloParamsCipherSuites {
        /// Acceptable cipher suites in order of descending
        #[serde(rename = "cipher-suite")]
        #[serde(default)]
        pub cipher_suite: Vec<String>,
    }
}

/// Root wrapper for RFC 7951 JSON encoding.
///
/// The JSON document root key is `ietf-system-tacacs-plus:tacacs-plus`.
#[derive(Debug, Clone, Deserialize)]
pub struct YangConfigRoot {
    #[serde(rename = "ietf-system-tacacs-plus:tacacs-plus")]
    pub tacacs_plus: tacacs_plus::TacacsPlus,
}
