// Auto-generated from YANG modules by yang2rust.py — DO NOT EDIT

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Types from `ietf-system-tacacs-plus`.
pub mod tacacs_plus {
    use serde::{Deserialize, Serialize};
    use super::keystore;
    use super::tls_common;
    use super::truststore;

    pub type ClientCredentialsRef = String;
    pub type ServerCredentialsRef = String;

    /// For externally established PSKs, the Hash algorithm must be
    /// set when the PSK is established or default to SHA-256 if no
    /// such algorithm is defined.
    #[derive(Debug, Clone, Serialize, Deserialize)]
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

    impl serde::Serialize for TacacsPlusServerType {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let tokens = [
                (Self::AUTHENTICATION, "authentication"),
                (Self::AUTHORIZATION, "authorization"),
                (Self::ACCOUNTING, "accounting"),
            ]
            .into_iter()
            .filter_map(|(flag, name)| self.contains(flag).then_some(name))
            .collect::<Vec<_>>()
            .join(" ");
            serializer.serialize_str(&tokens)
        }
    }

    /// Specifies the client identity using a certificate.
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    use serde::{Deserialize, Serialize};
    use super::crypto_types;

    pub type CentralSymmetricKeyRef = String;
    pub type CentralAsymmetricKeyRef = String;

    /// A container to hold the local key definition.
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// An asymmetric key.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct AsymmetricKey {
        /// An arbitrary name for the asymmetric key.
        pub name: String,
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
        pub encrypted_private_key: Option<crypto_types::PrivateKeyEncryptedPrivateKey2>,
        /// Certificates associated with this asymmetric key.
        #[serde(default)]
        pub certificates: Option<crypto_types::Certificates>,
    }

    /// Choice constraints for [`AsymmetricKey`].
    impl AsymmetricKey {
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

    /// A list of asymmetric keys.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct AsymmetricKeys {
        /// An asymmetric key.
        #[serde(rename = "asymmetric-key")]
        #[serde(default)]
        pub asymmetric_key: Vec<AsymmetricKey>,
    }

    /// A symmetric key.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct SymmetricKey {
        /// An arbitrary name for the symmetric key.
        pub name: String,
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
        pub encrypted_symmetric_key: Option<crypto_types::PrivateKeyEncryptedPrivateKey2>,
    }

    /// Choice constraints for [`SymmetricKey`].
    impl SymmetricKey {
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

    /// A list of symmetric keys.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct SymmetricKeys {
        /// A symmetric key.
        #[serde(rename = "symmetric-key")]
        #[serde(default)]
        pub symmetric_key: Vec<SymmetricKey>,
    }

    /// A central keystore containing a list of symmetric keys and
    /// a list of asymmetric keys.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct Keystore {
        /// A list of asymmetric keys.
        #[serde(rename = "asymmetric-keys")]
        #[serde(default)]
        pub asymmetric_keys: Option<AsymmetricKeys>,
        /// A list of symmetric keys.
        #[serde(rename = "symmetric-keys")]
        #[serde(default)]
        pub symmetric_keys: Option<SymmetricKeys>,
    }
}

/// Types from `ietf-crypto-types`.
pub mod crypto_types {
    use serde::{Deserialize, Serialize};

    pub type CsrInfo = String;
    pub type P10Csr = String;
    pub type X509 = String;
    pub type Crl = String;
    pub type OscpRequest = String;
    pub type OscpResponse = String;
    pub type Cms = String;
    pub type DataContentCms = String;
    pub type SignedDataCms = String;
    pub type EnvelopedDataCms = String;
    pub type DigestedDataCms = String;
    pub type EncryptedDataCms = String;
    pub type AuthenticatedDataCms = String;
    pub type TrustAnchorCertX509 = String;
    pub type EndEntityCertX509 = String;
    pub type TrustAnchorCertCms = String;
    pub type EndEntityCertCms = String;

    /// Valid identities derived from `ietf-crypto-types:public-key-format`.
    /// Base key-format identity for public keys.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(clippy::doc_markdown)]
    pub enum PublicKeyFormat {
        /// Indicates that the public key value is a Secure Shell (SSH)
        SshPublicKeyFormat,
        /// Indicates that the public key value is a SubjectPublicKeyInfo
        SubjectPublicKeyInfoFormat,
    }

    impl PublicKeyFormat {
        /// All valid identities for this base.
        pub const ALL: &[Self] = &[Self::SshPublicKeyFormat, Self::SubjectPublicKeyInfoFormat];

        /// RFC 7951 JSON string values accepted for this identity.
        pub const ALLOWED_VALUES: &[&str] = &[
            "ietf-crypto-types:ssh-public-key-format",
            "ietf-crypto-types:subject-public-key-info-format",
        ];

        /// Returns the RFC 7951 module-qualified JSON string.
        #[must_use]
        pub fn as_rfc7951_str(&self) -> &'static str {
            match self {
                Self::SshPublicKeyFormat => "ietf-crypto-types:ssh-public-key-format",
                Self::SubjectPublicKeyInfoFormat => {
                    "ietf-crypto-types:subject-public-key-info-format"
                }
            }
        }

        /// Parses an RFC 7951 module-qualified string into this identity.
        #[must_use]
        pub fn from_rfc7951_str(s: &str) -> Option<Self> {
            match s {
                "ietf-crypto-types:ssh-public-key-format" => Some(Self::SshPublicKeyFormat),
                "ietf-crypto-types:subject-public-key-info-format" => {
                    Some(Self::SubjectPublicKeyInfoFormat)
                }
                _ => None,
            }
        }

        /// Checks whether the given string is a valid RFC 7951 value for this identity.
        #[must_use]
        pub fn is_valid(s: &str) -> bool {
            Self::from_rfc7951_str(s).is_some()
        }
    }

    /// Valid identities derived from `ietf-crypto-types:private-key-format`.
    /// Base key-format identity for private keys.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(clippy::doc_markdown)]
    pub enum PrivateKeyFormat {
        /// Indicates that the private key value is encoded as
        RsaPrivateKeyFormat,
        /// Indicates that the private key value is encoded as
        EcPrivateKeyFormat,
        /// Indicates that the private key value is a
        /// Requires YANG features: one-asymmetric-key-format
        OneAsymmetricKeyFormat,
    }

    impl PrivateKeyFormat {
        /// All valid identities for this base.
        pub const ALL: &[Self] = &[
            Self::RsaPrivateKeyFormat,
            Self::EcPrivateKeyFormat,
            Self::OneAsymmetricKeyFormat,
        ];

        /// RFC 7951 JSON string values accepted for this identity.
        pub const ALLOWED_VALUES: &[&str] = &[
            "ietf-crypto-types:rsa-private-key-format",
            "ietf-crypto-types:ec-private-key-format",
            "ietf-crypto-types:one-asymmetric-key-format",
        ];

        /// Returns the RFC 7951 module-qualified JSON string.
        #[must_use]
        pub fn as_rfc7951_str(&self) -> &'static str {
            match self {
                Self::RsaPrivateKeyFormat => "ietf-crypto-types:rsa-private-key-format",
                Self::EcPrivateKeyFormat => "ietf-crypto-types:ec-private-key-format",
                Self::OneAsymmetricKeyFormat => "ietf-crypto-types:one-asymmetric-key-format",
            }
        }

        /// Parses an RFC 7951 module-qualified string into this identity.
        #[must_use]
        pub fn from_rfc7951_str(s: &str) -> Option<Self> {
            match s {
                "ietf-crypto-types:rsa-private-key-format" => Some(Self::RsaPrivateKeyFormat),
                "ietf-crypto-types:ec-private-key-format" => Some(Self::EcPrivateKeyFormat),
                "ietf-crypto-types:one-asymmetric-key-format" => Some(Self::OneAsymmetricKeyFormat),
                _ => None,
            }
        }

        /// Checks whether the given string is a valid RFC 7951 value for this identity.
        #[must_use]
        pub fn is_valid(s: &str) -> bool {
            Self::from_rfc7951_str(s).is_some()
        }
    }

    /// Valid identities derived from `ietf-crypto-types:encrypted-value-format`.
    /// Base format identity for encrypted values.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(clippy::doc_markdown)]
    pub enum EncryptedValueFormat {
        /// Base format identity for symmetrically encrypted
        /// Requires YANG features: symmetrically-encrypted-value-format
        SymmetricallyEncryptedValueFormat,
        /// Base format identity for asymmetrically encrypted
        /// Requires YANG features: asymmetrically-encrypted-value-format
        AsymmetricallyEncryptedValueFormat,
        /// Indicates that the encrypted value conforms to
        /// Requires YANG features: cms-encrypted-data-format
        CmsEncryptedDataFormat,
        /// Indicates that the encrypted value conforms to the
        /// Requires YANG features: cms-enveloped-data-format
        CmsEnvelopedDataFormat,
    }

    impl EncryptedValueFormat {
        /// All valid identities for this base.
        pub const ALL: &[Self] = &[
            Self::SymmetricallyEncryptedValueFormat,
            Self::AsymmetricallyEncryptedValueFormat,
            Self::CmsEncryptedDataFormat,
            Self::CmsEnvelopedDataFormat,
        ];

        /// RFC 7951 JSON string values accepted for this identity.
        pub const ALLOWED_VALUES: &[&str] = &[
            "ietf-crypto-types:symmetrically-encrypted-value-format",
            "ietf-crypto-types:asymmetrically-encrypted-value-format",
            "ietf-crypto-types:cms-encrypted-data-format",
            "ietf-crypto-types:cms-enveloped-data-format",
        ];

        /// Returns the RFC 7951 module-qualified JSON string.
        #[must_use]
        pub fn as_rfc7951_str(&self) -> &'static str {
            match self {
                Self::SymmetricallyEncryptedValueFormat => {
                    "ietf-crypto-types:symmetrically-encrypted-value-format"
                }
                Self::AsymmetricallyEncryptedValueFormat => {
                    "ietf-crypto-types:asymmetrically-encrypted-value-format"
                }
                Self::CmsEncryptedDataFormat => "ietf-crypto-types:cms-encrypted-data-format",
                Self::CmsEnvelopedDataFormat => "ietf-crypto-types:cms-enveloped-data-format",
            }
        }

        /// Parses an RFC 7951 module-qualified string into this identity.
        #[must_use]
        pub fn from_rfc7951_str(s: &str) -> Option<Self> {
            match s {
                "ietf-crypto-types:symmetrically-encrypted-value-format" => {
                    Some(Self::SymmetricallyEncryptedValueFormat)
                }
                "ietf-crypto-types:asymmetrically-encrypted-value-format" => {
                    Some(Self::AsymmetricallyEncryptedValueFormat)
                }
                "ietf-crypto-types:cms-encrypted-data-format" => Some(Self::CmsEncryptedDataFormat),
                "ietf-crypto-types:cms-enveloped-data-format" => Some(Self::CmsEnvelopedDataFormat),
                _ => None,
            }
        }

        /// Checks whether the given string is a valid RFC 7951 value for this identity.
        #[must_use]
        pub fn is_valid(s: &str) -> bool {
            Self::from_rfc7951_str(s).is_some()
        }
    }

    /// Valid identities derived from `ietf-crypto-types:symmetric-key-format`.
    /// Base key-format identity for symmetric keys.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(clippy::doc_markdown)]
    pub enum SymmetricKeyFormat {
        /// Indicates that the key is encoded as a raw octet string.
        OctetStringKeyFormat,
        /// Indicates that the private key value is a CMS
        /// Requires YANG features: one-symmetric-key-format
        OneSymmetricKeyFormat,
    }

    impl SymmetricKeyFormat {
        /// All valid identities for this base.
        pub const ALL: &[Self] = &[Self::OctetStringKeyFormat, Self::OneSymmetricKeyFormat];

        /// RFC 7951 JSON string values accepted for this identity.
        pub const ALLOWED_VALUES: &[&str] = &[
            "ietf-crypto-types:octet-string-key-format",
            "ietf-crypto-types:one-symmetric-key-format",
        ];

        /// Returns the RFC 7951 module-qualified JSON string.
        #[must_use]
        pub fn as_rfc7951_str(&self) -> &'static str {
            match self {
                Self::OctetStringKeyFormat => "ietf-crypto-types:octet-string-key-format",
                Self::OneSymmetricKeyFormat => "ietf-crypto-types:one-symmetric-key-format",
            }
        }

        /// Parses an RFC 7951 module-qualified string into this identity.
        #[must_use]
        pub fn from_rfc7951_str(s: &str) -> Option<Self> {
            match s {
                "ietf-crypto-types:octet-string-key-format" => Some(Self::OctetStringKeyFormat),
                "ietf-crypto-types:one-symmetric-key-format" => Some(Self::OneSymmetricKeyFormat),
                _ => None,
            }
        }

        /// Checks whether the given string is a valid RFC 7951 value for this identity.
        #[must_use]
        pub fn is_valid(s: &str) -> bool {
            Self::from_rfc7951_str(s).is_some()
        }
    }

    /// An empty container enabling a reference to the key that
    /// encrypted the value to be augmented in.  The referenced
    /// key MUST be a symmetric key or an asymmetric key.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct EncryptedValueEncryptedBy {}

    /// A container for the encrypted asymmetric private key
    /// value.  The interpretation of the 'encrypted-value'
    /// node is via the 'private-key-format' node
    #[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// An empty container enabling a reference to the key that
    /// encrypted the value to be augmented in.  The referenced
    /// key MUST be a symmetric key or an asymmetric key.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct EncryptedValueEncryptedBy2 {
        /// Identifies the symmetric key used to encrypt the
        #[serde(rename = "symmetric-key-ref")]
        #[serde(default)]
        pub symmetric_key_ref: Option<String>,
        /// Identifies the asymmetric key whose public key
        #[serde(rename = "asymmetric-key-ref")]
        #[serde(default)]
        pub asymmetric_key_ref: Option<String>,
    }

    /// Choice constraints for [`EncryptedValueEncryptedBy2`].
    impl EncryptedValueEncryptedBy2 {
        /// YANG choice `encrypted-by` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_ENCRYPTED_BY: &[(&str, &[&str])] = &[
            ("central-symmetric-key-ref", &["symmetric-key-ref"]),
            ("central-asymmetric-key-ref", &["asymmetric-key-ref"]),
        ];
        pub const CHOICE_ENCRYPTED_BY_MANDATORY: bool = true;
    }

    /// A container for the encrypted asymmetric private key
    /// value.  The interpretation of the 'encrypted-value'
    /// node is via the 'private-key-format' node
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct PrivateKeyEncryptedPrivateKey2 {
        /// An empty container enabling a reference to the key that
        #[serde(rename = "encrypted-by")]
        #[serde(default)]
        pub encrypted_by: Option<EncryptedValueEncryptedBy2>,
        /// Identifies the format of the 'encrypted-value' leaf.
        #[serde(rename = "encrypted-value-format")]
        pub encrypted_value_format: String,
        /// The value, encrypted using the referenced symmetric
        #[serde(rename = "encrypted-value")]
        pub encrypted_value: String,
    }

    /// A certificate for this asymmetric key.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct AsymmetricKeyPairWithCertsCertificate {
        /// An arbitrary name for the certificate.
        pub name: String,
        /// The binary certificate data for this certificate.
        #[serde(rename = "cert-data")]
        pub cert_data: String,
    }

    /// Certificates associated with this asymmetric key.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct Certificates {
        /// A certificate for this asymmetric key.
        #[serde(default)]
        pub certificate: Vec<AsymmetricKeyPairWithCertsCertificate>,
    }
}

/// Types from `ietf-truststore`.
pub mod truststore {
    use serde::{Deserialize, Serialize};

    pub type CentralCertificateBagRef = String;
    pub type CentralCertificateRef = String;
    pub type CentralPublicKeyBagRef = String;
    pub type CentralPublicKeyRef = String;

    /// A trust anchor certificate or chain of certificates.
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct CertsInlineDefinition {
        /// A trust anchor certificate or chain of certificates.
        #[serde(default)]
        pub certificate: Vec<CertsCertificate>,
    }

    /// A public key definition.
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct PublicKeysInlineDefinition {
        /// A public key definition.
        #[serde(rename = "public-key")]
        #[serde(default)]
        pub public_key: Vec<PublicKeysPublicKey>,
    }

    /// A bag of certificates.  Each bag of certificates should
    /// be for a specific purpose.  For instance, one bag could
    /// be used to authenticate a specific set of servers, while
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct CertificateBag {
        /// An arbitrary name for this bag of certificates.
        pub name: String,
        /// A description for this bag of certificates.  The
        #[serde(default)]
        pub description: Option<String>,
        /// A trust anchor certificate or chain of certificates.
        #[serde(default)]
        pub certificate: Vec<CertsCertificate>,
    }

    /// A collection of certificate bags.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct CertificateBags {
        /// A bag of certificates.  Each bag of certificates should
        #[serde(rename = "certificate-bag")]
        #[serde(default)]
        pub certificate_bag: Vec<CertificateBag>,
    }

    /// A bag of public keys.  Each bag of keys SHOULD be for
    /// a specific purpose.  For instance, one bag could be used
    /// to authenticate a specific set of servers, while another
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct PublicKeyBag {
        /// An arbitrary name for this bag of public keys.
        pub name: String,
        /// A description for this bag of public keys.  The
        #[serde(default)]
        pub description: Option<String>,
        /// A public key.
        #[serde(rename = "public-key")]
        #[serde(default)]
        pub public_key: Vec<PublicKeysPublicKey>,
    }

    /// A collection of public key bags.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct PublicKeyBags {
        /// A bag of public keys.  Each bag of keys SHOULD be for
        #[serde(rename = "public-key-bag")]
        #[serde(default)]
        pub public_key_bag: Vec<PublicKeyBag>,
    }

    /// The truststore contains bags of certificates and
    /// public keys.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct Truststore {
        /// A collection of certificate bags.
        #[serde(rename = "certificate-bags")]
        #[serde(default)]
        pub certificate_bags: Option<CertificateBags>,
        /// A collection of public key bags.
        #[serde(rename = "public-key-bags")]
        #[serde(default)]
        pub public_key_bags: Option<PublicKeyBags>,
    }
}

/// Types from `ietf-tls-common`.
pub mod tls_common {
    use serde::{Deserialize, Serialize};

    /// As per Section 4.2.11 of RFC 8446, the hash algorithm
    /// supported by an instance of an External Pre-Shared
    /// Key (EPSK).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum EpskSupportedHash {
        /// The SHA-256 hash.
        #[serde(rename = "sha-256")]
        Sha256,
        /// The SHA-384 hash.
        #[serde(rename = "sha-384")]
        Sha384,
    }

    /// Valid identities derived from `ietf-tls-common:tls-version-base`.
    /// Base identity used to identify TLS protocol versions.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(clippy::doc_markdown)]
    pub enum TlsVersionBase {
        /// TLS Protocol Version 1.2.
        /// Requires YANG features: tls12
        Tls12,
        /// TLS Protocol Version 1.3.
        /// Requires YANG features: tls13
        Tls13,
    }

    impl TlsVersionBase {
        /// All valid identities for this base.
        pub const ALL: &[Self] = &[Self::Tls12, Self::Tls13];

        /// RFC 7951 JSON string values accepted for this identity.
        pub const ALLOWED_VALUES: &[&str] = &["ietf-tls-common:tls12", "ietf-tls-common:tls13"];

        /// Returns the RFC 7951 module-qualified JSON string.
        #[must_use]
        pub fn as_rfc7951_str(&self) -> &'static str {
            match self {
                Self::Tls12 => "ietf-tls-common:tls12",
                Self::Tls13 => "ietf-tls-common:tls13",
            }
        }

        /// Parses an RFC 7951 module-qualified string into this identity.
        #[must_use]
        pub fn from_rfc7951_str(s: &str) -> Option<Self> {
            match s {
                "ietf-tls-common:tls12" => Some(Self::Tls12),
                "ietf-tls-common:tls13" => Some(Self::Tls13),
                _ => None,
            }
        }

        /// Checks whether the given string is a valid RFC 7951 value for this identity.
        #[must_use]
        pub fn is_valid(s: &str) -> bool {
            Self::from_rfc7951_str(s).is_some()
        }
    }

    /// Parameters limiting which TLS versions, amongst
    /// those enabled by 'features', are presented during
    /// the TLS handshake.
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YangConfigRoot {
    #[serde(rename = "ietf-system-tacacs-plus:tacacs-plus")]
    pub tacacs_plus: tacacs_plus::TacacsPlus,
}
