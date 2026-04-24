// Auto-generated from YANG modules by yang2rust.py — DO NOT EDIT

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(clippy::doc_markdown)]

#![allow(clippy::too_long_first_doc_paragraph)]

#![allow(rustdoc::broken_intra_doc_links)]

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
            /// authentication services.
            const AUTHENTICATION = 1 << 0;
            /// Indicates that the TACACS+ server is providing
            /// authorization services.
            const AUTHORIZATION = 1 << 1;
            /// Indicates that the TACACS+ server is providing accounting
            /// services.
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
                    other => return Err(serde::de::Error::unknown_variant(
                        other,
                        &["authentication", "authorization", "accounting"],
                    )),
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
        /// an asymmetric key stored in the central keystore.
        #[serde(rename = "central-keystore-reference")]
        #[serde(default)]
        pub central_keystore_reference: Option<keystore::EndEntityCertWithKeyCentralKeystoreReference>,
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
        /// the central keystore.  The intent is to reference
        /// just the asymmetric key without any regard for
        /// any certificates that may be associated with it.
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

    fn default_tls13_epsk_hash() -> EpskSupportedHash { EpskSupportedHash::Sha256 }

    /// An EPSK is established or provisioned out-of-band.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct Tls13Epsk {
        /// A container to hold the local key definition.
        #[serde(rename = "inline-definition")]
        #[serde(default)]
        pub inline_definition: Option<keystore::SymmetricKeyInlineDefinition>,
        /// A reference to a symmetric key that exists in
        /// the central keystore.
        #[serde(rename = "central-keystore-reference")]
        #[serde(default)]
        pub central_keystore_reference: Option<String>,
        /// A sequence of bytes used to identify an EPSK. A label for
        /// a pre-shared key established externally.
        #[serde(rename = "external-identity")]
        pub external_identity: String,
        /// For externally established PSKs, the Hash algorithm must be
        /// set when the PSK is established or default to SHA-256 if no
        /// such algorithm is defined.
        #[serde(default = "default_tls13_epsk_hash")]
        pub hash: EpskSupportedHash,
        /// The context used to determine the EPSK, if any exists. For
        /// example, context may include information about peer roles or
        /// identities to mitigate Selfie-style reflection attacks.
        #[serde(default)]
        pub context: Option<String>,
        /// Specifies the protocol for which a PSK is imported for
        /// use.
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
    /// when configuring server instances.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ClientCredentials {
        /// An identifier that uniquely identifies a client
        /// identity within the device configuration.
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
    /// chain of trust to a configured CA certificate.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ServerAuthenticationCaCerts {
        /// A container for locally configured trust anchor
        /// certificates.
        #[serde(rename = "inline-definition")]
        #[serde(default)]
        pub inline_definition: Option<truststore::CertsInlineDefinition>,
        /// A reference to a certificate bag that exists in the
        /// central truststore.
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
    /// to a configured raw public key.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ServerAuthenticationRawPublicKeys {
        /// A container to hold local public key definitions.
        #[serde(rename = "inline-definition")]
        #[serde(default)]
        pub inline_definition: Option<truststore::PublicKeysInlineDefinition>,
        /// A reference to a bag of public keys that exists
        /// in the central truststore.
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
        /// credentials within the device configuration.
        pub id: String,
        /// A set of CA certificates used by the TLS client to
        /// authenticate TLS server certificates.
        /// A server certificate is authenticated if it has a valid
        /// chain of trust to a configured CA certificate.
        #[serde(rename = "ca-certs")]
        #[serde(default)]
        pub ca_certs: Option<ServerAuthenticationCaCerts>,
        /// A set of server certificates (i.e., end entity certificates)
        /// used by a TLS client to authenticate certificates
        /// presented by TLS servers. A server certificate is
        /// authenticated if it is an exact match to a configured server
        /// certificate.
        #[serde(rename = "ee-certs")]
        #[serde(default)]
        pub ee_certs: Option<ServerAuthenticationCaCerts>,
        /// A set of raw public keys used by a TLS client to
        /// authenticate raw public keys presented by the TLS server.
        /// A raw public key is authenticated if it is an exact match
        /// to a configured raw public key.
        #[serde(rename = "raw-public-keys")]
        #[serde(default)]
        pub raw_public_keys: Option<ServerAuthenticationRawPublicKeys>,
        /// Indicates that a TLS client can authenticate TLS servers
        /// using configured EPSKs.
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
        /// authenticate TLS server certificates.
        /// A server certificate is authenticated if it has a valid
        /// chain of trust to a configured CA certificate.
        #[serde(rename = "ca-certs")]
        #[serde(default)]
        pub ca_certs: Option<ServerAuthenticationCaCerts>,
        /// A set of server certificates (i.e., end entity certificates)
        /// used by a TLS client to authenticate certificates
        /// presented by TLS servers. A server certificate is
        /// authenticated if it is an exact match to a configured server
        /// certificate.
        #[serde(rename = "ee-certs")]
        #[serde(default)]
        pub ee_certs: Option<ServerAuthenticationCaCerts>,
        /// A set of raw public keys used by a TLS client to
        /// authenticate raw public keys presented by the TLS server.
        /// A raw public key is authenticated if it is an exact match
        /// to a configured raw public key.
        #[serde(rename = "raw-public-keys")]
        #[serde(default)]
        pub raw_public_keys: Option<ServerAuthenticationRawPublicKeys>,
        /// Indicates that a TLS client can authenticate TLS servers
        /// using configured EPSKs.
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
        /// those enabled by 'features', are presented during
        /// the TLS handshake.
        #[serde(rename = "tls-versions")]
        #[serde(default)]
        pub tls_versions: Option<tls_common::HelloParamsTlsVersions>,
        /// Parameters regarding cipher suites.
        #[serde(rename = "cipher-suites")]
        #[serde(default)]
        pub cipher_suites: Option<tls_common::HelloParamsCipherSuites>,
    }

    fn default_tacacs_plus_server_timeout() -> u16 { 5 }

    /// List of TACACS+ servers used by the device.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct TacacsPlusServer {
        /// A name that is used to uniquely identify a TACACS+
        /// server within the device configuration.
        /// This name is not to be confused with the domain-name.
        pub name: String,
        /// Server type: authentication/authorization/accounting and
        /// various combinations.
        #[serde(rename = "server-type")]
        pub server_type: TacacsPlusServerType,
        /// Provides a domain name of the TACACS+ server.
        #[serde(rename = "domain-name")]
        #[serde(default)]
        pub domain_name: Option<String>,
        /// Enables the use of SNI, when set to true. Disables the
        /// use of SNI, when set to false.
        #[serde(rename = "sni-enabled")]
        #[serde(default)]
        pub sni_enabled: Option<bool>,
        /// The IP address or name of the TACACS+ server.
        pub address: String,
        /// The port number of TACACS+ server.
        /// Default port number for legacy TACACS+ is 49,
        /// while it is TBD for TACACS+TLS.
        pub port: u16,
        /// Identity credentials that a TLS client may present when
        /// establishing a connection to a TLS server.
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
        /// TACACS+ client and server. TACACS+ server
        /// administrators SHOULD configure a shared secret with
        /// a minimum length of 16 characters.
        /// It is highly recommended that this shared secret is
        /// at least 32 characters long and sufficiently complex
        /// with a mix of different character types,
        /// i.e., upper case, lower case, numeric, and
        /// punctuation.  Note that this security mechanism is
        /// best described as 'obfuscation' and not 'encryption'
        /// as it does not provide any meaningful integrity,
        /// privacy, or replay protection.
        /// 
        /// The use of obfuscation is deprecated in favor
        /// of TLS.
        /// 
        /// This choice is provided in the model to accommodate
        /// installed base.
        #[serde(rename = "shared-secret")]
        #[serde(default)]
        pub shared_secret: Option<String>,
        /// Specifies the source IP address for TACACS+ outbound
        /// packets.
        #[serde(rename = "source-ip")]
        #[serde(default)]
        pub source_ip: Option<String>,
        /// Specifies the interface from which the IP address
        /// is derived for use as the source for outbound
        /// TACACS+ packets.
        #[serde(rename = "source-interface")]
        #[serde(default)]
        pub source_interface: Option<String>,
        /// Specifies the VPN Routing and Forwarding (VRF) instance
        /// to use to communicate with the TACACS+ server.
        /// If 'source-interface' is configured, this value MUST
        /// match the network instance bound to the source interface
        /// (via bind-ni-name).
        #[serde(rename = "vrf-instance")]
        #[serde(default)]
        pub vrf_instance: Option<String>,
        /// Indicates whether the Single Connection Mode is enabled
        /// for the server.
        #[serde(rename = "single-connection")]
        #[serde(default)]
        pub single_connection: bool,
        /// The number of seconds that the device will wait for a
        /// response from each TACACS+ server before trying with a
        /// different server.
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
        /// when establishing a connection to a TLS server.
        /// A list of client credentials that can be referenced
        /// when configuring server instances.
        #[serde(rename = "client-credentials")]
        #[serde(default)]
        pub client_credentials: Vec<ClientCredentials>,
        /// Identity credentials that a TLS client may use
        /// to authenticate a TLS server.
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
        /// ensure that the incoming public key value is encoded in the
        /// specified format.
        #[serde(rename = "public-key-format")]
        #[serde(default)]
        pub public_key_format: Option<crypto_types::PublicKeyFormat>,
        /// The binary value of the public key.  The interpretation
        /// of the value is defined by the 'public-key-format' field.
        #[serde(rename = "public-key")]
        #[serde(with = "crate::serde_helpers::base64_binary::option_bytes")]
        #[serde(default)]
        pub public_key: Option<Vec<u8>>,
        /// Identifies the private key's format.  Implementations SHOULD
        /// ensure that the incoming private key value is encoded in the
        /// specified format.
        /// 
        /// For encrypted keys, the value is the decrypted key's
        /// format (i.e., the 'encrypted-value-format' conveys the
        /// encrypted key's format).
        #[serde(rename = "private-key-format")]
        #[serde(default)]
        pub private_key_format: Option<crypto_types::PrivateKeyFormat>,
        /// The value of the binary key.  The key's value is
        /// interpreted by the 'private-key-format' field.
        #[serde(rename = "cleartext-private-key")]
        #[serde(with = "crate::serde_helpers::base64_binary::option_bytes")]
        #[serde(default)]
        pub cleartext_private_key: Option<Vec<u8>>,
        /// A hidden key.  It is of type 'empty' as its value is
        /// inaccessible via management interfaces.  Though hidden
        /// to users, such keys are not hidden to the server and
        /// may be referenced by configuration to indicate which
        /// key a server should use for a cryptographic operation.
        /// How such keys are created is outside the scope of this
        /// module.
        #[serde(rename = "hidden-private-key")]
        #[serde(default)]
        pub hidden_private_key: Option<bool>,
        /// A container for the encrypted asymmetric private key
        /// value.  The interpretation of the 'encrypted-value'
        /// node is via the 'private-key-format' node
        #[serde(rename = "encrypted-private-key")]
        #[serde(default)]
        pub encrypted_private_key: Option<crypto_types::PrivateKeyEncryptedPrivateKey>,
        /// The binary certificate data for this certificate.
        #[serde(rename = "cert-data")]
        #[serde(with = "crate::serde_helpers::base64_binary::option_bytes")]
        #[serde(default)]
        pub cert_data: Option<Vec<u8>>,
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
        /// asymmetric key in the keystore.
        #[serde(default)]
        pub certificate: Option<String>,
    }

    /// A container to hold the local key definition.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct AsymmetricKeyInlineDefinition {
        /// Identifies the public key's format.  Implementations SHOULD
        /// ensure that the incoming public key value is encoded in the
        /// specified format.
        #[serde(rename = "public-key-format")]
        #[serde(default)]
        pub public_key_format: Option<crypto_types::PublicKeyFormat>,
        /// The binary value of the public key.  The interpretation
        /// of the value is defined by the 'public-key-format' field.
        #[serde(rename = "public-key")]
        #[serde(with = "crate::serde_helpers::base64_binary::option_bytes")]
        #[serde(default)]
        pub public_key: Option<Vec<u8>>,
        /// Identifies the private key's format.  Implementations SHOULD
        /// ensure that the incoming private key value is encoded in the
        /// specified format.
        /// 
        /// For encrypted keys, the value is the decrypted key's
        /// format (i.e., the 'encrypted-value-format' conveys the
        /// encrypted key's format).
        #[serde(rename = "private-key-format")]
        #[serde(default)]
        pub private_key_format: Option<crypto_types::PrivateKeyFormat>,
        /// The value of the binary key.  The key's value is
        /// interpreted by the 'private-key-format' field.
        #[serde(rename = "cleartext-private-key")]
        #[serde(with = "crate::serde_helpers::base64_binary::option_bytes")]
        #[serde(default)]
        pub cleartext_private_key: Option<Vec<u8>>,
        /// A hidden key.  It is of type 'empty' as its value is
        /// inaccessible via management interfaces.  Though hidden
        /// to users, such keys are not hidden to the server and
        /// may be referenced by configuration to indicate which
        /// key a server should use for a cryptographic operation.
        /// How such keys are created is outside the scope of this
        /// module.
        #[serde(rename = "hidden-private-key")]
        #[serde(default)]
        pub hidden_private_key: Option<bool>,
        /// A container for the encrypted asymmetric private key
        /// value.  The interpretation of the 'encrypted-value'
        /// node is via the 'private-key-format' node
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
        /// SHOULD ensure that the incoming symmetric key value is
        /// encoded in the specified format.
        /// 
        /// For encrypted keys, the value is the decrypted key's
        /// format (i.e., the 'encrypted-value-format' conveys the
        /// encrypted key's format).
        #[serde(rename = "key-format")]
        #[serde(default)]
        pub key_format: Option<crypto_types::SymmetricKeyFormat>,
        /// The binary value of the key.  The interpretation of
        /// the value is defined by the 'key-format' field.
        #[serde(rename = "cleartext-symmetric-key")]
        #[serde(with = "crate::serde_helpers::base64_binary::option_bytes")]
        #[serde(default)]
        pub cleartext_symmetric_key: Option<Vec<u8>>,
        /// A hidden key is not exportable and not extractable;
        /// therefore, it is of type 'empty' as its value is
        /// inaccessible via management interfaces.  Though hidden
        /// to users, such keys are not hidden to the server and
        /// may be referenced by configuration to indicate which
        /// key a server should use for a cryptographic operation.
        /// How such keys are created is outside the scope of this
        /// module.
        #[serde(rename = "hidden-symmetric-key")]
        #[serde(default)]
        pub hidden_symmetric_key: Option<bool>,
        /// A container for the encrypted symmetric key value.
        /// The interpretation of the 'encrypted-value' node
        /// is via the 'key-format' node
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
        /// ensure that the incoming public key value is encoded in the
        /// specified format.
        #[serde(rename = "public-key-format")]
        #[serde(default)]
        pub public_key_format: Option<crypto_types::PublicKeyFormat>,
        /// The binary value of the public key.  The interpretation
        /// of the value is defined by the 'public-key-format' field.
        #[serde(rename = "public-key")]
        #[serde(with = "crate::serde_helpers::base64_binary::option_bytes")]
        #[serde(default)]
        pub public_key: Option<Vec<u8>>,
        /// Identifies the private key's format.  Implementations SHOULD
        /// ensure that the incoming private key value is encoded in the
        /// specified format.
        /// 
        /// For encrypted keys, the value is the decrypted key's
        /// format (i.e., the 'encrypted-value-format' conveys the
        /// encrypted key's format).
        #[serde(rename = "private-key-format")]
        #[serde(default)]
        pub private_key_format: Option<crypto_types::PrivateKeyFormat>,
        /// The value of the binary key.  The key's value is
        /// interpreted by the 'private-key-format' field.
        #[serde(rename = "cleartext-private-key")]
        #[serde(with = "crate::serde_helpers::base64_binary::option_bytes")]
        #[serde(default)]
        pub cleartext_private_key: Option<Vec<u8>>,
        /// A hidden key.  It is of type 'empty' as its value is
        /// inaccessible via management interfaces.  Though hidden
        /// to users, such keys are not hidden to the server and
        /// may be referenced by configuration to indicate which
        /// key a server should use for a cryptographic operation.
        /// How such keys are created is outside the scope of this
        /// module.
        #[serde(rename = "hidden-private-key")]
        #[serde(default)]
        pub hidden_private_key: Option<bool>,
        /// A container for the encrypted asymmetric private key
        /// value.  The interpretation of the 'encrypted-value'
        /// node is via the 'private-key-format' node
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
        /// SHOULD ensure that the incoming symmetric key value is
        /// encoded in the specified format.
        /// 
        /// For encrypted keys, the value is the decrypted key's
        /// format (i.e., the 'encrypted-value-format' conveys the
        /// encrypted key's format).
        #[serde(rename = "key-format")]
        #[serde(default)]
        pub key_format: Option<crypto_types::SymmetricKeyFormat>,
        /// The binary value of the key.  The interpretation of
        /// the value is defined by the 'key-format' field.
        #[serde(rename = "cleartext-symmetric-key")]
        #[serde(with = "crate::serde_helpers::base64_binary::option_bytes")]
        #[serde(default)]
        pub cleartext_symmetric_key: Option<Vec<u8>>,
        /// A hidden key is not exportable and not extractable;
        /// therefore, it is of type 'empty' as its value is
        /// inaccessible via management interfaces.  Though hidden
        /// to users, such keys are not hidden to the server and
        /// may be referenced by configuration to indicate which
        /// key a server should use for a cryptographic operation.
        /// How such keys are created is outside the scope of this
        /// module.
        #[serde(rename = "hidden-symmetric-key")]
        #[serde(default)]
        pub hidden_symmetric_key: Option<bool>,
        /// A container for the encrypted symmetric key value.
        /// The interpretation of the 'encrypted-value' node
        /// is via the 'key-format' node
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

    pub type CsrInfo = Vec<u8>;
    pub type P10Csr = Vec<u8>;
    pub type X509 = Vec<u8>;
    pub type Crl = Vec<u8>;
    pub type OscpRequest = Vec<u8>;
    pub type OscpResponse = Vec<u8>;
    pub type Cms = Vec<u8>;
    pub type DataContentCms = Vec<u8>;
    pub type SignedDataCms = Vec<u8>;
    pub type EnvelopedDataCms = Vec<u8>;
    pub type DigestedDataCms = Vec<u8>;
    pub type EncryptedDataCms = Vec<u8>;
    pub type AuthenticatedDataCms = Vec<u8>;
    pub type TrustAnchorCertX509 = Vec<u8>;
    pub type EndEntityCertX509 = Vec<u8>;
    pub type TrustAnchorCertCms = Vec<u8>;
    pub type EndEntityCertCms = Vec<u8>;

    /// Valid identities derived from `ietf-crypto-types:public-key-format`.
    /// Base key-format identity for public keys.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(clippy::doc_markdown)]
    pub enum PublicKeyFormat {
        /// Indicates that the public key value is a Secure Shell (SSH)
        /// public key, as specified in RFC 4253, Section 6.6, i.e.:
        /// 
        /// string    certificate or public key format
        /// identifier
        /// byte[n]   key/certificate data.
        SshPublicKeyFormat,
        /// Indicates that the public key value is a SubjectPublicKeyInfo
        /// structure, as described in RFC 5280, encoded using ASN.1
        /// distinguished encoding rules (DER), as specified in
        /// ITU-T X.690.
        SubjectPublicKeyInfoFormat,
    }

    impl PublicKeyFormat {
        /// All valid identities for this base.
        pub const ALL: &[Self] = &[
            Self::SshPublicKeyFormat,
            Self::SubjectPublicKeyInfoFormat,
        ];

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
                Self::SubjectPublicKeyInfoFormat => "ietf-crypto-types:subject-public-key-info-format",
            }
        }

        /// Parses an RFC 7951 module-qualified string into this identity.
        #[must_use]
        pub fn from_rfc7951_str(s: &str) -> Option<Self> {
            match s {
                "ietf-crypto-types:ssh-public-key-format" => Some(Self::SshPublicKeyFormat),
                "ietf-crypto-types:subject-public-key-info-format" => Some(Self::SubjectPublicKeyInfoFormat),
                _ => None,
            }
        }

        /// Checks whether the given string is a valid RFC 7951 value for this identity.
        #[must_use]
        pub fn is_valid(s: &str) -> bool {
            Self::from_rfc7951_str(s).is_some()
        }
    }

    impl<'de> serde::Deserialize<'de> for PublicKeyFormat {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Self::from_rfc7951_str(&s).ok_or_else(|| {
                serde::de::Error::unknown_variant(&s, Self::ALLOWED_VALUES)
            })
        }
    }

    impl serde::Serialize for PublicKeyFormat {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(self.as_rfc7951_str())
        }
    }

    /// Valid identities derived from `ietf-crypto-types:private-key-format`.
    /// Base key-format identity for private keys.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(clippy::doc_markdown)]
    pub enum PrivateKeyFormat {
        /// Indicates that the private key value is encoded as
        /// an RSAPrivateKey (from RFC 8017), encoded using ASN.1
        /// distinguished encoding rules (DER), as specified in
        /// ITU-T X.690.
        RsaPrivateKeyFormat,
        /// Indicates that the private key value is encoded as
        /// an ECPrivateKey (from RFC 5915), encoded using ASN.1
        /// distinguished encoding rules (DER), as specified in
        /// ITU-T X.690.
        EcPrivateKeyFormat,
        /// Indicates that the private key value is a
        /// Cryptographic Message Syntax (CMS) OneAsymmetricKey
        /// structure, as defined in RFC 5958, encoded using
        /// ASN.1 distinguished encoding rules (DER), as
        /// specified in ITU-T X.690.
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

    impl<'de> serde::Deserialize<'de> for PrivateKeyFormat {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Self::from_rfc7951_str(&s).ok_or_else(|| {
                serde::de::Error::unknown_variant(&s, Self::ALLOWED_VALUES)
            })
        }
    }

    impl serde::Serialize for PrivateKeyFormat {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(self.as_rfc7951_str())
        }
    }

    /// Valid identities derived from `ietf-crypto-types:encrypted-value-format`.
    /// Base format identity for encrypted values.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(clippy::doc_markdown)]
    pub enum EncryptedValueFormat {
        /// Base format identity for symmetrically encrypted
        /// values.
        /// Requires YANG features: symmetrically-encrypted-value-format
        SymmetricallyEncryptedValueFormat,
        /// Base format identity for asymmetrically encrypted
        /// values.
        /// Requires YANG features: asymmetrically-encrypted-value-format
        AsymmetricallyEncryptedValueFormat,
        /// Indicates that the encrypted value conforms to
        /// the 'encrypted-data-cms' type with the constraint
        /// that the 'unprotectedAttrs' value is not set.
        /// Requires YANG features: cms-encrypted-data-format
        CmsEncryptedDataFormat,
        /// Indicates that the encrypted value conforms to the
        /// 'enveloped-data-cms' type with the following constraints:
        /// 
        /// The EnvelopedData structure MUST have exactly one
        /// 'RecipientInfo'.
        /// 
        /// If the asymmetric key supports public key cryptography
        /// (e.g., RSA), then the 'RecipientInfo' must be a
        /// 'KeyTransRecipientInfo' with the 'RecipientIdentifier'
        /// using a 'subjectKeyIdentifier' with the value set using
        /// 'method 1' in RFC 7093 over the recipient's public key.
        /// 
        /// Otherwise, if the asymmetric key supports key agreement
        /// (e.g., Elliptic Curve Cryptography (ECC)), then the
        /// 'RecipientInfo' must be a 'KeyAgreeRecipientInfo'.  The
        /// 'OriginatorIdentifierOrKey' value must use the
        /// 'OriginatorPublicKey' alternative.  The
        /// 'UserKeyingMaterial' value must not be present.  There
        /// must be exactly one 'RecipientEncryptedKeys' value
        /// having the 'KeyAgreeRecipientIdentifier' set to 'rKeyId'
        /// with the value set using 'method 1' in RFC 7093 over the
        /// recipient's public key.
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
                Self::SymmetricallyEncryptedValueFormat => "ietf-crypto-types:symmetrically-encrypted-value-format",
                Self::AsymmetricallyEncryptedValueFormat => "ietf-crypto-types:asymmetrically-encrypted-value-format",
                Self::CmsEncryptedDataFormat => "ietf-crypto-types:cms-encrypted-data-format",
                Self::CmsEnvelopedDataFormat => "ietf-crypto-types:cms-enveloped-data-format",
            }
        }

        /// Parses an RFC 7951 module-qualified string into this identity.
        #[must_use]
        pub fn from_rfc7951_str(s: &str) -> Option<Self> {
            match s {
                "ietf-crypto-types:symmetrically-encrypted-value-format" => Some(Self::SymmetricallyEncryptedValueFormat),
                "ietf-crypto-types:asymmetrically-encrypted-value-format" => Some(Self::AsymmetricallyEncryptedValueFormat),
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

    impl<'de> serde::Deserialize<'de> for EncryptedValueFormat {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Self::from_rfc7951_str(&s).ok_or_else(|| {
                serde::de::Error::unknown_variant(&s, Self::ALLOWED_VALUES)
            })
        }
    }

    impl serde::Serialize for EncryptedValueFormat {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(self.as_rfc7951_str())
        }
    }

    /// Valid identities derived from `ietf-crypto-types:symmetric-key-format`.
    /// Base key-format identity for symmetric keys.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[allow(clippy::doc_markdown)]
    pub enum SymmetricKeyFormat {
        /// Indicates that the key is encoded as a raw octet string.
        /// The length of the octet string MUST be appropriate for
        /// the associated algorithm's block size.
        /// 
        /// The identity of the associated algorithm is outside the
        /// scope of this specification.  This is also true when
        /// the octet string has been encrypted.
        OctetStringKeyFormat,
        /// Indicates that the private key value is a CMS
        /// OneSymmetricKey structure, as defined in RFC 6031,
        /// encoded using ASN.1 distinguished encoding rules
        /// (DER), as specified in ITU-T X.690.
        /// Requires YANG features: one-symmetric-key-format
        OneSymmetricKeyFormat,
    }

    impl SymmetricKeyFormat {
        /// All valid identities for this base.
        pub const ALL: &[Self] = &[
            Self::OctetStringKeyFormat,
            Self::OneSymmetricKeyFormat,
        ];

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

    impl<'de> serde::Deserialize<'de> for SymmetricKeyFormat {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Self::from_rfc7951_str(&s).ok_or_else(|| {
                serde::de::Error::unknown_variant(&s, Self::ALLOWED_VALUES)
            })
        }
    }

    impl serde::Serialize for SymmetricKeyFormat {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(self.as_rfc7951_str())
        }
    }

    /// An empty container enabling a reference to the key that
    /// encrypted the value to be augmented in.  The referenced
    /// key MUST be a symmetric key or an asymmetric key.
    /// 
    /// A symmetric key MUST be referenced via a leaf node called
    /// 'symmetric-key-ref'.  An asymmetric key MUST be referenced
    /// via a leaf node called 'asymmetric-key-ref'.
    /// 
    /// The leaf nodes MUST be direct descendants in the data tree
    /// and MAY be direct descendants in the schema tree (e.g.,
    /// 'choice'/'case' statements are allowed but not a
    /// container).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct EncryptedValueEncryptedBy {
    }

    /// A container for the encrypted asymmetric private key
    /// value.  The interpretation of the 'encrypted-value'
    /// node is via the 'private-key-format' node
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct PrivateKeyEncryptedPrivateKey {
        /// An empty container enabling a reference to the key that
        /// encrypted the value to be augmented in.  The referenced
        /// key MUST be a symmetric key or an asymmetric key.
        /// 
        /// A symmetric key MUST be referenced via a leaf node called
        /// 'symmetric-key-ref'.  An asymmetric key MUST be referenced
        /// via a leaf node called 'asymmetric-key-ref'.
        /// 
        /// The leaf nodes MUST be direct descendants in the data tree
        /// and MAY be direct descendants in the schema tree (e.g.,
        /// 'choice'/'case' statements are allowed but not a
        /// container).
        #[serde(rename = "encrypted-by")]
        #[serde(default)]
        pub encrypted_by: Option<EncryptedValueEncryptedBy>,
        /// Identifies the format of the 'encrypted-value' leaf.
        /// 
        /// If 'encrypted-by' points to a symmetric key, then an
        /// identity based on 'symmetrically-encrypted-value-format'
        /// MUST be set (e.g., 'cms-encrypted-data-format').
        /// 
        /// If 'encrypted-by' points to an asymmetric key, then an
        /// identity based on 'asymmetrically-encrypted-value-format'
        /// MUST be set (e.g., 'cms-enveloped-data-format').
        #[serde(rename = "encrypted-value-format")]
        pub encrypted_value_format: EncryptedValueFormat,
        /// The value, encrypted using the referenced symmetric
        /// or asymmetric key.  The value MUST be encoded using
        /// the format associated with the 'encrypted-value-format'
        /// leaf.
        #[serde(rename = "encrypted-value")]
        #[serde(with = "crate::serde_helpers::base64_binary::bytes")]
        pub encrypted_value: Vec<u8>,
    }

    /// An empty container enabling a reference to the key that
    /// encrypted the value to be augmented in.  The referenced
    /// key MUST be a symmetric key or an asymmetric key.
    /// 
    /// A symmetric key MUST be referenced via a leaf node called
    /// 'symmetric-key-ref'.  An asymmetric key MUST be referenced
    /// via a leaf node called 'asymmetric-key-ref'.
    /// 
    /// The leaf nodes MUST be direct descendants in the data tree
    /// and MAY be direct descendants in the schema tree (e.g.,
    /// 'choice'/'case' statements are allowed but not a
    /// container).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct EncryptedValueEncryptedBy2 {
        /// Identifies the symmetric key used to encrypt the
        /// associated key.
        #[serde(rename = "symmetric-key-ref")]
        #[serde(default)]
        pub symmetric_key_ref: Option<String>,
        /// Identifies the asymmetric key whose public key
        /// encrypted the associated key.
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
        /// encrypted the value to be augmented in.  The referenced
        /// key MUST be a symmetric key or an asymmetric key.
        /// 
        /// A symmetric key MUST be referenced via a leaf node called
        /// 'symmetric-key-ref'.  An asymmetric key MUST be referenced
        /// via a leaf node called 'asymmetric-key-ref'.
        /// 
        /// The leaf nodes MUST be direct descendants in the data tree
        /// and MAY be direct descendants in the schema tree (e.g.,
        /// 'choice'/'case' statements are allowed but not a
        /// container).
        #[serde(rename = "encrypted-by")]
        #[serde(default)]
        pub encrypted_by: Option<EncryptedValueEncryptedBy2>,
        /// Identifies the format of the 'encrypted-value' leaf.
        /// 
        /// If 'encrypted-by' points to a symmetric key, then an
        /// identity based on 'symmetrically-encrypted-value-format'
        /// MUST be set (e.g., 'cms-encrypted-data-format').
        /// 
        /// If 'encrypted-by' points to an asymmetric key, then an
        /// identity based on 'asymmetrically-encrypted-value-format'
        /// MUST be set (e.g., 'cms-enveloped-data-format').
        #[serde(rename = "encrypted-value-format")]
        pub encrypted_value_format: EncryptedValueFormat,
        /// The value, encrypted using the referenced symmetric
        /// or asymmetric key.  The value MUST be encoded using
        /// the format associated with the 'encrypted-value-format'
        /// leaf.
        #[serde(rename = "encrypted-value")]
        #[serde(with = "crate::serde_helpers::base64_binary::bytes")]
        pub encrypted_value: Vec<u8>,
    }

    /// A certificate for this asymmetric key.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct AsymmetricKeyPairWithCertsCertificate {
        /// An arbitrary name for the certificate.
        pub name: String,
        /// The binary certificate data for this certificate.
        #[serde(rename = "cert-data")]
        #[serde(with = "crate::serde_helpers::base64_binary::bytes")]
        pub cert_data: Vec<u8>,
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
    use super::crypto_types;

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
        #[serde(with = "crate::serde_helpers::base64_binary::bytes")]
        pub cert_data: Vec<u8>,
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
        /// ensure that the incoming public key value is encoded in the
        /// specified format.
        #[serde(rename = "public-key-format")]
        pub public_key_format: crypto_types::PublicKeyFormat,
        /// The binary value of the public key.  The interpretation
        /// of the value is defined by the 'public-key-format' field.
        #[serde(rename = "public-key")]
        #[serde(with = "crate::serde_helpers::base64_binary::bytes")]
        pub public_key: Vec<u8>,
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
    /// another could be used to authenticate a specific set of
    /// clients.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct CertificateBag {
        /// An arbitrary name for this bag of certificates.
        pub name: String,
        /// A description for this bag of certificates.  The
        /// intended purpose for the bag SHOULD be described.
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
        /// be for a specific purpose.  For instance, one bag could
        /// be used to authenticate a specific set of servers, while
        /// another could be used to authenticate a specific set of
        /// clients.
        #[serde(rename = "certificate-bag")]
        #[serde(default)]
        pub certificate_bag: Vec<CertificateBag>,
    }

    /// A bag of public keys.  Each bag of keys SHOULD be for
    /// a specific purpose.  For instance, one bag could be used
    /// to authenticate a specific set of servers, while another
    /// could be used to authenticate a specific set of clients.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct PublicKeyBag {
        /// An arbitrary name for this bag of public keys.
        pub name: String,
        /// A description for this bag of public keys.  The
        /// intended purpose for the bag MUST be described.
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
        /// a specific purpose.  For instance, one bag could be used
        /// to authenticate a specific set of servers, while another
        /// could be used to authenticate a specific set of clients.
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

    /// Acceptable cipher suites in order of descending
    /// preference.  The configured host key algorithms should
    /// be compatible with the algorithm used by the configured
    /// private key.  Please see Section 5 of RFC 9645 for
    /// valid combinations.
    /// 
    /// If this leaf-list is not configured (has zero elements),
    /// the acceptable cipher suites are implementation-
    /// defined.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum TlsCipherSuiteAlgorithm {
        /// Enumeration for the 'TLS_NULL_WITH_NULL_NULL' algorithm.
        #[serde(rename = "TLS_NULL_WITH_NULL_NULL")]
        Tls_null_with_null_null,
        /// Enumeration for the 'TLS_RSA_WITH_NULL_MD5' algorithm.
        #[serde(rename = "TLS_RSA_WITH_NULL_MD5")]
        Tls_rsa_with_null_md5,
        /// Enumeration for the 'TLS_RSA_WITH_NULL_SHA' algorithm.
        #[serde(rename = "TLS_RSA_WITH_NULL_SHA")]
        Tls_rsa_with_null_sha,
        /// Enumeration for the 'TLS_RSA_EXPORT_WITH_RC4_40_MD5'
        /// algorithm.
        #[serde(rename = "TLS_RSA_EXPORT_WITH_RC4_40_MD5")]
        Tls_rsa_export_with_rc4_40_md5,
        /// Enumeration for the 'TLS_RSA_WITH_RC4_128_MD5'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_RC4_128_MD5")]
        Tls_rsa_with_rc4_128_md5,
        /// Enumeration for the 'TLS_RSA_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_RC4_128_SHA")]
        Tls_rsa_with_rc4_128_sha,
        /// Enumeration for the 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5'
        /// algorithm.
        #[serde(rename = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5")]
        Tls_rsa_export_with_rc2_cbc_40_md5,
        /// Enumeration for the 'TLS_RSA_WITH_IDEA_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_IDEA_CBC_SHA")]
        Tls_rsa_with_idea_cbc_sha,
        /// Enumeration for the 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA")]
        Tls_rsa_export_with_des40_cbc_sha,
        /// Enumeration for the 'TLS_RSA_WITH_DES_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_DES_CBC_SHA")]
        Tls_rsa_with_des_cbc_sha,
        /// Enumeration for the 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_3DES_EDE_CBC_SHA")]
        Tls_rsa_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA")]
        Tls_dh_dss_export_with_des40_cbc_sha,
        /// Enumeration for the 'TLS_DH_DSS_WITH_DES_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_DES_CBC_SHA")]
        Tls_dh_dss_with_des_cbc_sha,
        /// Enumeration for the 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA")]
        Tls_dh_dss_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA")]
        Tls_dh_rsa_export_with_des40_cbc_sha,
        /// Enumeration for the 'TLS_DH_RSA_WITH_DES_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_DES_CBC_SHA")]
        Tls_dh_rsa_with_des_cbc_sha,
        /// Enumeration for the 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA")]
        Tls_dh_rsa_with_3des_ede_cbc_sha,
        /// Enumeration for the
        /// 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA' algorithm.
        #[serde(rename = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA")]
        Tls_dhe_dss_export_with_des40_cbc_sha,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_DES_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_DES_CBC_SHA")]
        Tls_dhe_dss_with_des_cbc_sha,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA")]
        Tls_dhe_dss_with_3des_ede_cbc_sha,
        /// Enumeration for the
        /// 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA' algorithm.
        #[serde(rename = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA")]
        Tls_dhe_rsa_export_with_des40_cbc_sha,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_DES_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_DES_CBC_SHA")]
        Tls_dhe_rsa_with_des_cbc_sha,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA")]
        Tls_dhe_rsa_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5")]
        Tls_dh_anon_export_with_rc4_40_md5,
        /// Enumeration for the 'TLS_DH_anon_WITH_RC4_128_MD5'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_RC4_128_MD5")]
        Tls_dh_anon_with_rc4_128_md5,
        /// Enumeration for the
        /// 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA' algorithm.
        #[serde(rename = "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA")]
        Tls_dh_anon_export_with_des40_cbc_sha,
        /// Enumeration for the 'TLS_DH_anon_WITH_DES_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_DES_CBC_SHA")]
        Tls_dh_anon_with_des_cbc_sha,
        /// Enumeration for the 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA")]
        Tls_dh_anon_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_KRB5_WITH_DES_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_WITH_DES_CBC_SHA")]
        Tls_krb5_with_des_cbc_sha,
        /// Enumeration for the 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA")]
        Tls_krb5_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_KRB5_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_WITH_RC4_128_SHA")]
        Tls_krb5_with_rc4_128_sha,
        /// Enumeration for the 'TLS_KRB5_WITH_IDEA_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_WITH_IDEA_CBC_SHA")]
        Tls_krb5_with_idea_cbc_sha,
        /// Enumeration for the 'TLS_KRB5_WITH_DES_CBC_MD5'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_WITH_DES_CBC_MD5")]
        Tls_krb5_with_des_cbc_md5,
        /// Enumeration for the 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5")]
        Tls_krb5_with_3des_ede_cbc_md5,
        /// Enumeration for the 'TLS_KRB5_WITH_RC4_128_MD5'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_WITH_RC4_128_MD5")]
        Tls_krb5_with_rc4_128_md5,
        /// Enumeration for the 'TLS_KRB5_WITH_IDEA_CBC_MD5'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_WITH_IDEA_CBC_MD5")]
        Tls_krb5_with_idea_cbc_md5,
        /// Enumeration for the 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA")]
        Tls_krb5_export_with_des_cbc_40_sha,
        /// Enumeration for the 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA")]
        Tls_krb5_export_with_rc2_cbc_40_sha,
        /// Enumeration for the 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA")]
        Tls_krb5_export_with_rc4_40_sha,
        /// Enumeration for the 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5")]
        Tls_krb5_export_with_des_cbc_40_md5,
        /// Enumeration for the 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5")]
        Tls_krb5_export_with_rc2_cbc_40_md5,
        /// Enumeration for the 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5'
        /// algorithm.
        #[serde(rename = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5")]
        Tls_krb5_export_with_rc4_40_md5,
        /// Enumeration for the 'TLS_PSK_WITH_NULL_SHA' algorithm.
        #[serde(rename = "TLS_PSK_WITH_NULL_SHA")]
        Tls_psk_with_null_sha,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_NULL_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_NULL_SHA")]
        Tls_dhe_psk_with_null_sha,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_NULL_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_NULL_SHA")]
        Tls_rsa_psk_with_null_sha,
        /// Enumeration for the 'TLS_RSA_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_AES_128_CBC_SHA")]
        Tls_rsa_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_DH_DSS_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_AES_128_CBC_SHA")]
        Tls_dh_dss_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_DH_RSA_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_AES_128_CBC_SHA")]
        Tls_dh_rsa_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA")]
        Tls_dhe_dss_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA")]
        Tls_dhe_rsa_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_DH_anon_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_AES_128_CBC_SHA")]
        Tls_dh_anon_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_RSA_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_AES_256_CBC_SHA")]
        Tls_rsa_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_DH_DSS_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_AES_256_CBC_SHA")]
        Tls_dh_dss_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_DH_RSA_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_AES_256_CBC_SHA")]
        Tls_dh_rsa_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA")]
        Tls_dhe_dss_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA")]
        Tls_dhe_rsa_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_DH_anon_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_AES_256_CBC_SHA")]
        Tls_dh_anon_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_RSA_WITH_NULL_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_NULL_SHA256")]
        Tls_rsa_with_null_sha256,
        /// Enumeration for the 'TLS_RSA_WITH_AES_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_AES_128_CBC_SHA256")]
        Tls_rsa_with_aes_128_cbc_sha256,
        /// Enumeration for the 'TLS_RSA_WITH_AES_256_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_AES_256_CBC_SHA256")]
        Tls_rsa_with_aes_256_cbc_sha256,
        /// Enumeration for the 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256")]
        Tls_dh_dss_with_aes_128_cbc_sha256,
        /// Enumeration for the 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256")]
        Tls_dh_rsa_with_aes_128_cbc_sha256,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256")]
        Tls_dhe_dss_with_aes_128_cbc_sha256,
        /// Enumeration for the 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA")]
        Tls_rsa_with_camellia_128_cbc_sha,
        /// Enumeration for the 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA")]
        Tls_dh_dss_with_camellia_128_cbc_sha,
        /// Enumeration for the 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA")]
        Tls_dh_rsa_with_camellia_128_cbc_sha,
        /// Enumeration for the
        /// 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA' algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA")]
        Tls_dhe_dss_with_camellia_128_cbc_sha,
        /// Enumeration for the
        /// 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA' algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA")]
        Tls_dhe_rsa_with_camellia_128_cbc_sha,
        /// Enumeration for the
        /// 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA' algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA")]
        Tls_dh_anon_with_camellia_128_cbc_sha,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256")]
        Tls_dhe_rsa_with_aes_128_cbc_sha256,
        /// Enumeration for the 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256")]
        Tls_dh_dss_with_aes_256_cbc_sha256,
        /// Enumeration for the 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256")]
        Tls_dh_rsa_with_aes_256_cbc_sha256,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256")]
        Tls_dhe_dss_with_aes_256_cbc_sha256,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256")]
        Tls_dhe_rsa_with_aes_256_cbc_sha256,
        /// Enumeration for the 'TLS_DH_anon_WITH_AES_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_AES_128_CBC_SHA256")]
        Tls_dh_anon_with_aes_128_cbc_sha256,
        /// Enumeration for the 'TLS_DH_anon_WITH_AES_256_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_AES_256_CBC_SHA256")]
        Tls_dh_anon_with_aes_256_cbc_sha256,
        /// Enumeration for the 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA")]
        Tls_rsa_with_camellia_256_cbc_sha,
        /// Enumeration for the 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA")]
        Tls_dh_dss_with_camellia_256_cbc_sha,
        /// Enumeration for the 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA")]
        Tls_dh_rsa_with_camellia_256_cbc_sha,
        /// Enumeration for the
        /// 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA' algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA")]
        Tls_dhe_dss_with_camellia_256_cbc_sha,
        /// Enumeration for the
        /// 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA' algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA")]
        Tls_dhe_rsa_with_camellia_256_cbc_sha,
        /// Enumeration for the
        /// 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA' algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA")]
        Tls_dh_anon_with_camellia_256_cbc_sha,
        /// Enumeration for the 'TLS_PSK_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_RC4_128_SHA")]
        Tls_psk_with_rc4_128_sha,
        /// Enumeration for the 'TLS_PSK_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_3DES_EDE_CBC_SHA")]
        Tls_psk_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_PSK_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_AES_128_CBC_SHA")]
        Tls_psk_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_PSK_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_AES_256_CBC_SHA")]
        Tls_psk_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_RC4_128_SHA")]
        Tls_dhe_psk_with_rc4_128_sha,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA")]
        Tls_dhe_psk_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA")]
        Tls_dhe_psk_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA")]
        Tls_dhe_psk_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_RC4_128_SHA")]
        Tls_rsa_psk_with_rc4_128_sha,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA")]
        Tls_rsa_psk_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA")]
        Tls_rsa_psk_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA")]
        Tls_rsa_psk_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_RSA_WITH_SEED_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_SEED_CBC_SHA")]
        Tls_rsa_with_seed_cbc_sha,
        /// Enumeration for the 'TLS_DH_DSS_WITH_SEED_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_SEED_CBC_SHA")]
        Tls_dh_dss_with_seed_cbc_sha,
        /// Enumeration for the 'TLS_DH_RSA_WITH_SEED_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_SEED_CBC_SHA")]
        Tls_dh_rsa_with_seed_cbc_sha,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_SEED_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_SEED_CBC_SHA")]
        Tls_dhe_dss_with_seed_cbc_sha,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_SEED_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_SEED_CBC_SHA")]
        Tls_dhe_rsa_with_seed_cbc_sha,
        /// Enumeration for the 'TLS_DH_anon_WITH_SEED_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_SEED_CBC_SHA")]
        Tls_dh_anon_with_seed_cbc_sha,
        /// Enumeration for the 'TLS_RSA_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_AES_128_GCM_SHA256")]
        Tls_rsa_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_RSA_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_AES_256_GCM_SHA384")]
        Tls_rsa_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256")]
        Tls_dhe_rsa_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384")]
        Tls_dhe_rsa_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256")]
        Tls_dh_rsa_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384")]
        Tls_dh_rsa_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256")]
        Tls_dhe_dss_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384")]
        Tls_dhe_dss_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256")]
        Tls_dh_dss_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384")]
        Tls_dh_dss_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_DH_anon_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_AES_128_GCM_SHA256")]
        Tls_dh_anon_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_DH_anon_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_AES_256_GCM_SHA384")]
        Tls_dh_anon_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_PSK_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_AES_128_GCM_SHA256")]
        Tls_psk_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_PSK_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_AES_256_GCM_SHA384")]
        Tls_psk_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256")]
        Tls_dhe_psk_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384")]
        Tls_dhe_psk_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256")]
        Tls_rsa_psk_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384")]
        Tls_rsa_psk_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_PSK_WITH_AES_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_AES_128_CBC_SHA256")]
        Tls_psk_with_aes_128_cbc_sha256,
        /// Enumeration for the 'TLS_PSK_WITH_AES_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_AES_256_CBC_SHA384")]
        Tls_psk_with_aes_256_cbc_sha384,
        /// Enumeration for the 'TLS_PSK_WITH_NULL_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_NULL_SHA256")]
        Tls_psk_with_null_sha256,
        /// Enumeration for the 'TLS_PSK_WITH_NULL_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_NULL_SHA384")]
        Tls_psk_with_null_sha384,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256")]
        Tls_dhe_psk_with_aes_128_cbc_sha256,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384")]
        Tls_dhe_psk_with_aes_256_cbc_sha384,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_NULL_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_NULL_SHA256")]
        Tls_dhe_psk_with_null_sha256,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_NULL_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_NULL_SHA384")]
        Tls_dhe_psk_with_null_sha384,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256")]
        Tls_rsa_psk_with_aes_128_cbc_sha256,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384")]
        Tls_rsa_psk_with_aes_256_cbc_sha384,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_NULL_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_NULL_SHA256")]
        Tls_rsa_psk_with_null_sha256,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_NULL_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_NULL_SHA384")]
        Tls_rsa_psk_with_null_sha384,
        /// Enumeration for the 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_rsa_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_dh_dss_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_dh_rsa_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_dhe_dss_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_dhe_rsa_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_dh_anon_with_camellia_128_cbc_sha256,
        /// Enumeration for the 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256")]
        Tls_rsa_with_camellia_256_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256")]
        Tls_dh_dss_with_camellia_256_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256")]
        Tls_dh_rsa_with_camellia_256_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256")]
        Tls_dhe_dss_with_camellia_256_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256")]
        Tls_dhe_rsa_with_camellia_256_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256")]
        Tls_dh_anon_with_camellia_256_cbc_sha256,
        /// Enumeration for the 'TLS_SM4_GCM_SM3' algorithm.
        #[serde(rename = "TLS_SM4_GCM_SM3")]
        Tls_sm4_gcm_sm3,
        /// Enumeration for the 'TLS_SM4_CCM_SM3' algorithm.
        #[serde(rename = "TLS_SM4_CCM_SM3")]
        Tls_sm4_ccm_sm3,
        /// Enumeration for the 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'
        /// algorithm.
        #[serde(rename = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")]
        Tls_empty_renegotiation_info_scsv,
        /// Enumeration for the 'TLS_AES_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_AES_128_GCM_SHA256")]
        Tls_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_AES_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_AES_256_GCM_SHA384")]
        Tls_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_CHACHA20_POLY1305_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_CHACHA20_POLY1305_SHA256")]
        Tls_chacha20_poly1305_sha256,
        /// Enumeration for the 'TLS_AES_128_CCM_SHA256' algorithm.
        #[serde(rename = "TLS_AES_128_CCM_SHA256")]
        Tls_aes_128_ccm_sha256,
        /// Enumeration for the 'TLS_AES_128_CCM_8_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_AES_128_CCM_8_SHA256")]
        Tls_aes_128_ccm_8_sha256,
        /// Enumeration for the 'TLS_AEGIS_256_SHA512' algorithm.
        #[serde(rename = "TLS_AEGIS_256_SHA512")]
        Tls_aegis_256_sha512,
        /// Enumeration for the 'TLS_AEGIS_128L_SHA256' algorithm.
        #[serde(rename = "TLS_AEGIS_128L_SHA256")]
        Tls_aegis_128l_sha256,
        /// Enumeration for the 'TLS_FALLBACK_SCSV' algorithm.
        #[serde(rename = "TLS_FALLBACK_SCSV")]
        Tls_fallback_scsv,
        /// Enumeration for the 'TLS_ECDH_ECDSA_WITH_NULL_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_NULL_SHA")]
        Tls_ecdh_ecdsa_with_null_sha,
        /// Enumeration for the 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA")]
        Tls_ecdh_ecdsa_with_rc4_128_sha,
        /// Enumeration for the 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA")]
        Tls_ecdh_ecdsa_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA")]
        Tls_ecdh_ecdsa_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA")]
        Tls_ecdh_ecdsa_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_ECDHE_ECDSA_WITH_NULL_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_NULL_SHA")]
        Tls_ecdhe_ecdsa_with_null_sha,
        /// Enumeration for the 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA")]
        Tls_ecdhe_ecdsa_with_rc4_128_sha,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA' algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA")]
        Tls_ecdhe_ecdsa_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")]
        Tls_ecdhe_ecdsa_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA")]
        Tls_ecdhe_ecdsa_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_ECDH_RSA_WITH_NULL_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_NULL_SHA")]
        Tls_ecdh_rsa_with_null_sha,
        /// Enumeration for the 'TLS_ECDH_RSA_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_RC4_128_SHA")]
        Tls_ecdh_rsa_with_rc4_128_sha,
        /// Enumeration for the 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA")]
        Tls_ecdh_rsa_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA")]
        Tls_ecdh_rsa_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA")]
        Tls_ecdh_rsa_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_ECDHE_RSA_WITH_NULL_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_NULL_SHA")]
        Tls_ecdhe_rsa_with_null_sha,
        /// Enumeration for the 'TLS_ECDHE_RSA_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_RC4_128_SHA")]
        Tls_ecdhe_rsa_with_rc4_128_sha,
        /// Enumeration for the 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA")]
        Tls_ecdhe_rsa_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")]
        Tls_ecdhe_rsa_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")]
        Tls_ecdhe_rsa_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_ECDH_anon_WITH_NULL_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_anon_WITH_NULL_SHA")]
        Tls_ecdh_anon_with_null_sha,
        /// Enumeration for the 'TLS_ECDH_anon_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_anon_WITH_RC4_128_SHA")]
        Tls_ecdh_anon_with_rc4_128_sha,
        /// Enumeration for the 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA")]
        Tls_ecdh_anon_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA")]
        Tls_ecdh_anon_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA")]
        Tls_ecdh_anon_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA")]
        Tls_srp_sha_with_3des_ede_cbc_sha,
        /// Enumeration for the
        /// 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA' algorithm.
        #[serde(rename = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA")]
        Tls_srp_sha_rsa_with_3des_ede_cbc_sha,
        /// Enumeration for the
        /// 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA' algorithm.
        #[serde(rename = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA")]
        Tls_srp_sha_dss_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA")]
        Tls_srp_sha_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA")]
        Tls_srp_sha_rsa_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA")]
        Tls_srp_sha_dss_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA")]
        Tls_srp_sha_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA")]
        Tls_srp_sha_rsa_with_aes_256_cbc_sha,
        /// Enumeration for the 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA")]
        Tls_srp_sha_dss_with_aes_256_cbc_sha,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256")]
        Tls_ecdhe_ecdsa_with_aes_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384")]
        Tls_ecdhe_ecdsa_with_aes_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256")]
        Tls_ecdh_ecdsa_with_aes_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384")]
        Tls_ecdh_ecdsa_with_aes_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256")]
        Tls_ecdhe_rsa_with_aes_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")]
        Tls_ecdhe_rsa_with_aes_256_cbc_sha384,
        /// Enumeration for the 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256")]
        Tls_ecdh_rsa_with_aes_128_cbc_sha256,
        /// Enumeration for the 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384")]
        Tls_ecdh_rsa_with_aes_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")]
        Tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")]
        Tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256")]
        Tls_ecdh_ecdsa_with_aes_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384")]
        Tls_ecdh_ecdsa_with_aes_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")]
        Tls_ecdhe_rsa_with_aes_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")]
        Tls_ecdhe_rsa_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256")]
        Tls_ecdh_rsa_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384")]
        Tls_ecdh_rsa_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_ECDHE_PSK_WITH_RC4_128_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_RC4_128_SHA")]
        Tls_ecdhe_psk_with_rc4_128_sha,
        /// Enumeration for the 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA")]
        Tls_ecdhe_psk_with_3des_ede_cbc_sha,
        /// Enumeration for the 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA")]
        Tls_ecdhe_psk_with_aes_128_cbc_sha,
        /// Enumeration for the 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA")]
        Tls_ecdhe_psk_with_aes_256_cbc_sha,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256")]
        Tls_ecdhe_psk_with_aes_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384")]
        Tls_ecdhe_psk_with_aes_256_cbc_sha384,
        /// Enumeration for the 'TLS_ECDHE_PSK_WITH_NULL_SHA'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_NULL_SHA")]
        Tls_ecdhe_psk_with_null_sha,
        /// Enumeration for the 'TLS_ECDHE_PSK_WITH_NULL_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_NULL_SHA256")]
        Tls_ecdhe_psk_with_null_sha256,
        /// Enumeration for the 'TLS_ECDHE_PSK_WITH_NULL_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_NULL_SHA384")]
        Tls_ecdhe_psk_with_null_sha384,
        /// Enumeration for the 'TLS_RSA_WITH_ARIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_ARIA_128_CBC_SHA256")]
        Tls_rsa_with_aria_128_cbc_sha256,
        /// Enumeration for the 'TLS_RSA_WITH_ARIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_ARIA_256_CBC_SHA384")]
        Tls_rsa_with_aria_256_cbc_sha384,
        /// Enumeration for the 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256")]
        Tls_dh_dss_with_aria_128_cbc_sha256,
        /// Enumeration for the 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384")]
        Tls_dh_dss_with_aria_256_cbc_sha384,
        /// Enumeration for the 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256")]
        Tls_dh_rsa_with_aria_128_cbc_sha256,
        /// Enumeration for the 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384")]
        Tls_dh_rsa_with_aria_256_cbc_sha384,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256")]
        Tls_dhe_dss_with_aria_128_cbc_sha256,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384")]
        Tls_dhe_dss_with_aria_256_cbc_sha384,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256")]
        Tls_dhe_rsa_with_aria_128_cbc_sha256,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384")]
        Tls_dhe_rsa_with_aria_256_cbc_sha384,
        /// Enumeration for the 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256")]
        Tls_dh_anon_with_aria_128_cbc_sha256,
        /// Enumeration for the 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384")]
        Tls_dh_anon_with_aria_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256")]
        Tls_ecdhe_ecdsa_with_aria_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384")]
        Tls_ecdhe_ecdsa_with_aria_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256")]
        Tls_ecdh_ecdsa_with_aria_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384")]
        Tls_ecdh_ecdsa_with_aria_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256")]
        Tls_ecdhe_rsa_with_aria_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384")]
        Tls_ecdhe_rsa_with_aria_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256")]
        Tls_ecdh_rsa_with_aria_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384")]
        Tls_ecdh_rsa_with_aria_256_cbc_sha384,
        /// Enumeration for the 'TLS_RSA_WITH_ARIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_ARIA_128_GCM_SHA256")]
        Tls_rsa_with_aria_128_gcm_sha256,
        /// Enumeration for the 'TLS_RSA_WITH_ARIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_ARIA_256_GCM_SHA384")]
        Tls_rsa_with_aria_256_gcm_sha384,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256")]
        Tls_dhe_rsa_with_aria_128_gcm_sha256,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384")]
        Tls_dhe_rsa_with_aria_256_gcm_sha384,
        /// Enumeration for the 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256")]
        Tls_dh_rsa_with_aria_128_gcm_sha256,
        /// Enumeration for the 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384")]
        Tls_dh_rsa_with_aria_256_gcm_sha384,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256")]
        Tls_dhe_dss_with_aria_128_gcm_sha256,
        /// Enumeration for the 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384")]
        Tls_dhe_dss_with_aria_256_gcm_sha384,
        /// Enumeration for the 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256")]
        Tls_dh_dss_with_aria_128_gcm_sha256,
        /// Enumeration for the 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384")]
        Tls_dh_dss_with_aria_256_gcm_sha384,
        /// Enumeration for the 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256")]
        Tls_dh_anon_with_aria_128_gcm_sha256,
        /// Enumeration for the 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384")]
        Tls_dh_anon_with_aria_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256")]
        Tls_ecdhe_ecdsa_with_aria_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384")]
        Tls_ecdhe_ecdsa_with_aria_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256")]
        Tls_ecdh_ecdsa_with_aria_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384")]
        Tls_ecdh_ecdsa_with_aria_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256")]
        Tls_ecdhe_rsa_with_aria_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384")]
        Tls_ecdhe_rsa_with_aria_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256")]
        Tls_ecdh_rsa_with_aria_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384")]
        Tls_ecdh_rsa_with_aria_256_gcm_sha384,
        /// Enumeration for the 'TLS_PSK_WITH_ARIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_ARIA_128_CBC_SHA256")]
        Tls_psk_with_aria_128_cbc_sha256,
        /// Enumeration for the 'TLS_PSK_WITH_ARIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_ARIA_256_CBC_SHA384")]
        Tls_psk_with_aria_256_cbc_sha384,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256")]
        Tls_dhe_psk_with_aria_128_cbc_sha256,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384")]
        Tls_dhe_psk_with_aria_256_cbc_sha384,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256")]
        Tls_rsa_psk_with_aria_128_cbc_sha256,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384")]
        Tls_rsa_psk_with_aria_256_cbc_sha384,
        /// Enumeration for the 'TLS_PSK_WITH_ARIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_ARIA_128_GCM_SHA256")]
        Tls_psk_with_aria_128_gcm_sha256,
        /// Enumeration for the 'TLS_PSK_WITH_ARIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_ARIA_256_GCM_SHA384")]
        Tls_psk_with_aria_256_gcm_sha384,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256")]
        Tls_dhe_psk_with_aria_128_gcm_sha256,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384")]
        Tls_dhe_psk_with_aria_256_gcm_sha384,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256")]
        Tls_rsa_psk_with_aria_128_gcm_sha256,
        /// Enumeration for the 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384")]
        Tls_rsa_psk_with_aria_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256")]
        Tls_ecdhe_psk_with_aria_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384")]
        Tls_ecdhe_psk_with_aria_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_ecdhe_ecdsa_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384")]
        Tls_ecdhe_ecdsa_with_camellia_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_ecdh_ecdsa_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384")]
        Tls_ecdh_ecdsa_with_camellia_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_ecdhe_rsa_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384")]
        Tls_ecdhe_rsa_with_camellia_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_ecdh_rsa_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384")]
        Tls_ecdh_rsa_with_camellia_256_cbc_sha384,
        /// Enumeration for the 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_rsa_with_camellia_128_gcm_sha256,
        /// Enumeration for the 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_rsa_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_dhe_rsa_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_dhe_rsa_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_dh_rsa_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_dh_rsa_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_dhe_dss_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_dhe_dss_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_dh_dss_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_dh_dss_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_dh_anon_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_dh_anon_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_ecdhe_ecdsa_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_ecdhe_ecdsa_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_ecdh_ecdsa_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_ecdh_ecdsa_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_ecdhe_rsa_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_ecdhe_rsa_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_ecdh_rsa_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_ecdh_rsa_with_camellia_256_gcm_sha384,
        /// Enumeration for the 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_psk_with_camellia_128_gcm_sha256,
        /// Enumeration for the 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_psk_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_dhe_psk_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_dhe_psk_with_camellia_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256")]
        Tls_rsa_psk_with_camellia_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384")]
        Tls_rsa_psk_with_camellia_256_gcm_sha384,
        /// Enumeration for the 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_psk_with_camellia_128_cbc_sha256,
        /// Enumeration for the 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384")]
        Tls_psk_with_camellia_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_dhe_psk_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384")]
        Tls_dhe_psk_with_camellia_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_rsa_psk_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384")]
        Tls_rsa_psk_with_camellia_256_cbc_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256")]
        Tls_ecdhe_psk_with_camellia_128_cbc_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384")]
        Tls_ecdhe_psk_with_camellia_256_cbc_sha384,
        /// Enumeration for the 'TLS_RSA_WITH_AES_128_CCM'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_AES_128_CCM")]
        Tls_rsa_with_aes_128_ccm,
        /// Enumeration for the 'TLS_RSA_WITH_AES_256_CCM'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_AES_256_CCM")]
        Tls_rsa_with_aes_256_ccm,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_AES_128_CCM'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_AES_128_CCM")]
        Tls_dhe_rsa_with_aes_128_ccm,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_AES_256_CCM'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_AES_256_CCM")]
        Tls_dhe_rsa_with_aes_256_ccm,
        /// Enumeration for the 'TLS_RSA_WITH_AES_128_CCM_8'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_AES_128_CCM_8")]
        Tls_rsa_with_aes_128_ccm_8,
        /// Enumeration for the 'TLS_RSA_WITH_AES_256_CCM_8'
        /// algorithm.
        #[serde(rename = "TLS_RSA_WITH_AES_256_CCM_8")]
        Tls_rsa_with_aes_256_ccm_8,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_AES_128_CCM_8'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_AES_128_CCM_8")]
        Tls_dhe_rsa_with_aes_128_ccm_8,
        /// Enumeration for the 'TLS_DHE_RSA_WITH_AES_256_CCM_8'
        /// algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_AES_256_CCM_8")]
        Tls_dhe_rsa_with_aes_256_ccm_8,
        /// Enumeration for the 'TLS_PSK_WITH_AES_128_CCM'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_AES_128_CCM")]
        Tls_psk_with_aes_128_ccm,
        /// Enumeration for the 'TLS_PSK_WITH_AES_256_CCM'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_AES_256_CCM")]
        Tls_psk_with_aes_256_ccm,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_AES_128_CCM'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_AES_128_CCM")]
        Tls_dhe_psk_with_aes_128_ccm,
        /// Enumeration for the 'TLS_DHE_PSK_WITH_AES_256_CCM'
        /// algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_AES_256_CCM")]
        Tls_dhe_psk_with_aes_256_ccm,
        /// Enumeration for the 'TLS_PSK_WITH_AES_128_CCM_8'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_AES_128_CCM_8")]
        Tls_psk_with_aes_128_ccm_8,
        /// Enumeration for the 'TLS_PSK_WITH_AES_256_CCM_8'
        /// algorithm.
        #[serde(rename = "TLS_PSK_WITH_AES_256_CCM_8")]
        Tls_psk_with_aes_256_ccm_8,
        /// Enumeration for the 'TLS_PSK_DHE_WITH_AES_128_CCM_8'
        /// algorithm.
        #[serde(rename = "TLS_PSK_DHE_WITH_AES_128_CCM_8")]
        Tls_psk_dhe_with_aes_128_ccm_8,
        /// Enumeration for the 'TLS_PSK_DHE_WITH_AES_256_CCM_8'
        /// algorithm.
        #[serde(rename = "TLS_PSK_DHE_WITH_AES_256_CCM_8")]
        Tls_psk_dhe_with_aes_256_ccm_8,
        /// Enumeration for the 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM")]
        Tls_ecdhe_ecdsa_with_aes_128_ccm,
        /// Enumeration for the 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM")]
        Tls_ecdhe_ecdsa_with_aes_256_ccm,
        /// Enumeration for the 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8")]
        Tls_ecdhe_ecdsa_with_aes_128_ccm_8,
        /// Enumeration for the 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8")]
        Tls_ecdhe_ecdsa_with_aes_256_ccm_8,
        /// Enumeration for the 'TLS_ECCPWD_WITH_AES_128_GCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_ECCPWD_WITH_AES_128_GCM_SHA256")]
        Tls_eccpwd_with_aes_128_gcm_sha256,
        /// Enumeration for the 'TLS_ECCPWD_WITH_AES_256_GCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_ECCPWD_WITH_AES_256_GCM_SHA384")]
        Tls_eccpwd_with_aes_256_gcm_sha384,
        /// Enumeration for the 'TLS_ECCPWD_WITH_AES_128_CCM_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_ECCPWD_WITH_AES_128_CCM_SHA256")]
        Tls_eccpwd_with_aes_128_ccm_sha256,
        /// Enumeration for the 'TLS_ECCPWD_WITH_AES_256_CCM_SHA384'
        /// algorithm.
        #[serde(rename = "TLS_ECCPWD_WITH_AES_256_CCM_SHA384")]
        Tls_eccpwd_with_aes_256_ccm_sha384,
        /// Enumeration for the 'TLS_SHA256_SHA256' algorithm.
        #[serde(rename = "TLS_SHA256_SHA256")]
        Tls_sha256_sha256,
        /// Enumeration for the 'TLS_SHA384_SHA384' algorithm.
        #[serde(rename = "TLS_SHA384_SHA384")]
        Tls_sha384_sha384,
        /// Enumeration for the
        /// 'TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC'
        /// algorithm.
        #[serde(rename = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC")]
        Tls_gostr341112_256_with_kuznyechik_ctr_omac,
        /// Enumeration for the
        /// 'TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC' algorithm.
        #[serde(rename = "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC")]
        Tls_gostr341112_256_with_magma_ctr_omac,
        /// Enumeration for the
        /// 'TLS_GOSTR341112_256_WITH_28147_CNT_IMIT' algorithm.
        #[serde(rename = "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT")]
        Tls_gostr341112_256_with_28147_cnt_imit,
        /// Enumeration for the
        /// 'TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L' algorithm.
        #[serde(rename = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L")]
        Tls_gostr341112_256_with_kuznyechik_mgm_l,
        /// Enumeration for the 'TLS_GOSTR341112_256_WITH_MAGMA_MGM_L'
        /// algorithm.
        #[serde(rename = "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L")]
        Tls_gostr341112_256_with_magma_mgm_l,
        /// Enumeration for the
        /// 'TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S' algorithm.
        #[serde(rename = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S")]
        Tls_gostr341112_256_with_kuznyechik_mgm_s,
        /// Enumeration for the 'TLS_GOSTR341112_256_WITH_MAGMA_MGM_S'
        /// algorithm.
        #[serde(rename = "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S")]
        Tls_gostr341112_256_with_magma_mgm_s,
        /// Enumeration for the
        /// 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")]
        Tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'
        /// algorithm.
        #[serde(rename = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")]
        Tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
        /// Enumeration for the
        /// 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256' algorithm.
        #[serde(rename = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256")]
        Tls_dhe_rsa_with_chacha20_poly1305_sha256,
        /// Enumeration for the
        /// 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256' algorithm.
        #[serde(rename = "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256")]
        Tls_psk_with_chacha20_poly1305_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256")]
        Tls_ecdhe_psk_with_chacha20_poly1305_sha256,
        /// Enumeration for the
        /// 'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256' algorithm.
        #[serde(rename = "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256")]
        Tls_dhe_psk_with_chacha20_poly1305_sha256,
        /// Enumeration for the
        /// 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256' algorithm.
        #[serde(rename = "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256")]
        Tls_rsa_psk_with_chacha20_poly1305_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256")]
        Tls_ecdhe_psk_with_aes_128_gcm_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384")]
        Tls_ecdhe_psk_with_aes_256_gcm_sha384,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256")]
        Tls_ecdhe_psk_with_aes_128_ccm_8_sha256,
        /// Enumeration for the
        /// 'TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256' algorithm.
        #[serde(rename = "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256")]
        Tls_ecdhe_psk_with_aes_128_ccm_sha256,
    }

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
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        pub const ALL: &[Self] = &[
            Self::Tls12,
            Self::Tls13,
        ];

        /// RFC 7951 JSON string values accepted for this identity.
        pub const ALLOWED_VALUES: &[&str] = &[
            "ietf-tls-common:tls12",
            "ietf-tls-common:tls13",
        ];

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

    impl<'de> serde::Deserialize<'de> for TlsVersionBase {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Self::from_rfc7951_str(&s).ok_or_else(|| {
                serde::de::Error::unknown_variant(&s, Self::ALLOWED_VALUES)
            })
        }
    }

    impl serde::Serialize for TlsVersionBase {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(self.as_rfc7951_str())
        }
    }

    /// Parameters limiting which TLS versions, amongst
    /// those enabled by 'features', are presented during
    /// the TLS handshake.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct HelloParamsTlsVersions {
        /// If not specified, then there is no configured
        /// minimum version.
        #[serde(default)]
        pub min: Option<TlsVersionBase>,
        /// If not specified, then there is no configured
        /// maximum version.
        #[serde(default)]
        pub max: Option<TlsVersionBase>,
    }

    /// Parameters regarding cipher suites.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct HelloParamsCipherSuites {
        /// Acceptable cipher suites in order of descending
        /// preference.  The configured host key algorithms should
        /// be compatible with the algorithm used by the configured
        /// private key.  Please see Section 5 of RFC 9645 for
        /// valid combinations.
        /// 
        /// If this leaf-list is not configured (has zero elements),
        /// the acceptable cipher suites are implementation-
        /// defined.
        #[serde(rename = "cipher-suite")]
        #[serde(default)]
        pub cipher_suite: Vec<TlsCipherSuiteAlgorithm>,
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
