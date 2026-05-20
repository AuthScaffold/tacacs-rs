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
    use super::tacacsrs_tls_psk_dhe;
    use super::truststore;

    pub type ClientCredentialsRef = String;
    pub type ServerCredentialsRef = String;

    /// For externally established PSKs, the hash algorithm must be
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
    }

    /// Choice constraints for [`ClientIdentityCertificate`].
    impl ClientIdentityCertificate {
        /// YANG choice `inline-or-keystore` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_INLINE_OR_KEYSTORE: &[(&str, &[&str])] =
            &[("inline", &["inline-definition"])];
        pub const CHOICE_INLINE_OR_KEYSTORE_MANDATORY: bool = true;
    }

    fn default_tls13_epsk_hash() -> EpskSupportedHash {
        EpskSupportedHash::Sha256
    }

    /// An EPSK is established or provisioned out of band.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct Tls13Epsk {
        /// A container to hold the local key definition.
        #[serde(rename = "inline-definition")]
        #[serde(default)]
        pub inline_definition: Option<keystore::SymmetricKeyInlineDefinition>,
        /// A sequence of bytes used to identify an EPSK. A label for
        /// a PSK established externally.
        #[serde(rename = "external-identity")]
        pub external_identity: String,
        /// For externally established PSKs, the hash algorithm must be
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
        /// Supported groups to offer, in preference order, in
        /// ClientHello key_share when using TLS 1.3 PSK psk_dhe_ke.
        #[serde(rename = "tacacsrs-tls-psk-dhe:psk-dhe-ke-groups")]
        #[serde(default)]
        pub psk_dhe_ke_groups: Vec<tacacsrs_tls_psk_dhe::PskDheKeSupportedGroup>,
    }

    /// Choice constraints for [`Tls13Epsk`].
    impl Tls13Epsk {
        /// YANG choice `inline-or-keystore` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_INLINE_OR_KEYSTORE: &[(&str, &[&str])] =
            &[("inline", &["inline-definition"])];
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
        /// An EPSK is established or provisioned out of band.
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
    }

    /// Choice constraints for [`ServerAuthenticationCaCerts`].
    impl ServerAuthenticationCaCerts {
        /// YANG choice `inline-or-truststore` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_INLINE_OR_TRUSTSTORE: &[(&str, &[&str])] =
            &[("inline", &["inline-definition"])];
        pub const CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY: bool = true;
    }

    /// Identity credentials that a TLS client may use
    /// to authenticate a TLS server.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ServerCredentials {
        /// An identifier that uniquely identifies server
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
        /// An EPSK is established or provisioned out of band.
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
            ("explicit/auth-type", &["certificate", "tls13-epsk"]),
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
            ("explicit", &["ca-certs", "ee-certs", "tls13-epsks"]),
        ];
        pub const CHOICE_REF_OR_EXPLICIT_MANDATORY: bool = false;
    }

    fn default_tacacs_plus_server_timeout() -> u16 {
        5
    }

    /// List of TACACS+ servers used by the device.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct TacacsPlusServer {
        /// A name that is used to uniquely identify a TACACS+
        /// server within the device configuration.
        /// This name is not to be confused with the
        /// 'domain-name'.
        pub name: String,
        /// The server type can be authentication, authorization,
        /// accounting, or any combination of the three types.
        #[serde(rename = "server-type")]
        pub server_type: TacacsPlusServerType,
        /// Provides a domain name of the TACACS+ server.
        #[serde(rename = "domain-name")]
        #[serde(default)]
        pub domain_name: Option<String>,
        /// Enables the use of SNI when set to true. Disables the
        /// use of SNI when set to false.
        #[serde(rename = "sni-enabled")]
        #[serde(default)]
        pub sni_enabled: Option<bool>,
        /// The IP address or name of the TACACS+ server.
        pub address: String,
        /// The port number of the TACACS+ server.
        /// The default port number for legacy TACACS+ is 49,
        /// while it is 300 for TACACS+ over TLS.
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
            ("tls", &["client-identity", "server-authentication"]),
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
        pub const CHOICE_PRIVATE_KEY_TYPE: &[(&str, &[&str])] =
            &[("cleartext-private-key", &["cleartext-private-key"])];
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
    }

    /// Choice constraints for [`SymmetricKeyInlineDefinition`].
    impl SymmetricKeyInlineDefinition {
        /// YANG choice `key-type` (mandatory).
        ///
        /// Each inner slice is one case; at most one case may have fields set.
        pub const CHOICE_KEY_TYPE: &[(&str, &[&str])] =
            &[("cleartext-symmetric-key", &["cleartext-symmetric-key"])];
        pub const CHOICE_KEY_TYPE_MANDATORY: bool = true;
    }
}

/// Types from `ietf-crypto-types`.
pub mod crypto_types {
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

    impl<'de> serde::Deserialize<'de> for PublicKeyFormat {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Self::from_rfc7951_str(&s)
                .ok_or_else(|| serde::de::Error::unknown_variant(&s, Self::ALLOWED_VALUES))
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
            Self::from_rfc7951_str(&s)
                .ok_or_else(|| serde::de::Error::unknown_variant(&s, Self::ALLOWED_VALUES))
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

    impl<'de> serde::Deserialize<'de> for SymmetricKeyFormat {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Self::from_rfc7951_str(&s)
                .ok_or_else(|| serde::de::Error::unknown_variant(&s, Self::ALLOWED_VALUES))
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
}

/// Types from `tacacsrs-tls-psk-dhe`.
pub mod tacacsrs_tls_psk_dhe {
    use serde::{Deserialize, Serialize};

    /// TLS 1.3 supported groups that tacacs-rs may use for
    /// psk_dhe_ke ClientHello key share generation.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum PskDheKeSupportedGroup {
        /// X25519 elliptic curve group.
        #[serde(rename = "x25519")]
        X25519,
        /// NIST P-256 elliptic curve group.
        #[serde(rename = "secp256r1")]
        Secp256r1,
        /// NIST P-384 elliptic curve group.
        #[serde(rename = "secp384r1")]
        Secp384r1,
        /// NIST P-521 elliptic curve group.
        #[serde(rename = "secp521r1")]
        Secp521r1,
        /// Finite field Diffie-Hellman group ffdhe2048.
        #[serde(rename = "ffdhe2048")]
        Ffdhe2048,
        /// Finite field Diffie-Hellman group ffdhe3072.
        #[serde(rename = "ffdhe3072")]
        Ffdhe3072,
        /// Finite field Diffie-Hellman group ffdhe4096.
        #[serde(rename = "ffdhe4096")]
        Ffdhe4096,
        /// Finite field Diffie-Hellman group ffdhe6144.
        #[serde(rename = "ffdhe6144")]
        Ffdhe6144,
        /// Finite field Diffie-Hellman group ffdhe8192.
        #[serde(rename = "ffdhe8192")]
        Ffdhe8192,
    }
}

/// Types from `ietf-truststore`.
pub mod truststore {
    use serde::{Deserialize, Serialize};

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
}

/// Root wrapper for RFC 7951 JSON encoding.
///
/// The JSON document root key is `ietf-system-tacacs-plus:tacacs-plus`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YangConfigRoot {
    #[serde(rename = "ietf-system-tacacs-plus:tacacs-plus")]
    pub tacacs_plus: tacacs_plus::TacacsPlus,
}
