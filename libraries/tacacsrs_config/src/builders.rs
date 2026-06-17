use crate::{
    crypto_types, keystore, ClientIdentityCertificate, EpskSupportedHash, PskDheKeSupportedGroup,
    TacacsPlus, TacacsPlusServer, TacacsPlusServerType, Tls13Epsk, TlsClientClientIdentity,
    TlsClientServerAuthentication,
};
use crate::validation::{self, ValidationOptions};

/// Default TLS 1.3 PSK-DHE groups, in preferred `ClientHello` key share order.
pub const DEFAULT_PSK_DHE_KE_GROUPS: &[PskDheKeSupportedGroup] = &[
    PskDheKeSupportedGroup::Secp384r1,
    PskDheKeSupportedGroup::Secp256r1,
];

/// Builder for constructing a [`TacacsPlus`] root configuration in code.
///
/// This builder is the in-process counterpart to parsing YANG JSON via
/// [`crate::parse_yang_json`]. It composes one or more
/// [`TacacsPlusServerBuilder`] values into the root configuration consumed by
/// the agent service.
///
/// The shared `client-credentials` / `server-credentials` bundles are
/// intentionally left empty: in-code construction is expected to inline all
/// security material directly on each server, bypassing the YANG references
/// mechanism.
#[derive(Debug, Clone)]
pub struct TacacsPlusBuilder {
    root: TacacsPlus,
}

impl Default for TacacsPlusBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TacacsPlusBuilder {
    /// Creates an empty root configuration with no servers and no credential bundles.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: TacacsPlus {
                client_credentials: Vec::new(),
                server_credentials: Vec::new(),
                server: Vec::new(),
            },
        }
    }

    /// Appends a pre-built [`TacacsPlusServer`] to the root.
    #[must_use]
    pub fn with_server(mut self, server: TacacsPlusServer) -> Self {
        self.root.server.push(server);
        self
    }

    /// Builds and appends a [`TacacsPlusServer`] from the supplied builder.
    #[must_use]
    pub fn with_server_builder(self, builder: TacacsPlusServerBuilder) -> Self {
        self.with_server(builder.build())
    }

    /// Validates and returns the constructed [`TacacsPlus`] root.
    ///
    /// Applies the same YANG constraint checks as [`crate::parse_yang_json`],
    /// including server presence, unique endpoints, SNI requirements, security
    /// choice constraints, and credential reference integrity.
    ///
    /// # Errors
    ///
    /// Returns an error if any validation constraint is violated.
    pub fn build(self) -> anyhow::Result<TacacsPlus> {
        self.build_with_options(&ValidationOptions::default())
    }

    /// Validates and returns the constructed [`TacacsPlus`] root using the
    /// supplied validation options.
    ///
    /// Behaves identically to [`Self::build`] except that the supplied
    /// [`ValidationOptions`] are applied during validation, allowing callers
    /// to opt into specific relaxations.
    ///
    /// # Errors
    ///
    /// Returns an error if any validation constraint is violated (subject to `options`).
    pub fn build_with_options(self, options: &ValidationOptions) -> anyhow::Result<TacacsPlus> {
        validation::validate_config_with_options(&self.root, options)?;
        Ok(self.root)
    }
}

/// Builder for constructing `TacacsPlusServer` values in code.
#[derive(Debug, Clone)]
pub struct TacacsPlusServerBuilder {
    server: TacacsPlusServer,
}

impl TacacsPlusServerBuilder {
    /// Creates a server builder with the workspace's standard default field values.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        server_type: TacacsPlusServerType,
        address: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            server: TacacsPlusServer {
                name: name.into(),
                server_type,
                domain_name: None,
                sni_enabled: None,
                address: address.into(),
                port,
                client_identity: None,
                server_authentication: None,
                shared_secret: None,
                source_ip: None,
                source_interface: None,
                vrf_instance: None,
                single_connection: false,
                timeout: 5,
            },
        }
    }

    /// Sets the server timeout in seconds.
    #[must_use]
    pub fn with_timeout(mut self, timeout: u16) -> Self {
        self.server.timeout = timeout;
        self
    }

    /// Selects obfuscation mode using the supplied shared secret.
    ///
    /// This clears any previously configured TLS identity fields. To add a
    /// shared secret alongside an already-configured TLS identity (for
    /// migration purposes), use [`Self::with_shared_secret_alongside_tls`]
    /// instead.
    #[must_use]
    pub fn with_shared_secret(mut self, shared_secret: impl Into<String>) -> Self {
        self.server.shared_secret = Some(shared_secret.into());
        self.server.client_identity = None;
        self.server.server_authentication = None;
        self
    }

    /// Sets the shared secret without affecting any TLS configuration fields.
    ///
    /// Use this when constructing a server that has both TLS and a shared
    /// secret configured simultaneously (e.g. during a migration from legacy
    /// TACACS+ obfuscation to TLS).  The resulting configuration will only
    /// pass validation when
    /// [`ValidationRelaxation::AllowTlsWithSharedSecret`][crate::ValidationRelaxation::AllowTlsWithSharedSecret]
    /// is active.
    #[must_use]
    pub fn with_shared_secret_alongside_tls(mut self, shared_secret: impl Into<String>) -> Self {
        self.server.shared_secret = Some(shared_secret.into());
        self
    }

    /// Selects TLS using a client certificate identity.
    #[must_use]
    pub fn with_tls_client_certificate(
        self,
        cert_data: Option<Vec<u8>>,
        cleartext_private_key: Option<Vec<u8>>,
    ) -> Self {
        self.with_tls_client_certificate_with_key_format(cert_data, cleartext_private_key, None)
    }

    /// Selects TLS using a client certificate identity and private key format.
    #[must_use]
    pub fn with_tls_client_certificate_with_key_format(
        mut self,
        cert_data: Option<Vec<u8>>,
        cleartext_private_key: Option<Vec<u8>>,
        private_key_format: Option<crypto_types::PrivateKeyFormat>,
    ) -> Self {
        self.server.shared_secret = None;
        self.server.client_identity = Some(TlsClientClientIdentity {
            credentials_reference: None,
            certificate: Some(ClientIdentityCertificate {
                inline_definition: Some(keystore::EndEntityCertWithKeyInlineDefinition {
                    public_key_format: None,
                    public_key: None,
                    private_key_format,
                    cleartext_private_key,
                    cert_data,
                }),
            }),
            tls13_epsk: None,
        });
        self.server.server_authentication = None;
        self
    }

    /// Selects TLS using a TLS 1.3 externally provisioned PSK.
    #[must_use]
    pub fn with_tls13_epsk(
        self,
        external_identity: impl Into<String>,
        cleartext_symmetric_key: Vec<u8>,
    ) -> Self {
        self.with_tls13_epsk_with_psk_dhe_groups(
            external_identity,
            cleartext_symmetric_key,
            DEFAULT_PSK_DHE_KE_GROUPS.to_vec(),
        )
    }

    /// Selects TLS using a TLS 1.3 externally provisioned PSK in PSK-only mode.
    #[must_use]
    pub fn with_tls13_epsk_psk_only(
        self,
        external_identity: impl Into<String>,
        cleartext_symmetric_key: Vec<u8>,
    ) -> Self {
        self.with_tls13_epsk_with_psk_dhe_groups(
            external_identity,
            cleartext_symmetric_key,
            Vec::new(),
        )
    }

    /// Selects TLS using a TLS 1.3 externally provisioned PSK with PSK-DHE groups.
    #[must_use]
    pub fn with_tls13_epsk_with_psk_dhe_groups(
        mut self,
        external_identity: impl Into<String>,
        cleartext_symmetric_key: Vec<u8>,
        psk_dhe_ke_groups: Vec<PskDheKeSupportedGroup>,
    ) -> Self {
        self.server.shared_secret = None;
        self.server.client_identity = Some(TlsClientClientIdentity {
            credentials_reference: None,
            certificate: None,
            tls13_epsk: Some(Tls13Epsk {
                inline_definition: Some(keystore::SymmetricKeyInlineDefinition {
                    key_format: None,
                    cleartext_symmetric_key: Some(cleartext_symmetric_key),
                }),
                external_identity: external_identity.into(),
                hash: EpskSupportedHash::Sha256,
                context: None,
                target_protocol: None,
                target_kdf: None,
                psk_dhe_ke_groups,
            }),
        });
        self.server.server_authentication = None;
        self
    }

    /// Selects TLS without a client identity by setting the server-authentication container.
    #[must_use]
    pub fn with_tls_server_authentication(mut self) -> Self {
        self.server.shared_secret = None;
        self.server.client_identity = None;
        self.server.server_authentication = Some(TlsClientServerAuthentication {
            credentials_reference: None,
            ca_certs: None,
            ee_certs: None,
            tls13_epsks: None,
        });
        self
    }

    /// Returns the constructed server.
    #[must_use]
    pub fn build(self) -> TacacsPlusServer {
        self.server
    }
}

#[cfg(test)]
mod tests {
    use crate::{PskDheKeSupportedGroup, TacacsPlusServerExt, TacacsPlusServerType, enumerate_servers};

    use super::{TacacsPlusBuilder, TacacsPlusServerBuilder};

    #[test]
    fn builder_defaults_match_current_cli_construction() {
        let server =
            TacacsPlusServerBuilder::new("cli", TacacsPlusServerType::all(), "192.0.2.10", 49)
                .build();

        assert_eq!(server.name, "cli");
        assert_eq!(server.socket_address(), "192.0.2.10:49");
        assert_eq!(server.timeout, 5);
        assert!(!server.single_connection);
        assert!(server.shared_secret.is_none());
        assert!(server.client_identity.is_none());
        assert!(server.server_authentication.is_none());
    }

    #[test]
    fn builder_security_modes_replace_previous_mode() {
        let server =
            TacacsPlusServerBuilder::new("cli", TacacsPlusServerType::ACCOUNTING, "192.0.2.10", 49)
                .with_shared_secret("secret")
                .with_tls_server_authentication()
                .build();

        assert!(server.shared_secret.is_none());
        assert!(server.client_identity.is_none());
        assert!(server.server_authentication.is_some());
        assert!(server.is_tls());
    }

    #[test]
    fn tls13_epsk_builder_defaults_to_psk_dhe_groups() {
        let server =
            TacacsPlusServerBuilder::new("cli", TacacsPlusServerType::ACCOUNTING, "192.0.2.10", 49)
                .with_tls13_epsk("client", b"secret".to_vec())
                .build();
        let groups = &server
            .client_identity
            .expect("client identity")
            .tls13_epsk
            .expect("tls13 epsk")
            .psk_dhe_ke_groups;

        assert!(matches!(groups.first(), Some(PskDheKeSupportedGroup::Secp384r1)));
        assert!(matches!(groups.get(1), Some(PskDheKeSupportedGroup::Secp256r1)));
    }

    #[test]
    fn tls13_epsk_builder_supports_psk_only_mode() {
        let server =
            TacacsPlusServerBuilder::new("cli", TacacsPlusServerType::ACCOUNTING, "192.0.2.10", 49)
                .with_tls13_epsk_psk_only("client", b"secret".to_vec())
                .build();
        let groups = &server
            .client_identity
            .expect("client identity")
            .tls13_epsk
            .expect("tls13 epsk")
            .psk_dhe_ke_groups;

        assert!(groups.is_empty());
    }

    #[test]
    fn root_builder_build_rejects_empty_server_list() {
        let err = TacacsPlusBuilder::new()
            .build()
            .expect_err("empty server list should be rejected");
        assert!(err.to_string().contains("at least one"), "unexpected error: {err}");
    }

    #[test]
    fn root_builder_preserves_server_order() {
        let root = TacacsPlusBuilder::new()
            .with_server_builder(
                TacacsPlusServerBuilder::new(
                    "primary",
                    TacacsPlusServerType::all(),
                    "192.0.2.10",
                    49,
                )
                .with_shared_secret("secret"),
            )
            .with_server_builder(
                TacacsPlusServerBuilder::new(
                    "secondary",
                    TacacsPlusServerType::all(),
                    "192.0.2.11",
                    49,
                )
                .with_shared_secret("secret"),
            )
            .build()
            .expect("valid config should build successfully");

        assert_eq!(root.server.len(), 2);
        assert_eq!(root.server[0].name, "primary");
        assert_eq!(root.server[1].name, "secondary");
    }

    #[test]
    fn root_builder_roundtrips_through_enumerate_servers() {
        let root = TacacsPlusBuilder::new()
            .with_server_builder(
                TacacsPlusServerBuilder::new(
                    "primary",
                    TacacsPlusServerType::all(),
                    "192.0.2.10",
                    49,
                )
                .with_shared_secret("secret"),
            )
            .build()
            .expect("valid config should build successfully");

        let enumerated = enumerate_servers(&root).expect("enumeration should succeed");
        assert_eq!(enumerated.len(), 1);
        assert_eq!(enumerated[0].name, "primary");
        assert_eq!(enumerated[0].shared_secret.as_deref(), Some("secret"));
    }

    #[test]
    fn build_accepts_valid_config() {
        let result = TacacsPlusBuilder::new()
            .with_server_builder(
                TacacsPlusServerBuilder::new(
                    "primary",
                    TacacsPlusServerType::all(),
                    "192.0.2.10",
                    49,
                )
                .with_shared_secret("secret"),
            )
            .build();

        assert!(result.is_ok(), "valid config should pass validation: {result:?}");
        let config = result.unwrap();
        assert_eq!(config.server.len(), 1);
        assert_eq!(config.server[0].name, "primary");
    }

    #[test]
    fn build_rejects_empty_server_list() {
        let result = TacacsPlusBuilder::new().build();

        let err = result.expect_err("empty server list should be rejected");
        assert!(err.to_string().contains("at least one"), "unexpected error: {err}");
    }

    #[test]
    fn build_rejects_duplicate_endpoints() {
        let result = TacacsPlusBuilder::new()
            .with_server_builder(
                TacacsPlusServerBuilder::new(
                    "primary",
                    TacacsPlusServerType::all(),
                    "192.0.2.10",
                    49,
                )
                .with_shared_secret("secret"),
            )
            .with_server_builder(
                TacacsPlusServerBuilder::new(
                    "duplicate",
                    TacacsPlusServerType::all(),
                    "192.0.2.10",
                    49,
                )
                .with_shared_secret("secret"),
            )
            .build();

        let err = result.expect_err("duplicate endpoints should be rejected");
        assert!(
            err.to_string().contains("duplicate server address+port"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn build_rejects_sni_without_domain_name() {
        let mut server =
            TacacsPlusServerBuilder::new("s", TacacsPlusServerType::all(), "192.0.2.10", 49)
                .with_shared_secret("secret")
                .build();
        server.sni_enabled = Some(true);
        server.domain_name = None;

        let result = TacacsPlusBuilder::new().with_server(server).build();

        let err = result.expect_err("sni-enabled without domain-name should be rejected");
        assert!(
            err.to_string().contains("sni-enabled requires domain-name"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn build_rejects_missing_security_choice() {
        let server =
            TacacsPlusServerBuilder::new("s", TacacsPlusServerType::all(), "192.0.2.10", 49)
                .build();

        let result = TacacsPlusBuilder::new().with_server(server).build();

        let err = result.expect_err("server with no security choice should be rejected");
        assert!(err.to_string().contains("security"), "unexpected error: {err}");
    }
}
