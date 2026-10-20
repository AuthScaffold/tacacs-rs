//! Projects canonical YANG fields into connection-ready transport inputs.

use anyhow::{Context, Result, ensure};

use tacacsrs_networking::{
    ConnectOptions, ConnectPreflight, PreparedEndpoint, CertificateIdentity, CertificateTrust,
    PrivateKeyEncoding, PskHash, PskDheGroup, PreparedTransport, TlsClientConfig, PskClientConfig,
    ServerAddress, CertificateVerification,
};
use tacacsrs_secrets::SecretBytes;

use crate::{TacacsPlusServer, TacacsPlusServerExt, EpskSupportedHash, PskDheKeSupportedGroup};
use crate::crypto_types::{PrivateKeyFormat, PublicKeyFormat};

/// Execution controls that do not replace canonical YANG configuration.
///
/// The server supplies its connection timeout. Preparation does not accept a
/// timeout override. Preflight runs only when a client opens the prepared endpoint.
/// Certificate verification defaults to `CertificateVerification::Required`.
///
/// ```compile_fail
/// use std::time::Duration;
/// use tacacsrs_config::prepare::PrepareOptions;
///
/// let options = PrepareOptions::default().with_timeout(Duration::from_secs(1));
/// ```
#[derive(Debug, Clone, Default)]
pub struct PrepareOptions {
    certificate_verification: CertificateVerification,
    preflight: ConnectPreflight,
    payload_ledger: Option<std::sync::Arc<dyn tacacsrs_networking::PreparationPayloadLedger>>,
}

impl PrepareOptions {
    /// Uses one candidate ledger for Rust-owned endpoint preparation payload.
    #[must_use]
    pub fn with_payload_ledger(
        mut self,
        ledger: std::sync::Arc<dyn tacacsrs_networking::PreparationPayloadLedger>,
    ) -> Self {
        self.payload_ledger = Some(ledger);
        self
    }
    /// Selects the certificate verification policy.
    ///
    /// CAUTION: `DisabledForDevelopment` permits server impersonation. Do not use it in production.
    ///
    /// ```compile_fail,E0308
    /// use tacacsrs_config::prepare::PrepareOptions;
    /// PrepareOptions::default().with_certificate_verification(true);
    /// ```
    ///
    /// ```compile_fail,E0599
    /// use tacacsrs_config::prepare::PrepareOptions;
    /// PrepareOptions::default().with_certificate_verification_disabled(true);
    /// ```
    #[must_use]
    pub const fn with_certificate_verification(
        mut self,
        verification: CertificateVerification,
    ) -> Self {
        self.certificate_verification = verification;
        self
    }

    /// Selects the readiness check that client construction will run.
    #[must_use]
    pub const fn with_preflight(mut self, preflight: ConnectPreflight) -> Self {
        self.preflight = preflight;
        self
    }
}

/// Prepares transport material without opening a connection or changing `server`.
///
/// The canonical server timeout bounds TCP connection establishment.
/// Credentials must already be materialized. TLS contexts are reusable across
/// connection attempts. DNS resolution and handshakes occur during execution.
///
/// # Errors
///
/// Returns an error if certificate, key, PSK, or native context preparation fails.
///
/// # Example
///
/// ```rust
/// use tacacsrs_config::{prepare::{prepare_endpoint, PrepareOptions}, TacacsPlusServer};
/// use tacacsrs_networking::TacacsClient;
///
/// # async fn connect(server: &TacacsPlusServer) -> anyhow::Result<()> {
/// let endpoint = prepare_endpoint(server, PrepareOptions::default())?;
/// let client = TacacsClient::connect_prepared(endpoint).await?;
/// # Ok(())
/// # }
/// ```
pub fn prepare_endpoint(
    server: &TacacsPlusServer,
    options: PrepareOptions,
) -> Result<PreparedEndpoint> {
    super::readiness::validate_runtime_features(server)?;
    if let Some(identity) = &server.client_identity {
        ensure!(
            identity.certificate.is_none() || identity.tls13_epsk.is_none(),
            "A TLS client identity cannot select both certificate and PSK authentication"
        );
    }
    let payload = options
        .payload_ledger
        .map(tacacsrs_networking::PreparationPayload::new)
        .unwrap_or_default();
    if server.address.parse::<std::net::IpAddr>().is_err() {
        payload.retain(server.address.len())?;
    }
    if let Some(secret) = &server.shared_secret {
        payload.retain(secret.expose_secret().len())?;
    }
    payload.retain(server.name.len())?;
    payload.retain(server.name.len())?;
    let address = ServerAddress::new(&server.address, server.port)?;
    let finalize = |transport| {
        PreparedEndpoint::new(
            address,
            transport,
            server.single_connection,
            server.obfuscation_key().map(SecretBytes::new),
            ConnectOptions::default()
                .with_timeout(server.timeout_duration())
                .with_preflight(options.preflight),
        )
        .with_preparation_payload(payload.clone())
    };
    if let Some(epsk) = server
        .client_identity
        .as_ref()
        .and_then(|identity| identity.tls13_epsk.as_ref())
    {
        let key = epsk
            .inline_definition
            .as_ref()
            .and_then(|inline| inline.cleartext_symmetric_key.as_ref())
            .context("TLS 1.3 EPSK inline-definition.cleartext-symmetric-key must be configured")?;
        let hash = match epsk.hash {
            EpskSupportedHash::Sha256 => PskHash::Sha256,
            EpskSupportedHash::Sha384 => PskHash::Sha384,
        };
        let groups = epsk
            .psk_dhe_ke_groups
            .iter()
            .copied()
            .map(psk_group)
            .collect::<Vec<_>>();
        return Ok(finalize(PreparedTransport::Psk(PskClientConfig::prepare_with_payload(
            &epsk.external_identity,
            key.expose_secret(),
            hash,
            &groups,
            tls_sni_name(server)?,
            payload.clone(),
        )?)));
    }
    if !server.is_tls() {
        return Ok(finalize(PreparedTransport::Tcp));
    }
    for bag in server
        .server_authentication
        .iter()
        .flat_map(|auth| auth.ca_certs.iter().chain(auth.ee_certs.iter()))
    {
        ensure!(
            bag.inline_definition
                .as_ref()
                .is_some_and(|inline| !inline.certificate.is_empty()),
            "Configured certificate trust bags must contain materialized certificates"
        );
    }
    let authority_bag = server
        .server_authentication
        .as_ref()
        .and_then(|auth| auth.ca_certs.as_ref());
    let peer_bag = server
        .server_authentication
        .as_ref()
        .and_then(|auth| auth.ee_certs.as_ref());
    let authorities = trust_certificates(authority_bag);
    let peers = trust_certificates(peer_bag);
    let trust = if authority_bag.is_none() && peer_bag.is_none() {
        CertificateTrust::Platform
    } else {
        CertificateTrust::Certificates {
            authorities: &authorities,
            end_entities: &peers,
        }
    };
    let intermediates = server
        .client_identity
        .iter()
        .filter_map(|identity| identity.certificate.as_ref())
        .filter_map(|certificate| certificate.inline_definition.as_ref())
        .flat_map(|inline| inline.intermediate_certificate.iter().map(Vec::as_slice))
        .collect::<Vec<_>>();
    let identity = certificate_identity(server, &intermediates)?;
    let config = TlsClientConfig::prepare_with_payload(
        certificate_peer_identity(server),
        tls_sni_name(server)?,
        trust,
        identity,
        options.certificate_verification,
        payload.clone(),
    )?
    .with_revocation_policy(certificate_revocation(server)?)?;
    Ok(finalize(PreparedTransport::Tls(apply_crl_evidence(config, server)?)))
}

fn apply_crl_evidence(
    mut config: TlsClientConfig,
    server: &TacacsPlusServer,
) -> Result<TlsClientConfig> {
    if let Some(policy) = server
        .server_authentication
        .as_ref()
        .and_then(|auth| auth.require_ocsp.as_ref())
    {
        config = config.with_ocsp_response(
            policy
                .response
                .as_deref()
                .context("Resolve OCSP evidence before endpoint preparation")?,
            std::time::Duration::from_secs(u64::from(policy.max_response_age_seconds)),
        )?;
    }
    if let Some(policy) = server
        .server_authentication
        .as_ref()
        .and_then(|authentication| authentication.require_crls.as_ref())
    {
        let lists = policy
            .crl
            .as_ref()
            .context("Resolve CRL evidence before endpoint preparation")?;
        return config.with_crls(
            &lists.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            std::time::Duration::from_secs(u64::from(policy.max_age_seconds)),
        );
    }
    Ok(config)
}

fn certificate_revocation(
    server: &TacacsPlusServer,
) -> Result<tacacsrs_networking::CertificateRevocationPolicy> {
    server
        .server_authentication
        .as_ref()
        .and_then(|authentication| authentication.require_stapled_ocsp.as_ref())
        .map(|policy| {
            tacacsrs_networking::CertificateRevocationPolicy::require_stapled_ocsp(
                std::time::Duration::from_secs(u64::from(policy.max_response_age_seconds)),
            )
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn certificate_identity<'a>(
    server: &'a TacacsPlusServer,
    intermediates: &'a [&'a [u8]],
) -> Result<Option<CertificateIdentity<'a>>> {
    server
        .client_identity
        .as_ref()
        .and_then(|identity| identity.certificate.as_ref())
        .map(|certificate| {
            let inline = certificate
                .inline_definition
                .as_ref()
                .context("TLS client certificate requires materialized inline credentials")?;
            Ok::<_, anyhow::Error>(CertificateIdentity {
                intermediates,
                public_key_info: match (inline.public_key_format, inline.public_key.as_deref()) {
                    (None, None) => None,
                    (Some(PublicKeyFormat::SubjectPublicKeyInfoFormat), Some(bytes)) => Some(bytes),
                    (Some(PublicKeyFormat::SshPublicKeyFormat), _) => anyhow::bail!("SSH public-key format is not supported for TLS client certificate metadata"),
                    _ => anyhow::bail!("TLS client certificate public-key and public-key-format must be supplied together"),
                },
                certificate: inline
                    .cert_data
                    .as_deref()
                    .context("TLS client certificate requires cert-data")?,
                private_key: inline
                    .cleartext_private_key
                    .as_ref()
                    .context("TLS client certificate requires cleartext-private-key")?
                    .expose_secret(),
                private_key_encoding: match inline.private_key_format {
                    Some(PrivateKeyFormat::RsaPrivateKeyFormat) => PrivateKeyEncoding::RsaPkcs1,
                    Some(PrivateKeyFormat::EcPrivateKeyFormat) => PrivateKeyEncoding::EcSec1,
                    Some(PrivateKeyFormat::OneAsymmetricKeyFormat) | None => {
                        PrivateKeyEncoding::Pkcs8
                    }
                },
            })
        })
        .transpose()
}

fn trust_certificates(bag: Option<&crate::ServerAuthenticationCaCerts>) -> Vec<&[u8]> {
    bag.into_iter()
        .filter_map(|bag| bag.inline_definition.as_ref())
        .flat_map(|inline| {
            inline
                .certificate
                .iter()
                .map(|certificate| certificate.cert_data.as_slice())
        })
        .collect()
}

fn certificate_peer_identity(server: &TacacsPlusServer) -> &str {
    server.domain_name.as_deref().unwrap_or(&server.address)
}

fn tls_sni_name(server: &TacacsPlusServer) -> Result<Option<&str>> {
    if server.sni_enabled() {
        Ok(Some(
            server
                .domain_name
                .as_deref()
                .context("sni-enabled requires domain-name")?,
        ))
    } else {
        Ok(None)
    }
}

fn psk_group(group: PskDheKeSupportedGroup) -> PskDheGroup {
    match group {
        PskDheKeSupportedGroup::X25519 => PskDheGroup::X25519,
        PskDheKeSupportedGroup::Secp256r1 => PskDheGroup::Secp256r1,
        PskDheKeSupportedGroup::Secp384r1 => PskDheGroup::Secp384r1,
        PskDheKeSupportedGroup::Secp521r1 => PskDheGroup::Secp521r1,
        PskDheKeSupportedGroup::Ffdhe2048 => PskDheGroup::Ffdhe2048,
        PskDheKeSupportedGroup::Ffdhe3072 => PskDheGroup::Ffdhe3072,
        PskDheKeSupportedGroup::Ffdhe4096 => PskDheGroup::Ffdhe4096,
        PskDheKeSupportedGroup::Ffdhe6144 => PskDheGroup::Ffdhe6144,
        PskDheKeSupportedGroup::Ffdhe8192 => PskDheGroup::Ffdhe8192,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use crate::{TacacsPlusServerBuilder, TacacsPlusServerType};
    use tacacsrs_networking::TacacsClient;

    use super::*;

    fn builder() -> TacacsPlusServerBuilder {
        TacacsPlusServerBuilder::new("prepared", TacacsPlusServerType::all(), "127.0.0.1", 1)
    }

    #[test]
    fn preparation_defaults_to_required_certificate_verification() {
        assert_eq!(
            PrepareOptions::default().certificate_verification,
            CertificateVerification::Required
        );
    }

    #[test]
    fn combined_configuration_and_certificate_payload_obey_exact_high_water_limit() {
        #[derive(Debug)]
        struct Ledger(std::sync::Mutex<super::super::ConfigurationMaterialBudget>);
        impl tacacsrs_networking::PreparationPayloadLedger for Ledger {
            fn reserve(&self, bytes: u64) -> anyhow::Result<()> {
                self.0.lock().unwrap().reserve_extra(bytes)
            }
            fn release(&self, bytes: u64) {
                self.0.lock().unwrap().release_extra(bytes);
            }
        }

        let (certificate, key) = fixture_certificate("client");
        let mut server = builder()
            .with_tls_client_certificate(
                Some(certificate.to_der().unwrap()),
                Some(key.private_key_to_pkcs8().unwrap()),
            )
            .build();
        server.server_authentication = Some(crate::TlsClientServerAuthentication {
            ca_certs: Some(crate::ServerAuthenticationCaCerts {
                inline_definition: Some(crate::truststore::CertsInlineDefinition {
                    certificate: vec![crate::truststore::CertsCertificate {
                        name: "fixture".to_owned(),
                        cert_data: certificate.to_der().unwrap(),
                    }],
                }),
                central_truststore_reference: None,
            }),
            ..Default::default()
        });
        let logical = super::super::server_payload_bytes(&server).unwrap();
        let measure = |limit| {
            let mut budget = super::super::ConfigurationMaterialBudget::new(limit, 1);
            budget.reserve_logical(logical).unwrap();
            let ledger = Arc::new(Ledger(std::sync::Mutex::new(budget)));
            let endpoint = prepare_endpoint(
                &server,
                PrepareOptions::default().with_payload_ledger(ledger.clone()),
            );
            (endpoint, ledger)
        };
        let (endpoint, ledger) = measure(u64::MAX);
        let endpoint = endpoint.unwrap();
        let (_, extra, exact) = ledger.0.lock().unwrap().charges();
        assert!(extra > 0);
        assert!(
            exact > logical + extra,
            "temporary certificate comparison must contribute to high water"
        );
        assert_eq!(endpoint.retained_payload_bytes(), extra);
        drop(endpoint);
        assert_eq!(ledger.0.lock().unwrap().charges().1, 0);
        let (endpoint, ledger) = measure(exact);
        assert!(endpoint.is_ok());
        drop(endpoint);
        assert_eq!(ledger.0.lock().unwrap().charges().1, 0);
        let (endpoint, ledger) = measure(exact - 1);
        assert!(endpoint.is_err());
        assert_eq!(ledger.0.lock().unwrap().charges().1, 0);
    }

    #[test]
    fn canonical_address_fields_are_not_combined_or_reparsed() {
        for host in [
            "server.example.",
            "Server_Name.Example.",
            "127.0.0.1",
            "::1:49",
            "::ffff:127.0.0.1",
        ] {
            let mut server = builder().build();
            server.address = host.to_owned();
            server.port = 300;
            let original = server.clone();
            let endpoint = prepare_endpoint(&server, PrepareOptions::default()).unwrap();
            assert_eq!(endpoint.address().host(), host);
            assert_eq!(endpoint.address().port(), 300);
            assert_eq!(server, original);
        }
        for (host, port) in [
            ("host:49", 300),
            ("[::1]", 300),
            ("fe80::1%eth0", 49),
            ("localhost", 0),
        ] {
            let mut server = builder().build();
            server.address = host.to_owned();
            server.port = port;
            let original = server.clone();
            assert!(prepare_endpoint(&server, PrepareOptions::default()).is_err());
            assert_eq!(server, original);
        }
    }

    #[test]
    fn preparation_uses_canonical_timeout_without_changing_source() {
        for timeout in [1, 17, u16::MAX] {
            let server = builder().with_timeout(timeout).build();
            let original = server.clone();
            for options in [
                PrepareOptions::default(),
                PrepareOptions::default().with_preflight(ConnectPreflight::AccountingWatchdog),
                PrepareOptions::default()
                    .with_certificate_verification(CertificateVerification::DisabledForDevelopment),
            ] {
                let endpoint = prepare_endpoint(&server, options).unwrap();
                assert_eq!(endpoint.connection_timeout(), Some(server.timeout_duration()));
                assert_eq!(server, original);
            }
        }
    }

    #[test]
    fn server_names_preserve_protocol_specific_sni_behavior() {
        for address in ["192.0.2.1", "2001:db8::1", "::1", "tacacs.example.com"] {
            let mut server = builder().with_tls_server_authentication().build();
            server.address = address.to_owned();
            server.domain_name = Some("configured.example.com".to_owned());
            assert_eq!(certificate_peer_identity(&server), "configured.example.com");
            assert_eq!(tls_sni_name(&server).unwrap(), None);
            server.sni_enabled = Some(true);
            assert_eq!(certificate_peer_identity(&server), "configured.example.com");
            assert_eq!(tls_sni_name(&server).unwrap(), Some("configured.example.com"));
            server.domain_name = None;
            assert_eq!(certificate_peer_identity(&server), address);
            assert!(tls_sni_name(&server).is_err());
        }
    }

    #[test]
    fn every_generated_psk_hash_and_group_prepares_without_source_mutation() {
        let expected_groups = [
            PskDheGroup::X25519,
            PskDheGroup::Secp256r1,
            PskDheGroup::Secp384r1,
            PskDheGroup::Secp521r1,
            PskDheGroup::Ffdhe2048,
            PskDheGroup::Ffdhe3072,
            PskDheGroup::Ffdhe4096,
            PskDheGroup::Ffdhe6144,
            PskDheGroup::Ffdhe8192,
        ];
        assert_eq!(
            PskDheKeSupportedGroup::ALL
                .iter()
                .copied()
                .map(psk_group)
                .collect::<Vec<_>>(),
            expected_groups
        );
        for hash in EpskSupportedHash::ALL {
            let mut server = builder()
                .with_tls13_epsk("client", b"valid-psk-credential".to_vec())
                .build();
            let epsk = server
                .client_identity
                .as_mut()
                .unwrap()
                .tls13_epsk
                .as_mut()
                .unwrap();
            epsk.hash = *hash;
            epsk.psk_dhe_ke_groups = PskDheKeSupportedGroup::ALL.to_vec();
            let original = server.clone();
            prepare_endpoint(&server, PrepareOptions::default()).unwrap();
            assert_eq!(server, original);
        }
    }

    #[test]
    fn invalid_psk_sni_fails_before_io_without_source_mutation() {
        for name in ["bad\0name", "", "127.0.0.1", "::1", "*.example", "bad host"] {
            let mut server = builder()
                .with_tls13_epsk_psk_only("client", b"valid-psk-credential".to_vec())
                .build();
            server.domain_name = Some(name.to_owned());
            server.sni_enabled = Some(true);
            let original = server.clone();
            assert!(prepare_endpoint(&server, PrepareOptions::default()).is_err());
            assert_eq!(server, original);
        }
    }

    #[test]
    fn invalid_psk_fails_during_projection() {
        let server = builder()
            .with_tls13_epsk_psk_only("client", b"short".to_vec())
            .build();
        let error = prepare_endpoint(&server, PrepareOptions::default()).unwrap_err();
        assert!(format!("{error:#}").contains("PSK key must be at least 16 bytes"));
    }

    #[test]
    fn empty_explicit_trust_bag_cannot_select_platform_trust() {
        for end_entity in [false, true] {
            let mut server = builder().with_tls_server_authentication().build();
            let bag = crate::ServerAuthenticationCaCerts {
                inline_definition: Some(crate::truststore::CertsInlineDefinition {
                    certificate: Vec::new(),
                }),
                central_truststore_reference: None,
            };
            server.server_authentication = Some(crate::TlsClientServerAuthentication {
                require_crls: None,
                require_ocsp: None,
                require_stapled_ocsp: None,
                ca_certs: (!end_entity).then(|| bag.clone()),
                ee_certs: end_entity.then_some(bag),
                credentials_reference: None,
                tls13_epsks: None,
            });
            let original = server.clone();
            assert!(
                prepare_endpoint(&server, PrepareOptions::default()).is_err(),
                "empty explicit trust must fail"
            );
            assert_eq!(server, original);
        }
    }

    #[test]
    fn mismatched_explicit_public_key_is_rejected_before_runtime() {
        let (certificate, key) = fixture_certificate("client");
        let (_, other_key) = fixture_certificate("server");
        let mut server = builder()
            .with_tls_client_certificate(
                Some(certificate.to_der().unwrap()),
                Some(key.private_key_to_pkcs8().unwrap()),
            )
            .build();
        let inline = server
            .client_identity
            .as_mut()
            .unwrap()
            .certificate
            .as_mut()
            .unwrap()
            .inline_definition
            .as_mut()
            .unwrap();
        inline.public_key_format =
            Some(crate::crypto_types::PublicKeyFormat::SubjectPublicKeyInfoFormat);
        inline.public_key = Some(other_key.public_key_to_der().unwrap());
        let original = server.clone();
        assert!(prepare_endpoint(&server, PrepareOptions::default()).is_err());
        assert_eq!(server, original);
    }

    #[test]
    fn explicit_public_key_metadata_is_checked_for_rsa_and_ec_identities() {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        let (authority, authority_key) = fixture_certificate("ca");
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let ec_certificate =
            signed_peer(&authority, &authority_key, &ec_key, (now - 60, now + 3600), false, false);
        for (certificate, key) in [fixture_certificate("client"), (ec_certificate, ec_key)] {
            let server = builder()
                .with_tls_client_certificate(
                    Some(certificate.to_der().unwrap()),
                    Some(key.private_key_to_pkcs8().unwrap()),
                )
                .build();
            let public = key.public_key_to_der().unwrap();
            let mut trailing = public.clone();
            trailing.extend_from_slice(b"sensitive-trailing-data");
            for (format, bytes, expected) in [
                (None, None, true),
                (Some(PublicKeyFormat::SubjectPublicKeyInfoFormat), Some(public.clone()), true),
                (None, Some(public.clone()), false),
                (Some(PublicKeyFormat::SubjectPublicKeyInfoFormat), None, false),
                (Some(PublicKeyFormat::SshPublicKeyFormat), Some(public.clone()), false),
                (Some(PublicKeyFormat::SubjectPublicKeyInfoFormat), Some(Vec::new()), false),
                (Some(PublicKeyFormat::SubjectPublicKeyInfoFormat), Some(trailing), false),
            ] {
                let mut source = server.clone();
                let inline = source
                    .client_identity
                    .as_mut()
                    .unwrap()
                    .certificate
                    .as_mut()
                    .unwrap()
                    .inline_definition
                    .as_mut()
                    .unwrap();
                inline.public_key_format = format;
                inline.public_key = bytes;
                let original = source.clone();
                for verification in [
                    CertificateVerification::Required,
                    CertificateVerification::DisabledForDevelopment,
                ] {
                    let result = prepare_endpoint(
                        &source,
                        PrepareOptions::default().with_certificate_verification(verification),
                    );
                    assert_eq!(
                        result.is_ok(),
                        expected,
                        "format {format:?}, verification {verification:?}"
                    );
                    if let Err(error) = result {
                        assert!(!format!("{error:#}").contains("sensitive-trailing-data"));
                    }
                }
                assert_eq!(source, original);
            }
            let mut mismatched = server;
            let inline = mismatched
                .client_identity
                .as_mut()
                .unwrap()
                .certificate
                .as_mut()
                .unwrap()
                .inline_definition
                .as_mut()
                .unwrap();
            inline.public_key_format = Some(PublicKeyFormat::SubjectPublicKeyInfoFormat);
            inline.public_key = Some(public);
            inline.cleartext_private_key =
                Some(SecretBytes::new(authority_key.private_key_to_pkcs8().unwrap()));
            assert!(prepare_endpoint(&mismatched, PrepareOptions::default()).is_err());
        }
    }

    #[test]
    fn preparation_preserves_the_source_and_redacts_runtime_state() {
        let server = builder()
            .with_shared_secret("private-obfuscation-key")
            .build();
        let original = server.clone();
        let endpoint = prepare_endpoint(&server, PrepareOptions::default()).unwrap();
        assert_eq!(server, original);
        assert_eq!(endpoint.address().to_string(), "127.0.0.1:1");
        assert_eq!(endpoint.single_connection(), server.single_connection);
        assert!(!format!("{endpoint:?}").contains("private-obfuscation-key"));
    }

    #[test]
    fn unresolved_credentials_fail_without_changing_references() {
        let mut server = builder()
            .with_tls13_epsk("client", b"valid-psk-credential".to_vec())
            .build();
        let identity = server.client_identity.as_mut().unwrap();
        identity.credentials_reference = Some("private-bundle-reference".to_owned());
        let original = server.clone();
        let error = prepare_endpoint(&server, PrepareOptions::default()).unwrap_err();
        assert!(error.to_string().contains("Expand credential bundles"));
        assert!(!format!("{error:#}").contains("private-bundle-reference"));
        assert_eq!(server, original);

        let identity = server.client_identity.as_mut().unwrap();
        identity.credentials_reference = None;
        let epsk = identity.tls13_epsk.as_mut().unwrap();
        epsk.inline_definition = None;
        epsk.central_keystore_reference = Some("private-central-reference".to_owned());
        let original = server.clone();
        let error = prepare_endpoint(&server, PrepareOptions::default()).unwrap_err();
        assert!(error.to_string().contains("Resolve central credentials"));
        assert!(!format!("{error:#}").contains("private-central-reference"));
        assert_eq!(server, original);
    }

    #[tokio::test]
    async fn lazy_client_rejects_invalid_or_incomplete_certificate_material() {
        for (certificate, key) in [
            (Some(b"invalid-der".to_vec()), Some(b"private-key-data".to_vec())),
            (None, Some(b"private-key-data".to_vec())),
            (Some(b"invalid-der".to_vec()), None),
            (None, None),
        ] {
            let server = builder()
                .with_tls_client_certificate(certificate, key)
                .build();
            let Err(error) = prepare_endpoint(&server, PrepareOptions::default()) else {
                panic!("invalid certificate material must fail before the lazy client is returned");
            };
            assert!(!format!("{error:#}").contains("private-key-data"));
        }
    }

    #[tokio::test]
    async fn live_client_does_not_retain_the_source_model() {
        let server = Arc::new(
            builder()
                .with_tls13_epsk("client", b"valid-psk-credential".to_vec())
                .build(),
        );
        let weak = Arc::downgrade(&server);
        let client = TacacsClient::connect_prepared(
            prepare_endpoint(&server, PrepareOptions::default()).unwrap(),
        )
        .await
        .unwrap();
        drop(server);
        assert!(weak.upgrade().is_none());
        drop(client);
    }

    fn certificate() -> (openssl::x509::X509, openssl::pkey::PKey<openssl::pkey::Private>) {
        certificate_with_names(Some("server.example.test"))
    }

    fn certificate_with_names(
        dns_san: Option<&str>,
    ) -> (openssl::x509::X509, openssl::pkey::PKey<openssl::pkey::Private>) {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509, X509NameBuilder};

        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        if let Some(dns_san) = dns_san {
            let san = openssl::x509::extension::SubjectAlternativeName::new()
                .dns("localhost")
                .dns(dns_san)
                .ip("127.0.0.1")
                .ip("::1")
                .build(&certificate.x509v3_context(None, None))
                .unwrap();
            certificate.append_extension(san).unwrap();
        }
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        (certificate.build(), key)
    }

    fn server_trust(
        certificate: &openssl::x509::X509,
        end_entity: bool,
    ) -> crate::TlsClientServerAuthentication {
        let trust = crate::ServerAuthenticationCaCerts {
            inline_definition: Some(crate::truststore::CertsInlineDefinition {
                certificate: vec![crate::truststore::CertsCertificate {
                    name: "loopback".to_owned(),
                    cert_data: certificate.to_der().unwrap(),
                }],
            }),
            central_truststore_reference: None,
        };
        crate::TlsClientServerAuthentication {
            require_crls: None,
            require_ocsp: None,
            require_stapled_ocsp: None,
            credentials_reference: None,
            ca_certs: (!end_entity).then(|| trust.clone()),
            ee_certs: end_entity.then_some(trust),
            tls13_epsks: None,
        }
    }

    #[tokio::test]
    async fn configured_end_entity_authenticates_an_exact_ca_signed_leaf() {
        let (certificate, key) = fixture_certificate("server");
        assert_ne!(
            certificate.issuer_name().to_der().unwrap(),
            certificate.subject_name().to_der().unwrap()
        );
        assert!(
            probe_certificate_trust(
                &certificate,
                &key,
                server_trust(&certificate, true),
                None,
                &[]
            )
            .await,
            "an exact end-entity match must not require its issuer as a CA anchor"
        );
    }

    fn fixture_certificate(
        name: &str,
    ) -> (openssl::x509::X509, openssl::pkey::PKey<openssl::pkey::Private>) {
        let fixtures = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../lde/containers/config/certificates");
        let certificate = openssl::x509::X509::from_pem(
            &std::fs::read(fixtures.join(format!("{name}.crt"))).unwrap(),
        )
        .unwrap();
        let key = openssl::pkey::PKey::private_key_from_pem(
            &std::fs::read(fixtures.join(format!("{name}.key"))).unwrap(),
        )
        .unwrap();
        (certificate, key)
    }

    // The checked conversion narrows to the native 32-bit time_t on ARMhf.
    #[allow(clippy::useless_conversion)]
    fn signed_peer(
        authority: &openssl::x509::X509,
        authority_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        peer_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        validity: (i64, i64),
        client_only: bool,
        is_ca: bool,
    ) -> openssl::x509::X509 {
        use openssl::asn1::Asn1Time;
        use openssl::x509::{X509, X509NameBuilder};
        use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName};
        let mut name = X509NameBuilder::new().unwrap();
        let fingerprint = openssl::sha::sha256(&peer_key.public_key_to_der().unwrap());
        let authority_name = format!(
            "Intermediate-{:016x}",
            u64::from_be_bytes(fingerprint[..8].try_into().unwrap())
        );
        name.append_entry_by_text(
            "CN",
            if is_ca {
                &authority_name
            } else {
                "localhost"
            },
        )
        .unwrap();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(
                &openssl::bn::BigNum::from_u32(42)
                    .unwrap()
                    .to_asn1_integer()
                    .unwrap(),
            )
            .unwrap();
        certificate.set_subject_name(&name.build()).unwrap();
        certificate
            .set_issuer_name(authority.subject_name())
            .unwrap();
        certificate.set_pubkey(peer_key).unwrap();
        certificate
            .set_not_before(&Asn1Time::from_unix(validity.0.try_into().unwrap()).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::from_unix(validity.1.try_into().unwrap()).unwrap())
            .unwrap();
        let mut constraints = BasicConstraints::new();
        if is_ca {
            constraints.ca();
        }
        certificate
            .append_extension(constraints.build().unwrap())
            .unwrap();
        if !is_ca {
            let mut usage = ExtendedKeyUsage::new();
            if client_only {
                usage.client_auth();
            } else {
                usage.server_auth();
            }
            certificate
                .append_extension(usage.build().unwrap())
                .unwrap();
        }
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .ip("127.0.0.1")
            .build(&certificate.x509v3_context(Some(authority), None))
            .unwrap();
        certificate.append_extension(san).unwrap();
        certificate
            .sign(authority_key, openssl::hash::MessageDigest::sha256())
            .unwrap();
        certificate.build()
    }

    #[tokio::test]
    async fn canonical_client_chains_authenticate_with_native_mtls_without_source_rewrites() {
        let (authority, authority_key) = fixture_certificate("ca");
        let (peer_certificate, peer_key) = fixture_certificate("server");
        let (_, client_key) = fixture_certificate("client");
        let intermediate_key =
            openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let upper_key =
            openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let upper =
            signed_peer(&authority, &authority_key, &upper_key, (now - 60, now + 180), false, true);
        let intermediate =
            signed_peer(&upper, &upper_key, &intermediate_key, (now - 60, now + 60), false, true);
        let expired_intermediate =
            signed_peer(&upper, &upper_key, &intermediate_key, (0, 1), false, true)
                .to_der()
                .unwrap();
        let future_intermediate =
            signed_peer(&upper, &upper_key, &intermediate_key, (now + 60, now + 120), false, true)
                .to_der()
                .unwrap();
        let expired_upper =
            signed_peer(&authority, &authority_key, &upper_key, (0, 1), false, true)
                .to_der()
                .unwrap();
        let future_upper =
            signed_peer(&authority, &authority_key, &upper_key, (now + 60, now + 120), false, true)
                .to_der()
                .unwrap();
        let leaf = signed_peer(
            &intermediate,
            &intermediate_key,
            &client_key,
            (now - 60, now + 600),
            true,
            false,
        );
        let leaf_der = leaf.to_der().unwrap();
        let intermediate_der = intermediate.to_der().unwrap();
        let upper_der = upper.to_der().unwrap();
        let wrong =
            signed_peer(&authority, &authority_key, &peer_key, (now - 60, now + 600), false, true)
                .to_der()
                .unwrap();
        let mut context =
            openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_server()).unwrap();
        context
            .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
            .unwrap();
        context
            .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
            .unwrap();
        context.set_certificate(&peer_certificate).unwrap();
        context.set_private_key(&peer_key).unwrap();
        context
            .cert_store_mut()
            .add_cert(authority.clone())
            .unwrap();
        context.set_verify(
            openssl::ssl::SslVerifyMode::PEER | openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        );
        let context = context.build();
        for (mode, intermediates, expected) in [
            ("inline", vec![intermediate_der.clone(), upper_der.clone()], true),
            ("pem", vec![intermediate_der.clone(), upper_der.clone()], true),
            ("bundle", vec![intermediate_der.clone(), upper_der.clone()], true),
            ("provider", vec![intermediate_der.clone(), upper_der.clone()], true),
            ("inline", Vec::new(), false),
            ("inline", vec![intermediate_der.clone()], false),
            ("inline", vec![upper_der.clone(), intermediate_der.clone()], false),
            ("inline", vec![wrong], false),
            ("inline", vec![expired_intermediate, upper_der.clone()], false),
            ("inline", vec![future_intermediate, upper_der.clone()], false),
            ("inline", vec![intermediate_der.clone(), expired_upper], false),
            ("inline", vec![intermediate_der.clone(), future_upper], false),
            ("inline", vec![intermediate_der.clone(), intermediate_der.clone()], false),
            (
                "inline",
                vec![
                    intermediate_der.clone(),
                    upper_der,
                    authority.to_der().unwrap(),
                ],
                false,
            ),
            ("inline", vec![leaf_der.clone(), intermediate_der.clone()], false),
            (
                "inline",
                vec![[intermediate_der.as_slice(), intermediate_der.as_slice()].concat()],
                false,
            ),
        ] {
            let (source, resolver) =
                client_chain_source(mode, &leaf_der, &intermediates, &client_key, &authority);
            assert_eq!(
                probe_client_chain(source, &resolver, &context, &intermediates).await,
                expected,
                "{mode}"
            );
        }
    }

    fn client_chain_source(
        mode: &str,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
        key: &openssl::pkey::PKey<openssl::pkey::Private>,
        authority: &openssl::x509::X509,
    ) -> (crate::TacacsPlus, tacacsrs_credential_resolution::FakeCredentialResolver) {
        use tacacsrs_credential_resolution::{
            CertificateWithKeyMaterial, CredentialValidity, FakeCredentialResolver, PublicBytes,
            RequestSlot, ResolvedCredential,
        };
        let chain = if mode == "pem" {
            let mut pem = openssl::x509::X509::from_der(leaf)
                .unwrap()
                .to_pem()
                .unwrap();
            for intermediate in intermediates {
                pem.extend(
                    openssl::x509::X509::from_der(intermediate)
                        .unwrap()
                        .to_pem()
                        .unwrap(),
                );
            }
            crate::input::normalize_cli_certificate_data(&pem).unwrap()
        } else {
            crate::input::ClientCertificateChain {
                leaf: leaf.to_vec(),
                intermediates: intermediates.to_vec(),
            }
        };
        let mut server = builder()
            .with_tls_client_certificate_chain(
                Some(chain.leaf),
                chain.intermediates,
                Some(key.private_key_to_pkcs8().unwrap()),
                None,
            )
            .build();
        server.server_authentication = Some(server_trust(authority, false));
        let mut source = crate::TacacsPlus {
            client_credentials: Vec::new(),
            server_credentials: Vec::new(),
            server: vec![server],
        };
        let mut resolver = FakeCredentialResolver::new();
        let identity = source.server[0].client_identity.as_mut().unwrap();
        if mode == "bundle" {
            source.client_credentials.push(crate::ClientCredentials {
                id: "chain-bundle".to_owned(),
                certificate: identity.certificate.take(),
                tls13_epsk: None,
            });
            identity.credentials_reference = Some("chain-bundle".to_owned());
        } else if mode == "provider" {
            identity.certificate = Some(crate::ClientIdentityCertificate {
                inline_definition: None,
                central_keystore_reference: Some(
                    crate::keystore::EndEntityCertWithKeyCentralKeystoreReference {
                        asymmetric_key: Some("opaque-key".to_owned()),
                        certificate: Some("opaque-certificate".to_owned()),
                    },
                ),
            });
            resolver = resolver.with_response(
                RequestSlot::from_index(0),
                ResolvedCredential::CertificateWithKey(CertificateWithKeyMaterial {
                    validity: CredentialValidity::unbounded(),
                    public_key_format: None,
                    public_key: None,
                    private_key_format:
                        tacacsrs_credential_resolution::PrivateKeyFormat::OneAsymmetricKeyFormat,
                    certificate: PublicBytes::new(leaf.to_vec()),
                    intermediates: intermediates
                        .iter()
                        .cloned()
                        .map(PublicBytes::new)
                        .collect(),
                    private_key: tacacsrs_secrets::SecretBytes::new(
                        key.private_key_to_pkcs8().unwrap(),
                    ),
                }),
            );
        }
        (source, resolver)
    }

    async fn probe_client_chain(
        mut source: crate::TacacsPlus,
        resolver: &dyn tacacsrs_credential_resolution::CredentialResolver,
        context: &openssl::ssl::SslContext,
        intermediates: &[Vec<u8>],
    ) -> bool {
        use std::pin::Pin;
        use std::time::Duration;
        use tokio::io::AsyncReadExt;
        use tacacsrs_protocol::operations::AccountingOperation;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        source.server[0].port = listener.local_addr().unwrap().port();
        let original = source.clone();
        let materialized = crate::prepare::enumerate_materialized_servers(
            &source,
            resolver,
            &crate::ValidationOptions::default(),
        )
        .await;
        assert_eq!(source, original);
        let Ok(materialized) = materialized else {
            return false;
        };
        let endpoint = prepare_endpoint(materialized[0].server(), PrepareOptions::default());
        assert_eq!(source, original);
        let Ok(endpoint) = endpoint else {
            return false;
        };
        let peer = async {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream =
                tokio_openssl::SslStream::new(openssl::ssl::Ssl::new(context).unwrap(), tcp)
                    .unwrap();
            if Pin::new(&mut stream).accept().await.is_err() {
                return false;
            }
            let verified = stream.ssl().verified_chain().unwrap();
            for intermediate in intermediates {
                assert!(verified
                    .iter()
                    .any(|certificate| certificate.to_der().unwrap() == *intermediate));
            }
            stream.read(&mut [0]).await.unwrap_or(0) != 0
        };
        let client = async {
            let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
            let _ = client
                .execute(
                    &AccountingOperation {
                        user: "chain-test".to_owned(),
                        port: "test".to_owned(),
                        remote_address: "127.0.0.1".to_owned(),
                        command: "show".to_owned(),
                        command_arguments: Vec::new(),
                    }
                    .exchange()
                    .unwrap(),
                )
                .await;
        };
        let (received, ()) =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(peer, client) })
                .await
                .unwrap();
        received
    }

    #[tokio::test]
    async fn certificate_trust_roles_are_additive_without_delegating_peer_pins() {
        let (authority, authority_key) = fixture_certificate("ca");
        let (leaf, leaf_key) = fixture_certificate("server");
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let renewed = signed_peer(
            &authority,
            &authority_key,
            &leaf_key,
            (now - 60, now + 3600),
            false,
            false,
        );
        let expired = signed_peer(&authority, &authority_key, &leaf_key, (0, 1), false, false);
        let future = signed_peer(
            &authority,
            &authority_key,
            &leaf_key,
            (now + 3600, now + 7200),
            false,
            false,
        );
        let wrong_usage =
            signed_peer(&authority, &authority_key, &leaf_key, (now - 60, now + 3600), true, false);
        assert_ne!(leaf.to_der().unwrap(), renewed.to_der().unwrap());
        assert_eq!(
            leaf.public_key().unwrap().public_key_to_der().unwrap(),
            renewed.public_key().unwrap().public_key_to_der().unwrap()
        );
        let mut combined = server_trust(&authority, false);
        combined.ee_certs = server_trust(&leaf, true).ee_certs;
        for (label, peer, policy, identity, expected) in [
            ("CA anchor", &leaf, server_trust(&authority, false), None, true),
            ("exact signed pin", &leaf, server_trust(&leaf, true), None, true),
            ("renewed certificate is not exact", &renewed, server_trust(&leaf, true), None, false),
            ("peer pin is not an authority", &leaf, server_trust(&authority, true), None, false),
            ("CA and pins are additive", &renewed, combined, None, true),
            ("wrong identity", &leaf, server_trust(&leaf, true), Some("wrong.example.test"), false),
            ("expired pin", &expired, server_trust(&expired, true), None, false),
            ("not-yet-valid pin", &future, server_trust(&future, true), None, false),
            ("client-only pin", &wrong_usage, server_trust(&wrong_usage, true), None, false),
        ] {
            assert_eq!(
                probe_certificate_trust(peer, &leaf_key, policy, identity, &[]).await,
                expected,
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn a_peer_pin_does_not_hide_an_independent_authority_path() {
        let (authority, authority_key) = fixture_certificate("ca");
        let (_, leaf_key) = fixture_certificate("server");
        let intermediate_key =
            openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let intermediate = signed_peer(
            &authority,
            &authority_key,
            &intermediate_key,
            (now - 60, now + 3600),
            false,
            true,
        );
        let leaf = signed_peer(
            &intermediate,
            &intermediate_key,
            &leaf_key,
            (now - 60, now + 3600),
            false,
            false,
        );
        let mut policy = server_trust(&authority, false);
        policy.ee_certs = server_trust(&intermediate, true).ee_certs;
        assert!(probe_certificate_trust(&leaf, &leaf_key, policy, None, &[intermediate]).await);
    }

    #[tokio::test]
    async fn established_ca_and_pin_connections_survive_certificate_expiry() {
        let (authority, authority_key) = fixture_certificate("ca");
        let (_, leaf_key) = fixture_certificate("server");
        let intermediate_key =
            openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let intermediate = signed_peer(
            &authority,
            &authority_key,
            &intermediate_key,
            (now - 60, now + 4),
            false,
            true,
        );
        let leaf = signed_peer(
            &intermediate,
            &intermediate_key,
            &leaf_key,
            (now - 60, now + 4),
            false,
            false,
        );
        let unused =
            signed_peer(&authority, &authority_key, &leaf_key, (now - 60, now + 1), false, false);
        let mut ordinary = server_trust(&authority, false);
        ordinary.ee_certs = server_trust(&unused, true).ee_certs;
        let mut alternate = ordinary.clone();
        alternate
            .ee_certs
            .as_mut()
            .unwrap()
            .inline_definition
            .as_mut()
            .unwrap()
            .certificate
            .push(crate::truststore::CertsCertificate {
                name: "intermediate-pin".to_owned(),
                cert_data: intermediate.to_der().unwrap(),
            });
        let mut exact = server_trust(&leaf, true);
        exact
            .ee_certs
            .as_mut()
            .unwrap()
            .inline_definition
            .as_mut()
            .unwrap()
            .certificate
            .push(crate::truststore::CertsCertificate {
                name: "unused-pin".to_owned(),
                cert_data: unused.to_der().unwrap(),
            });
        let expires_at =
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::try_from(now + 4).unwrap());
        let (ordinary_result, alternate_result, exact_result) = tokio::join!(
            probe_peer_survives_expiry(
                &leaf,
                &leaf_key,
                ordinary,
                std::slice::from_ref(&intermediate),
                expires_at,
            ),
            probe_peer_survives_expiry(
                &leaf,
                &leaf_key,
                alternate,
                std::slice::from_ref(&intermediate),
                expires_at,
            ),
            probe_peer_survives_expiry(&leaf, &leaf_key, exact, &[], expires_at),
        );
        ordinary_result.unwrap();
        alternate_result.unwrap();
        exact_result.unwrap();
    }

    #[tokio::test]
    async fn disconnected_peer_recovers_with_a_fresh_non_resumed_handshake_without_reload() {
        use std::pin::Pin;
        use std::time::Duration;
        use openssl::ssl::{Ssl, SslContext, SslMethod};
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio_openssl::SslStream;
        let (authority, authority_key) = fixture_certificate("ca");
        let (_, key) = fixture_certificate("server");
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let contexts = [60, 600].map(|seconds| {
            let certificate = signed_peer(
                &authority,
                &authority_key,
                &key,
                (now - 60, now + seconds),
                false,
                false,
            );
            let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
            context.set_certificate(&certificate).unwrap();
            context.set_private_key(&key).unwrap();
            context.build()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut server = builder().with_tls_server_authentication().build();
        server.port = listener.local_addr().unwrap().port();
        server.server_authentication = Some(server_trust(&authority, false));
        let original = server.clone();
        let endpoint = prepare_endpoint(&server, PrepareOptions::default()).unwrap();
        let (handshakes, mut accepted) = tokio::sync::mpsc::channel(1);
        let peer = tokio::spawn(async move {
            for (index, context) in contexts.into_iter().enumerate() {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut stream = SslStream::new(Ssl::new(&context).unwrap(), tcp).unwrap();
                Pin::new(&mut stream).accept().await.unwrap();
                handshakes
                    .send(stream.ssl().session_reused())
                    .await
                    .unwrap();
                if index != 0 {
                    let _ = stream.read(&mut [0_u8; 1]).await;
                }
            }
        });
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let mut original_session = client.open_conversation().await.unwrap();
        let reused = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("server must complete the initial TLS handshake")
            .expect("server handshake task must remain active");
        assert!(!reused, "initial certificate handshake must not resume a session");
        original_session.complete().await;
        let mut replacement = client.open_conversation().await.unwrap();
        let reused = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("server must complete the replacement TLS handshake")
            .expect("server handshake task must remain active");
        assert!(!reused, "replacement certificate handshake must not resume a session");
        replacement.complete().await;
        client
            .close_and_join(tacacsrs_networking::RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server, original);
    }

    async fn probe_peer_survives_expiry(
        certificate: &openssl::x509::X509,
        key: &openssl::pkey::PKey<openssl::pkey::Private>,
        policy: crate::TlsClientServerAuthentication,
        chain: &[openssl::x509::X509],
        expires_at: std::time::SystemTime,
    ) -> anyhow::Result<()> {
        use std::pin::Pin;
        use std::time::Duration;
        use openssl::ssl::{Ssl, SslContext, SslMethod};
        use tacacsrs_networking::{PacketReadResult, PacketReader, PacketWriteResult, PacketWriter};
        use tacacsrs_protocol::accounting::reply::AccountingReply;
        use tacacsrs_protocol::body::TacacsBodyTrait;
        use tacacsrs_protocol::operations::AccountingOperation;
        use tacacsrs_protocol::packet::{Packet, PacketTrait};
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio_openssl::SslStream;
        let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
        context.set_certificate(certificate).unwrap();
        context.set_private_key(key).unwrap();
        for certificate in chain {
            context.add_extra_chain_cert(certificate.clone()).unwrap();
        }
        let context = context.build();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut server = builder().with_tls_server_authentication().build();
        server.port = listener.local_addr().unwrap().port();
        server.single_connection = true;
        server.server_authentication = Some(policy);
        let original = server.clone();
        let endpoint = prepare_endpoint(&server, PrepareOptions::default()).unwrap();
        let (handshake, accepted) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = SslStream::new(Ssl::new(&context).unwrap(), tcp).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();
            let _ = handshake.send(());
            for _ in 0..2 {
                let request = match PacketReader::new(None).read_packet(&mut stream).await {
                    PacketReadResult::Success(packet) => packet,
                    result => panic!("expected application request: {result:?}"),
                };
                let body = AccountingReply {
                    status: tacacsrs_protocol::enumerations::TacacsAccountingStatus::TacPlusAcctStatusSuccess,
                    server_msg: "accepted".to_owned(),
                    data: String::new(),
                }
                .to_bytes()
                .unwrap();
                let mut header = request.header().clone();
                header.seq_no += 1;
                header.length = u32::try_from(body.len()).unwrap();
                let reply = Packet::new(header, body).unwrap();
                assert!(matches!(
                    PacketWriter::new(None)
                        .write_packet(&mut stream, reply)
                        .await,
                    PacketWriteResult::Success
                ));
            }
            let _ = stream.read(&mut [0_u8; 1]).await;
        });
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let operation = || {
            AccountingOperation {
                user: "test".to_owned(),
                port: "test".to_owned(),
                remote_address: "127.0.0.1".to_owned(),
                command: "show".to_owned(),
                command_arguments: Vec::new(),
            }
            .exchange()
        };
        let prepared = operation()?;
        let first = client.execute(&prepared);
        tokio::pin!(first);
        let (accepted, first) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(accepted, &mut first)
        })
        .await
        .expect("server and client must complete the first exchange");
        accepted.expect("server handshake task must remain active");
        first?;
        let remaining = expires_at
            .duration_since(std::time::SystemTime::now())
            .unwrap_or_default();
        tokio::time::sleep(remaining + Duration::from_secs(1)).await;
        tokio::time::timeout(Duration::from_secs(3), client.execute(&prepared))
            .await
            .expect("post-expiry exchange must complete")?;
        client
            .close_and_join(
                tacacsrs_networking::RequestDeadline::after(Duration::from_secs(2)).unwrap(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server, original);
        Ok(())
    }

    async fn probe_certificate_trust(
        certificate: &openssl::x509::X509,
        key: &openssl::pkey::PKey<openssl::pkey::Private>,
        policy: crate::TlsClientServerAuthentication,
        peer_identity: Option<&str>,
        chain: &[openssl::x509::X509],
    ) -> bool {
        use std::pin::Pin;
        use std::time::Duration;
        use openssl::ssl::{Ssl, SslContext, SslMethod};
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio_openssl::SslStream;
        use tacacsrs_protocol::operations::AccountingOperation;

        let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
        context.set_certificate(certificate).unwrap();
        context.set_private_key(key).unwrap();
        for certificate in chain {
            context.add_extra_chain_cert(certificate.clone()).unwrap();
        }
        let context = context.build();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut server = builder().with_tls_server_authentication().build();
        server.port = listener.local_addr().unwrap().port();
        server.domain_name = peer_identity.map(str::to_owned);
        server.server_authentication = Some(policy);
        let original = server.clone();
        let endpoint = prepare_endpoint(&server, PrepareOptions::default()).unwrap();
        let peer = async {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = SslStream::new(Ssl::new(&context).unwrap(), tcp).unwrap();
            if Pin::new(&mut stream).accept().await.is_err() {
                return false;
            }
            let mut byte = [0];
            stream.read(&mut byte).await.unwrap_or(0) != 0
        };
        let client = async {
            let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
            let _ = client
                .execute(
                    &AccountingOperation {
                        user: "test".to_owned(),
                        port: "test".to_owned(),
                        remote_address: "127.0.0.1".to_owned(),
                        command: "show".to_owned(),
                        command_arguments: Vec::new(),
                    }
                    .exchange()
                    .unwrap(),
                )
                .await;
        };
        let (received, ()) =
            tokio::time::timeout(Duration::from_secs(3), async { tokio::join!(peer, client) })
                .await
                .unwrap();
        assert_eq!(server, original);
        received
    }

    #[tokio::test]
    async fn trusted_certificate_with_wrong_identity_receives_no_tacacs_bytes() {
        probe_certificate_identity(
            Some("server.example.test"),
            "127.0.0.1",
            Some("wrong.example.test"),
            true,
            false,
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn certificate_names_preserve_schema_dns_spelling_on_native_connections() {
        for name in ["server_name.example.test", "server_name.example.test."] {
            for sni in [false, true] {
                probe_certificate_identity(Some(name), "127.0.0.1", Some(name), sni, false, true)
                    .await;
            }
        }
    }

    #[tokio::test]
    async fn certificate_identity_and_sni_are_independent() {
        for (san, address, domain, sni, insecure, allowed) in [
            (
                Some("server.example.test"),
                "127.0.0.1",
                Some("server.example.test"),
                true,
                false,
                true,
            ),
            (
                Some("server.example.test"),
                "127.0.0.1",
                Some("server.example.test"),
                false,
                false,
                true,
            ),
            (
                Some("server.example.test"),
                "127.0.0.1",
                Some("wrong.example.test"),
                false,
                false,
                false,
            ),
            (Some("server.example.test"), "127.0.0.1", None, false, false, true),
            (Some("server.example.test"), "localhost", None, false, false, true),
            (Some("server.example.test"), "127.0.0.1", Some("127.0.0.2"), false, false, false),
            (None, "127.0.0.1", Some("localhost"), true, false, false),
            (Some("*.example.test"), "127.0.0.1", Some("server.example.test"), true, false, true),
            (
                Some("*.example.test"),
                "127.0.0.1",
                Some("nested.server.example.test"),
                true,
                false,
                false,
            ),
            (
                Some("serv*.example.test"),
                "127.0.0.1",
                Some("server.example.test"),
                true,
                false,
                false,
            ),
            (
                Some("server.example.test"),
                "127.0.0.1",
                Some("wrong.example.test"),
                false,
                true,
                true,
            ),
        ] {
            probe_certificate_identity(san, address, domain, sni, insecure, allowed).await;
        }
    }

    async fn probe_certificate_identity(
        dns_san: Option<&str>,
        address: &str,
        domain: Option<&str>,
        sni: bool,
        insecure: bool,
        allowed: bool,
    ) {
        use std::pin::Pin;
        use std::time::Duration;

        use openssl::ssl::{Ssl, SslContext, SslMethod, NameType};
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio_openssl::SslStream;
        use tacacsrs_protocol::operations::AccountingOperation;

        let (certificate, key) = certificate_with_names(dns_san);
        let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
        context.set_certificate(&certificate).unwrap();
        context.set_private_key(&key).unwrap();
        let context = context.build();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut server = builder().with_tls_server_authentication().build();
        server.port = listener.local_addr().unwrap().port();
        server.address = address.to_owned();
        server.domain_name = domain.map(str::to_owned);
        server.sni_enabled = domain.map(|_| sni);
        server.server_authentication = Some(server_trust(&certificate, false));
        let original = server.clone();
        let endpoint = prepare_endpoint(
            &server,
            PrepareOptions::default().with_certificate_verification(if insecure {
                CertificateVerification::DisabledForDevelopment
            } else {
                CertificateVerification::Required
            }),
        )
        .unwrap();
        let peer = async {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = SslStream::new(Ssl::new(&context).unwrap(), tcp).unwrap();
            let handshake = Pin::new(&mut stream).accept().await;
            let observed_sni = stream
                .ssl()
                .servername(NameType::HOST_NAME)
                .map(str::to_owned);
            if handshake.is_err() {
                return (false, observed_sni);
            }
            let mut byte = [0];
            (stream.read(&mut byte).await.unwrap_or(0) != 0, observed_sni)
        };
        let client = async {
            let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
            client
                .execute(
                    &AccountingOperation {
                        user: "test".to_owned(),
                        port: "test".to_owned(),
                        remote_address: "127.0.0.1".to_owned(),
                        command: "show".to_owned(),
                        command_arguments: Vec::new(),
                    }
                    .exchange()
                    .unwrap(),
                )
                .await
        };
        let ((received_data, observed_sni), result) =
            tokio::time::timeout(Duration::from_secs(3), async { tokio::join!(peer, client) })
                .await
                .unwrap();
        assert_eq!(
            received_data, allowed,
            "SAN {dns_san:?}, address {address}, domain {domain:?}, SNI {sni}, insecure {insecure}"
        );
        assert_eq!(
            observed_sni.as_deref(),
            if sni {
                domain
            } else {
                None
            }
        );
        if !allowed {
            assert!(result.is_err());
        }
        assert_eq!(server, original);
    }

    #[tokio::test]
    async fn prepared_tls_context_supports_repeated_tls_and_mtls_connections() {
        use std::pin::Pin;
        use std::time::Duration;

        use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        use tokio_openssl::SslStream;
        use tacacsrs_networking::{PacketReader, PacketReadResult};
        use tacacsrs_protocol::packet::{Packet, PacketTrait};
        use tacacsrs_protocol::header::Header;
        use tacacsrs_protocol::enumerations::{
            TacacsFlags, TacacsType, TacacsMajorVersion, TacacsMinorVersion,
        };

        let (certificate, key) = certificate();
        for (mutual_tls, end_entity_trust) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
            context.set_certificate(&certificate).unwrap();
            context.set_private_key(&key).unwrap();
            context
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            context
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            if mutual_tls {
                context
                    .cert_store_mut()
                    .add_cert(certificate.clone())
                    .unwrap();
                context.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            }
            let context = context.build();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut server = if mutual_tls {
                builder()
                    .with_tls_client_certificate(
                        Some(certificate.to_der().unwrap()),
                        Some(key.private_key_to_der().unwrap()),
                    )
                    .build()
            } else {
                builder().with_tls_server_authentication().build()
            };
            server.port = address.port();
            server.server_authentication = Some(server_trust(&certificate, end_entity_trust));
            let original = server.clone();
            let endpoint = prepare_endpoint(&server, PrepareOptions::default()).unwrap();
            assert_eq!(server, original);
            let peer = async {
                for _ in 0..2 {
                    let (tcp, _) = listener.accept().await?;
                    let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
                    Pin::new(&mut stream).accept().await?;
                    assert_eq!(stream.ssl().version2(), Some(SslVersion::TLS1_3));
                    assert_eq!(stream.ssl().peer_certificate().is_some(), mutual_tls);
                    let PacketReadResult::Success(request) =
                        PacketReader::new(None).read_packet(&mut stream).await
                    else {
                        anyhow::bail!("expected a TACACS+ request");
                    };
                    let mut header = request.header().clone();
                    header.seq_no = 2;
                    stream
                        .write_all(&Packet::new(header, request.body().to_vec())?.to_bytes())
                        .await?;
                }
                Ok::<_, anyhow::Error>(())
            };
            let client = async {
                for marker in [17, 29] {
                    let endpoint = endpoint.clone();
                    let client = TacacsClient::connect_prepared(endpoint).await?;
                    let mut conversation = client.open_conversation().await?;
                    let request = Packet::new(
                        Header {
                            major_version: TacacsMajorVersion::TacacsPlusMajor1,
                            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                            tacacs_type: TacacsType::TacPlusAccounting,
                            seq_no: 1,
                            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                            session_id: conversation.session_id().unwrap(),
                            length: 1,
                        },
                        vec![marker],
                    )?;
                    let response = conversation.round_trip(request).await?;
                    assert_eq!(response.body(), &[marker]);
                    conversation.complete().await;
                }
                Ok::<_, anyhow::Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), async { tokio::try_join!(peer, client) })
                .await
                .expect("TLS loopback must complete")
                .unwrap();
        }
    }
}
