//! Projects canonical YANG fields into connection-ready transport inputs.

use anyhow::{Context, Result, ensure};

use tacacsrs_networking::{
    ConnectOptions, ConnectPreflight, PreparedEndpoint, CertificateIdentity, CertificateTrust,
    PrivateKeyEncoding, PskHash, PskDheGroup,
};
use tacacsrs_secrets::SecretBytes;

use crate::{TacacsPlusServer, TacacsPlusServerExt, EpskSupportedHash, PskDheKeSupportedGroup};
use crate::crypto_types::{PrivateKeyFormat, PublicKeyFormat};

/// Execution controls that do not replace canonical YANG configuration.
///
/// The server supplies its connection timeout. Preparation does not accept a
/// timeout override. Preflight runs only when a client opens the prepared endpoint.
///
/// ```compile_fail
/// use std::time::Duration;
/// use tacacsrs_config::prepare::PrepareOptions;
///
/// let options = PrepareOptions::default().with_timeout(Duration::from_secs(1));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct PrepareOptions {
    disable_certificate_verification: bool,
    preflight: ConnectPreflight,
}

impl PrepareOptions {
    /// Controls the development-only certificate-verification override.
    ///
    /// CAUTION: A true value permits server impersonation. Do not use it in production.
    #[must_use]
    pub const fn with_certificate_verification_disabled(mut self, disabled: bool) -> Self {
        self.disable_certificate_verification = disabled;
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
    let endpoint = PreparedEndpoint::tcp(
        server.socket_address(),
        server.single_connection,
        server.obfuscation_key().map(SecretBytes::new),
        ConnectOptions::default()
            .with_timeout(server.timeout_duration())
            .with_certificate_verification_disabled(options.disable_certificate_verification)
            .with_preflight(options.preflight),
    );
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
        return endpoint.with_psk(
            &epsk.external_identity,
            key.expose_secret(),
            hash,
            &groups,
            tls_sni_name(server)?,
        );
    }
    if !server.is_tls() {
        return Ok(endpoint);
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
    let identity = certificate_identity(server)?;
    endpoint.with_certificate_tls(
        certificate_peer_identity(server),
        tls_sni_name(server)?,
        trust,
        identity,
    )
}

fn certificate_identity(server: &TacacsPlusServer) -> Result<Option<CertificateIdentity<'_>>> {
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
    fn preparation_uses_canonical_timeout_without_changing_source() {
        for timeout in [1, 17, u16::MAX] {
            let server = builder().with_timeout(timeout).build();
            let original = server.clone();
            for options in [
                PrepareOptions::default(),
                PrepareOptions::default().with_preflight(ConnectPreflight::AccountingWatchdog),
                PrepareOptions::default().with_certificate_verification_disabled(true),
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
                for disabled in [false, true] {
                    let result = prepare_endpoint(
                        &source,
                        PrepareOptions::default().with_certificate_verification_disabled(disabled),
                    );
                    assert_eq!(
                        result.is_ok(),
                        expected,
                        "format {format:?}, verification disabled {disabled}"
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
        assert_eq!(endpoint.address(), "127.0.0.1:1");
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
        name.append_entry_by_text(
            "CN",
            if is_ca {
                "Trust Intermediate"
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
            .set_not_before(&Asn1Time::from_unix(validity.0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::from_unix(validity.1).unwrap())
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
    async fn negotiated_chain_expiry_uses_selected_ca_or_pin_not_unused_trust() {
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
            (now - 60, now + 60),
            false,
            true,
        );
        let leaf = signed_peer(
            &intermediate,
            &intermediate_key,
            &leaf_key,
            (now - 60, now + 600),
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
        for (policy, seconds) in [(ordinary, 61), (alternate, 61), (exact, 601)] {
            probe_peer_expiry(
                &leaf,
                &leaf_key,
                policy,
                std::slice::from_ref(&intermediate),
                std::time::Duration::from_secs(seconds),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn expired_peer_connection_recovers_with_a_fresh_certificate_without_reload() {
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
        let (closed, observed) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut closed = Some(closed);
            for context in contexts {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut stream = SslStream::new(Ssl::new(&context).unwrap(), tcp).unwrap();
                Pin::new(&mut stream).accept().await.unwrap();
                match stream.read(&mut [0]).await {
                    Ok(0) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::BrokenPipe
                        ) => {}
                    result => panic!("expected transport closure: {result:?}"),
                }
                if let Some(closed) = closed.take() {
                    let _ = closed.send(());
                }
            }
        });
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let mut original_session = client.open_conversation().await.unwrap();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(1), observed)
            .await
            .unwrap()
            .unwrap();
        original_session.complete().await;
        let mut replacement = client.open_conversation().await.unwrap();
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

    async fn probe_peer_expiry(
        certificate: &openssl::x509::X509,
        key: &openssl::pkey::PKey<openssl::pkey::Private>,
        policy: crate::TlsClientServerAuthentication,
        chain: &[openssl::x509::X509],
        expiry: std::time::Duration,
    ) {
        use std::pin::Pin;
        use std::time::Duration;
        use openssl::ssl::{Ssl, SslContext, SslMethod};
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
        server.server_authentication = Some(policy);
        let original = server.clone();
        let endpoint = prepare_endpoint(&server, PrepareOptions::default()).unwrap();
        let (closed, mut observed) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = SslStream::new(Ssl::new(&context).unwrap(), tcp).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();
            match stream.read(&mut [0]).await {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                result => {
                    panic!("expired transport must close without application bytes: {result:?}")
                }
            }
            let _ = closed.send(());
        });
        let client = TacacsClient::connect_prepared(endpoint).await.unwrap();
        let mut conversation = client.open_conversation().await.unwrap();
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::time::resume();
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut observed)
                .await
                .is_err(),
            "unused trust must not shorten this connection's lifetime"
        );
        tokio::time::pause();
        tokio::time::advance(expiry).await;
        tokio::time::resume();
        let expired = tokio::time::timeout(Duration::from_millis(250), observed).await;
        conversation.complete().await;
        client
            .close_and_join(tacacsrs_networking::RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), peer)
            .await
            .unwrap()
            .unwrap();
        assert!(expired.is_ok(), "selected certificate path must expire the connection");
        assert_eq!(server, original);
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
                    AccountingOperation {
                        user: "test".to_owned(),
                        port: "test".to_owned(),
                        remote_address: "127.0.0.1".to_owned(),
                        command: "show".to_owned(),
                        command_arguments: Vec::new(),
                    }
                    .exchange(),
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
            PrepareOptions::default().with_certificate_verification_disabled(insecure),
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
                    AccountingOperation {
                        user: "test".to_owned(),
                        port: "test".to_owned(),
                        remote_address: "127.0.0.1".to_owned(),
                        command: "show".to_owned(),
                        command_arguments: Vec::new(),
                    }
                    .exchange(),
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
