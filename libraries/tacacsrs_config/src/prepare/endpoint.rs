//! Projects canonical YANG fields into connection-ready transport inputs.

use anyhow::{Context, Result, ensure};

use tacacsrs_networking::{
    ConnectOptions, ConnectPreflight, PreparedEndpoint, CertificateIdentity, PrivateKeyEncoding,
    PskHash, PskDheGroup,
};
use tacacsrs_secrets::SecretBytes;

use crate::{TacacsPlusServer, TacacsPlusServerExt, EpskSupportedHash, PskDheKeSupportedGroup};
use crate::crypto_types::PrivateKeyFormat;

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
            psk_server_name(server)?,
        );
    }
    if !server.is_tls() {
        return Ok(endpoint);
    }
    let roots = server
        .server_authentication
        .iter()
        .flat_map(|auth| auth.ca_certs.iter().chain(auth.ee_certs.iter()))
        .filter_map(|certs| certs.inline_definition.as_ref())
        .flat_map(|inline| {
            inline
                .certificate
                .iter()
                .map(|cert| cert.cert_data.as_slice())
        });
    let identity = server
        .client_identity
        .as_ref()
        .and_then(|identity| identity.certificate.as_ref())
        .map(|certificate| {
            let inline = certificate
                .inline_definition
                .as_ref()
                .context("TLS client certificate requires materialized inline credentials")?;
            Ok::<_, anyhow::Error>(CertificateIdentity {
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
        .transpose()?;
    endpoint.with_certificate_tls(certificate_server_name(server), roots, identity)
}

fn certificate_server_name(server: &TacacsPlusServer) -> &str {
    if server.sni_enabled() {
        server.domain_name.as_deref().unwrap_or(&server.address)
    } else {
        &server.address
    }
}

fn psk_server_name(server: &TacacsPlusServer) -> Result<Option<&str>> {
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
            assert_eq!(certificate_server_name(&server), address);
            assert_eq!(psk_server_name(&server).unwrap(), None);
            server.sni_enabled = Some(true);
            assert_eq!(certificate_server_name(&server), "configured.example.com");
            assert_eq!(psk_server_name(&server).unwrap(), Some("configured.example.com"));
            server.domain_name = None;
            assert_eq!(certificate_server_name(&server), address);
            assert!(psk_server_name(&server).is_err());
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
