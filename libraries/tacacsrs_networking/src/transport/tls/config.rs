//! Certificate TLS preparation from DER material without a configuration schema.

use anyhow::{Context, Result};
use openssl::ec::EcKey;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::SslContext;
use openssl::x509::X509;
use tokio::net::TcpStream;

use super::{connect_tls, RevocationEvidenceLifetime, TlsConfigurationBuilder};
use crate::transport::BoxedTransport;

/// DER encoding of a client private key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateKeyEncoding {
    /// PKCS#1 RSA private key.
    RsaPkcs1,
    /// SEC1 elliptic-curve private key.
    EcSec1,
    /// PKCS#8 asymmetric private key.
    Pkcs8,
}

/// Borrowed DER material for certificate-based client authentication.
pub struct CertificateIdentity<'a> {
    /// End-entity certificate in DER format.
    pub certificate: &'a [u8],
    /// DER intermediate certificates in issuer order, excluding the leaf and root.
    pub intermediates: &'a [&'a [u8]],
    /// Optional DER `SubjectPublicKeyInfo` that must match the certificate's key.
    pub public_key_info: Option<&'a [u8]>,
    /// Private key corresponding to the certificate.
    pub private_key: &'a [u8],
    /// Encoding of the private key.
    pub private_key_encoding: PrivateKeyEncoding,
}

/// Borrowed certificate trust inputs with explicit authority and peer roles.
#[derive(Clone, Copy)]
pub enum CertificateTrust<'a> {
    /// Use the platform trust store when no explicit trust was selected.
    Platform,
    /// Trust chains to `authorities` or exact certificates in `end_entities`.
    /// At least one collection must be nonempty. Platform roots are not added.
    Certificates {
        /// DER-encoded trust anchors.
        authorities: &'a [&'a [u8]],
        /// DER-encoded certificates authorized only as exact peer matches.
        end_entities: &'a [&'a [u8]],
    },
}

/// Controls server certificate verification without changing SNI or credential validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CertificateVerification {
    /// Requires certificate trust and peer identity verification.
    #[default]
    Required,
    /// Disables trust and peer identity verification for controlled development use.
    ///
    /// CAUTION: This policy permits server impersonation. Do not use it in production.
    /// Authentication certificate dates still apply. Required revocation evidence is rejected.
    DisabledForDevelopment,
}

/// Reusable certificate TLS configuration with private native context ownership.
///
/// Attach required OCSP and CRL evidence before finalizing an endpoint.
#[derive(Clone)]
pub struct TlsClientConfig {
    context: SslContext,
    peer_identity: String,
    sni_name: Option<String>,
    has_client_intermediates: bool,
    pub(crate) evidence_lifetime: Option<RevocationEvidenceLifetime>,
    crls: Option<std::sync::Arc<super::revocation::crls::CrlEvidence>>,
    peer_pins: bool,
    pub(crate) revocation: super::CertificateRevocationPolicy,
    revocation_issuers: Vec<X509>,
    verification: CertificateVerification,
    provided_ocsp: Option<super::revocation::ProvidedResponse>,
    payload: crate::PreparationPayload,
}

impl std::fmt::Debug for TlsClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsClientConfig")
            .field("peer_identity", &self.peer_identity)
            .field("sni_name", &self.sni_name)
            .field("verification", &self.verification)
            .field("revocation", &self.revocation)
            .field("crls", &self.crls.is_some())
            .field("fetched_ocsp", &self.provided_ocsp.is_some())
            .finish_non_exhaustive()
    }
}

impl TlsClientConfig {
    /// Prepares trust, client credentials, peer identity, and optional SNI without I/O.
    ///
    /// CAUTION: `CertificateVerification::DisabledForDevelopment` permits server impersonation. Do not use it in production.
    /// Authentication certificate dates still apply to each new connection.
    /// Names retain their spelling and optional trailing dot. SNI rejects IP addresses.
    ///
    /// # Errors
    /// Returns an error for invalid credentials, trust, identity, or native configuration.
    ///
    /// A positional boolean cannot select the verification policy.
    ///
    /// ```compile_fail,E0308
    /// use tacacsrs_networking::{CertificateTrust, TlsClientConfig};
    ///
    /// TlsClientConfig::prepare("localhost", None, CertificateTrust::Platform, None, true);
    /// ```
    pub fn prepare(
        peer_identity: &str,
        sni_name: Option<&str>,
        trust: CertificateTrust<'_>,
        identity: Option<CertificateIdentity<'_>>,
        verification: CertificateVerification,
    ) -> Result<Self> {
        Self::prepare_with_payload(
            peer_identity,
            sni_name,
            trust,
            identity,
            verification,
            crate::PreparationPayload::default(),
        )
    }

    /// Prepares certificate TLS with explicit Rust payload admission.
    /// # Errors
    /// Returns a material, native preparation, or payload admission error.
    pub fn prepare_with_payload(
        peer_identity: &str,
        sni_name: Option<&str>,
        trust: CertificateTrust<'_>,
        identity: Option<CertificateIdentity<'_>>,
        verification: CertificateVerification,
        payload: crate::PreparationPayload,
    ) -> Result<Self> {
        payload.retain(peer_identity.len())?;
        payload.retain(sni_name.map_or(0, str::len))?;
        crate::ServerAddress::new(peer_identity, 1).context("invalid TLS peer identity")?;
        if let Some(name) = sni_name {
            anyhow::ensure!(
                name.parse::<std::net::IpAddr>().is_err(),
                "TLS SNI must be a DNS name, not an IP address"
            );
            crate::ServerAddress::new(name, 1).context("invalid TLS SNI name")?;
        }
        let mut builder = TlsConfigurationBuilder::new()
            .with_payload(payload.clone())
            .with_certificate_verification_disabled(
                verification == CertificateVerification::DisabledForDevelopment,
            );
        let peer_pins = matches!(&trust, CertificateTrust::Certificates { end_entities, .. } if !end_entities.is_empty());
        let mut revocation_issuers = Vec::new();
        if let CertificateTrust::Certificates {
            authorities,
            end_entities,
        } = trust
        {
            anyhow::ensure!(
                !authorities.is_empty() || !end_entities.is_empty(),
                "Explicit certificate trust must contain certificates"
            );
            let authorities = authorities
                .iter()
                .map(|data| {
                    Ok((
                        parse_certificate_data_accounted(data, &payload)?,
                        payload
                            .native_bytes(data.len(), || Ok::<_, anyhow::Error>(data.to_vec()))?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let end_entities = end_entities
                .iter()
                .map(|data| {
                    Ok((
                        parse_certificate_data_accounted(data, &payload)?,
                        payload
                            .native_bytes(data.len(), || Ok::<_, anyhow::Error>(data.to_vec()))?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            revocation_issuers = authorities
                .iter()
                .map(|(certificate, _)| certificate.clone())
                .collect();
            builder = builder.with_certificate_trust(authorities, end_entities);
        }
        let mut has_client_intermediates = false;
        if let Some(identity) = identity {
            has_client_intermediates = !identity.intermediates.is_empty();
            let certificate = parse_certificate_data_accounted(identity.certificate, &payload)
                .context("Failed to parse TLS certificate")?;
            if let Some(public_key_info) = identity.public_key_info {
                let public_key = PKey::public_key_from_der(public_key_info)
                    .context("failed to parse DER client public key information")?;
                anyhow::ensure!(
                    payload
                        .native_bytes(public_key_info.len(), || public_key.public_key_to_der())?
                        .as_slice()
                        == public_key_info,
                    "Client public key must contain exactly one DER SubjectPublicKeyInfo value"
                );
                let certificate_key = certificate
                    .public_key()
                    .context("read certificate public key")?;
                anyhow::ensure!(
                    certificate_key.public_eq(&public_key),
                    "Explicit client public key does not match the certificate"
                );
            }
            let key = parse_private_key_data(identity.private_key, identity.private_key_encoding)
                .context("Failed to parse TLS private key")?;
            let mut chain = Vec::with_capacity(identity.intermediates.len() + 1);
            chain.push((certificate, identity.certificate.len()));
            for intermediate in identity.intermediates {
                chain.push((
                    parse_certificate_data_accounted(intermediate, &payload)
                        .context("Failed to parse TLS client intermediate certificate")?,
                    intermediate.len(),
                ));
            }
            builder = builder.with_client_auth_der(chain, key);
        }
        let context = builder
            .build()
            .context("Failed to build TLS configuration")?;
        if verification == CertificateVerification::DisabledForDevelopment {
            log::warn!("TLS certificate verification is disabled for development; server impersonation is possible");
        }
        Ok(Self {
            context,
            has_client_intermediates,
            crls: None,
            peer_pins,
            revocation: super::CertificateRevocationPolicy::disabled(),
            revocation_issuers,
            verification,
            provided_ocsp: None,
            evidence_lifetime: None,
            peer_identity: peer_identity.to_owned(),
            sni_name: sni_name.map(str::to_owned),
            payload,
        })
    }

    /// Requires stapled OCSP independently of fetched evidence.
    ///
    /// # Errors
    /// Rejects required evidence when certificate verification is disabled.
    pub fn with_revocation_policy(
        mut self,
        policy: super::CertificateRevocationPolicy,
    ) -> Result<Self> {
        anyhow::ensure!(
            self.verification == CertificateVerification::Required
                || policy.maximum_response_age().is_none(),
            "Required OCSP evidence cannot be combined with disabled certificate verification"
        );
        self.revocation = policy;
        Ok(self)
    }

    /// Attaches fresh full CRLs and explicitly paired deltas for CA authentication.
    ///
    /// # Errors
    /// Rejects invalid evidence, exact peer pins, or disabled verification.
    pub fn with_crls(mut self, lists: &[&[u8]], maximum_age: std::time::Duration) -> Result<Self> {
        anyhow::ensure!(
            self.verification == CertificateVerification::Required && !self.peer_pins,
            "CRL mode requires CA authentication with certificate verification enabled"
        );
        let evidence =
            super::revocation::crls::CrlEvidence::prepare(lists, maximum_age, &self.payload)?;
        self.evidence_lifetime = Some(match self.evidence_lifetime {
            Some(lifetime) => lifetime.intersect(evidence.lifetime)?,
            None => evidence.lifetime,
        });
        self.crls = Some(std::sync::Arc::new(evidence));
        Ok(self)
    }

    pub(crate) fn validate_client_certificate_dates(&self) -> Result<()> {
        super::config_builder::validate_client_certificate_dates(
            &self.context,
            self.has_client_intermediates,
        )
    }

    fn local_authentication_certificates(&self) -> Result<Vec<Vec<u8>>> {
        let mut certificates = self
            .context
            .certificate()
            .map(|certificate| certificate.to_der())
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();
        if self.has_client_intermediates {
            certificates.extend(
                self.context
                    .extra_chain_certs()
                    .iter()
                    .map(openssl::x509::X509Ref::to_der)
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        Ok(certificates)
    }

    pub(crate) async fn connect(&self, tcp_stream: TcpStream) -> Result<BoxedTransport> {
        self.validate_client_certificate_dates()
            .context(crate::statistics::CertificateFailure)?;
        let (stream, verified_evidence) = connect_tls(
            &self.context,
            tcp_stream,
            &self.peer_identity,
            self.sni_name.as_deref(),
            super::revocation::ConnectionRevocation::new(
                self.revocation,
                &self.revocation_issuers,
                self.local_authentication_certificates()?,
                self.provided_ocsp.clone(),
            ),
            self.crls.clone(),
        )
        .await
        .context("Failed to establish TLS connection")?;
        let peer = stream
            .ssl()
            .peer_certificate()
            .context("TLS peer certificate is missing")?;
        if self.verification == CertificateVerification::DisabledForDevelopment {
            let now = std::time::SystemTime::now();
            let valid_from = super::validity::system_time(peer.not_before())?;
            let valid_until = super::validity::system_time(peer.not_after())?;
            if !(valid_from <= now && now < valid_until) {
                return Err(anyhow::anyhow!("Peer certificate validity excludes the current time")
                    .context(crate::statistics::CertificateFailure));
            }
        }
        let lifetime = match verified_evidence {
            Some(validity) => {
                let verified = RevocationEvidenceLifetime::new(validity)?;
                Some(
                    self.evidence_lifetime
                        .map_or(Ok(verified), |prepared| prepared.intersect(verified))?,
                )
            }
            None => self.evidence_lifetime,
        };
        let details = crate::TlsDetails::from_ssl(stream.ssl());
        let transport = BoxedTransport::new(stream).with_tls_details(details);
        Ok(match lifetime {
            Some(lifetime) => transport.with_revocation_evidence_lifetime(lifetime),
            None => transport,
        })
    }

    /// Attaches fetched OCSP evidence without replacing a mandatory staple policy.
    ///
    /// # Errors
    /// Rejects invalid or stale evidence and disabled certificate verification.
    pub fn with_ocsp_response(
        mut self,
        encoded: &[u8],
        maximum_age: std::time::Duration,
    ) -> Result<Self> {
        anyhow::ensure!(
            self.verification == CertificateVerification::Required,
            "Fetched OCSP requires certificate verification"
        );
        let response =
            super::revocation::ProvidedResponse::prepare(encoded, maximum_age, &self.payload)?;
        self.evidence_lifetime = Some(match self.evidence_lifetime {
            Some(current) => current.intersect(response.lifetime)?,
            None => response.lifetime,
        });
        self.provided_ocsp = Some(response);
        Ok(self)
    }
}

/// Returns whether `data` contains a PEM block marker.
///
/// Certificate and private-key inputs must be DER. A PEM marker means the caller
/// supplied the wrong encoding, so the DER parsers reject it before OpenSSL runs.
#[must_use]
fn data_contains_pem_header(data: &[u8]) -> bool {
    const PEM_HEADER: &[u8] = b"-----BEGIN";

    data.windows(PEM_HEADER.len())
        .any(|window| window == PEM_HEADER)
}

#[cfg(test)]
fn parse_certificate_data(data: &[u8]) -> Result<X509> {
    parse_certificate_data_accounted(data, &crate::PreparationPayload::default())
}

fn parse_certificate_data_accounted(
    data: &[u8],
    payload: &crate::PreparationPayload,
) -> Result<X509> {
    anyhow::ensure!(!data.is_empty(), "certificate DER data is empty");
    anyhow::ensure!(
        !data_contains_pem_header(data),
        "PEM-encoded certificates are not supported; provide DER bytes"
    );
    let certificate = X509::from_der(data).context("failed to parse DER certificate")?;
    anyhow::ensure!(
        payload
            .native_bytes(data.len(), || certificate.to_der())?
            .as_slice()
            == data,
        "certificate input must contain exactly one DER certificate without trailing data"
    );
    Ok(certificate)
}

fn parse_private_key_data(data: &[u8], encoding: PrivateKeyEncoding) -> Result<PKey<Private>> {
    anyhow::ensure!(!data.is_empty(), "private key DER data is empty");
    anyhow::ensure!(
        !data_contains_pem_header(data),
        "PEM-encoded private keys are not supported; provide DER bytes"
    );
    match encoding {
        PrivateKeyEncoding::RsaPkcs1 => {
            let key =
                Rsa::private_key_from_der(data).context("failed to parse DER RSA private key")?;
            PKey::from_rsa(key).context("failed to convert RSA private key")
        }
        PrivateKeyEncoding::EcSec1 => {
            let key =
                EcKey::private_key_from_der(data).context("failed to parse DER EC private key")?;
            PKey::from_ec_key(key).context("failed to convert EC private key")
        }
        PrivateKeyEncoding::Pkcs8 => {
            PKey::private_key_from_der(data).context("failed to parse DER PKCS#8 private key")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_omits_client_key_and_native_context() {
        let certificate = X509::from_pem(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../lde/containers/config/certificates/client.crt",
        )))
        .unwrap()
        .to_der()
        .unwrap();
        let key = PKey::private_key_from_pem(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../lde/containers/config/certificates/client.key",
        )))
        .unwrap()
        .private_key_to_pkcs8()
        .unwrap();
        let config = TlsClientConfig::prepare(
            "localhost",
            Some("server.example"),
            CertificateTrust::Platform,
            Some(CertificateIdentity {
                certificate: &certificate,
                intermediates: &[],
                public_key_info: None,
                private_key: &key,
                private_key_encoding: PrivateKeyEncoding::Pkcs8,
            }),
            CertificateVerification::Required,
        )
        .unwrap();
        for rendered in [
            format!("{config:?}"),
            format!("{config:#?}"),
            format!("{:?}", crate::PreparedTransport::Tls(config)),
        ] {
            assert!(rendered.contains("server.example"));
            assert!(rendered.contains("Required"));
            assert!(!rendered.contains(&format!("{key:?}")));
            assert!(!rendered.contains("private_key"));
            assert!(!rendered.contains("context"));
        }
    }

    #[test]
    fn certificate_names_use_the_validated_host_contract() {
        for verification in [
            CertificateVerification::Required,
            CertificateVerification::DisabledForDevelopment,
        ] {
            for name in [
                "bad host",
                "bad\0name",
                "",
                "*.example",
                "host:49",
                "[::1]",
                "host..example",
                "127.1",
                "0x7f000001",
                "127.0.0.1.",
            ] {
                assert!(
                    TlsClientConfig::prepare(
                        name,
                        None,
                        CertificateTrust::Platform,
                        None,
                        verification
                    )
                    .is_err(),
                    "peer identity {name:?}"
                );
                assert!(
                    TlsClientConfig::prepare(
                        "localhost",
                        Some(name),
                        CertificateTrust::Platform,
                        None,
                        verification
                    )
                    .is_err(),
                    "SNI {name:?}"
                );
            }
            for name in [
                "server.example",
                "Server.Example.",
                "tacacs_server.example",
                "_tacacs._tcp.example.",
            ] {
                let config = TlsClientConfig::prepare(
                    name,
                    Some(name),
                    CertificateTrust::Platform,
                    None,
                    verification,
                )
                .unwrap();
                assert_eq!(config.peer_identity, name);
                assert_eq!(config.sni_name.as_deref(), Some(name));
            }
            for address in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
                assert!(TlsClientConfig::prepare(
                    address,
                    None,
                    CertificateTrust::Platform,
                    None,
                    verification
                )
                .is_ok());
                assert!(TlsClientConfig::prepare(
                    "localhost",
                    Some(address),
                    CertificateTrust::Platform,
                    None,
                    verification
                )
                .is_err());
            }
        }
    }

    #[test]
    fn verification_policy_defaults_to_required_and_controls_native_mode() {
        assert_eq!(CertificateVerification::default(), CertificateVerification::Required);
        for (verification, mode) in [
            (CertificateVerification::Required, openssl::ssl::SslVerifyMode::PEER),
            (CertificateVerification::DisabledForDevelopment, openssl::ssl::SslVerifyMode::NONE),
        ] {
            let config = TlsClientConfig::prepare(
                "localhost",
                Some("server.example"),
                CertificateTrust::Platform,
                None,
                verification,
            )
            .unwrap();
            assert_eq!(config.context.verify_mode(), mode);
            assert_eq!(config.peer_identity, "localhost");
            assert_eq!(config.sni_name.as_deref(), Some("server.example"));
        }
    }

    #[test]
    fn development_verification_rejects_all_required_revocation_evidence() {
        let config = TlsClientConfig::prepare(
            "localhost",
            None,
            CertificateTrust::Platform,
            None,
            CertificateVerification::DisabledForDevelopment,
        )
        .unwrap();
        let maximum_age = std::time::Duration::from_secs(300);
        assert!(config
            .clone()
            .with_revocation_policy(
                super::super::CertificateRevocationPolicy::require_stapled_ocsp(maximum_age)
                    .unwrap(),
            )
            .unwrap_err()
            .to_string()
            .contains("disabled certificate verification"));
        assert!(config
            .clone()
            .with_crls(&[], maximum_age)
            .unwrap_err()
            .to_string()
            .contains("verification enabled"));
        assert!(config
            .with_ocsp_response(&[], maximum_age)
            .unwrap_err()
            .to_string()
            .contains("requires certificate verification"));
    }

    #[test]
    fn explicit_empty_trust_is_rejected_even_with_verification_disabled() {
        for verification in [
            CertificateVerification::Required,
            CertificateVerification::DisabledForDevelopment,
        ] {
            let trust = CertificateTrust::Certificates {
                authorities: &[],
                end_entities: &[],
            };
            assert!(TlsClientConfig::prepare("localhost", None, trust, None, verification).is_err());
        }
        assert!(TlsClientConfig::prepare(
            "localhost",
            None,
            CertificateTrust::Platform,
            None,
            CertificateVerification::Required
        )
        .is_ok());
    }

    #[tokio::test]
    async fn peer_dates_are_checked_at_connection_even_with_verification_disabled() {
        use std::pin::Pin;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        use openssl::asn1::Asn1Time;
        use openssl::ssl::{Ssl, SslMethod};
        use openssl::x509::X509NameBuilder;
        use tokio::net::TcpListener;
        use tokio_openssl::SslStream;

        let key = PKey::private_key_from_pem(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../lde/containers/config/certificates/server.key"
        )))
        .unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (start, end) in [(now - 120, now - 60), (now + 60, now + 120)] {
            let mut certificate = X509::builder().unwrap();
            certificate.set_version(2).unwrap();
            certificate.set_subject_name(&name).unwrap();
            certificate.set_issuer_name(&name).unwrap();
            certificate.set_pubkey(&key).unwrap();
            certificate
                .set_not_before(&Asn1Time::from_unix(start.try_into().unwrap()).unwrap())
                .unwrap();
            certificate
                .set_not_after(&Asn1Time::from_unix(end.try_into().unwrap()).unwrap())
                .unwrap();
            certificate
                .sign(&key, openssl::hash::MessageDigest::sha256())
                .unwrap();
            let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
            context.set_certificate(&certificate.build()).unwrap();
            context.set_private_key(&key).unwrap();
            // The client intentionally closes after it rejects the certificate dates.
            // Avoid unnecessary post-handshake ticket writes to the closed stream.
            context.set_num_tickets(0).unwrap();
            let context = context.build();
            let config = TlsClientConfig::prepare(
                "localhost",
                None,
                CertificateTrust::Platform,
                None,
                CertificateVerification::DisabledForDevelopment,
            )
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let peer = async {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut stream = SslStream::new(Ssl::new(&context).unwrap(), tcp).unwrap();
                Pin::new(&mut stream).accept().await.unwrap();
            };
            let connect = async {
                let tcp = TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                config.connect(tcp).await
            };
            let (result, ()) =
                tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(connect, peer) })
                    .await
                    .unwrap();
            let error = match result {
                Ok(_) => panic!("invalid peer dates must reject a new connection"),
                Err(error) => error,
            };
            assert!(format!("{error:#}").contains("Peer certificate validity excludes"));
        }
    }

    #[test]
    fn der_certificate_parser_requires_exactly_one_certificate() {
        let pem = std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../lde/containers/config/certificates/client.crt"),
        )
        .unwrap();
        let der = X509::from_pem(&pem).unwrap().to_der().unwrap();
        assert!(parse_certificate_data(&der).is_ok());
        let key_pem = std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../lde/containers/config/certificates/client.key"),
        )
        .unwrap();
        let key = PKey::private_key_from_pem(&key_pem)
            .unwrap()
            .private_key_to_pkcs8()
            .unwrap();
        assert!(TlsClientConfig::prepare(
            "localhost",
            None,
            CertificateTrust::Platform,
            Some(CertificateIdentity {
                intermediates: &[],
                certificate: &der,
                public_key_info: None,
                private_key: &key,
                private_key_encoding: PrivateKeyEncoding::Pkcs8,
            }),
            CertificateVerification::Required
        )
        .is_ok());
        for suffix in [der.as_slice(), b"trailing-data".as_slice()] {
            let mut combined = der.clone();
            combined.extend_from_slice(suffix);
            assert!(
                parse_certificate_data(&combined).is_err(),
                "trailing certificate data must not be ignored"
            );
            let certificates = [combined.as_slice()];
            for verification in [
                CertificateVerification::Required,
                CertificateVerification::DisabledForDevelopment,
            ] {
                for trust in [
                    CertificateTrust::Certificates {
                        authorities: &certificates,
                        end_entities: &[],
                    },
                    CertificateTrust::Certificates {
                        authorities: &[],
                        end_entities: &certificates,
                    },
                ] {
                    assert!(TlsClientConfig::prepare("localhost", None, trust, None, verification)
                        .is_err());
                }
                let identity = CertificateIdentity {
                    intermediates: &[],
                    certificate: &combined,
                    public_key_info: None,
                    private_key: &key,
                    private_key_encoding: PrivateKeyEncoding::Pkcs8,
                };
                assert!(TlsClientConfig::prepare(
                    "localhost",
                    None,
                    CertificateTrust::Platform,
                    Some(identity),
                    verification
                )
                .is_err());
            }
        }
    }

    #[test]
    fn der_parsers_reject_pem_and_leading_noise() {
        for prefix in ["", "\n\t \u{feff}"] {
            assert_eq!(
                parse_certificate_data(
                    format!("{prefix}-----BEGIN CERTIFICATE-----\n...").as_bytes()
                )
                .unwrap_err()
                .to_string(),
                "PEM-encoded certificates are not supported; provide DER bytes"
            );
            assert_eq!(
                parse_private_key_data(
                    format!("{prefix}-----BEGIN PRIVATE KEY-----\n...").as_bytes(),
                    PrivateKeyEncoding::Pkcs8
                )
                .unwrap_err()
                .to_string(),
                "PEM-encoded private keys are not supported; provide DER bytes"
            );
        }
    }

    #[test]
    fn private_key_encodings_accept_matching_der() {
        use openssl::ec::EcGroup;
        use openssl::nid::Nid;
        let rsa = Rsa::generate(2048).unwrap();
        assert!(parse_private_key_data(
            &rsa.private_key_to_der().unwrap(),
            PrivateKeyEncoding::RsaPkcs1
        )
        .is_ok());
        let key = PKey::from_rsa(rsa).unwrap();
        assert!(parse_private_key_data(
            &key.private_key_to_pkcs8().unwrap(),
            PrivateKeyEncoding::Pkcs8
        )
        .is_ok());
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let der = ec.private_key_to_der().unwrap();
        assert!(parse_private_key_data(&der, PrivateKeyEncoding::EcSec1).is_ok());
        assert!(parse_private_key_data(&der, PrivateKeyEncoding::RsaPkcs1).is_err());
    }

    #[test]
    fn data_contains_pem_header_accepts_plain_pem() {
        assert!(data_contains_pem_header(b"-----BEGIN CERTIFICATE-----\n..."));
    }

    #[test]
    fn data_contains_pem_header_finds_marker_after_leading_noise() {
        assert!(data_contains_pem_header(b"\n\t \xEF\xBB\xBF-----BEGIN PRIVATE KEY-----\n..."));
    }

    #[test]
    fn data_contains_pem_header_rejects_der_and_empty_data() {
        assert!(!data_contains_pem_header(b"\x30\x82\x01\x00fake-der"));
        assert!(!data_contains_pem_header(b"\n\t "));
    }
}
