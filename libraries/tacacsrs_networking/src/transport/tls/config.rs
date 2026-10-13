//! Certificate TLS preparation from DER material without a configuration schema.

use anyhow::{Context, Result};
use openssl::ec::EcKey;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::SslContext;
use openssl::x509::X509;
use tokio::net::TcpStream;

use super::{connect_tls, TlsConfigurationBuilder, CertificateLifetime};
use crate::helpers::data_contains_pem_header;
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

#[derive(Clone)]
pub(crate) struct TlsClientConfig {
    context: SslContext,
    peer_identity: String,
    sni_name: Option<String>,
    pub(crate) lifetime: Option<CertificateLifetime>,
    pub(crate) client_validity: Option<super::CertificateValidity>,
    crls: Option<std::sync::Arc<super::revocation::crls::CrlEvidence>>,
    peer_pins: bool,
    peer_validity_index: super::config_builder::PeerValidityIndex,
    pub(crate) revocation: super::CertificateRevocationPolicy,
    revocation_issuers: Vec<X509>,
    verification_disabled: bool,
}

impl TlsClientConfig {
    pub(crate) fn prepare(
        peer_identity: &str,
        sni_name: Option<&str>,
        trust: CertificateTrust<'_>,
        identity: Option<CertificateIdentity<'_>>,
        disable_verification: bool,
    ) -> Result<Self> {
        anyhow::ensure!(
            !peer_identity.is_empty() && !peer_identity.contains(['\0', '*']),
            "TLS peer identity must be a nonempty DNS name or IP address without wildcards"
        );
        if let Some(name) = sni_name {
            anyhow::ensure!(
                !name.is_empty()
                    && !name.contains(['\0', '*'])
                    && name.parse::<std::net::IpAddr>().is_err(),
                "TLS SNI must be a nonempty DNS name, not an IP address"
            );
        }
        let mut builder = TlsConfigurationBuilder::new()
            .with_certificate_verification_disabled(disable_verification);
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
                .map(|data| parse_certificate_data(data))
                .collect::<Result<Vec<_>>>()?;
            let end_entities = end_entities
                .iter()
                .map(|data| parse_certificate_data(data))
                .collect::<Result<Vec<_>>>()?;
            revocation_issuers.clone_from(&authorities);
            builder = builder.with_certificate_trust(authorities, end_entities);
        }
        if let Some(identity) = identity {
            let certificate = parse_certificate_data(identity.certificate)
                .context("Failed to parse TLS certificate")?;
            if let Some(public_key_info) = identity.public_key_info {
                let public_key = PKey::public_key_from_der(public_key_info)
                    .context("failed to parse DER client public key information")?;
                anyhow::ensure!(
                    public_key.public_key_to_der()?.as_slice() == public_key_info,
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
            chain.push(certificate);
            for intermediate in identity.intermediates {
                chain.push(
                    parse_certificate_data(intermediate)
                        .context("Failed to parse TLS client intermediate certificate")?,
                );
            }
            builder = builder.with_client_auth_der(chain, key);
        }
        let prepared = builder
            .build()
            .context("Failed to build TLS configuration")?;
        Ok(Self {
            context: prepared.context,
            client_validity: prepared.validity,
            crls: None,
            peer_pins,
            peer_validity_index: prepared.peer_validity_index,
            revocation: super::CertificateRevocationPolicy::disabled(),
            revocation_issuers,
            verification_disabled: disable_verification,
            lifetime: prepared
                .validity
                .map(CertificateLifetime::new)
                .transpose()?,
            peer_identity: peer_identity.to_owned(),
            sni_name: sni_name.map(str::to_owned),
        })
    }

    pub(crate) fn with_revocation_policy(
        mut self,
        policy: super::CertificateRevocationPolicy,
    ) -> Result<Self> {
        anyhow::ensure!(
            !self.verification_disabled || policy.maximum_response_age().is_none(),
            "Required OCSP evidence cannot be combined with disabled certificate verification"
        );
        anyhow::ensure!(
            self.crls.is_none() || policy.maximum_response_age().is_none(),
            "CRL and stapled OCSP modes cannot be combined"
        );
        self.revocation = policy;
        Ok(self)
    }

    pub(crate) fn with_crls(
        mut self,
        lists: &[&[u8]],
        maximum_age: std::time::Duration,
    ) -> Result<Self> {
        anyhow::ensure!(
            !self.verification_disabled && !self.peer_pins,
            "CRL mode requires CA authentication with certificate verification enabled"
        );
        anyhow::ensure!(
            self.revocation.maximum_response_age().is_none(),
            "CRL and stapled OCSP modes cannot be combined"
        );
        let evidence = super::revocation::crls::CrlEvidence::prepare(lists, maximum_age)?;
        self.lifetime = Some(match self.lifetime {
            Some(lifetime) => lifetime.intersect(evidence.lifetime)?,
            None => evidence.lifetime,
        });
        self.crls = Some(std::sync::Arc::new(evidence));
        Ok(self)
    }

    pub(crate) async fn connect(&self, tcp_stream: TcpStream) -> Result<BoxedTransport> {
        let handshake = connect_tls(
            &self.context,
            tcp_stream,
            &self.peer_identity,
            self.sni_name.as_deref(),
            self.peer_validity_index,
            super::revocation::ConnectionRevocation::new(self.revocation, &self.revocation_issuers),
            self.crls.clone(),
        );
        let stream = match self.lifetime {
            Some(lifetime) => lifetime.run(handshake).await,
            None => handshake.await,
        }
        .context("Failed to establish TLS connection")?;
        let peer = stream
            .ssl()
            .peer_certificate()
            .context("TLS peer certificate is missing")?;
        let validity = if stream
            .ssl()
            .verify_mode()
            .contains(openssl::ssl::SslVerifyMode::PEER)
        {
            let selected = stream
                .ssl()
                .ex_data(self.peer_validity_index)
                .and_then(|slot| {
                    *slot
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                });
            match selected {
                Some(selected) => selected,
                None => super::CertificateValidity::from_chain(
                    stream
                        .ssl()
                        .verified_chain()
                        .context("Verified TLS peer chain is missing")?,
                )?,
            }
        } else {
            super::CertificateValidity::from_certificate(&peer)?
        };
        let validity = match super::revocation::verified_validity(stream.ssl())? {
            Some(evidence) => validity.intersect(evidence)?,
            None => validity,
        };
        let peer_lifetime = CertificateLifetime::new(validity)?;
        let lifetime = self
            .lifetime
            .map_or(Ok(peer_lifetime), |local| local.intersect(peer_lifetime))?;
        Ok(BoxedTransport::new(stream).with_certificate_lifetime(lifetime))
    }
}

fn parse_certificate_data(data: &[u8]) -> Result<X509> {
    anyhow::ensure!(!data.is_empty(), "certificate DER data is empty");
    anyhow::ensure!(
        !data_contains_pem_header(data),
        "PEM-encoded certificates are not supported; provide DER bytes"
    );
    let certificate = X509::from_der(data).context("failed to parse DER certificate")?;
    anyhow::ensure!(
        certificate.to_der()?.as_slice() == data,
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
    fn explicit_empty_trust_is_rejected_even_with_verification_disabled() {
        for disabled in [false, true] {
            let trust = CertificateTrust::Certificates {
                authorities: &[],
                end_entities: &[],
            };
            assert!(TlsClientConfig::prepare("localhost", None, trust, None, disabled).is_err());
        }
        assert!(TlsClientConfig::prepare(
            "localhost",
            None,
            CertificateTrust::Platform,
            None,
            false
        )
        .is_ok());
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
            false
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
            for disabled in [false, true] {
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
                    assert!(
                        TlsClientConfig::prepare("localhost", None, trust, None, disabled).is_err()
                    );
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
                    disabled
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
}
