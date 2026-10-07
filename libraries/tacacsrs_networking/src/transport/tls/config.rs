//! Certificate TLS preparation from DER material without a configuration schema.

use anyhow::{Context, Result};
use openssl::ec::EcKey;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::SslContext;
use openssl::x509::X509;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::{connect_tls, TlsConfigurationBuilder};
use crate::helpers::data_contains_pem_header;

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
    /// Private key corresponding to the certificate.
    pub private_key: &'a [u8],
    /// Encoding of the private key.
    pub private_key_encoding: PrivateKeyEncoding,
}

#[derive(Clone)]
pub(crate) struct TlsClientConfig {
    context: SslContext,
    peer_identity: String,
    sni_name: Option<String>,
}

impl TlsClientConfig {
    pub(crate) fn prepare<'a>(
        peer_identity: &str,
        sni_name: Option<&str>,
        roots: impl IntoIterator<Item = &'a [u8]>,
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
        let roots = roots
            .into_iter()
            .map(parse_certificate_data)
            .collect::<Result<Vec<_>>>()?;
        let mut builder = TlsConfigurationBuilder::new()
            .with_root_certificates(roots)
            .with_certificate_verification_disabled(disable_verification);
        if let Some(identity) = identity {
            let certificate = parse_certificate_data(identity.certificate)
                .context("Failed to parse TLS certificate")?;
            let key = parse_private_key_data(identity.private_key, identity.private_key_encoding)
                .context("Failed to parse TLS private key")?;
            builder = builder.with_client_auth_der(vec![certificate], key);
        }
        Ok(Self {
            context: builder
                .build()
                .context("Failed to build TLS configuration")?,
            peer_identity: peer_identity.to_owned(),
            sni_name: sni_name.map(str::to_owned),
        })
    }

    pub(crate) async fn connect(&self, tcp_stream: TcpStream) -> Result<SslStream<TcpStream>> {
        connect_tls(&self.context, tcp_stream, &self.peer_identity, self.sni_name.as_deref())
            .await
            .context("Failed to establish TLS connection")
    }
}

fn parse_certificate_data(data: &[u8]) -> Result<X509> {
    anyhow::ensure!(!data.is_empty(), "certificate DER data is empty");
    anyhow::ensure!(
        !data_contains_pem_header(data),
        "PEM-encoded certificates are not supported; provide DER bytes"
    );
    X509::from_der(data).context("failed to parse DER certificate")
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
    fn parse_certificate_data_der_bytes() {
        let pem = std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../lde/containers/config/certificates/client.crt"),
        )
        .unwrap();
        let der = X509::from_pem(&pem).unwrap().to_der().unwrap();
        assert!(parse_certificate_data(&der).is_ok());
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
