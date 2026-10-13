use std::path::Path;

use anyhow::Context;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use crate::crypto_types::PrivateKeyFormat;

fn data_contains_pem_header(data: &[u8]) -> bool {
    const PEM_HEADER: &[u8] = b"-----BEGIN";

    data.windows(PEM_HEADER.len())
        .any(|window| window == PEM_HEADER)
}

/// A normalized certificate file with a leaf and ordered DER intermediates.
///
/// Native preparation validates certificate contents, issuer order, and dates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificateChain {
    /// The first certificate in the input file.
    pub leaf: Vec<u8>,
    /// Remaining certificates in input order. Native preparation rejects roots.
    pub intermediates: Vec<Vec<u8>>,
}

/// Normalizes a PEM certificate chain or a single DER certificate.
///
/// # Errors
///
/// Returns an error if the data is empty, PEM parsing fails, or the PEM file
/// does not contain any certificates.
pub fn normalize_cli_certificate_data(data: &[u8]) -> anyhow::Result<ClientCertificateChain> {
    if data.is_empty() {
        anyhow::bail!("client certificate data is empty");
    }

    if !data_contains_pem_header(data) {
        return Ok(ClientCertificateChain {
            leaf: data.to_vec(),
            intermediates: Vec::new(),
        });
    }

    let certificates = CertificateDer::pem_slice_iter(data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| anyhow::anyhow!("cannot parse PEM client certificate: {err}"))?;

    let mut certificates = certificates.into_iter();
    let leaf = certificates
        .next()
        .context("Client certificate file contains no PEM certificates")?
        .as_ref()
        .to_vec();
    Ok(ClientCertificateChain {
        leaf,
        intermediates: certificates
            .map(|certificate| certificate.as_ref().to_vec())
            .collect(),
    })
}

/// Normalizes PEM or DER private key data into DER bytes and a YANG key format.
///
/// # Errors
///
/// Returns an error if the data is empty or not a supported PKCS#1, SEC1, or
/// PKCS#8 private key.
pub fn normalize_cli_private_key_data(data: &[u8]) -> anyhow::Result<(Vec<u8>, PrivateKeyFormat)> {
    if data.is_empty() {
        anyhow::bail!("client private key data is empty");
    }

    let private_key = if data_contains_pem_header(data) {
        PrivateKeyDer::from_pem_slice(data)
            .map_err(|err| anyhow::anyhow!("cannot parse PEM client private key: {err}"))?
    } else {
        PrivateKeyDer::try_from(data).map_err(|_| {
            anyhow::anyhow!(
                "unsupported DER client private key format; expected PKCS#1, SEC1, or PKCS#8"
            )
        })?
    };

    let private_key_format = match &private_key {
        PrivateKeyDer::Pkcs1(_) => PrivateKeyFormat::RsaPrivateKeyFormat,
        PrivateKeyDer::Sec1(_) => PrivateKeyFormat::EcPrivateKeyFormat,
        PrivateKeyDer::Pkcs8(_) => PrivateKeyFormat::OneAsymmetricKeyFormat,
        _ => anyhow::bail!("unsupported client private key format"),
    };

    Ok((private_key.secret_der().to_vec(), private_key_format))
}

/// Reads and normalizes a client certificate file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_client_certificate(path: &Path) -> anyhow::Result<ClientCertificateChain> {
    let cert_data = std::fs::read(path)
        .with_context(|| format!("cannot read client certificate {}", path.display()))?;
    normalize_cli_certificate_data(&cert_data)
        .with_context(|| format!("cannot parse client certificate {}", path.display()))
}

/// Reads and normalizes a client private key file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_client_private_key(path: &Path) -> anyhow::Result<(Vec<u8>, PrivateKeyFormat)> {
    let key_data = std::fs::read(path)
        .with_context(|| format!("cannot read client key {}", path.display()))?;
    normalize_cli_private_key_data(&key_data)
        .with_context(|| format!("cannot parse client key {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_certificate_rejected() {
        let err = normalize_cli_certificate_data(&[]).expect_err("empty certificate must fail");
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn der_certificate_passthrough() {
        assert_eq!(
            normalize_cli_certificate_data(b"der").unwrap(),
            ClientCertificateChain {
                leaf: b"der".to_vec(),
                intermediates: Vec::new()
            }
        );
    }

    #[test]
    fn client_pem_input_preserves_certificate_chain_order() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../lde/containers/config/certificates");
        let certificate = std::fs::read(path.join("client.crt")).unwrap();
        let intermediate = std::fs::read(path.join("server.crt")).unwrap();
        let leaf = normalize_cli_certificate_data(&certificate).unwrap();
        let issuer = normalize_cli_certificate_data(&intermediate).unwrap();
        let chain = [certificate.as_slice(), b"\n", intermediate.as_slice()].concat();
        let normalized = normalize_cli_certificate_data(&chain).unwrap();
        assert_eq!(normalized.leaf, leaf.leaf);
        assert_eq!(normalized.intermediates, [issuer.leaf]);
    }
}
