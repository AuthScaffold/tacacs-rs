use std::path::Path;

use anyhow::Context;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tacacsrs_config::crypto_types::PrivateKeyFormat;

fn data_contains_pem_header(data: &[u8]) -> bool {
    const PEM_HEADER: &[u8] = b"-----BEGIN";

    data.windows(PEM_HEADER.len())
        .any(|window| window == PEM_HEADER)
}

/// Normalize PEM or DER certificate data into DER bytes.
///
/// # Errors
///
/// Returns an error if the data is empty, PEM parsing fails, or the PEM file
/// does not contain exactly one certificate.
pub fn normalize_cli_certificate_data(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.is_empty() {
        anyhow::bail!("client certificate data is empty");
    }

    if !data_contains_pem_header(data) {
        return Ok(data.to_vec());
    }

    let certificates = CertificateDer::pem_slice_iter(data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| anyhow::anyhow!("failed to parse PEM client certificate: {err}"))?;

    if certificates.len() != 1 {
        anyhow::bail!("client certificate file must contain exactly one PEM certificate");
    }

    Ok(certificates[0].as_ref().to_vec())
}

/// Normalize PEM or DER private key data into DER bytes and its YANG key format.
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
            .map_err(|err| anyhow::anyhow!("failed to parse PEM client private key: {err}"))?
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

/// Read and normalize a client certificate file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_client_certificate(path: &Path) -> anyhow::Result<Vec<u8>> {
    let cert_data = std::fs::read(path)
        .with_context(|| format!("Failed to read client certificate: {}", path.display()))?;
    normalize_cli_certificate_data(&cert_data)
        .with_context(|| format!("Failed to parse client certificate: {}", path.display()))
}

/// Read and normalize a client private key file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_client_private_key(path: &Path) -> anyhow::Result<(Vec<u8>, PrivateKeyFormat)> {
    let key_data = std::fs::read(path)
        .with_context(|| format!("Failed to read client key: {}", path.display()))?;
    normalize_cli_private_key_data(&key_data)
        .with_context(|| format!("Failed to parse client key: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_certificate_rejected() {
        let err = normalize_cli_certificate_data(&[]).expect_err("empty cert should fail");
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn der_certificate_passthrough() {
        assert_eq!(normalize_cli_certificate_data(b"der").unwrap(), b"der");
    }
}
