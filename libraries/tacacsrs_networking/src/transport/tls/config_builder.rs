use std::{path::PathBuf, sync::Arc};

use rustls_cert_file_reader::{FileReader, Format, ReadCerts, ReadKey};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio_rustls::rustls;

use super::danger::NoCertificateVerification;

/// A builder for creating TLS client configurations.
///
/// This builder provides a fluent API for configuring TLS settings including:
/// - Root certificate stores for server verification
/// - Client authentication certificates
/// - Session resumption settings
/// - Certificate verification bypass (dangerous, for testing only)
///
/// # Example
///
/// ```no_run
/// use tacacsrs_networking::transport::tls::TlsConfigurationBuilder;
///
/// # async fn example() -> anyhow::Result<()> {
/// let config = TlsConfigurationBuilder::new()
///     .with_resumption(true)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct TlsConfigurationBuilder {
    root_cert_store: rustls::RootCertStore,
    resumption_enabled: bool,
    certificate_chain: Option<Vec<CertificateDer<'static>>>,
    private_key: Option<PrivateKeyDer<'static>>,
    disable_certificate_verification: bool,
}

impl Default for TlsConfigurationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfigurationBuilder {
    /// Creates a new `TlsConfigurationBuilder` with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root_cert_store: crate::helpers::default_root_cert_store(),
            resumption_enabled: false,
            certificate_chain: None,
            private_key: None,
            disable_certificate_verification: false,
        }
    }

    /// Sets the root certificate store for verifying server certificates.
    #[must_use]
    pub fn with_root_certificates(mut self, root_cert_store: rustls::RootCertStore) -> Self {
        self.root_cert_store = root_cert_store;
        self
    }

    /// Enables or disables TLS session resumption.
    #[must_use]
    pub const fn with_resumption(mut self, enabled: bool) -> Self {
        self.resumption_enabled = enabled;
        self
    }

    /// Loads client authentication certificates and private key from files.
    ///
    /// # Arguments
    ///
    /// * `certificate_chain_file` - Path to the PEM-encoded certificate chain file
    /// * `private_key_file` - Path to the PEM-encoded private key file
    /// # Errors
    ///
    /// Returns an error if:
    /// - A certificate chain is provided without a private key
    /// - The TLS certificate/key files cannot be read
    pub async fn with_client_auth_cert_files(
        mut self,
        certificate_chain_file: impl Into<PathBuf>,
        private_key_file: impl Into<PathBuf>,
    ) -> anyhow::Result<Self> {
        let cert_file_reader: FileReader<Vec<CertificateDer<'_>>> =
            FileReader::new(certificate_chain_file, Format::PEM);
        let cert_chain = cert_file_reader.read_certs().await?;

        let key_file_reader: FileReader<PrivateKeyDer<'_>> =
            FileReader::new(private_key_file, Format::PEM);
        let key_der = key_file_reader.read_key().await?;

        self.certificate_chain = cert_chain.into();
        self.private_key = key_der.into();
        Ok(self)
    }

    /// Loads client authentication certificates and private key from PEM strings.
    ///
    /// This is the in-memory equivalent of [`with_client_auth_cert_files`](Self::with_client_auth_cert_files)
    /// — useful when certificate/key data comes from a YANG configuration file
    /// rather than the filesystem.
    ///
    /// # Arguments
    ///
    /// * `cert_pem` - PEM-encoded certificate chain
    /// * `key_pem` - PEM-encoded private key
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM data cannot be parsed as valid certificates
    /// or a private key.
    pub fn with_client_auth_cert_pem(
        mut self,
        cert_pem: &str,
        key_pem: &str,
    ) -> anyhow::Result<Self> {
        let cert_chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("failed to parse certificate PEM: {e}"))?;

        if cert_chain.is_empty() {
            anyhow::bail!("no certificates found in PEM data");
        }

        let key_der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to parse private key PEM: {e}"))?;

        self.certificate_chain = Some(cert_chain);
        self.private_key = Some(key_der);
        Ok(self)
    }

    /// Sets client authentication from pre-parsed DER certificate chain and
    /// private key.
    ///
    /// This is the preferred path when the YANG `private-key-format` identity
    /// is known, since the caller can decode and wrap the DER bytes into the
    /// correct [`PrivateKeyDer`] variant directly.
    #[must_use]
    pub fn with_client_auth_der(
        mut self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Self {
        self.certificate_chain = Some(cert_chain);
        self.private_key = Some(key_der);
        self
    }

    /// Disables certificate verification.
    ///
    /// # Warning
    ///
    /// This is dangerous and should only be used for testing or in controlled environments.
    /// Using this in production exposes you to man-in-the-middle attacks.
    #[must_use]
    pub const fn with_certificate_verification_disabled(mut self, disabled: bool) -> Self {
        self.disable_certificate_verification = disabled;
        self
    }

    /// Builds the TLS client configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A certificate chain is provided without a private key
    /// - The client authentication configuration is invalid
    pub fn build(self) -> anyhow::Result<rustls::ClientConfig> {
        let supported_tls_versions = vec![&rustls::version::TLS13];

        let config =
            rustls::ClientConfig::builder_with_protocol_versions(supported_tls_versions.as_slice())
                .with_root_certificates(self.root_cert_store);

        let mut config = match self.certificate_chain {
            Some(cert_chain) => match self.private_key {
                Some(key_der) => config.with_client_auth_cert(cert_chain, key_der)?,
                None => {
                    return Err(anyhow::Error::msg("Private key not provided"));
                }
            },
            None => config.with_no_client_auth(),
        };

        if !self.resumption_enabled {
            config.resumption = config
                .resumption
                .tls12_resumption(rustls::client::Tls12Resumption::Disabled);
        }

        if self.disable_certificate_verification {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                )));
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::TlsConfigurationBuilder;

    fn sample_path(file_name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("samples")
            .join(file_name)
    }

    #[test]
    fn with_client_auth_cert_pem_accepts_valid_pem() {
        let cert_pem = fs::read_to_string(sample_path("client.crt")).expect("sample cert exists");
        let key_pem = fs::read_to_string(sample_path("client.key")).expect("sample key exists");

        let config = TlsConfigurationBuilder::new()
            .with_client_auth_cert_pem(&cert_pem, &key_pem)
            .and_then(TlsConfigurationBuilder::build);

        assert!(config.is_ok(), "unexpected error: {config:?}");
    }

    #[test]
    fn with_client_auth_cert_pem_rejects_invalid_pem() {
        let invalid_cert_pem =
            "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n";
        let invalid_key_pem =
            "-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----\n";
        let err = TlsConfigurationBuilder::new()
            .with_client_auth_cert_pem(invalid_cert_pem, invalid_key_pem)
            .err()
            .expect("invalid PEM should fail");

        assert!(
            err.to_string().contains("failed to parse certificate PEM"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn with_client_auth_cert_pem_rejects_empty_certificate_pem() {
        let key_pem = fs::read_to_string(sample_path("client.key")).expect("sample key exists");

        let err = TlsConfigurationBuilder::new()
            .with_client_auth_cert_pem("", &key_pem)
            .err()
            .expect("empty PEM should fail");

        assert!(
            err.to_string()
                .contains("no certificates found in PEM data"),
            "unexpected error: {err}",
        );
    }
}
