use std::{path::PathBuf, sync::Arc};

use rustls_cert_file_reader::{FileReader, Format, ReadCerts, ReadKey};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
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
/// use tacacsrs_networking::tls::TlsConfigurationBuilder;
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
    pub fn new() -> Self {
        Self {
            root_cert_store: rustls::RootCertStore::empty(),
            resumption_enabled: false,
            certificate_chain: None,
            private_key: None,
            disable_certificate_verification: false,
        }
    }

    /// Sets the root certificate store for verifying server certificates.
    pub fn with_root_certificates(mut self, root_cert_store: rustls::RootCertStore) -> Self {
        self.root_cert_store = root_cert_store;
        self
    }

    /// Enables or disables TLS session resumption.
    pub fn with_resumption(mut self, enabled: bool) -> Self {
        self.resumption_enabled = enabled;
        self
    }

    /// Loads client authentication certificates and private key from files.
    ///
    /// # Arguments
    ///
    /// * `certificate_chain_file` - Path to the PEM-encoded certificate chain file
    /// * `private_key_file` - Path to the PEM-encoded private key file
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

    /// Disables certificate verification.
    ///
    /// # Warning
    ///
    /// This is dangerous and should only be used for testing or in controlled environments.
    /// Using this in production exposes you to man-in-the-middle attacks.
    pub fn with_certificate_verification_disabled(mut self, disabled: bool) -> Self {
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
            config.dangerous().set_certificate_verifier(Arc::new(
                NoCertificateVerification::new(rustls::crypto::aws_lc_rs::default_provider()),
            ));
        }

        Ok(config)
    }
}
