use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
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
    /// * `certificate_chain_file` - Path to the DER-encoded certificate file
    /// * `private_key_file` - Path to the PKCS#8 DER-encoded private key file
    /// # Errors
    ///
    /// Returns an error if:
    /// - A certificate chain is provided without a private key
    /// - The TLS certificate/key files cannot be read
    /// - Either file contains PEM text instead of DER bytes
    pub async fn with_client_auth_cert_files(
        mut self,
        certificate_chain_file: impl Into<PathBuf>,
        private_key_file: impl Into<PathBuf>,
    ) -> anyhow::Result<Self> {
        let cert_der = tokio::fs::read(certificate_chain_file.into())
            .await
            .context("failed to read client certificate file")?;
        reject_pem_input(&cert_der, "certificate")?;

        let key_der = tokio::fs::read(private_key_file.into())
            .await
            .context("failed to read client private key file")?;
        reject_pem_input(&key_der, "private key")?;

        self.certificate_chain = Some(vec![CertificateDer::from(cert_der)]);
        self.private_key =
            Some(PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(key_der)));
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

fn reject_pem_input(data: &[u8], label: &str) -> anyhow::Result<()> {
    if data.starts_with(b"-----BEGIN") {
        anyhow::bail!("PEM-encoded {label} data is not supported; provide DER bytes");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    use super::TlsConfigurationBuilder;

    fn sample_path(file_name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("samples")
            .join(file_name)
    }

    fn sample_client_auth_der() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let cert_pem = fs::read_to_string(sample_path("client.crt")).expect("sample cert exists");
        let key_pem = fs::read_to_string(sample_path("client.key")).expect("sample key exists");

        let cert_chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("sample cert PEM should parse");
        let key_der =
            PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("sample key PEM should parse");

        (cert_chain, key_der)
    }

    fn temp_path(suffix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("tls-builder-test-{unique}.{suffix}"))
    }

    #[test]
    fn with_client_auth_der_accepts_valid_der() {
        let (cert_chain, key_der) = sample_client_auth_der();

        let config = TlsConfigurationBuilder::new()
            .with_client_auth_der(cert_chain, key_der)
            .build();

        assert!(config.is_ok(), "unexpected error: {config:?}");
    }

    #[tokio::test]
    async fn with_client_auth_cert_files_accepts_valid_der() {
        let (cert_chain, key_der) = sample_client_auth_der();
        let cert_path = temp_path("crt.der");
        let key_path = temp_path("key.der");

        fs::write(&cert_path, cert_chain[0].as_ref()).expect("cert temp file should be written");
        fs::write(&key_path, key_der.secret_der()).expect("key temp file should be written");

        let config = TlsConfigurationBuilder::new()
            .with_client_auth_cert_files(&cert_path, &key_path)
            .await
            .and_then(TlsConfigurationBuilder::build);

        fs::remove_file(&cert_path).ok();
        fs::remove_file(&key_path).ok();

        assert!(config.is_ok(), "unexpected error: {config:?}");
    }

    #[tokio::test]
    async fn with_client_auth_cert_files_rejects_pem_input() {
        let err = TlsConfigurationBuilder::new()
            .with_client_auth_cert_files(sample_path("client.crt"), sample_path("client.key"))
            .await
            .err()
            .expect("PEM input should fail");

        assert!(
            err.to_string()
                .contains("PEM-encoded certificate data is not supported; provide DER bytes"),
            "unexpected error: {err}",
        );
    }
}
