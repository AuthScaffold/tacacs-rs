use std::sync::Arc;

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls;

use super::danger::NoCertificateVerification;

/// Internal builder used by [`super::establish_from_server`] to assemble a
/// [`rustls::ClientConfig`] from configuration material that has already been
/// extracted from a [`tacacsrs_config::TacacsPlusServer`].
///
/// This type is intentionally **not** part of the public API: all callers must
/// drive TLS connection construction through
/// [`crate::config_connect::establish_stream`], which guarantees that the YANG
/// configuration model is the single source of truth for transport parameters.
pub(crate) struct TlsConfigurationBuilder {
    root_cert_store: rustls::RootCertStore,
    certificate_chain: Option<Vec<CertificateDer<'static>>>,
    private_key: Option<PrivateKeyDer<'static>>,
    disable_certificate_verification: bool,
}

impl TlsConfigurationBuilder {
    /// Creates a new builder seeded with the default web PKI root store and no
    /// client authentication.
    pub(crate) fn new() -> Self {
        Self {
            root_cert_store: crate::helpers::default_root_cert_store(),
            certificate_chain: None,
            private_key: None,
            disable_certificate_verification: false,
        }
    }

    /// Replaces the trust anchors used to verify the server certificate.
    pub(crate) fn with_root_certificates(mut self, root_cert_store: rustls::RootCertStore) -> Self {
        self.root_cert_store = root_cert_store;
        self
    }

    /// Sets the client authentication certificate chain and private key,
    /// already decoded into the appropriate `rustls` DER variants.
    pub(crate) fn with_client_auth_der(
        mut self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Self {
        self.certificate_chain = Some(cert_chain);
        self.private_key = Some(key_der);
        self
    }

    /// Disables certificate verification. Dangerous; only intended for the
    /// CLI's `--insecure` style flags and tightly controlled test setups.
    pub(crate) const fn with_certificate_verification_disabled(mut self, disabled: bool) -> Self {
        self.disable_certificate_verification = disabled;
        self
    }

    /// Builds the `rustls` client configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if a certificate chain was provided without a private
    /// key, or if `rustls` rejects the supplied client authentication
    /// material.
    pub(crate) fn build(self) -> anyhow::Result<rustls::ClientConfig> {
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

        // TLS 1.2 session resumption is unconditionally disabled because the
        // workspace only negotiates TLS 1.3.
        config.resumption = config
            .resumption
            .tls12_resumption(rustls::client::Tls12Resumption::Disabled);

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

    #[test]
    #[cfg_attr(miri, ignore)] // aws-lc-rs FFI in ClientConfig crypto provider
    fn with_client_auth_der_accepts_valid_der() {
        let (cert_chain, key_der) = sample_client_auth_der();

        let config = TlsConfigurationBuilder::new()
            .with_client_auth_der(cert_chain, key_der)
            .build();

        assert!(config.is_ok(), "unexpected error: {config:?}");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // aws-lc-rs FFI in ClientConfig crypto provider
    fn build_without_client_auth_succeeds() {
        let config = TlsConfigurationBuilder::new().build();
        assert!(config.is_ok(), "unexpected error: {config:?}");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // aws-lc-rs FFI in ClientConfig crypto provider
    fn build_with_disabled_verification_succeeds() {
        let config = TlsConfigurationBuilder::new()
            .with_certificate_verification_disabled(true)
            .build();
        assert!(config.is_ok(), "unexpected error: {config:?}");
    }
}
