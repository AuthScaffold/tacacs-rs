use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::{X509, X509VerifyResult, X509StoreContext, X509PurposeId};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;

/// Builds a native context from validated certificate and key objects.
pub(crate) struct TlsConfigurationBuilder {
    root_certificates: Option<Vec<X509>>,
    end_entity_certificates: Vec<X509>,
    certificate_chain: Option<Vec<X509>>,
    private_key: Option<PKey<Private>>,
    disable_certificate_verification: bool,
}

impl TlsConfigurationBuilder {
    /// Creates a builder with OpenSSL's default trust paths and no
    /// client authentication.
    pub(crate) fn new() -> Self {
        Self {
            root_certificates: None,
            end_entity_certificates: Vec::new(),
            certificate_chain: None,
            private_key: None,
            disable_certificate_verification: false,
        }
    }

    /// Selects explicit trust anchors and exact peer certificates.
    pub(crate) fn with_certificate_trust(
        mut self,
        authorities: Vec<X509>,
        end_entities: Vec<X509>,
    ) -> Self {
        self.root_certificates = Some(authorities);
        self.end_entity_certificates = end_entities;
        self
    }

    /// Sets the client authentication certificate chain and private key,
    /// already decoded into OpenSSL certificate and key objects.
    pub(crate) fn with_client_auth_der(
        mut self,
        cert_chain: Vec<X509>,
        key: PKey<Private>,
    ) -> Self {
        self.certificate_chain = Some(cert_chain);
        self.private_key = Some(key);
        self
    }

    /// Disables certificate verification.
    ///
    /// This option is dangerous. Use it only for CLI `--insecure` options and
    /// controlled tests.
    pub(crate) const fn with_certificate_verification_disabled(mut self, disabled: bool) -> Self {
        self.disable_certificate_verification = disabled;
        self
    }

    /// Builds the OpenSSL client context.
    ///
    /// # Errors
    ///
    /// Returns an error if a certificate chain was provided without a private
    /// key, or if OpenSSL rejects the supplied TLS material.
    pub(crate) fn build(self) -> anyhow::Result<SslContext> {
        let mut builder = SslContext::builder(SslMethod::tls_client())?;

        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        if self.disable_certificate_verification {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER);
            if let Some(authorities) = self.root_certificates {
                configure_certificate_trust(
                    &mut builder,
                    authorities,
                    self.end_entity_certificates,
                )?;
            } else {
                builder.set_default_verify_paths()?;
            }
        }

        if let Some(mut cert_chain) = self.certificate_chain {
            let Some(key) = self.private_key else {
                anyhow::bail!("Client private key was not provided");
            };
            if cert_chain.is_empty() {
                anyhow::bail!("Client certificate chain was not provided");
            }

            let leaf = cert_chain.remove(0);
            builder.set_certificate(&leaf)?;
            for cert in cert_chain {
                builder.add_extra_chain_cert(cert)?;
            }
            builder.set_private_key(&key)?;
            builder.check_private_key()?;
        }

        Ok(builder.build())
    }
}

fn configure_certificate_trust(
    builder: &mut SslContextBuilder,
    authorities: Vec<X509>,
    end_entities: Vec<X509>,
) -> anyhow::Result<()> {
    let authority_der = authorities
        .iter()
        .map(|certificate| certificate.to_der())
        .collect::<Result<Vec<_>, _>>()?;
    let peer_der = end_entities
        .iter()
        .map(|certificate| certificate.to_der())
        .collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(
        !authority_der.is_empty() || !peer_der.is_empty(),
        "Explicit certificate trust must contain certificates"
    );
    let authority_store = if !authorities.is_empty() && !peer_der.is_empty() {
        let mut store = X509StoreBuilder::new()?;
        store.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
        store.set_purpose(X509PurposeId::SSL_SERVER)?;
        for authority in &authorities {
            store.add_cert(authority.clone())?;
        }
        Some(store.build())
    } else {
        None
    };
    let store = builder.cert_store_mut();
    store.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
    for cert in authorities.into_iter().chain(end_entities) {
        store.add_cert(cert)?;
    }
    let ssl_index = X509StoreContext::ssl_idx()?;
    builder.set_verify_callback(SslVerifyMode::PEER, move |verified, context| {
        if !verified {
            return false;
        }
        if context.error_depth() != 0 {
            return true;
        }
        let exact_peer = context.current_cert().is_some_and(|certificate| {
            certificate
                .to_der()
                .is_ok_and(|der| peer_der.contains(&der))
        });
        let authority_path = context
            .chain()
            .and_then(|chain| chain.iter().next_back())
            .is_some_and(|anchor| {
                anchor
                    .to_der()
                    .is_ok_and(|der| authority_der.contains(&der))
            });
        if exact_peer || authority_path {
            return true;
        }
        let alternate_authority_path = authority_store.as_ref().is_some_and(|store| {
            let Some(certificate) = context.current_cert() else {
                return false;
            };
            let Some(ssl) = context.ex_data(ssl_index) else {
                return false;
            };
            let Some(chain) = ssl.peer_cert_chain() else {
                return false;
            };
            X509StoreContext::new()
                .and_then(|mut verification| {
                    verification.init(
                        store,
                        certificate,
                        chain,
                        openssl::x509::X509StoreContextRef::verify_cert,
                    )
                })
                .unwrap_or(false)
        });
        if alternate_authority_path {
            return true;
        }
        context.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
        false
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use openssl::pkey::{PKey, Private};
    use openssl::x509::X509;

    use super::TlsConfigurationBuilder;

    fn sample_path(file_name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("lde/containers/config/certificates")
            .join(file_name)
    }

    fn sample_client_auth_der() -> (Vec<X509>, PKey<Private>) {
        let cert_pem =
            fs::read_to_string(sample_path("client.crt")).expect("sample certificate must exist");
        let key_pem = fs::read_to_string(sample_path("client.key")).expect("sample key must exist");

        let cert_chain =
            X509::stack_from_pem(cert_pem.as_bytes()).expect("sample certificate PEM must parse");
        let key_der =
            PKey::private_key_from_pem(key_pem.as_bytes()).expect("sample key PEM must parse");

        (cert_chain, key_der)
    }

    #[test]
    fn with_client_auth_der_accepts_valid_der() {
        let (cert_chain, key_der) = sample_client_auth_der();

        let config = TlsConfigurationBuilder::new()
            .with_client_auth_der(cert_chain, key_der)
            .build();

        assert!(config.is_ok(), "unexpected error: {config:?}");
    }

    #[test]
    fn build_without_client_auth_succeeds() {
        let config = TlsConfigurationBuilder::new().build();
        assert!(config.is_ok(), "unexpected error: {config:?}");
    }

    #[test]
    fn build_with_disabled_verification_succeeds() {
        let config = TlsConfigurationBuilder::new()
            .with_certificate_verification_disabled(true)
            .build();
        assert!(config.is_ok(), "unexpected error: {config:?}");
    }
}
