use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::{X509, X509VerifyResult, X509StoreContext, X509PurposeId};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;

use super::CertificateValidity;

pub(crate) type PeerValidityIndex =
    openssl::ex_data::Index<openssl::ssl::Ssl, std::sync::Mutex<Option<CertificateValidity>>>;

fn peer_validity_index() -> Result<PeerValidityIndex, openssl::error::ErrorStack> {
    static INDEX: std::sync::OnceLock<Result<PeerValidityIndex, openssl::error::ErrorStack>> =
        std::sync::OnceLock::new();
    INDEX
        .get_or_init(openssl::ssl::Ssl::new_ex_index)
        .as_ref()
        .copied()
        .map_err(Clone::clone)
}

pub(crate) struct PreparedTlsContext {
    pub(crate) context: SslContext,
    pub(crate) validity: Option<CertificateValidity>,
    pub(crate) peer_validity_index: PeerValidityIndex,
}

impl std::fmt::Debug for PreparedTlsContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedTlsContext")
            .field("validity", &self.validity)
            .finish_non_exhaustive()
    }
}

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
    pub(crate) fn build(self) -> anyhow::Result<PreparedTlsContext> {
        let mut builder = SslContext::builder(SslMethod::tls_client())?;
        let peer_validity_index = peer_validity_index()?;

        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        super::revocation::configure_verifier(&mut builder)?;

        if self.disable_certificate_verification {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER);
            if let Some(authorities) = self.root_certificates {
                configure_certificate_trust(
                    &mut builder,
                    authorities,
                    self.end_entity_certificates,
                    peer_validity_index,
                )?;
            } else {
                builder.set_default_verify_paths()?;
                let ssl_index = X509StoreContext::ssl_idx()?;
                builder.set_verify_callback(SslVerifyMode::PEER, move |verified, context| {
                    if !verified || context.error_depth() != 0 {
                        return verified;
                    }
                    let accepted = context.ex_data(ssl_index).is_some_and(|ssl| {
                        super::revocation::crls::verify(ssl, context.chain()).is_ok()
                    });
                    if !accepted {
                        context.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
                    }
                    accepted
                });
            }
        }

        let mut validity: Option<CertificateValidity> = None;
        if let Some(mut cert_chain) = self.certificate_chain {
            let Some(key) = self.private_key else {
                anyhow::bail!("Client private key was not provided");
            };
            if cert_chain.is_empty() {
                anyhow::bail!("Client certificate chain was not provided");
            }
            validate_client_chain(&cert_chain)?;

            for certificate in &cert_chain {
                let current = CertificateValidity::from_certificate(certificate)?;
                validity = Some(match validity {
                    Some(previous) => previous.intersect(current)?,
                    None => current,
                });
            }

            let leaf = cert_chain.remove(0);
            builder.set_certificate(&leaf)?;
            for cert in cert_chain {
                builder.add_extra_chain_cert(cert)?;
            }
            builder.set_private_key(&key)?;
            builder.check_private_key()?;
        }

        anyhow::ensure!(
            validity.is_none_or(|bounds| bounds.is_valid_at(std::time::SystemTime::now())),
            "Client certificate validity excludes the current time"
        );
        Ok(PreparedTlsContext {
            context: builder.build(),
            validity,
            peer_validity_index,
        })
    }
}

fn validate_client_chain(chain: &[X509]) -> anyhow::Result<()> {
    if chain.len() < 2 {
        return Ok(());
    }
    let mut seen = std::collections::BTreeSet::new();
    for certificate in chain {
        anyhow::ensure!(
            seen.insert(certificate.to_der()?),
            "Client certificate chain contains duplicate certificates"
        );
    }
    for pair in chain.windows(2) {
        let issuer = &pair[1];
        anyhow::ensure!(
            issuer.issued(&pair[0]) == X509VerifyResult::OK,
            "Client intermediate certificates must follow issuer order"
        );
        let public_key = issuer.public_key()?;
        anyhow::ensure!(
            issuer.subject_name().try_cmp(issuer.issuer_name())? != std::cmp::Ordering::Equal
                || !issuer.verify(&public_key)?,
            "Client intermediate certificates must not include a self-signed root"
        );
    }
    let mut store = X509StoreBuilder::new()?;
    store.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
    store.set_purpose(X509PurposeId::SSL_CLIENT)?;
    let anchor = chain
        .last()
        .ok_or_else(|| anyhow::anyhow!("Client certificate chain is empty"))?;
    store.add_cert(anchor.clone())?;
    let store = store.build();
    let mut untrusted = openssl::stack::Stack::new()?;
    for certificate in chain.iter().skip(1).take(chain.len() - 2) {
        untrusted.push(certificate.clone())?;
    }
    let mut verification = X509StoreContext::new()?;
    anyhow::ensure!(
        verification.init(
            &store,
            &chain[0],
            &untrusted,
            openssl::x509::X509StoreContextRef::verify_cert
        )?,
        "Client certificate chain failed native validation"
    );
    Ok(())
}

fn configure_certificate_trust(
    builder: &mut SslContextBuilder,
    authorities: Vec<X509>,
    end_entities: Vec<X509>,
    peer_validity_index: PeerValidityIndex,
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
        let selected = if exact_peer {
            context
                .current_cert()
                .and_then(|certificate| CertificateValidity::from_certificate(certificate).ok())
        } else if authority_path {
            context
                .chain()
                .and_then(|chain| CertificateValidity::from_chain(chain).ok())
        } else {
            authority_store.as_ref().and_then(|store| {
                let certificate = context.current_cert()?;
                let ssl = context.ex_data(ssl_index)?;
                let chain = ssl.peer_cert_chain()?;
                X509StoreContext::new()
                    .and_then(|mut verification| {
                        verification.init(store, certificate, chain, |verified| {
                            if !verified.verify_cert()? {
                                return Ok(None);
                            }
                            Ok(verified
                                .chain()
                                .and_then(|chain| CertificateValidity::from_chain(chain).ok()))
                        })
                    })
                    .ok()
                    .flatten()
            })
        };
        if let Some(validity) = selected {
            if context
                .ex_data(ssl_index)
                .is_some_and(|ssl| super::revocation::crls::verify(ssl, context.chain()).is_err())
            {
                context.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
                return false;
            }
            if let Some(slot) = context
                .ex_data(ssl_index)
                .and_then(|ssl| ssl.ex_data(peer_validity_index))
            {
                *slot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(validity);
                return true;
            }
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
    fn client_identity_outside_validity_is_rejected_even_without_peer_verification() {
        let (chain, key) = sample_client_auth_der();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (start, end) in [(now - 120, now - 60), (now + 60, now + 120)] {
            let mut certificate = X509::builder().unwrap();
            certificate.set_version(2).unwrap();
            certificate
                .set_subject_name(chain[0].subject_name())
                .unwrap();
            certificate
                .set_issuer_name(chain[0].subject_name())
                .unwrap();
            certificate.set_pubkey(&key).unwrap();
            certificate
                .set_not_before(
                    &openssl::asn1::Asn1Time::from_unix(start.try_into().unwrap()).unwrap(),
                )
                .unwrap();
            certificate
                .set_not_after(
                    &openssl::asn1::Asn1Time::from_unix(end.try_into().unwrap()).unwrap(),
                )
                .unwrap();
            certificate
                .sign(&key, openssl::hash::MessageDigest::sha256())
                .unwrap();
            let certificate = certificate.build();
            for insecure in [false, true] {
                assert!(
                    TlsConfigurationBuilder::new()
                        .with_client_auth_der(vec![certificate.clone()], key.clone())
                        .with_certificate_verification_disabled(insecure)
                        .build()
                        .is_err(),
                    "invalid local identity must fail during preparation"
                );
            }
        }
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
