use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::{X509, X509VerifyResult, X509StoreContext, X509PurposeId};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;

/// Builds a native context from validated certificate and key objects.
pub(crate) struct TlsConfigurationBuilder {
    root_certificates: Option<Vec<(X509, crate::preparation_payload::PayloadBytes)>>,
    end_entity_certificates: Vec<(X509, crate::preparation_payload::PayloadBytes)>,
    certificate_chain: Option<Vec<(X509, usize)>>,
    private_key: Option<PKey<Private>>,
    disable_certificate_verification: bool,
    payload: crate::PreparationPayload,
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
            payload: crate::PreparationPayload::default(),
        }
    }

    pub(crate) fn with_payload(mut self, payload: crate::PreparationPayload) -> Self {
        self.payload = payload;
        self
    }

    /// Selects explicit trust anchors and exact peer certificates.
    pub(crate) fn with_certificate_trust(
        mut self,
        authorities: Vec<(X509, crate::preparation_payload::PayloadBytes)>,
        end_entities: Vec<(X509, crate::preparation_payload::PayloadBytes)>,
    ) -> Self {
        self.root_certificates = Some(authorities);
        self.end_entity_certificates = end_entities;
        self
    }

    /// Sets the client authentication certificate chain and private key,
    /// already decoded into OpenSSL certificate and key objects.
    pub(crate) fn with_client_auth_der(
        mut self,
        cert_chain: Vec<(X509, usize)>,
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
        let has_extra_chain = self
            .certificate_chain
            .as_ref()
            .is_some_and(|chain| chain.len() > 1);

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

        if let Some(mut cert_chain) = self.certificate_chain {
            let Some(key) = self.private_key else {
                anyhow::bail!("Client private key was not provided");
            };
            if cert_chain.is_empty() {
                anyhow::bail!("Client certificate chain was not provided");
            }
            validate_client_chain(&cert_chain, &self.payload)?;

            let (leaf, _) = cert_chain.remove(0);
            builder.set_certificate(&leaf)?;
            for (cert, _) in cert_chain {
                builder.add_extra_chain_cert(cert)?;
            }
            builder.set_private_key(&key)?;
            builder.check_private_key()?;
        }

        let context = builder.build();
        validate_client_certificate_dates(&context, has_extra_chain)?;
        Ok(context)
    }
}

pub(super) fn validate_client_certificate_dates(
    context: &SslContext,
    has_extra_chain: bool,
) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now();
    let validate = |certificate: &openssl::x509::X509Ref| -> anyhow::Result<()> {
        let valid_from = super::validity::system_time(certificate.not_before())?;
        let valid_until = super::validity::system_time(certificate.not_after())?;
        anyhow::ensure!(
            valid_from <= now && now < valid_until,
            "Client certificate validity excludes the current time"
        );
        Ok(())
    };
    if let Some(certificate) = context.certificate() {
        validate(certificate)?;
    }
    if has_extra_chain {
        for certificate in context.extra_chain_certs() {
            validate(certificate)?;
        }
    }
    Ok(())
}

fn validate_client_chain(
    chain: &[(X509, usize)],
    payload: &crate::PreparationPayload,
) -> anyhow::Result<()> {
    if chain.len() < 2 {
        return Ok(());
    }
    #[expect(
        clippy::mutable_key_type,
        reason = "Only immutable DER bytes determine ordering. Accounting guards do not affect keys."
    )]
    let mut seen = std::collections::BTreeSet::new();
    for (certificate, encoded_bytes) in chain {
        let encoded = payload.native_bytes(*encoded_bytes, || certificate.to_der())?;
        anyhow::ensure!(
            seen.insert(encoded),
            "Client certificate chain contains duplicate certificates"
        );
    }
    for pair in chain.windows(2) {
        let issuer = &pair[1].0;
        anyhow::ensure!(
            issuer.issued(&pair[0].0) == X509VerifyResult::OK,
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
    store.add_cert(anchor.0.clone())?;
    let store = store.build();
    let mut untrusted = openssl::stack::Stack::new()?;
    for (certificate, _) in chain.iter().skip(1).take(chain.len() - 2) {
        untrusted.push(certificate.clone())?;
    }
    let mut verification = X509StoreContext::new()?;
    anyhow::ensure!(
        verification.init(
            &store,
            &chain[0].0,
            &untrusted,
            openssl::x509::X509StoreContextRef::verify_cert
        )?,
        "Client certificate chain failed native validation"
    );
    Ok(())
}

fn configure_certificate_trust(
    builder: &mut SslContextBuilder,
    authorities: Vec<(X509, crate::preparation_payload::PayloadBytes)>,
    end_entities: Vec<(X509, crate::preparation_payload::PayloadBytes)>,
) -> anyhow::Result<()> {
    let (authorities, authority_der): (Vec<_>, Vec<_>) = authorities.into_iter().unzip();
    let (end_entities, peer_der): (Vec<_>, Vec<_>) = end_entities.into_iter().unzip();
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
                .is_ok_and(|der| peer_der.iter().any(|pin| pin.as_slice() == der))
        });
        let authority_path = context
            .chain()
            .and_then(|chain| chain.iter().next_back())
            .is_some_and(|anchor| {
                anchor
                    .to_der()
                    .is_ok_and(|der| authority_der.iter().any(|pin| pin.as_slice() == der))
            });
        let accepted = if exact_peer || authority_path {
            true
        } else {
            authority_store
                .as_ref()
                .and_then(|store| {
                    let certificate = context.current_cert()?;
                    let ssl = context.ex_data(ssl_index)?;
                    let chain = ssl.peer_cert_chain()?;
                    X509StoreContext::new()
                        .and_then(|mut verification| {
                            verification
                                .init(store, certificate, chain, |verified| verified.verify_cert())
                        })
                        .ok()
                })
                .unwrap_or(false)
        };
        if accepted {
            if context
                .ex_data(ssl_index)
                .is_some_and(|ssl| super::revocation::crls::verify(ssl, context.chain()).is_err())
            {
                context.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
                return false;
            }
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
            .with_client_auth_der(
                cert_chain
                    .into_iter()
                    .map(|certificate| {
                        let bytes = certificate.to_der().unwrap().len();
                        (certificate, bytes)
                    })
                    .collect(),
                key_der,
            )
            .build();

        assert!(config.is_ok(), "unexpected error: {config:?}");
    }

    #[test]
    fn client_chain_duplicate_lookup_is_subquadratic_and_accounted() {
        use std::sync::{Arc, Mutex};

        use crate::preparation_payload::PayloadBytes;
        use crate::{PreparationPayload, PreparationPayloadLedger};

        #[derive(Debug)]
        struct Ledger {
            limit: u64,
            counts: Mutex<(u64, u64)>,
        }

        impl PreparationPayloadLedger for Ledger {
            fn reserve(&self, bytes: u64) -> anyhow::Result<()> {
                let mut counts = self.counts.lock().unwrap();
                let next = counts.0.checked_add(bytes).unwrap();
                anyhow::ensure!(next <= self.limit, "comparison payload limit");
                counts.0 = next;
                counts.1 = counts.1.max(next);
                Ok(())
            }

            fn release(&self, bytes: u64) {
                let mut counts = self.counts.lock().unwrap();
                counts.0 = counts.0.checked_sub(bytes).unwrap();
            }
        }

        let (sample, key) = sample_client_auth_der();
        let mut measurements = Vec::new();
        for count in [64, 256] {
            let chain = (1..=count)
                .map(|serial| {
                    let mut certificate = X509::builder().unwrap();
                    certificate.set_version(2).unwrap();
                    certificate
                        .set_serial_number(
                            &openssl::bn::BigNum::from_u32(serial)
                                .unwrap()
                                .to_asn1_integer()
                                .unwrap(),
                        )
                        .unwrap();
                    certificate
                        .set_subject_name(sample[0].subject_name())
                        .unwrap();
                    certificate
                        .set_issuer_name(sample[0].issuer_name())
                        .unwrap();
                    certificate.set_pubkey(&key).unwrap();
                    certificate.set_not_before(sample[0].not_before()).unwrap();
                    certificate.set_not_after(sample[0].not_after()).unwrap();
                    certificate
                        .sign(&key, openssl::hash::MessageDigest::sha256())
                        .unwrap();
                    let certificate = certificate.build();
                    let bytes = certificate.to_der().unwrap().len();
                    (certificate, bytes)
                })
                .collect::<Vec<_>>();
            let bytes = chain.iter().map(|(_, bytes)| *bytes as u64).sum::<u64>();
            for limit in [bytes - 1, bytes] {
                let ledger = Arc::new(Ledger {
                    limit,
                    counts: Mutex::new((0, 0)),
                });
                let payload = PreparationPayload::new(ledger.clone());
                let before = PayloadBytes::comparison_count();
                let error = super::validate_client_chain(&chain, &payload).unwrap_err();
                let comparisons = PayloadBytes::comparison_count() - before;
                assert_eq!(payload.retained_bytes(), 0);
                let (live, peak) = *ledger.counts.lock().unwrap();
                assert_eq!(live, 0, "all comparison owners must release their reservations");
                if limit == bytes {
                    assert_eq!(peak, bytes, "deduplication must charge all live DER owners");
                    assert!(error.to_string().contains("issuer order"));
                    measurements.push(comparisons);
                } else {
                    assert!(error.to_string().contains("comparison payload limit"));
                    assert!(peak < bytes);
                }
            }
            let mut duplicated = chain.clone();
            duplicated.push(chain[chain.len() / 2].clone());
            let duplicated_bytes = bytes + chain[chain.len() / 2].1 as u64;
            let ledger = Arc::new(Ledger {
                limit: duplicated_bytes,
                counts: Mutex::new((0, 0)),
            });
            let payload = PreparationPayload::new(ledger.clone());
            let error = super::validate_client_chain(&duplicated, &payload).unwrap_err();
            assert!(error.to_string().contains("duplicate certificates"));
            assert_eq!(payload.retained_bytes(), 0);
            assert_eq!(
                *ledger.counts.lock().unwrap(),
                (0, duplicated_bytes),
                "the duplicate must be charged before lookup and released after rejection"
            );
        }
        println!("DER comparisons for 64 and 256 certificates: {measurements:?}");
        assert!(
            measurements[1] < measurements[0] * 8,
            "four times as many certificates must need less than eight times as many comparisons"
        );
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
                        .with_client_auth_der(
                            vec![(certificate.clone(), certificate.to_der().unwrap().len())],
                            key.clone()
                        )
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
