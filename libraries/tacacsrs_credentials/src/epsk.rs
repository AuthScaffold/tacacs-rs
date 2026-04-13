use anyhow::{Context, Result};
use tacacsrs_config::Tls13Epsk;

use crate::{CredentialResolver, encode_symmetric_key_data};

pub(crate) fn resolve_epsk_keystore_ref(
    epsk: &mut Tls13Epsk,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ks_ref) = epsk.central_keystore_reference {
        let material = resolver
            .resolve_symmetric_key(ks_ref)
            .context("failed to resolve central-keystore-reference for tls13-epsk")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "credential resolver did not resolve keystore reference '{ks_ref}' for tls13-epsk"
                )
            })?;

        epsk.inline_definition = Some(tacacsrs_config::keystore::SymmetricKeyInlineDefinition {
            key_format: material.key_format,
            cleartext_symmetric_key: Some(encode_symmetric_key_data(&material.key_bytes)),
            hidden_symmetric_key: None,
            encrypted_symmetric_key: None,
        });
        epsk.central_keystore_reference = None;
    }
    Ok(())
}

pub(crate) fn validate_epsk_keystore_refs(
    ci: &tacacsrs_config::TlsClientClientIdentity,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref epsk) = ci.tls13_epsk {
        if let Some(ref ks_ref) = epsk.central_keystore_reference {
            if let Err(error) = resolver.validate_symmetric_key(ks_ref) {
                errors.push(format!(
                    "server '{server_name}': tls13-epsk central-keystore-reference: {error}",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tacacsrs_config::crypto_types::SymmetricKeyFormat;
    use tacacsrs_config::{
        EpskSupportedHash, TacacsPlusServer, TacacsPlusServerType, Tls13Epsk,
        TlsClientClientIdentity,
    };

    use super::{resolve_epsk_keystore_ref, validate_epsk_keystore_refs};
    use crate::{
        NamedCertificateDer, TlsClientCertificateMaterial, TlsClientCertificateReference,
        resolve_server, validate_external_server_references, AsymmetricKeyMaterial,
        CredentialResolver, SymmetricKeyMaterial, TruststorePublicKeyMaterial,
    };

    struct SymmetricResolver {
        resolved: Option<SymmetricKeyMaterial>,
        resolve_error: Option<&'static str>,
        validate_error: Option<&'static str>,
    }

    impl CredentialResolver for SymmetricResolver {
        fn resolve_tls_client_certificate(
            &self,
            _reference: &TlsClientCertificateReference,
        ) -> Result<Option<TlsClientCertificateMaterial>> {
            panic!("unexpected certificate lookup")
        }

        fn resolve_tls_server_ca_certificates(
            &self,
            _key: &str,
        ) -> Result<Option<Vec<NamedCertificateDer>>> {
            panic!("unexpected certificate bag lookup")
        }

        fn resolve_tls_server_ee_certificates(
            &self,
            _key: &str,
        ) -> Result<Option<Vec<NamedCertificateDer>>> {
            panic!("unexpected certificate bag lookup")
        }

        fn resolve_asymmetric_key(&self, _key: &str) -> Result<Option<AsymmetricKeyMaterial>> {
            panic!("unexpected asymmetric key lookup")
        }

        fn resolve_symmetric_key(&self, _key: &str) -> Result<Option<SymmetricKeyMaterial>> {
            if let Some(message) = self.resolve_error {
                return Err(anyhow::anyhow!(message));
            }
            Ok(self.resolved.clone())
        }

        fn resolve_public_key_bag(
            &self,
            _key: &str,
        ) -> Result<Option<Vec<TruststorePublicKeyMaterial>>> {
            panic!("unexpected public key bag lookup")
        }

        fn validate_tls_client_certificate(
            &self,
            _reference: &TlsClientCertificateReference,
        ) -> Result<()> {
            panic!("unexpected certificate validation")
        }

        fn validate_tls_server_ca_certificates(&self, _key: &str) -> Result<()> {
            panic!("unexpected certificate bag validation")
        }

        fn validate_tls_server_ee_certificates(&self, _key: &str) -> Result<()> {
            panic!("unexpected certificate bag validation")
        }

        fn validate_asymmetric_key(&self, _key: &str) -> Result<()> {
            panic!("unexpected asymmetric key validation")
        }

        fn validate_symmetric_key(&self, _key: &str) -> Result<()> {
            if let Some(message) = self.validate_error {
                return Err(anyhow::anyhow!(message));
            }
            Ok(())
        }

        fn validate_public_key_bag(&self, _key: &str) -> Result<()> {
            panic!("unexpected public key bag validation")
        }
    }

    struct PanicResolver;

    impl CredentialResolver for PanicResolver {
        fn resolve_tls_client_certificate(
            &self,
            _reference: &TlsClientCertificateReference,
        ) -> Result<Option<TlsClientCertificateMaterial>> {
            panic!("resolver should not be called")
        }

        fn resolve_tls_server_ca_certificates(
            &self,
            _key: &str,
        ) -> Result<Option<Vec<NamedCertificateDer>>> {
            panic!("resolver should not be called")
        }

        fn resolve_tls_server_ee_certificates(
            &self,
            _key: &str,
        ) -> Result<Option<Vec<NamedCertificateDer>>> {
            panic!("resolver should not be called")
        }

        fn resolve_asymmetric_key(&self, _key: &str) -> Result<Option<AsymmetricKeyMaterial>> {
            panic!("resolver should not be called")
        }

        fn resolve_symmetric_key(&self, _key: &str) -> Result<Option<SymmetricKeyMaterial>> {
            panic!("resolver should not be called")
        }

        fn resolve_public_key_bag(
            &self,
            _key: &str,
        ) -> Result<Option<Vec<TruststorePublicKeyMaterial>>> {
            panic!("resolver should not be called")
        }

        fn validate_tls_client_certificate(
            &self,
            _reference: &TlsClientCertificateReference,
        ) -> Result<()> {
            panic!("resolver should not be called")
        }

        fn validate_tls_server_ca_certificates(&self, _key: &str) -> Result<()> {
            panic!("resolver should not be called")
        }

        fn validate_tls_server_ee_certificates(&self, _key: &str) -> Result<()> {
            panic!("resolver should not be called")
        }

        fn validate_asymmetric_key(&self, _key: &str) -> Result<()> {
            panic!("resolver should not be called")
        }

        fn validate_symmetric_key(&self, _key: &str) -> Result<()> {
            panic!("resolver should not be called")
        }

        fn validate_public_key_bag(&self, _key: &str) -> Result<()> {
            panic!("resolver should not be called")
        }
    }

    fn epsk_keystore(reference: &str, external_identity: &str) -> Tls13Epsk {
        Tls13Epsk {
            inline_definition: None,
            central_keystore_reference: Some(reference.to_owned()),
            external_identity: external_identity.to_owned(),
            hash: EpskSupportedHash::Sha256,
            context: None,
            target_protocol: None,
            target_kdf: None,
        }
    }

    fn epsk_inline(secret: &[u8], external_identity: &str) -> Tls13Epsk {
        Tls13Epsk {
            inline_definition: Some(tacacsrs_config::keystore::SymmetricKeyInlineDefinition {
                key_format: None,
                cleartext_symmetric_key: Some(secret.to_vec()),
                hidden_symmetric_key: None,
                encrypted_symmetric_key: None,
            }),
            central_keystore_reference: None,
            external_identity: external_identity.to_owned(),
            hash: EpskSupportedHash::Sha256,
            context: None,
            target_protocol: None,
            target_kdf: None,
        }
    }

    fn client_identity_with_epsk(epsk: Tls13Epsk) -> TlsClientClientIdentity {
        TlsClientClientIdentity {
            credentials_reference: None,
            certificate: None,
            raw_private_key: None,
            tls13_epsk: Some(epsk),
        }
    }

    fn server_with_client_identity(
        name: &str,
        client_identity: TlsClientClientIdentity,
    ) -> TacacsPlusServer {
        TacacsPlusServer {
            name: name.to_owned(),
            server_type: TacacsPlusServerType::ACCOUNTING,
            address: "10.0.0.2".to_owned(),
            port: 49,
            domain_name: None,
            sni_enabled: None,
            single_connection: false,
            timeout: 5,
            source_ip: None,
            source_interface: None,
            shared_secret: None,
            client_identity: Some(client_identity),
            server_authentication: None,
            hello_params: None,
            vrf_instance: None,
        }
    }

    #[test]
    fn resolve_epsk_keystore_ref_populates_inline_definition() {
        let mut epsk = epsk_keystore("epsk-ref", "client@example.com");
        let resolver = SymmetricResolver {
            resolved: Some(SymmetricKeyMaterial {
                key_bytes: b"EPSK_SECRET".to_vec(),
                key_format: Some(SymmetricKeyFormat::OctetStringKeyFormat),
            }),
            resolve_error: None,
            validate_error: None,
        };

        resolve_epsk_keystore_ref(&mut epsk, &resolver).unwrap();

        assert!(epsk.central_keystore_reference.is_none());
        let inline = epsk.inline_definition.as_ref().unwrap();
        assert_eq!(inline.cleartext_symmetric_key.as_deref(), Some(b"EPSK_SECRET".as_slice()),);
        assert_eq!(inline.key_format, Some(SymmetricKeyFormat::OctetStringKeyFormat),);
    }

    #[test]
    fn resolve_epsk_keystore_ref_returns_unresolved_error() {
        let mut epsk = epsk_keystore("missing-epsk", "client@example.com");
        let resolver = SymmetricResolver {
            resolved: None,
            resolve_error: None,
            validate_error: None,
        };

        let error = resolve_epsk_keystore_ref(&mut epsk, &resolver).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("did not resolve keystore reference 'missing-epsk'"));
        assert!(message.contains("tls13-epsk"));
    }

    #[test]
    fn resolve_server_preserves_inline_epsk_without_resolver_calls() {
        let server = server_with_client_identity(
            "epsk-inline",
            client_identity_with_epsk(epsk_inline(b"topsecret", "client@example.com")),
        );

        let resolved = resolve_server(server, Some(&PanicResolver)).unwrap();
        assert!(resolved.is_tls());

        let epsk = resolved
            .client_identity
            .as_ref()
            .and_then(|client_identity| client_identity.tls13_epsk.as_ref())
            .unwrap();
        assert_eq!(epsk.external_identity, "client@example.com");
        assert_eq!(
            epsk.inline_definition
                .as_ref()
                .and_then(|definition| definition.cleartext_symmetric_key.as_deref()),
            Some(b"topsecret".as_slice()),
        );
    }

    #[test]
    fn resolve_server_adds_server_context_for_epsk_errors() {
        let server = server_with_client_identity(
            "ctx-epsk",
            client_identity_with_epsk(epsk_keystore("err-epsk", "client@example.com")),
        );
        let resolver = SymmetricResolver {
            resolved: None,
            resolve_error: Some("resolution failed"),
            validate_error: None,
        };

        let error = resolve_server(server, Some(&resolver)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("ctx-epsk"));
        assert!(message.contains("central-keystore-reference for tls13-epsk"));
    }

    #[test]
    fn validate_epsk_keystore_refs_collects_resolver_errors() {
        let client_identity = client_identity_with_epsk(epsk_keystore("bad-epsk", "id"));
        let resolver = SymmetricResolver {
            resolved: None,
            resolve_error: None,
            validate_error: Some("resolution failed"),
        };
        let mut errors = Vec::new();

        validate_epsk_keystore_refs(&client_identity, "epsk-server", &resolver, &mut errors);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("server 'epsk-server': tls13-epsk central-keystore-reference"));
        assert!(errors[0].contains("resolution failed"));
    }

    #[test]
    fn validate_external_server_references_without_resolver_rejects_epsk_refs() {
        let server = server_with_client_identity(
            "noop-epsk",
            client_identity_with_epsk(epsk_keystore("epsk-ref", "id")),
        );

        let error = validate_external_server_references(&server, None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("tls13-epsk central-keystore-reference"));
    }

    #[test]
    fn resolve_server_without_resolver_rejects_epsk_refs() {
        let server = server_with_client_identity(
            "noop-epsk",
            client_identity_with_epsk(epsk_keystore("epsk-ref", "id")),
        );

        let error = resolve_server(server, None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("tls13-epsk"));
    }
}
