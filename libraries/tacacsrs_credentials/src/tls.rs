use anyhow::{Context, Result};
use tacacsrs_config::{ClientIdentityCertificate, ServerAuthenticationCaCerts};

use crate::CredentialResolver;

pub(crate) fn resolve_certificate_keystore_ref(
    cert: &mut ClientIdentityCertificate,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ks_ref) = cert.central_keystore_reference {
        let cert_ref = ks_ref.certificate.as_deref().unwrap_or_default();
        let material = resolver
            .resolve_keystore_certificate(cert_ref)
            .with_context(|| {
                format!("failed to resolve central-keystore-reference for certificate '{cert_ref}'")
            })?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "credential resolver did not resolve keystore certificate '{cert_ref}'"
                )
            })?;

        cert.inline_definition =
            Some(tacacsrs_config::keystore::EndEntityCertWithKeyInlineDefinition {
                public_key_format: material
                    .key_material
                    .public_key_format
                    .map(|f| f.as_rfc7951_str().to_owned()),
                public_key: material.key_material.public_key,
                private_key_format: material
                    .key_material
                    .private_key_format
                    .map(|f| f.as_rfc7951_str().to_owned()),
                cleartext_private_key: Some(material.key_material.cleartext_private_key),
                hidden_private_key: None,
                encrypted_private_key: None,
                cert_data: Some(material.cert_data),
            });
        cert.central_keystore_reference = None;
    }
    Ok(())
}

pub(crate) fn resolve_certs_truststore_ref(
    certs: &mut ServerAuthenticationCaCerts,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ts_ref) = certs.central_truststore_reference {
        let entries = resolver
            .resolve_certificate_bag(ts_ref)
            .context("failed to resolve central-truststore-reference for certs")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "credential resolver did not resolve truststore certificate bag '{ts_ref}'"
                )
            })?;

        certs.inline_definition = Some(tacacsrs_config::truststore::CertsInlineDefinition {
            certificate: entries
                .into_iter()
                .map(|entry| tacacsrs_config::truststore::CertsCertificate {
                    name: entry.name,
                    cert_data: entry.cert_data,
                })
                .collect(),
        });
        certs.central_truststore_reference = None;
    }
    Ok(())
}

pub(crate) fn validate_certificate_refs(
    ci: &tacacsrs_config::TlsClientClientIdentity,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref cert) = ci.certificate {
        if let Some(ref ks_ref) = cert.central_keystore_reference {
            let cert_ref = ks_ref.certificate.as_deref().unwrap_or_default();
            if let Err(error) = resolver.validate_keystore_certificate(cert_ref) {
                errors.push(format!(
                    "server '{server_name}': certificate central-keystore-reference: {error}",
                ));
            }
        }
    }
}

pub(crate) fn validate_server_auth_cert_refs(
    sa: &tacacsrs_config::TlsClientServerAuthentication,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref ca) = sa.ca_certs {
        if let Some(ref ts_ref) = ca.central_truststore_reference {
            if let Err(error) = resolver.validate_certificate_bag(ts_ref) {
                errors.push(format!(
                    "server '{server_name}': ca-certs central-truststore-reference: {error}",
                ));
            }
        }
    }
    if let Some(ref ee) = sa.ee_certs {
        if let Some(ref ts_ref) = ee.central_truststore_reference {
            if let Err(error) = resolver.validate_certificate_bag(ts_ref) {
                errors.push(format!(
                    "server '{server_name}': ee-certs central-truststore-reference: {error}",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use tacacsrs_config::{
        ClientIdentityCertificate, ServerAuthenticationCaCerts, TacacsPlusServer,
        TacacsPlusServerType, TlsClientClientIdentity, TlsClientServerAuthentication,
    };

    use super::{
        resolve_certificate_keystore_ref, resolve_certs_truststore_ref, validate_certificate_refs,
        validate_server_auth_cert_refs,
    };
    use crate::{
        resolve_server, validate_external_server_references, AsymmetricKeyMaterial,
        CertificateEntry, CredentialResolver, SymmetricKeyMaterial, TruststorePublicKeyMaterial,
        X509CertificateMaterial,
    };

    struct TlsResolver {
        certificate: Option<X509CertificateMaterial>,
        certificate_bag: Option<Vec<CertificateEntry>>,
        resolve_certificate_error: Option<&'static str>,
        resolve_bag_error: Option<&'static str>,
        validate_certificate_error: Option<&'static str>,
        validate_bag_error: Option<&'static str>,
    }

    impl CredentialResolver for TlsResolver {
        fn resolve_keystore_certificate(
            &self,
            _key: &str,
        ) -> Result<Option<X509CertificateMaterial>> {
            if let Some(message) = self.resolve_certificate_error {
                return Err(anyhow::anyhow!(message));
            }
            Ok(self.certificate.clone())
        }

        fn resolve_certificate_bag(&self, _key: &str) -> Result<Option<Vec<CertificateEntry>>> {
            if let Some(message) = self.resolve_bag_error {
                return Err(anyhow::anyhow!(message));
            }
            Ok(self.certificate_bag.clone())
        }

        fn resolve_asymmetric_key(&self, _key: &str) -> Result<Option<AsymmetricKeyMaterial>> {
            panic!("unexpected asymmetric key lookup")
        }

        fn resolve_symmetric_key(&self, _key: &str) -> Result<Option<SymmetricKeyMaterial>> {
            panic!("unexpected symmetric key lookup")
        }

        fn resolve_public_key_bag(
            &self,
            _key: &str,
        ) -> Result<Option<Vec<TruststorePublicKeyMaterial>>> {
            panic!("unexpected public key bag lookup")
        }

        fn validate_keystore_certificate(&self, _key: &str) -> Result<()> {
            if let Some(message) = self.validate_certificate_error {
                return Err(anyhow::anyhow!(message));
            }
            Ok(())
        }

        fn validate_asymmetric_key(&self, _key: &str) -> Result<()> {
            panic!("unexpected asymmetric key validation")
        }

        fn validate_symmetric_key(&self, _key: &str) -> Result<()> {
            panic!("unexpected symmetric key validation")
        }

        fn validate_certificate_bag(&self, _key: &str) -> Result<()> {
            if let Some(message) = self.validate_bag_error {
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
        fn resolve_keystore_certificate(
            &self,
            _key: &str,
        ) -> Result<Option<X509CertificateMaterial>> {
            panic!("resolver should not be called")
        }

        fn resolve_certificate_bag(&self, _key: &str) -> Result<Option<Vec<CertificateEntry>>> {
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

        fn validate_keystore_certificate(&self, _key: &str) -> Result<()> {
            panic!("resolver should not be called")
        }

        fn validate_asymmetric_key(&self, _key: &str) -> Result<()> {
            panic!("resolver should not be called")
        }

        fn validate_symmetric_key(&self, _key: &str) -> Result<()> {
            panic!("resolver should not be called")
        }

        fn validate_certificate_bag(&self, _key: &str) -> Result<()> {
            panic!("resolver should not be called")
        }

        fn validate_public_key_bag(&self, _key: &str) -> Result<()> {
            panic!("resolver should not be called")
        }
    }

    fn certificate_keystore_ref(reference: &str) -> ClientIdentityCertificate {
        ClientIdentityCertificate {
            inline_definition: None,
            central_keystore_reference: Some(
                tacacsrs_config::keystore::EndEntityCertWithKeyCentralKeystoreReference {
                    asymmetric_key: None,
                    certificate: Some(reference.to_owned()),
                },
            ),
        }
    }

    fn certificate_inline(
        cert_data: &str,
        cleartext_private_key: &str,
    ) -> ClientIdentityCertificate {
        ClientIdentityCertificate {
            inline_definition: Some(
                tacacsrs_config::keystore::EndEntityCertWithKeyInlineDefinition {
                    public_key_format: None,
                    public_key: None,
                    private_key_format: None,
                    cleartext_private_key: Some(cleartext_private_key.to_owned()),
                    hidden_private_key: None,
                    encrypted_private_key: None,
                    cert_data: Some(cert_data.to_owned()),
                },
            ),
            central_keystore_reference: None,
        }
    }

    fn client_identity_with_certificate(
        certificate: ClientIdentityCertificate,
    ) -> TlsClientClientIdentity {
        TlsClientClientIdentity {
            credentials_reference: None,
            certificate: Some(certificate),
            raw_private_key: None,
            tls13_epsk: None,
        }
    }

    fn certs_truststore_ref(reference: &str) -> ServerAuthenticationCaCerts {
        ServerAuthenticationCaCerts {
            inline_definition: None,
            central_truststore_reference: Some(reference.to_owned()),
        }
    }

    fn certs_inline(certs: &[(&str, &str)]) -> ServerAuthenticationCaCerts {
        ServerAuthenticationCaCerts {
            inline_definition: Some(tacacsrs_config::truststore::CertsInlineDefinition {
                certificate: certs
                    .iter()
                    .map(|(name, cert_data)| tacacsrs_config::truststore::CertsCertificate {
                        name: (*name).to_owned(),
                        cert_data: (*cert_data).to_owned(),
                    })
                    .collect(),
            }),
            central_truststore_reference: None,
        }
    }

    fn server_auth_with_ca(ca_certs: ServerAuthenticationCaCerts) -> TlsClientServerAuthentication {
        TlsClientServerAuthentication {
            credentials_reference: None,
            ca_certs: Some(ca_certs),
            ee_certs: None,
            raw_public_keys: None,
            tls13_epsks: None,
        }
    }

    fn server_auth_with_ee(ee_certs: ServerAuthenticationCaCerts) -> TlsClientServerAuthentication {
        TlsClientServerAuthentication {
            credentials_reference: None,
            ca_certs: None,
            ee_certs: Some(ee_certs),
            raw_public_keys: None,
            tls13_epsks: None,
        }
    }

    fn default_server() -> TacacsPlusServer {
        TacacsPlusServer {
            name: String::new(),
            server_type: TacacsPlusServerType::ACCOUNTING,
            address: "10.0.0.10".to_owned(),
            port: 49,
            domain_name: None,
            sni_enabled: None,
            single_connection: false,
            timeout: 5,
            source_ip: None,
            source_interface: None,
            shared_secret: None,
            client_identity: None,
            server_authentication: None,
            hello_params: None,
            vrf_instance: None,
        }
    }

    fn server_with_client_identity(
        name: &str,
        client_identity: TlsClientClientIdentity,
    ) -> TacacsPlusServer {
        TacacsPlusServer {
            name: name.to_owned(),
            client_identity: Some(client_identity),
            ..default_server()
        }
    }

    fn server_with_server_auth(
        name: &str,
        server_authentication: TlsClientServerAuthentication,
    ) -> TacacsPlusServer {
        TacacsPlusServer {
            name: name.to_owned(),
            server_authentication: Some(server_authentication),
            ..default_server()
        }
    }

    #[test]
    fn resolve_certificate_keystore_ref_populates_inline_definition() {
        let mut certificate = certificate_keystore_ref("my-cert");
        let resolver = TlsResolver {
            certificate: Some(X509CertificateMaterial {
                cert_data: "RESOLVED_CERT_PEM".to_owned(),
                key_material: AsymmetricKeyMaterial {
                    cleartext_private_key: "RESOLVED_KEY_PEM".to_owned(),
                    public_key: None,
                    private_key_format: None,
                    public_key_format: None,
                },
            }),
            certificate_bag: None,
            resolve_certificate_error: None,
            resolve_bag_error: None,
            validate_certificate_error: None,
            validate_bag_error: None,
        };

        resolve_certificate_keystore_ref(&mut certificate, &resolver).unwrap();

        assert!(certificate.central_keystore_reference.is_none());
        let inline = certificate.inline_definition.as_ref().unwrap();
        assert_eq!(inline.cert_data.as_deref(), Some("RESOLVED_CERT_PEM"));
        assert_eq!(inline.cleartext_private_key.as_deref(), Some("RESOLVED_KEY_PEM"));
    }

    #[test]
    fn resolve_certs_truststore_ref_populates_inline_definition() {
        let mut certs = certs_truststore_ref("ca-ref");
        let resolver = TlsResolver {
            certificate: None,
            certificate_bag: Some(vec![CertificateEntry {
                name: "ca-ref".to_owned(),
                cert_data: "CA_CERT_PEM".to_owned(),
            }]),
            resolve_certificate_error: None,
            resolve_bag_error: None,
            validate_certificate_error: None,
            validate_bag_error: None,
        };

        resolve_certs_truststore_ref(&mut certs, &resolver).unwrap();

        assert!(certs.central_truststore_reference.is_none());
        let inline = certs.inline_definition.as_ref().unwrap();
        assert_eq!(inline.certificate.len(), 1);
        assert_eq!(inline.certificate[0].name, "ca-ref");
        assert_eq!(inline.certificate[0].cert_data, "CA_CERT_PEM");
    }

    #[test]
    fn resolve_certificate_keystore_ref_returns_unresolved_error() {
        let mut certificate = certificate_keystore_ref("missing-cert");
        let resolver = TlsResolver {
            certificate: None,
            certificate_bag: None,
            resolve_certificate_error: None,
            resolve_bag_error: None,
            validate_certificate_error: None,
            validate_bag_error: None,
        };

        let error = resolve_certificate_keystore_ref(&mut certificate, &resolver).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("did not resolve keystore certificate 'missing-cert'"));
    }

    #[test]
    fn resolve_certs_truststore_ref_returns_unresolved_error() {
        let mut certs = certs_truststore_ref("missing-ca");
        let resolver = TlsResolver {
            certificate: None,
            certificate_bag: None,
            resolve_certificate_error: None,
            resolve_bag_error: None,
            validate_certificate_error: None,
            validate_bag_error: None,
        };

        let error = resolve_certs_truststore_ref(&mut certs, &resolver).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("did not resolve truststore certificate bag 'missing-ca'"));
    }

    #[test]
    fn resolve_server_preserves_inline_tls_material_without_resolver_calls() {
        let server = server_with_server_auth(
            "tls-inline",
            server_auth_with_ca(certs_inline(&[("ca1", "Y2EtY2VydC0x"), ("ca2", "Y2EtY2VydC0y")])),
        );
        let mut server = server;
        server.client_identity = Some(client_identity_with_certificate(certificate_inline(
            "Y2xpZW50LWNlcnQ=",
            "Y2xpZW50LWtleQ==",
        )));

        let resolved = resolve_server(server, Some(&PanicResolver)).unwrap();
        assert!(resolved.is_tls());

        let certificate = resolved
            .client_identity
            .as_ref()
            .and_then(|client_identity| client_identity.certificate.as_ref())
            .unwrap();
        let inline_certificate = certificate.inline_definition.as_ref().unwrap();
        assert_eq!(inline_certificate.cert_data.as_deref(), Some("Y2xpZW50LWNlcnQ="));
        assert_eq!(inline_certificate.cleartext_private_key.as_deref(), Some("Y2xpZW50LWtleQ=="),);

        let ca_certs = resolved
            .server_authentication
            .as_ref()
            .and_then(|server_authentication| server_authentication.ca_certs.as_ref())
            .unwrap();
        let inline_certs = ca_certs.inline_definition.as_ref().unwrap();
        assert_eq!(inline_certs.certificate.len(), 2);
    }

    #[test]
    fn resolve_server_adds_server_context_for_certificate_errors() {
        let server = server_with_client_identity(
            "ctx-cert",
            client_identity_with_certificate(certificate_keystore_ref("err-cert")),
        );
        let resolver = TlsResolver {
            certificate: None,
            certificate_bag: None,
            resolve_certificate_error: Some("resolution failed"),
            resolve_bag_error: None,
            validate_certificate_error: None,
            validate_bag_error: None,
        };

        let error = resolve_server(server, Some(&resolver)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("ctx-cert"));
        assert!(message.contains("central-keystore-reference for certificate 'err-cert'"));
    }

    #[test]
    fn resolve_server_adds_server_context_for_ee_truststore_errors() {
        let server = server_with_server_auth(
            "ctx-ee-ts",
            server_auth_with_ee(certs_truststore_ref("err-ee")),
        );
        let resolver = TlsResolver {
            certificate: None,
            certificate_bag: None,
            resolve_certificate_error: None,
            resolve_bag_error: Some("resolution failed"),
            validate_certificate_error: None,
            validate_bag_error: None,
        };

        let error = resolve_server(server, Some(&resolver)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("ctx-ee-ts"));
        assert!(message.contains("central-truststore-reference for certs"));
    }

    #[test]
    fn validate_certificate_refs_collects_resolver_errors() {
        let client_identity =
            client_identity_with_certificate(certificate_keystore_ref("bad-cert"));
        let resolver = TlsResolver {
            certificate: None,
            certificate_bag: None,
            resolve_certificate_error: None,
            resolve_bag_error: None,
            validate_certificate_error: Some("resolution failed"),
            validate_bag_error: None,
        };
        let mut errors = Vec::new();

        validate_certificate_refs(&client_identity, "tls-cert", &resolver, &mut errors);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("server 'tls-cert': certificate central-keystore-reference"));
        assert!(errors[0].contains("resolution failed"));
    }

    #[test]
    fn validate_server_auth_cert_refs_collects_ca_and_ee_errors() {
        let server_auth = TlsClientServerAuthentication {
            credentials_reference: None,
            ca_certs: Some(certs_truststore_ref("bad-ca")),
            ee_certs: Some(certs_truststore_ref("bad-ee")),
            raw_public_keys: None,
            tls13_epsks: None,
        };
        let resolver = TlsResolver {
            certificate: None,
            certificate_bag: None,
            resolve_certificate_error: None,
            resolve_bag_error: None,
            validate_certificate_error: None,
            validate_bag_error: Some("resolution failed"),
        };
        let mut errors = Vec::new();

        validate_server_auth_cert_refs(&server_auth, "tls-server", &resolver, &mut errors);

        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("ca-certs central-truststore-reference"));
        assert!(errors[1].contains("ee-certs central-truststore-reference"));
    }

    #[test]
    fn validate_external_server_references_without_resolver_rejects_ca_truststore_refs() {
        let server =
            server_with_server_auth("noop-ca", server_auth_with_ca(certs_truststore_ref("ca-ref")));

        let error = validate_external_server_references(&server, None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("ca-certs central-truststore-reference"));
    }

    #[test]
    fn validate_external_server_references_without_resolver_rejects_certificate_refs() {
        let server = server_with_client_identity(
            "noop-cert",
            client_identity_with_certificate(certificate_keystore_ref("cert-ref")),
        );

        let error = validate_external_server_references(&server, None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("certificate central-keystore-reference"));
    }

    #[test]
    fn validate_external_server_references_without_resolver_rejects_ee_truststore_refs() {
        let server =
            server_with_server_auth("noop-ee", server_auth_with_ee(certs_truststore_ref("ee-ref")));

        let error = validate_external_server_references(&server, None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("ee-certs central-truststore-reference"));
    }

    #[test]
    fn resolve_server_without_resolver_rejects_certificate_refs() {
        let server = server_with_client_identity(
            "noop-cert",
            client_identity_with_certificate(certificate_keystore_ref("cert-ref")),
        );

        let error = resolve_server(server, None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("certificate"));
    }

    #[test]
    fn resolve_server_without_resolver_rejects_ca_truststore_refs() {
        let server =
            server_with_server_auth("noop-ca", server_auth_with_ca(certs_truststore_ref("ca-ref")));

        let error = resolve_server(server, None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("central-truststore-reference for certs"));
    }
}
