use anyhow::{Context, Result};
use tacacsrs_config::crypto_types::PublicKeyFormat;
use tacacsrs_config::{RawPrivateKey, ServerAuthenticationRawPublicKeys};

use crate::{CredentialResolver, encode_private_key_data, encode_public_key_der};

pub(crate) fn resolve_raw_private_key_keystore_ref(
    rpk: &mut RawPrivateKey,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ks_ref) = rpk.central_keystore_reference {
        let material = resolver
            .resolve_asymmetric_key(ks_ref)
            .context("failed to resolve central-keystore-reference for raw-private-key")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "credential resolver did not resolve keystore reference '{ks_ref}' for raw-private-key"
                )
            })?;

        let encoded_private_key = encode_private_key_data(&material.private_key)?;

        rpk.inline_definition = Some(tacacsrs_config::keystore::AsymmetricKeyInlineDefinition {
            public_key_format: material
                .public_key
                .as_ref()
                .map(|_| PublicKeyFormat::SubjectPublicKeyInfoFormat),
            public_key: material.public_key.as_ref().map(encode_public_key_der),
            private_key_format: Some(encoded_private_key.format),
            cleartext_private_key: Some(encoded_private_key.der_bytes),
            hidden_private_key: None,
            encrypted_private_key: None,
        });
        rpk.central_keystore_reference = None;
    }
    Ok(())
}

pub(crate) fn resolve_raw_public_keys_truststore_ref(
    rpk: &mut ServerAuthenticationRawPublicKeys,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ts_ref) = rpk.central_truststore_reference {
        let entries = resolver
            .resolve_public_key_bag(ts_ref)
            .context("failed to resolve central-truststore-reference for raw-public-keys")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "credential resolver did not resolve truststore public key bag '{ts_ref}'"
                )
            })?;

        rpk.inline_definition = Some(tacacsrs_config::truststore::PublicKeysInlineDefinition {
            public_key: entries
                .into_iter()
                .map(|entry| tacacsrs_config::truststore::PublicKeysPublicKey {
                    name: entry.name,
                    public_key_format: PublicKeyFormat::SubjectPublicKeyInfoFormat,
                    public_key: encode_public_key_der(&entry.public_key),
                })
                .collect(),
        });
        rpk.central_truststore_reference = None;
    }
    Ok(())
}

pub(crate) fn validate_rpk_keystore_refs(
    ci: &tacacsrs_config::TlsClientClientIdentity,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref rpk) = ci.raw_private_key {
        if let Some(ref ks_ref) = rpk.central_keystore_reference {
            if let Err(error) = resolver.validate_asymmetric_key(ks_ref) {
                errors.push(format!(
                    "server '{server_name}': raw-private-key central-keystore-reference: {error}",
                ));
            }
        }
    }
}

pub(crate) fn validate_rpk_truststore_refs(
    sa: &tacacsrs_config::TlsClientServerAuthentication,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref rpk) = sa.raw_public_keys {
        if let Some(ref ts_ref) = rpk.central_truststore_reference {
            if let Err(error) = resolver.validate_public_key_bag(ts_ref) {
                errors.push(format!(
                    "server '{server_name}': raw-public-keys central-truststore-reference: {error}",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer};

    use tacacsrs_config::crypto_types::{PrivateKeyFormat, PublicKeyFormat};
    use tacacsrs_config::{
        RawPrivateKey, ServerAuthenticationRawPublicKeys, TacacsPlusServer, TacacsPlusServerType,
        TlsClientClientIdentity, TlsClientServerAuthentication,
    };

    use super::{
        resolve_raw_private_key_keystore_ref, resolve_raw_public_keys_truststore_ref,
        validate_rpk_keystore_refs, validate_rpk_truststore_refs,
    };
    use crate::{
        NamedCertificateDer, TlsClientCertificateMaterial, TlsClientCertificateReference,
        encode_private_key_data, encode_public_key_der, resolve_server,
        validate_external_server_references, AsymmetricKeyMaterial, CredentialResolver,
        SymmetricKeyMaterial, TruststorePublicKeyMaterial,
    };

    struct RpkResolver {
        asymmetric_key: Option<AsymmetricKeyMaterial>,
        public_key_bag: Option<Vec<TruststorePublicKeyMaterial>>,
        resolve_asymmetric_error: Option<&'static str>,
        resolve_public_key_bag_error: Option<&'static str>,
        validate_asymmetric_error: Option<&'static str>,
        validate_public_key_bag_error: Option<&'static str>,
    }

    impl CredentialResolver for RpkResolver {
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
            if let Some(message) = self.resolve_asymmetric_error {
                return Err(anyhow::anyhow!(message));
            }
            Ok(self.asymmetric_key.clone())
        }

        fn resolve_symmetric_key(&self, _key: &str) -> Result<Option<SymmetricKeyMaterial>> {
            panic!("unexpected symmetric key lookup")
        }

        fn resolve_public_key_bag(
            &self,
            _key: &str,
        ) -> Result<Option<Vec<TruststorePublicKeyMaterial>>> {
            if let Some(message) = self.resolve_public_key_bag_error {
                return Err(anyhow::anyhow!(message));
            }
            Ok(self.public_key_bag.clone())
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
            if let Some(message) = self.validate_asymmetric_error {
                return Err(anyhow::anyhow!(message));
            }
            Ok(())
        }

        fn validate_symmetric_key(&self, _key: &str) -> Result<()> {
            panic!("unexpected symmetric key validation")
        }

        fn validate_public_key_bag(&self, _key: &str) -> Result<()> {
            if let Some(message) = self.validate_public_key_bag_error {
                return Err(anyhow::anyhow!(message));
            }
            Ok(())
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

    fn sample_private_key_der(label: &str) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(label.as_bytes().to_vec()))
    }

    fn sample_public_key_der(label: &str) -> SubjectPublicKeyInfoDer<'static> {
        SubjectPublicKeyInfoDer::from(label.as_bytes().to_vec())
    }

    fn raw_private_key_keystore(reference: &str) -> RawPrivateKey {
        RawPrivateKey {
            inline_definition: None,
            central_keystore_reference: Some(reference.to_owned()),
        }
    }

    fn raw_private_key_inline(cleartext_private_key: &str) -> RawPrivateKey {
        RawPrivateKey {
            inline_definition: Some(tacacsrs_config::keystore::AsymmetricKeyInlineDefinition {
                public_key_format: None,
                public_key: None,
                private_key_format: None,
                cleartext_private_key: Some(cleartext_private_key.as_bytes().to_vec()),
                hidden_private_key: None,
                encrypted_private_key: None,
            }),
            central_keystore_reference: None,
        }
    }

    fn client_identity_with_raw_private_key(
        raw_private_key: RawPrivateKey,
    ) -> TlsClientClientIdentity {
        TlsClientClientIdentity {
            credentials_reference: None,
            certificate: None,
            raw_private_key: Some(raw_private_key),
            tls13_epsk: None,
        }
    }

    fn raw_public_keys_truststore_ref(reference: &str) -> ServerAuthenticationRawPublicKeys {
        ServerAuthenticationRawPublicKeys {
            inline_definition: None,
            central_truststore_reference: Some(reference.to_owned()),
        }
    }

    fn raw_public_keys_inline(public_keys: &[(&str, &str)]) -> ServerAuthenticationRawPublicKeys {
        ServerAuthenticationRawPublicKeys {
            inline_definition: Some(tacacsrs_config::truststore::PublicKeysInlineDefinition {
                public_key: public_keys
                    .iter()
                    .map(|(name, public_key)| tacacsrs_config::truststore::PublicKeysPublicKey {
                        name: (*name).to_owned(),
                        public_key_format: PublicKeyFormat::SubjectPublicKeyInfoFormat,
                        public_key: public_key.as_bytes().to_vec(),
                    })
                    .collect(),
            }),
            central_truststore_reference: None,
        }
    }

    fn server_auth_with_raw_public_keys(
        raw_public_keys: ServerAuthenticationRawPublicKeys,
    ) -> TlsClientServerAuthentication {
        TlsClientServerAuthentication {
            credentials_reference: None,
            ca_certs: None,
            ee_certs: None,
            raw_public_keys: Some(raw_public_keys),
            tls13_epsks: None,
        }
    }

    fn default_server() -> TacacsPlusServer {
        TacacsPlusServer {
            name: String::new(),
            server_type: TacacsPlusServerType::ACCOUNTING,
            address: "10.0.1.2".to_owned(),
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
    fn resolve_raw_private_key_keystore_ref_populates_inline_definition() {
        let mut raw_private_key = raw_private_key_keystore("rpk-ref");
        let resolver = RpkResolver {
            asymmetric_key: Some(AsymmetricKeyMaterial {
                private_key: sample_private_key_der("RPK_PRIVATE_KEY"),
                public_key: Some(sample_public_key_der("RPK_PUBLIC_KEY")),
            }),
            public_key_bag: None,
            resolve_asymmetric_error: None,
            resolve_public_key_bag_error: None,
            validate_asymmetric_error: None,
            validate_public_key_bag_error: None,
        };

        resolve_raw_private_key_keystore_ref(&mut raw_private_key, &resolver).unwrap();

        assert!(raw_private_key.central_keystore_reference.is_none());
        let inline = raw_private_key.inline_definition.as_ref().unwrap();
        assert_eq!(
            inline.cleartext_private_key.as_deref(),
            Some(
                encode_private_key_data(&sample_private_key_der("RPK_PRIVATE_KEY"))
                    .unwrap()
                    .der_bytes
                    .as_slice(),
            ),
        );
        assert_eq!(
            inline.public_key.as_deref(),
            Some(encode_public_key_der(&sample_public_key_der("RPK_PUBLIC_KEY")).as_slice()),
        );
        assert_eq!(inline.private_key_format, Some(PrivateKeyFormat::OneAsymmetricKeyFormat),);
        assert_eq!(inline.public_key_format, Some(PublicKeyFormat::SubjectPublicKeyInfoFormat),);
    }

    #[test]
    fn resolve_raw_private_key_keystore_ref_returns_unresolved_error() {
        let mut raw_private_key = raw_private_key_keystore("missing-rpk");
        let resolver = RpkResolver {
            asymmetric_key: None,
            public_key_bag: None,
            resolve_asymmetric_error: None,
            resolve_public_key_bag_error: None,
            validate_asymmetric_error: None,
            validate_public_key_bag_error: None,
        };

        let error =
            resolve_raw_private_key_keystore_ref(&mut raw_private_key, &resolver).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("did not resolve keystore reference 'missing-rpk'"));
        assert!(message.contains("raw-private-key"));
    }

    #[test]
    fn resolve_raw_public_keys_truststore_ref_populates_inline_definition() {
        let mut raw_public_keys = raw_public_keys_truststore_ref("rpk-ref");
        let resolver = RpkResolver {
            asymmetric_key: None,
            public_key_bag: Some(vec![TruststorePublicKeyMaterial {
                name: "rpk-ref".to_owned(),
                public_key: sample_public_key_der("PUB_KEY_DATA"),
            }]),
            resolve_asymmetric_error: None,
            resolve_public_key_bag_error: None,
            validate_asymmetric_error: None,
            validate_public_key_bag_error: None,
        };

        resolve_raw_public_keys_truststore_ref(&mut raw_public_keys, &resolver).unwrap();

        assert!(raw_public_keys.central_truststore_reference.is_none());
        let inline = raw_public_keys.inline_definition.as_ref().unwrap();
        assert_eq!(inline.public_key.len(), 1);
        assert_eq!(inline.public_key[0].name, "rpk-ref");
        assert_eq!(
            inline.public_key[0].public_key,
            encode_public_key_der(&sample_public_key_der("PUB_KEY_DATA")),
        );
        assert_eq!(
            inline.public_key[0].public_key_format,
            PublicKeyFormat::SubjectPublicKeyInfoFormat,
        );
    }

    #[test]
    fn resolve_raw_public_keys_truststore_ref_returns_unresolved_error() {
        let mut raw_public_keys = raw_public_keys_truststore_ref("missing-rpk");
        let resolver = RpkResolver {
            asymmetric_key: None,
            public_key_bag: None,
            resolve_asymmetric_error: None,
            resolve_public_key_bag_error: None,
            validate_asymmetric_error: None,
            validate_public_key_bag_error: None,
        };

        let error =
            resolve_raw_public_keys_truststore_ref(&mut raw_public_keys, &resolver).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("did not resolve truststore public key bag 'missing-rpk'"));
    }

    #[test]
    fn resolve_server_preserves_inline_raw_private_key_without_resolver_calls() {
        let server = server_with_client_identity(
            "inline-rpk",
            client_identity_with_raw_private_key(raw_private_key_inline("RPK_PRIVATE_KEY")),
        );

        let resolved = resolve_server(server, Some(&PanicResolver)).unwrap();

        let raw_private_key = resolved
            .client_identity
            .as_ref()
            .and_then(|client_identity| client_identity.raw_private_key.as_ref())
            .unwrap();
        let inline = raw_private_key.inline_definition.as_ref().unwrap();
        assert_eq!(inline.cleartext_private_key.as_deref(), Some(b"RPK_PRIVATE_KEY".as_slice()),);
        assert!(inline.public_key.is_none());
        assert!(inline.private_key_format.is_none());
        assert!(inline.public_key_format.is_none());
    }

    #[test]
    fn resolve_server_preserves_inline_raw_public_keys_without_resolver_calls() {
        let server = server_with_server_auth(
            "inline-rpk-ts",
            server_auth_with_raw_public_keys(raw_public_keys_inline(&[(
                "rpk-ref",
                "PUB_KEY_DATA",
            )])),
        );

        let resolved = resolve_server(server, Some(&PanicResolver)).unwrap();

        let raw_public_keys = resolved
            .server_authentication
            .as_ref()
            .and_then(|server_authentication| server_authentication.raw_public_keys.as_ref())
            .unwrap();
        let inline = raw_public_keys.inline_definition.as_ref().unwrap();
        assert_eq!(inline.public_key.len(), 1);
        assert_eq!(inline.public_key[0].name, "rpk-ref");
        assert_eq!(inline.public_key[0].public_key, b"PUB_KEY_DATA");
    }

    #[test]
    fn resolve_server_adds_server_context_for_raw_public_keys_errors() {
        let server = server_with_server_auth(
            "ctx-rpk-ts",
            server_auth_with_raw_public_keys(raw_public_keys_truststore_ref("err-rpk")),
        );
        let resolver = RpkResolver {
            asymmetric_key: None,
            public_key_bag: None,
            resolve_asymmetric_error: None,
            resolve_public_key_bag_error: Some("resolution failed"),
            validate_asymmetric_error: None,
            validate_public_key_bag_error: None,
        };

        let error = resolve_server(server, Some(&resolver)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("ctx-rpk-ts"));
        assert!(message.contains("central-truststore-reference for raw-public-keys"));
    }

    #[test]
    fn resolve_server_without_resolver_rejects_raw_public_keys_refs() {
        let server = server_with_server_auth(
            "noop-rpk-ts",
            server_auth_with_raw_public_keys(raw_public_keys_truststore_ref("rpk-ts-ref")),
        );

        let error = resolve_server(server, None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("raw-public-keys"));
    }

    #[test]
    fn resolve_server_without_resolver_rejects_raw_private_key_refs() {
        let server = server_with_client_identity(
            "noop-rpk",
            client_identity_with_raw_private_key(raw_private_key_keystore("rpk-ref")),
        );

        let error = resolve_server(server, None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("raw-private-key"));
    }

    #[test]
    fn validate_rpk_keystore_refs_collects_resolver_errors() {
        let client_identity =
            client_identity_with_raw_private_key(raw_private_key_keystore("bad-rpk"));
        let resolver = RpkResolver {
            asymmetric_key: None,
            public_key_bag: None,
            resolve_asymmetric_error: None,
            resolve_public_key_bag_error: None,
            validate_asymmetric_error: Some("resolution failed"),
            validate_public_key_bag_error: None,
        };
        let mut errors = Vec::new();

        validate_rpk_keystore_refs(&client_identity, "ext-rpk-ks", &resolver, &mut errors);

        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("server 'ext-rpk-ks': raw-private-key central-keystore-reference")
        );
        assert!(errors[0].contains("resolution failed"));
    }

    #[test]
    fn validate_rpk_truststore_refs_collects_resolver_errors() {
        let server_auth =
            server_auth_with_raw_public_keys(raw_public_keys_truststore_ref("bad-rpk-ts"));
        let resolver = RpkResolver {
            asymmetric_key: None,
            public_key_bag: None,
            resolve_asymmetric_error: None,
            resolve_public_key_bag_error: None,
            validate_asymmetric_error: None,
            validate_public_key_bag_error: Some("resolution failed"),
        };
        let mut errors = Vec::new();

        validate_rpk_truststore_refs(&server_auth, "ext-rpk-ts", &resolver, &mut errors);

        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("server 'ext-rpk-ts': raw-public-keys central-truststore-reference")
        );
        assert!(errors[0].contains("resolution failed"));
    }

    #[test]
    fn validate_external_server_references_without_resolver_rejects_rpk_keystore_refs() {
        let server = server_with_client_identity(
            "noop-rpk",
            client_identity_with_raw_private_key(raw_private_key_keystore("rpk-ref")),
        );

        let error = validate_external_server_references(&server, None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("raw-private-key central-keystore-reference"));
    }

    #[test]
    fn validate_external_server_references_without_resolver_rejects_rpk_truststore_refs() {
        let server = server_with_server_auth(
            "noop-rpk-ts",
            server_auth_with_raw_public_keys(raw_public_keys_truststore_ref("rpk-ts-ref")),
        );

        let error = validate_external_server_references(&server, None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no credential resolver configured"));
        assert!(message.contains("raw-public-keys central-truststore-reference"));
    }
}
