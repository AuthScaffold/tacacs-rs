use async_trait::async_trait;
use tacacsrs_config::crypto_types::{PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat};
use tacacsrs_config::{ValidationOptions, parse_yang_json};
use tacacsrs_credential_resolution::{
    CertificateBagMaterial, CertificateWithKeyMaterial, CredentialKind, CredentialRequest,
    CredentialResolver, MaterializationErrorKind, NamedCertificateMaterial, ProviderErrorKind,
    PublicBytes, ResolutionError, ResolvedCredential, SecretBytes, SymmetricKeyMaterial,
    enumerate_materialized_servers, materialize_servers,
};

struct CompleteResolver {
    failing_server: Option<&'static str>,
}

struct DuplicateBagNameResolver;

#[async_trait]
impl CredentialResolver for CompleteResolver {
    async fn resolve(
        &self,
        request: &CredentialRequest,
    ) -> Result<ResolvedCredential, ResolutionError> {
        if self.failing_server == Some(request.context().server_name()) {
            return Err(ResolutionError::provider(
                ProviderErrorKind::Unavailable,
                request.context(),
            ));
        }

        Ok(match request.kind() {
            CredentialKind::CertificateWithKey => {
                ResolvedCredential::CertificateWithKey(CertificateWithKeyMaterial {
                    public_key_format: Some(PublicKeyFormat::SubjectPublicKeyInfoFormat),
                    public_key: Some(PublicBytes::new(b"resolved-public-key".to_vec())),
                    private_key_format: PrivateKeyFormat::OneAsymmetricKeyFormat,
                    certificate: PublicBytes::new(b"resolved-certificate".to_vec()),
                    private_key: SecretBytes::new(b"resolved-private-key".to_vec()),
                })
            }
            CredentialKind::SymmetricKey => {
                ResolvedCredential::SymmetricKey(SymmetricKeyMaterial {
                    key_format: Some(SymmetricKeyFormat::OctetStringKeyFormat),
                    key: SecretBytes::new(b"resolved-epsk-material".to_vec()),
                })
            }
            CredentialKind::CaCertificateBag => {
                ResolvedCredential::CaCertificateBag(CertificateBagMaterial {
                    certificates: vec![
                        NamedCertificateMaterial {
                            name: "ca-primary".to_owned(),
                            certificate: PublicBytes::new(b"resolved-ca-primary".to_vec()),
                        },
                        NamedCertificateMaterial {
                            name: "ca-secondary".to_owned(),
                            certificate: PublicBytes::new(b"resolved-ca-secondary".to_vec()),
                        },
                    ],
                })
            }
            CredentialKind::EeCertificateBag => {
                ResolvedCredential::EeCertificateBag(CertificateBagMaterial {
                    certificates: vec![NamedCertificateMaterial {
                        name: "ee-primary".to_owned(),
                        certificate: PublicBytes::new(b"resolved-ee-primary".to_vec()),
                    }],
                })
            }
        })
    }
}

#[tokio::test]
async fn epsk_materialization_moves_secret_and_clears_reference() {
    let source = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "epsk",
                    "server-type": "accounting",
                    "address": "192.0.2.10",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "opaque-epsk-reference",
                            "external-identity": "client"
                        }
                    }
                }]
            }
        }"#,
    )
    .expect("central EPSK configuration must parse");
    let original = source.clone();

    let materialized = enumerate_materialized_servers(
        &source,
        &CompleteResolver {
            failing_server: None,
        },
        &ValidationOptions::default(),
    )
    .await
    .expect("EPSK materialization must succeed");

    assert_eq!(source, original, "source snapshot must remain unchanged");
    let epsk = materialized[0]
        .client_identity
        .as_ref()
        .and_then(|identity| identity.tls13_epsk.as_ref())
        .expect("materialized EPSK must exist");
    assert!(epsk.central_keystore_reference.is_none());
    let inline = epsk
        .inline_definition
        .as_ref()
        .expect("inline EPSK must exist");
    assert_eq!(inline.key_format, Some(SymmetricKeyFormat::OctetStringKeyFormat));
    assert_eq!(
        inline
            .cleartext_symmetric_key
            .as_ref()
            .expect("symmetric key must exist")
            .expose_secret(),
        b"resolved-epsk-material",
    );
}

#[tokio::test]
async fn certificate_materialization_preserves_formats_names_and_order() {
    let source = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "certificate",
                    "server-type": "accounting",
                    "address": "192.0.2.20",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "opaque-key-reference",
                                "certificate": "opaque-certificate-reference"
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {"central-truststore-reference": "opaque-ca-reference"},
                        "ee-certs": {"central-truststore-reference": "opaque-ee-reference"}
                    }
                }]
            }
        }"#,
    )
    .expect("central certificate configuration must parse");

    let materialized = enumerate_materialized_servers(
        &source,
        &CompleteResolver {
            failing_server: None,
        },
        &ValidationOptions::default(),
    )
    .await
    .expect("certificate materialization must succeed");
    let server = &materialized[0];
    let identity = server
        .client_identity
        .as_ref()
        .expect("client identity must exist");
    let certificate = identity
        .certificate
        .as_ref()
        .expect("certificate must exist");
    assert!(certificate.central_keystore_reference.is_none());
    let inline = certificate
        .inline_definition
        .as_ref()
        .expect("inline certificate must exist");
    assert_eq!(inline.public_key_format, Some(PublicKeyFormat::SubjectPublicKeyInfoFormat),);
    assert_eq!(inline.private_key_format, Some(PrivateKeyFormat::OneAsymmetricKeyFormat),);
    assert_eq!(inline.public_key.as_deref(), Some(b"resolved-public-key".as_slice()));
    assert_eq!(inline.cert_data.as_deref(), Some(b"resolved-certificate".as_slice()));
    assert_eq!(
        inline
            .cleartext_private_key
            .as_ref()
            .expect("private key must exist")
            .expose_secret(),
        b"resolved-private-key",
    );

    let authentication = server
        .server_authentication
        .as_ref()
        .expect("server authentication must exist");
    let ca = authentication
        .ca_certs
        .as_ref()
        .expect("CA certificates must exist");
    assert!(ca.central_truststore_reference.is_none());
    let ca_names = ca
        .inline_definition
        .as_ref()
        .expect("inline CA certificates must exist")
        .certificate
        .iter()
        .map(|certificate| certificate.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ca_names, ["ca-primary", "ca-secondary"]);
    let ee = authentication
        .ee_certs
        .as_ref()
        .expect("EE certificates must exist");
    assert!(ee.central_truststore_reference.is_none());
    assert_eq!(
        ee.inline_definition
            .as_ref()
            .expect("inline EE certificates must exist")
            .certificate[0]
            .name,
        "ee-primary",
    );
}

#[tokio::test]
async fn mixed_inline_local_bundle_and_central_servers_materialize_together() {
    let source = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [{
                    "id": "central-epsk",
                    "tls13-epsk": {
                        "central-keystore-reference": "opaque-bundle-reference",
                        "external-identity": "bundle-client"
                    }
                }],
                "server": [
                    {
                        "name": "inline",
                        "server-type": "accounting",
                        "address": "192.0.2.30",
                        "port": 49,
                        "shared-secret": "inline-secret"
                    },
                    {
                        "name": "local-bundle-central",
                        "server-type": "accounting",
                        "address": "192.0.2.31",
                        "port": 49,
                        "client-identity": {"credentials-reference": "central-epsk"}
                    }
                ]
            }
        }"#,
    )
    .expect("mixed credential configuration must parse");

    let materialized = enumerate_materialized_servers(
        &source,
        &CompleteResolver {
            failing_server: None,
        },
        &ValidationOptions::default(),
    )
    .await
    .expect("mixed credential materialization must succeed");

    assert_eq!(materialized.len(), 2);
    assert_eq!(
        materialized[0]
            .shared_secret
            .as_ref()
            .expect("inline shared secret must exist")
            .expose_secret(),
        "inline-secret",
    );
    let identity = materialized[1]
        .client_identity
        .as_ref()
        .expect("client identity must exist");
    assert!(identity.credentials_reference.is_none());
    let epsk = identity
        .tls13_epsk
        .as_ref()
        .expect("EPSK from the local bundle must exist");
    assert!(epsk.central_keystore_reference.is_none());
    assert!(epsk.inline_definition.is_some());
}

#[tokio::test]
async fn selected_set_failure_returns_no_partial_candidates() {
    let source = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "inline",
                        "server-type": "accounting",
                        "address": "192.0.2.40",
                        "port": 49,
                        "shared-secret": "inline-secret"
                    },
                    {
                        "name": "failing",
                        "server-type": "accounting",
                        "address": "192.0.2.41",
                        "port": 49,
                        "client-identity": {
                            "tls13-epsk": {
                                "central-keystore-reference": "opaque-failing-reference",
                                "external-identity": "client"
                            }
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("selected server configuration must parse");
    let enumerated =
        tacacsrs_config::enumerate_servers(&source).expect("server enumeration must succeed");

    let error = materialize_servers(
        enumerated,
        &CompleteResolver {
            failing_server: Some("failing"),
        },
        &ValidationOptions::default(),
    )
    .await
    .expect_err("one failed server must fail the selected transaction");

    assert_eq!(error.kind(), MaterializationErrorKind::Resolution);
    assert_eq!(error.server_name(), Some("failing"));
    let debug = format!("{error:?}");
    assert!(!debug.contains("opaque-failing-reference"));
    assert!(!debug.contains("resolved-epsk-material"));
}

#[async_trait]
impl CredentialResolver for DuplicateBagNameResolver {
    async fn resolve(
        &self,
        _request: &CredentialRequest,
    ) -> Result<ResolvedCredential, ResolutionError> {
        Ok(ResolvedCredential::CaCertificateBag(CertificateBagMaterial {
            certificates: vec![
                NamedCertificateMaterial {
                    name: "provider-name-sentinel".to_owned(),
                    certificate: PublicBytes::new(b"first-certificate".to_vec()),
                },
                NamedCertificateMaterial {
                    name: "provider-name-sentinel".to_owned(),
                    certificate: PublicBytes::new(b"second-certificate".to_vec()),
                },
            ],
        }))
    }
}

#[tokio::test]
async fn duplicate_provider_certificate_names_are_rejected_without_values() {
    let source = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "duplicate-bag",
                    "server-type": "accounting",
                    "address": "192.0.2.50",
                    "port": 49,
                    "server-authentication": {
                        "ca-certs": {"central-truststore-reference": "opaque-ca-reference"}
                    }
                }]
            }
        }"#,
    )
    .expect("central CA configuration must parse");

    let error = enumerate_materialized_servers(
        &source,
        &DuplicateBagNameResolver,
        &ValidationOptions::default(),
    )
    .await
    .expect_err("duplicate provider names must fail materialization");

    assert_eq!(error.kind(), MaterializationErrorKind::InvalidMaterial);
    assert_eq!(error.server_name(), Some("duplicate-bag"));
    assert_eq!(error.field_path(), Some("server-authentication/ca-certs"));
    let debug = format!("{error:?}");
    assert!(!debug.contains("provider-name-sentinel"));
    assert!(!debug.contains("opaque-ca-reference"));
    assert!(!debug.contains("first-certificate"));
}
