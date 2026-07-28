use tacacsrs_config::{enumerate_servers, parse_yang_json, pipeline};
use tacacsrs_credential_resolution::{
    CertificateBagMaterial, CertificateWithKeyMaterial, CredentialKind, CredentialReference,
    FakeCredentialResolver, ProviderErrorKind, PublicBytes, ResolutionErrorKind, ResolutionPlan,
    ResolvedCredential, ResolvedCredentialSet, ResolvedResponse, SecretBytes, resolve_plan,
};

fn certificate_and_trust_server() -> tacacsrs_config::TacacsPlusServer {
    parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "certificate-server",
                    "server-type": "accounting",
                    "address": "10.0.5.1",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "secret-reference-key",
                                "certificate": "secret-reference-certificate"
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {"central-truststore-reference": "secret-reference-ca"},
                        "ee-certs": {"central-truststore-reference": "secret-reference-ee"}
                    }
                }]
            }
        }"#,
    )
    .expect("certificate config should parse")
    .server
    .remove(0)
}

fn epsk_server() -> tacacsrs_config::TacacsPlusServer {
    parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "epsk-server",
                    "server-type": "accounting",
                    "address": "10.0.5.2",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "secret-reference-epsk",
                            "external-identity": "client@example.test"
                        }
                    }
                }]
            }
        }"#,
    )
    .expect("EPSK config should parse")
    .server
    .remove(0)
}

fn certificate_material() -> ResolvedCredential {
    ResolvedCredential::CertificateWithKey(CertificateWithKeyMaterial {
        certificate: PublicBytes::new(b"certificate".to_vec()),
        private_key: SecretBytes::new(b"private-key".to_vec()),
    })
}

fn ca_material() -> ResolvedCredential {
    ResolvedCredential::CaCertificateBag(CertificateBagMaterial {
        certificates: vec![PublicBytes::new(b"ca".to_vec())],
    })
}

fn ee_material() -> ResolvedCredential {
    ResolvedCredential::EeCertificateBag(CertificateBagMaterial {
        certificates: vec![PublicBytes::new(b"ee".to_vec())],
    })
}

#[tokio::test]
async fn fake_resolver_completes_all_request_variants() {
    let certificate_plan =
        ResolutionPlan::from_server(&certificate_and_trust_server()).expect("certificate plan");
    assert_eq!(
        certificate_plan
            .requests()
            .iter()
            .map(tacacsrs_credential_resolution::CredentialRequest::kind)
            .collect::<Vec<_>>(),
        [
            CredentialKind::CertificateWithKey,
            CredentialKind::CaCertificateBag,
            CredentialKind::EeCertificateBag,
        ]
    );
    let certificate_resolver = FakeCredentialResolver::new()
        .with_response(certificate_plan.requests()[0].slot(), certificate_material())
        .with_response(certificate_plan.requests()[1].slot(), ca_material())
        .with_response(certificate_plan.requests()[2].slot(), ee_material());
    let certificate_set = resolve_plan(&certificate_plan, &certificate_resolver)
        .await
        .expect("certificate plan should resolve");
    assert_eq!(certificate_set.len(), 3);
    assert_eq!(
        certificate_set
            .credential(certificate_plan.requests()[0].slot())
            .expect("certificate material")
            .kind(),
        CredentialKind::CertificateWithKey,
    );

    let epsk_plan = ResolutionPlan::from_server(&epsk_server()).expect("EPSK plan");
    let epsk_resolver = FakeCredentialResolver::new().with_response(
        epsk_plan.requests()[0].slot(),
        ResolvedCredential::SymmetricKey(SecretBytes::new(b"epsk".to_vec())),
    );
    let epsk_set = resolve_plan(&epsk_plan, &epsk_resolver)
        .await
        .expect("EPSK plan should resolve");
    assert_eq!(
        epsk_set
            .credential(epsk_plan.requests()[0].slot())
            .expect("EPSK material")
            .kind(),
        CredentialKind::SymmetricKey,
    );
}

#[test]
fn request_plan_is_deterministic_explicit_and_redacted() {
    let plan = ResolutionPlan::from_server(&certificate_and_trust_server()).expect("plan");
    let first = &plan.requests()[0];
    assert_eq!(first.context().server_name(), "certificate-server");
    assert_eq!(first.context().field_path(), "client-identity/certificate");
    assert_eq!(
        first.reference().certificate_with_key(),
        Some((Some("secret-reference-key"), Some("secret-reference-certificate"),))
    );

    let debug = format!("{plan:?} {first:?} {:?}", first.reference());
    assert!(debug.contains("<redacted>"));
    for forbidden in [
        "secret-reference-key",
        "secret-reference-certificate",
        "secret-reference-ca",
        "10.0.5.1",
    ] {
        assert!(!debug.contains(forbidden), "debug exposed {forbidden}");
    }
}

#[test]
fn planning_requires_enumeration_and_rejects_incomplete_request() {
    let raw = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [{
                    "id": "local-secret-id",
                    "certificate": {
                        "central-keystore-reference": {"asymmetric-key": "central-key"}
                    }
                }],
                "server": [{
                    "name": "bundled",
                    "server-type": "accounting",
                    "address": "10.0.5.3",
                    "port": 49,
                    "client-identity": {"credentials-reference": "local-secret-id"}
                }]
            }
        }"#,
    )
    .expect("raw bundle config");
    let error = ResolutionPlan::from_server(&raw.tacacs_plus.server[0])
        .expect_err("raw local reference should fail");
    assert_eq!(error.kind(), ResolutionErrorKind::EnumerationRequired);
    assert!(error.to_string().contains("credentials-reference"));
    assert!(!error.to_string().contains("local-secret-id"));

    let enumerated = enumerate_servers(&raw.tacacs_plus).expect("enumerate bundle");
    ResolutionPlan::from_server(&enumerated[0]).expect("enumerated plan");

    let incomplete = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "incomplete",
                    "server-type": "accounting",
                    "address": "10.0.5.4",
                    "port": 49,
                    "client-identity": {
                        "certificate": {"central-keystore-reference": {}}
                    }
                }]
            }
        }"#,
    )
    .expect("generated central container is structurally valid");
    let error = ResolutionPlan::from_server(&incomplete.server[0])
        .expect_err("incomplete central request should fail planning");
    assert_eq!(error.kind(), ResolutionErrorKind::IncompleteRequest);
    assert_eq!(error.expected(), Some(CredentialKind::CertificateWithKey));
}

#[test]
fn resolution_plan_covers_all_variants_after_bundle_enumeration() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [
                    {
                        "id": "certificate-bundle",
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "../opaque bundle key",
                                "certificate": "opaque bundle certificate"
                            }
                        }
                    },
                    {
                        "id": "epsk-bundle",
                        "tls13-epsk": {
                            "central-keystore-reference": "opaque bundle symmetric key",
                            "external-identity": "bundle@example.test"
                        }
                    }
                ],
                "server-credentials": [{
                    "id": "trust-bundle",
                    "ca-certs": {"central-truststore-reference": "opaque bundle CA"},
                    "ee-certs": {"central-truststore-reference": "opaque bundle EE"}
                }],
                "server": [
                    {
                        "name": "certificate-server",
                        "server-type": "accounting",
                        "address": "10.0.5.5",
                        "port": 49,
                        "client-identity": {"credentials-reference": "certificate-bundle"},
                        "server-authentication": {"credentials-reference": "trust-bundle"}
                    },
                    {
                        "name": "epsk-server",
                        "server-type": "accounting",
                        "address": "10.0.5.6",
                        "port": 49,
                        "client-identity": {"credentials-reference": "epsk-bundle"}
                    }
                ]
            }
        }"#,
    )
    .expect("bundle config should parse");
    let servers = enumerate_servers(&config).expect("bundles should enumerate");
    let certificate_plan = ResolutionPlan::from_server(&servers[0]).expect("certificate plan");
    let epsk_plan = ResolutionPlan::from_server(&servers[1]).expect("EPSK plan");

    assert_eq!(
        certificate_plan
            .requests()
            .iter()
            .map(tacacsrs_credential_resolution::CredentialRequest::kind)
            .collect::<Vec<_>>(),
        [
            CredentialKind::CertificateWithKey,
            CredentialKind::CaCertificateBag,
            CredentialKind::EeCertificateBag,
        ]
    );
    assert_eq!(
        certificate_plan.requests()[0]
            .reference()
            .certificate_with_key(),
        Some((Some("../opaque bundle key"), Some("opaque bundle certificate"),))
    );
    assert_eq!(
        certificate_plan.requests()[1].reference().certificate_bag(),
        Some("opaque bundle CA")
    );
    assert_eq!(
        certificate_plan.requests()[2].reference().certificate_bag(),
        Some("opaque bundle EE")
    );
    assert_eq!(epsk_plan.requests().len(), 1);
    assert_eq!(epsk_plan.requests()[0].kind(), CredentialKind::SymmetricKey);
    assert_eq!(
        epsk_plan.requests()[0].reference().symmetric_key(),
        Some("opaque bundle symmetric key")
    );
}

#[test]
fn result_set_rejects_missing_duplicate_unexpected_and_mismatched_responses() {
    let plan = ResolutionPlan::from_server(&certificate_and_trust_server()).expect("plan");
    let slots = plan.requests();

    let missing = ResolvedCredentialSet::from_responses(
        &plan,
        [
            ResolvedResponse::new(slots[0].slot(), certificate_material()),
            ResolvedResponse::new(slots[1].slot(), ca_material()),
        ],
    )
    .expect_err("missing response should fail");
    assert_eq!(missing.kind(), ResolutionErrorKind::MissingResponse);
    assert_eq!(missing.slot(), Some(slots[2].slot()));

    let duplicate = ResolvedCredentialSet::from_responses(
        &plan,
        [
            ResolvedResponse::new(slots[0].slot(), certificate_material()),
            ResolvedResponse::new(slots[0].slot(), certificate_material()),
        ],
    )
    .expect_err("duplicate response should fail");
    assert_eq!(duplicate.kind(), ResolutionErrorKind::DuplicateResponse);

    let unexpected = ResolvedCredentialSet::from_responses(
        &plan,
        [ResolvedResponse::new(
            tacacsrs_credential_resolution::RequestSlot::from_index(99),
            certificate_material(),
        )],
    )
    .expect_err("unexpected slot should fail");
    assert_eq!(unexpected.kind(), ResolutionErrorKind::UnexpectedResponse);

    let mismatch = ResolvedCredentialSet::from_responses(
        &plan,
        [
            ResolvedResponse::new(
                slots[0].slot(),
                ResolvedCredential::SymmetricKey(SecretBytes::new(b"wrong-kind".to_vec())),
            ),
            ResolvedResponse::new(slots[1].slot(), ca_material()),
            ResolvedResponse::new(slots[2].slot(), ee_material()),
        ],
    )
    .expect_err("wrong variant should fail");
    assert_eq!(mismatch.kind(), ResolutionErrorKind::ResponseMismatch);
    assert_eq!(mismatch.expected(), Some(CredentialKind::CertificateWithKey));
    assert_eq!(mismatch.actual(), Some(CredentialKind::SymmetricKey));
}

#[tokio::test]
async fn provider_failures_are_typed_and_sanitized() {
    let plan = ResolutionPlan::from_server(&epsk_server()).expect("EPSK plan");
    let resolver = FakeCredentialResolver::new()
        .with_error(plan.requests()[0].slot(), ProviderErrorKind::AccessDenied);

    let error = resolve_plan(&plan, &resolver)
        .await
        .expect_err("provider error should propagate");
    assert_eq!(error.kind(), ResolutionErrorKind::AccessDenied);
    assert!(error.to_string().contains("client-identity/tls13-epsk"));
    assert!(!error.to_string().contains("secret-reference-epsk"));
    assert!(!format!("{error:?}").contains("secret-reference-epsk"));
}

#[test]
fn request_reference_variants_expose_only_matching_accessors() {
    let certificate = CredentialReference::CertificateWithKey {
        asymmetric_key: Some("key".to_owned()),
        certificate: None,
    };
    assert_eq!(certificate.certificate_with_key(), Some((Some("key"), None)));
    assert_eq!(certificate.symmetric_key(), None);
    assert_eq!(certificate.certificate_bag(), None);
}
