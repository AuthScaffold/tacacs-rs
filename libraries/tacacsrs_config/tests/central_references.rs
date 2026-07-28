use tacacsrs_config::{
    CentralCredentialReference, CentralCredentialUsage, UnexpandedCredentialField,
    enumerate_servers, inspect_central_references, parse_yang_json, pipeline,
};

#[test]
fn inspection_emits_deterministic_typed_slots_without_interpreting_references() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "certificate-and-trust",
                        "server-type": "accounting",
                        "address": "10.0.4.1",
                        "port": 49,
                        "client-identity": {
                            "certificate": {
                                "central-keystore-reference": {
                                    "asymmetric-key": "../outside SONiC grammar",
                                    "certificate": "certificate with spaces"
                                }
                            }
                        },
                        "server-authentication": {
                            "ca-certs": {
                                "central-truststore-reference": "CA/bag with spaces"
                            },
                            "ee-certs": {
                                "central-truststore-reference": "EE:bag:opaque"
                            }
                        }
                    },
                    {
                        "name": "epsk",
                        "server-type": "accounting",
                        "address": "10.0.4.2",
                        "port": 49,
                        "client-identity": {
                            "tls13-epsk": {
                                "central-keystore-reference": "symmetric key opaque value",
                                "external-identity": "client@example.test"
                            }
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("central references should parse");

    let first =
        inspect_central_references(&config.server[0]).expect("direct server is inspectable");
    assert_eq!(
        first
            .iter()
            .map(tacacsrs_config::CentralCredentialSlot::usage)
            .collect::<Vec<_>>(),
        [
            CentralCredentialUsage::ClientCertificateWithKey,
            CentralCredentialUsage::ServerCaCertificateBag,
            CentralCredentialUsage::ServerEeCertificateBag,
        ]
    );
    assert_eq!(first[0].server_name(), "certificate-and-trust");
    assert_eq!(
        first[0].reference(),
        CentralCredentialReference::CertificateWithKey {
            asymmetric_key: Some("../outside SONiC grammar"),
            certificate: Some("certificate with spaces"),
        }
    );
    assert_eq!(
        first[1].reference(),
        CentralCredentialReference::CertificateBag("CA/bag with spaces")
    );
    assert_eq!(first[2].reference(), CentralCredentialReference::CertificateBag("EE:bag:opaque"));

    let second = inspect_central_references(&config.server[1]).expect("EPSK server is inspectable");
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].usage(), CentralCredentialUsage::ClientTls13Epsk);
    assert_eq!(
        second[0].reference(),
        CentralCredentialReference::SymmetricKey("symmetric key opaque value")
    );
}

#[test]
fn inspection_requires_config_local_bundles_to_be_enumerated_first() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [{
                    "id": "do-not-disclose-this-local-id",
                    "certificate": {
                        "central-keystore-reference": {
                            "asymmetric-key": "central-key"
                        }
                    }
                }],
                "server": [{
                    "name": "bundled-server",
                    "server-type": "accounting",
                    "address": "10.0.4.3",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "do-not-disclose-this-local-id"
                    }
                }]
            }
        }"#,
    )
    .expect("raw config should parse");

    let error = inspect_central_references(&root.tacacs_plus.server[0])
        .expect_err("raw local bundle reference must require enumeration");
    assert_eq!(error.server_name(), "bundled-server");
    assert_eq!(error.field(), UnexpandedCredentialField::ClientIdentity);
    assert!(error.to_string().contains("enumerate_server"));
    assert!(!error.to_string().contains("do-not-disclose-this-local-id"));

    let enumerated = enumerate_servers(&root.tacacs_plus).expect("bundle should enumerate");
    let slots =
        inspect_central_references(&enumerated[0]).expect("enumerated server is inspectable");
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].usage(), CentralCredentialUsage::ClientCertificateWithKey);
}

#[test]
fn inspection_preserves_structurally_incomplete_central_certificate_for_planning() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "incomplete-central",
                    "server-type": "accounting",
                    "address": "10.0.4.4",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {}
                        }
                    }
                }]
            }
        }"#,
    )
    .expect("generated model permits an empty central container");

    let slots = inspect_central_references(&config.server[0]).expect("server is inspectable");
    assert_eq!(
        slots[0].reference(),
        CentralCredentialReference::CertificateWithKey {
            asymmetric_key: None,
            certificate: None,
        }
    );
}

#[test]
fn slot_debug_output_redacts_all_opaque_reference_values() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "debug-server",
                    "server-type": "accounting",
                    "address": "10.0.4.5",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "never-render-this-reference",
                            "external-identity": "client@example.test"
                        }
                    }
                }]
            }
        }"#,
    )
    .expect("central EPSK should parse");

    let slots = inspect_central_references(&config.server[0]).expect("server is inspectable");
    let debug = format!("{:?} {:?}", slots[0], slots[0].reference());
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("never-render-this-reference"));
    assert!(!debug.contains("10.0.4.5"));
}
