use tacacsrs_config::{enumerate_servers, parse_yang_json, pipeline, validate_credential_references};

#[test]
fn enumerate_servers_inlines_credential_bundles() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [
                    {
                        "id": "corp-cert",
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "dGVzdC1jZXJ0",
                                "cleartext-private-key": "dGVzdC1rZXk="
                            }
                        }
                    }
                ],
                "server-credentials": [
                    {
                        "id": "corp-ca",
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "dGVzdC1jZXJ0"}
                                ]
                            }
                        }
                    }
                ],
                "server": [
                    {
                        "name": "tls-server",
                        "server-type": "accounting",
                        "address": "10.0.0.1",
                        "port": 4949,
                        "client-identity": {
                            "credentials-reference": "corp-cert"
                        },
                        "server-authentication": {
                            "credentials-reference": "corp-ca"
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let enumerated = enumerate_servers(&config).expect("enumeration should succeed");
    assert_eq!(enumerated.len(), 1);

    let server = &enumerated[0];
    let client_identity = server
        .client_identity
        .as_ref()
        .expect("client identity should exist");
    assert!(client_identity.credentials_reference.is_none());
    let certificate = client_identity
        .certificate
        .as_ref()
        .expect("certificate should be inlined from bundle");
    let inline_certificate = certificate
        .inline_definition
        .as_ref()
        .expect("certificate inline definition should exist");
    assert_eq!(inline_certificate.cert_data.as_deref(), Some(b"test-cert".as_slice()),);
    assert_eq!(
        inline_certificate
            .cleartext_private_key
            .as_ref()
            .map(tacacsrs_secrets::SecretBytes::expose_secret),
        Some(b"test-key".as_slice()),
    );

    let server_authentication = server
        .server_authentication
        .as_ref()
        .expect("server authentication should exist");
    assert!(server_authentication.credentials_reference.is_none());
    let ca_certs = server_authentication
        .ca_certs
        .as_ref()
        .expect("ca certs should be inlined from bundle");
    let inline_certs = ca_certs
        .inline_definition
        .as_ref()
        .expect("ca cert inline definition should exist");
    assert_eq!(inline_certs.certificate.len(), 1);
    assert_eq!(inline_certs.certificate[0].cert_data, b"test-cert");
}

#[test]
#[allow(clippy::too_many_lines)] // One snapshot assertion covers every preserved nested field.
fn enumerate_servers_preserves_all_nested_central_references_and_metadata() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [
                    {
                        "id": "central-cert",
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "opaque/asymmetric key",
                                "certificate": "opaque certificate"
                            }
                        }
                    },
                    {
                        "id": "central-epsk",
                        "tls13-epsk": {
                            "central-keystore-reference": "opaque symmetric key",
                            "external-identity": "client@example.test",
                            "hash": "sha-384",
                            "context": "provider context",
                            "target-protocol": 7,
                            "target-kdf": 9,
                            "tacacsrs:psk-dhe-ke-groups": ["secp384r1", "x25519"]
                        }
                    }
                ],
                "server-credentials": [
                    {
                        "id": "central-trust",
                        "ca-certs": {
                            "central-truststore-reference": "opaque CA bag"
                        },
                        "ee-certs": {
                            "central-truststore-reference": "opaque EE bag"
                        }
                    }
                ],
                "server": [
                    {
                        "name": "certificate-server",
                        "server-type": "accounting",
                        "address": "10.0.0.10",
                        "port": 49,
                        "client-identity": {"credentials-reference": "central-cert"},
                        "server-authentication": {"credentials-reference": "central-trust"}
                    },
                    {
                        "name": "epsk-server",
                        "server-type": "accounting",
                        "address": "10.0.0.11",
                        "port": 49,
                        "client-identity": {"credentials-reference": "central-epsk"}
                    }
                ]
            }
        }"#,
    )
    .expect("central bundle config should parse");

    let enumerated = enumerate_servers(&config).expect("enumeration should succeed");
    let certificate_identity = enumerated[0]
        .client_identity
        .as_ref()
        .expect("certificate identity");
    assert!(certificate_identity.credentials_reference.is_none());
    let certificate_reference = certificate_identity
        .certificate
        .as_ref()
        .and_then(|certificate| certificate.central_keystore_reference.as_ref())
        .expect("central certificate reference");
    assert_eq!(certificate_reference.asymmetric_key.as_deref(), Some("opaque/asymmetric key"));
    assert_eq!(certificate_reference.certificate.as_deref(), Some("opaque certificate"));

    let server_authentication = enumerated[0]
        .server_authentication
        .as_ref()
        .expect("server authentication");
    assert!(server_authentication.credentials_reference.is_none());
    assert_eq!(
        server_authentication
            .ca_certs
            .as_ref()
            .and_then(|certificates| certificates.central_truststore_reference.as_deref()),
        Some("opaque CA bag")
    );
    assert_eq!(
        server_authentication
            .ee_certs
            .as_ref()
            .and_then(|certificates| certificates.central_truststore_reference.as_deref()),
        Some("opaque EE bag")
    );

    let epsk_identity = enumerated[1]
        .client_identity
        .as_ref()
        .expect("EPSK identity");
    assert!(epsk_identity.credentials_reference.is_none());
    let epsk = epsk_identity.tls13_epsk.as_ref().expect("central EPSK");
    assert_eq!(epsk.central_keystore_reference.as_deref(), Some("opaque symmetric key"));
    assert_eq!(epsk.external_identity, "client@example.test");
    assert_eq!(epsk.hash, tacacsrs_config::EpskSupportedHash::Sha384);
    assert_eq!(epsk.context.as_deref(), Some("provider context"));
    assert_eq!(epsk.target_protocol, Some(7));
    assert_eq!(epsk.target_kdf, Some(9));
    assert_eq!(
        epsk.psk_dhe_ke_groups,
        [
            tacacsrs_config::PskDheKeSupportedGroup::Secp384r1,
            tacacsrs_config::PskDheKeSupportedGroup::X25519,
        ]
    );
}

#[test]
fn central_references_are_not_validated_as_local_bundle_ids() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "central-direct",
                    "server-type": "accounting",
                    "address": "10.0.0.12",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "missing-local-bundle",
                                "certificate": "also-not-local"
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "central-truststore-reference": "not-a-local-server-bundle"
                        }
                    }
                }]
            }
        }"#,
    )
    .expect("raw central references should parse");

    validate_credential_references(&root.tacacs_plus)
        .expect("external central references are not config-local bundle IDs");
}

#[test]
fn validate_credential_references_collects_missing_client_bundle_ref() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "missing-client",
                    "server-type": "accounting",
                    "address": "10.0.0.3",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "nonexistent-client"
                    }
                }]
            }
        }"#,
    )
    .expect("raw root should parse");

    let error =
        validate_credential_references(&root.tacacs_plus).expect_err("validation should fail");
    let message = error.to_string();
    assert!(message.contains("nonexistent-client"), "error: {message}");
    assert!(message.contains("client-identity credentials-reference"), "error: {message}");
}

#[test]
fn validate_credential_references_collects_missing_server_bundle_ref() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "missing-server",
                    "server-type": "accounting",
                    "address": "10.0.0.4",
                    "port": 49,
                    "server-authentication": {
                        "credentials-reference": "nonexistent-server"
                    }
                }]
            }
        }"#,
    )
    .expect("raw root should parse");

    let error =
        validate_credential_references(&root.tacacs_plus).expect_err("validation should fail");
    let message = error.to_string();
    assert!(message.contains("nonexistent-server"), "error: {message}");
    assert!(message.contains("server-authentication credentials-reference"), "error: {message}");
}

#[test]
fn validate_credential_references_collects_multiple_missing_bundle_refs() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "server-one",
                        "server-type": "accounting",
                        "address": "10.0.0.5",
                        "port": 49,
                        "client-identity": {
                            "credentials-reference": "missing-client"
                        }
                    },
                    {
                        "name": "server-two",
                        "server-type": "accounting",
                        "address": "10.0.0.6",
                        "port": 50,
                        "server-authentication": {
                            "credentials-reference": "missing-server"
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("raw root should parse");

    let error =
        validate_credential_references(&root.tacacs_plus).expect_err("validation should fail");
    let message = error.to_string();
    assert!(message.contains("missing-client"), "error: {message}");
    assert!(message.contains("missing-server"), "error: {message}");
}
