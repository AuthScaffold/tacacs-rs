use tacacsrs_config::{
    enumerate_server, enumerate_servers, parse_yang_json, pipeline, validate_credential_references,
};

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
    assert_eq!(inline_certificate.cleartext_private_key.as_deref(), Some(b"test-key".as_slice()),);

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
fn enumerate_server_preserves_external_references_from_bundles() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [
                    {
                        "id": "client-bundle",
                        "raw-private-key": {
                            "central-keystore-reference": "ext-key"
                        }
                    }
                ],
                "server-credentials": [
                    {
                        "id": "server-bundle",
                        "ca-certs": {
                            "central-truststore-reference": "ext-ca"
                        }
                    }
                ],
                "server": [
                    {
                        "name": "bundled-external",
                        "server-type": "accounting",
                        "address": "10.0.0.2",
                        "port": 49,
                        "client-identity": {
                            "credentials-reference": "client-bundle"
                        },
                        "server-authentication": {
                            "credentials-reference": "server-bundle"
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let enumerated = enumerate_server(&config, "bundled-external")
        .expect("enumeration should succeed for named server");

    let raw_private_key = enumerated
        .client_identity
        .as_ref()
        .and_then(|identity| identity.raw_private_key.as_ref())
        .expect("raw private key should be copied from bundle");
    assert!(raw_private_key.central_keystore_reference.as_deref() == Some("ext-key"));
    assert!(raw_private_key.inline_definition.is_none());

    let ca_certs = enumerated
        .server_authentication
        .as_ref()
        .and_then(|authentication| authentication.ca_certs.as_ref())
        .expect("ca certs should be copied from bundle");
    assert!(ca_certs.central_truststore_reference.as_deref() == Some("ext-ca"));
    assert!(ca_certs.inline_definition.is_none());
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
    assert!(message.contains("server-authentication credentials-reference"), "error: {message}",);
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
