use tacacsrs_config::{parse_yang_json, pipeline, to_connection_configs, ResolvedSecurity};

#[test]
fn to_connection_configs_maps_inline_tls_material() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "tls_inline",
                        "server-type": "accounting",
                        "address": "10.0.0.10",
                        "port": 4949,
                        "client-identity": {
                            "certificate": {
                                "inline-definition": {
                                    "cert-data": "CLIENT_CERT_PEM",
                                    "cleartext-private-key": "CLIENT_KEY_PEM"
                                }
                            }
                        },
                        "server-authentication": {
                            "ca-certs": {
                                "inline-definition": {
                                    "certificate": [
                                        {"name": "ca1", "cert-data": "CA_CERT_1"},
                                        {"name": "ca2", "cert-data": "CA_CERT_2"}
                                    ]
                                }
                            }
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let servers = to_connection_configs(&config).expect("mapping should succeed");
    assert_eq!(servers.len(), 1);

    let server = &servers[0];
    assert_eq!(server.name, "tls_inline");
    assert_eq!(server.address, "10.0.0.10");
    assert_eq!(server.port, 4949);

    assert!(matches!(&server.security, ResolvedSecurity::Tls { .. }));
    if let ResolvedSecurity::Tls {
        client_cert_pem,
        client_key_pem,
        ca_certs_pem,
        insecure_disable_certificate_verification,
    } = &server.security
    {
        assert_eq!(client_cert_pem.as_deref(), Some("CLIENT_CERT_PEM"));
        assert_eq!(client_key_pem.as_deref(), Some("CLIENT_KEY_PEM"));
        assert_eq!(
            ca_certs_pem,
            &vec!["CA_CERT_1".to_owned(), "CA_CERT_2".to_owned()],
        );
        assert!(!insecure_disable_certificate_verification);
    }
}

#[cfg(feature = "psk")]
#[test]
fn to_connection_configs_maps_tls13_epsk_to_psk() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "epsk-server",
                        "server-type": "accounting",
                        "address": "10.0.0.2",
                        "port": 49,
                        "client-identity": {
                            "tls13-epsk": {
                                "inline-definition": {
                                    "cleartext-symmetric-key": "topsecret"
                                },
                                "external-identity": "client@example.com"
                            }
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let servers = to_connection_configs(&config).expect("mapping should succeed");
    assert_eq!(servers.len(), 1);

    assert!(matches!(servers[0].security, ResolvedSecurity::Psk { .. }));
    if let ResolvedSecurity::Psk { identity, key } = &servers[0].security {
        assert_eq!(identity, "client@example.com");
        assert_eq!(key, "topsecret");
    }
}

#[test]
fn to_connection_configs_accepts_reference_based_tls_server() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [
                    {
                        "id": "corp-cert",
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "MIIB...",
                                "cleartext-private-key": "MIIEv..."
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
                                    {"name": "ca1", "cert-data": "MIIB..."}
                                ]
                            }
                        }
                    }
                ],
                "server": [
                    {
                        "name": "tls_server",
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

    let servers = to_connection_configs(&config).expect("mapping should succeed");
    assert_eq!(servers.len(), 1);

    let server = &servers[0];
    assert_eq!(server.name, "tls_server");
    assert_eq!(server.address, "10.0.0.1");
    assert_eq!(server.port, 4949);

    assert!(matches!(&server.security, ResolvedSecurity::Tls { .. }));
    if let ResolvedSecurity::Tls {
        client_cert_pem,
        client_key_pem,
        ca_certs_pem,
        ..
    } = &server.security
    {
        assert!(client_cert_pem.is_none());
        assert!(client_key_pem.is_none());
        assert!(ca_certs_pem.is_empty());
    }
}

#[test]
fn to_connection_configs_maps_tls_security_without_inline_material() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "tls_keystore_refs",
                        "server-type": "accounting",
                        "address": "10.0.0.11",
                        "port": 49,
                        "client-identity": {
                            "certificate": {
                                "central-keystore-reference": {
                                    "asymmetric-key": "key-1",
                                    "certificate": "cert-1"
                                }
                            }
                        },
                        "server-authentication": {
                            "ca-certs": {
                                "central-truststore-reference": "truststore-ca-id"
                            }
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let servers = to_connection_configs(&config).expect("mapping should succeed");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name, "tls_keystore_refs");

    assert!(matches!(&servers[0].security, ResolvedSecurity::Tls { .. }));
    if let ResolvedSecurity::Tls {
        client_cert_pem,
        client_key_pem,
        ca_certs_pem,
        ..
    } = &servers[0].security
    {
        assert!(client_cert_pem.is_none());
        assert!(client_key_pem.is_none());
        assert!(ca_certs_pem.is_empty());
    }
}

#[test]
fn to_connection_configs_maps_tls_hello_only_server() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "tls_hello_only",
                        "server-type": "accounting",
                        "address": "10.0.0.42",
                        "port": 49,
                        "hello-params": {
                            "tls-versions": {
                                "min": "tls13"
                            }
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let servers = to_connection_configs(&config).expect("mapping should succeed");
    assert_eq!(servers.len(), 1);

    assert!(matches!(&servers[0].security, ResolvedSecurity::Tls { .. }));
    if let ResolvedSecurity::Tls {
        client_cert_pem,
        client_key_pem,
        ca_certs_pem,
        ..
    } = &servers[0].security
    {
        assert!(client_cert_pem.is_none());
        assert!(client_key_pem.is_none());
        assert!(ca_certs_pem.is_empty());
    }
}

#[test]
fn to_connection_configs_maps_shared_secret_obfuscation_literal() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "obf_server",
                        "server-type": "accounting",
                        "address": "10.0.0.20",
                        "port": 49,
                        "shared-secret": "corp-shared-secret"
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let servers = to_connection_configs(&config).expect("mapping should succeed");
    assert_eq!(servers.len(), 1);

    let server = &servers[0];
    assert_eq!(server.name, "obf_server");
    assert_eq!(server.address, "10.0.0.20");
    assert_eq!(server.port, 49);

    assert!(matches!(&server.security, ResolvedSecurity::Obfuscation { .. }));
    if let ResolvedSecurity::Obfuscation { shared_secret } = &server.security {
        assert_eq!(shared_secret.as_deref(), Some("corp-shared-secret"));
    }
}

#[test]
fn socket_address_returns_address_and_port() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "sock",
                        "server-type": "accounting",
                        "address": "192.0.2.10",
                        "port": 4049,
                        "shared-secret": "secret"
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let servers = to_connection_configs(&config).expect("mapping should succeed");
    assert_eq!(servers[0].socket_address(), "192.0.2.10:4049");
}

#[test]
fn to_connection_configs_maps_tls_server_auth_only_no_client_identity() {
    // server_authentication is Some, client_identity is None — exercises the
    // decisive `|| server_authentication.is_some()` arm in resolve_security.
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "sa_only",
                        "server-type": "accounting",
                        "address": "10.0.0.50",
                        "port": 49,
                        "server-authentication": {
                            "ca-certs": {
                                "inline-definition": {
                                    "certificate": [
                                        {"name": "ca1", "cert-data": "CA_CERT"}
                                    ]
                                }
                            }
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let servers = to_connection_configs(&config).expect("mapping should succeed");
    assert_eq!(servers.len(), 1);

    assert!(matches!(&servers[0].security, ResolvedSecurity::Tls { .. }));
    if let ResolvedSecurity::Tls { client_cert_pem, client_key_pem, ca_certs_pem, .. } =
        &servers[0].security
    {
        assert!(client_cert_pem.is_none());
        assert!(client_key_pem.is_none());
        assert_eq!(ca_certs_pem, &vec!["CA_CERT".to_owned()]);
    }
}

#[test]
fn to_connection_configs_maps_none_obfuscation_for_unvalidated_server_without_security() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "bare",
                        "server-type": "accounting",
                        "address": "10.0.0.30",
                        "port": 49
                    }
                ]
            }
        }"#,
    )
    .expect("root should parse without validation");

    let servers = to_connection_configs(&root.tacacs_plus).expect("mapping should succeed");
    assert_eq!(servers.len(), 1);

    assert!(matches!(&servers[0].security, ResolvedSecurity::Obfuscation { .. }));
    if let ResolvedSecurity::Obfuscation { shared_secret } = &servers[0].security {
        assert!(shared_secret.is_none());
    }
}
