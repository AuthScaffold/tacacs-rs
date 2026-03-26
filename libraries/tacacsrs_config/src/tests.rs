use crate::{parse_yang_json, ServerType};

#[test]
fn parse_minimal_obfuscation_config() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "tac_plus1",
                    "server-type": "authentication",
                    "address": "192.0.2.2",
                    "port": 49,
                    "shared-secret": "QaEfThUkO198010075460923+h3TbE8n",
                    "source-ip": "192.0.2.12",
                    "timeout": 10
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("should parse minimal config");
    assert_eq!(config.server.len(), 1);

    let s = &config.server[0];
    assert_eq!(s.name, "tac_plus1");
    assert_eq!(s.server_type, ServerType::AUTHENTICATION);
    assert_eq!(s.address, "192.0.2.2");
    assert_eq!(s.port, 49);
    assert_eq!(s.timeout, 10);
    assert!(!s.single_connection);

    match &s.security {
        crate::Security::Obfuscation(secret) => {
            assert_eq!(secret, "QaEfThUkO198010075460923+h3TbE8n");
        }
        crate::Security::Tls(_) => panic!("expected obfuscation security"),
    }
}

#[test]
fn parse_multi_type_server() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "all_services",
                    "server-type": "authentication authorization accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "secret123"
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).unwrap();
    let st = config.server[0].server_type;
    assert!(st.contains(ServerType::AUTHENTICATION));
    assert!(st.contains(ServerType::AUTHORIZATION));
    assert!(st.contains(ServerType::ACCOUNTING));
}

#[test]
fn parse_tls_config() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "tls_server",
                    "server-type": "accounting",
                    "address": "10.0.0.2",
                    "port": 4949,
                    "domain-name": "tacacs.example.com",
                    "sni-enabled": true,
                    "single-connection": true,
                    "tls": {
                        "server-authentication": {
                            "ca-certs": {
                                "inline-definition": {
                                    "certificate": [
                                        {
                                            "name": "ca1",
                                            "cert-data": "MIIB..."
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).unwrap();
    let s = &config.server[0];
    assert_eq!(s.server_type, ServerType::ACCOUNTING);
    assert_eq!(s.domain_name.as_deref(), Some("tacacs.example.com"));
    assert_eq!(s.sni_enabled, Some(true));
    assert!(s.single_connection);
    assert_eq!(s.timeout, 5); // default

    match &s.security {
        crate::Security::Tls(tls) => {
            assert!(tls.client_identity.is_none());
            let sa = tls.server_authentication.inline.as_ref().unwrap();
            assert!(sa.ca_certs.is_some());
            let ca = sa.ca_certs.as_ref().unwrap();
            let certs = &ca.inline_definition.as_ref().unwrap().certificate;
            assert_eq!(certs.len(), 1);
            assert_eq!(certs[0].name, "ca1");
            assert_eq!(certs[0].cert_data, "MIIB...");
        }
        crate::Security::Obfuscation(_) => panic!("expected TLS security"),
    }
}

#[test]
fn parse_multiple_servers_with_failover_order() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "primary",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "key1"
                },
                {
                    "name": "secondary",
                    "server-type": "accounting",
                    "address": "10.0.0.2",
                    "port": 49,
                    "shared-secret": "key2"
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).unwrap();
    assert_eq!(config.server.len(), 2);
    assert_eq!(config.server[0].name, "primary");
    assert_eq!(config.server[1].name, "secondary");
}

#[test]
fn reject_duplicate_address_port() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "key1"
                },
                {
                    "name": "s2",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "key2"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("duplicate server address+port"), "unexpected error: {err}",);
}

#[test]
fn reject_sni_without_domain_name() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "sni-enabled": true,
                    "shared-secret": "key"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string().contains("sni-enabled requires domain-name"),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_empty_server_list() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": []
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("at least one entry"), "unexpected error: {err}",);
}

#[test]
fn reject_invalid_server_type() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad",
                    "server-type": "invalid_type",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "key"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("unknown variant"), "unexpected error: {err}",);
}

#[test]
fn default_timeout_applied() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "key"
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).unwrap();
    assert_eq!(config.server[0].timeout, 5);
}

#[test]
fn credential_reference_resolution() {
    let json = r#"{
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
                    "tls": {
                        "client-identity": {
                            "credentials-reference": "corp-cert"
                        },
                        "server-authentication": {
                            "credentials-reference": "corp-ca"
                        }
                    }
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).unwrap();
    let s = &config.server[0];
    match &s.security {
        crate::Security::Tls(tls) => {
            let ci = tls.client_identity.as_ref().unwrap();
            // Reference should be resolved — inline value populated.
            assert!(ci.auth_type.is_some());
            assert!(ci.credentials_reference.is_none());

            // Server auth reference should be resolved.
            assert!(tls.server_authentication.inline.is_some());
            assert!(tls.server_authentication.credentials_reference.is_none());
        }
        crate::Security::Obfuscation(_) => panic!("expected TLS security"),
    }
}

#[test]
fn reject_missing_credential_reference() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 4949,
                    "tls": {
                        "server-authentication": {
                            "credentials-reference": "nonexistent"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("not found"), "unexpected error: {err}",);
}
