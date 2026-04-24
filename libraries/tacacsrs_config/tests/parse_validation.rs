use std::path::PathBuf;

use tacacsrs_config::{
    enumerate_server as resolve_server, parse_yang_json, parse_yang_json_file, pipeline,
    validate_credential_references, YangConfigRoot, TacacsPlusServerType,
};

fn write_temp_json_file(json: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let unique = format!(
        "tacacsrs-config-test-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos(),
    );
    path.push(unique);

    std::fs::write(&path, json).expect("should write temp json file");
    path
}

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
    assert_eq!(s.server_type, TacacsPlusServerType::AUTHENTICATION);
    assert_eq!(s.address, "192.0.2.2");
    assert_eq!(s.port, 49);
    assert_eq!(s.timeout, 10);
    assert!(!s.single_connection);
    assert_eq!(s.shared_secret.as_deref(), Some("QaEfThUkO198010075460923+h3TbE8n"));
    assert!(s.client_identity.is_none());
    assert!(s.server_authentication.is_none());
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
    assert!(st.contains(TacacsPlusServerType::AUTHENTICATION));
    assert!(st.contains(TacacsPlusServerType::AUTHORIZATION));
    assert!(st.contains(TacacsPlusServerType::ACCOUNTING));
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
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "dGVzdC1jZXJ0",
                                "cleartext-private-key": "dGVzdC1rZXk="
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {
                                        "name": "ca1",
                                        "cert-data": "dGVzdC1jZXJ0"
                                    }
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).unwrap();
    let s = &config.server[0];
    assert_eq!(s.server_type, TacacsPlusServerType::ACCOUNTING);
    assert_eq!(s.domain_name.as_deref(), Some("tacacs.example.com"));
    assert_eq!(s.sni_enabled, Some(true));
    assert!(s.single_connection);
    assert_eq!(s.timeout, 5);

    let client_identity = s.client_identity.as_ref().unwrap();
    assert_eq!(
        client_identity
            .certificate
            .as_ref()
            .unwrap()
            .inline_definition
            .as_ref()
            .unwrap()
            .cert_data
            .as_deref(),
        Some(b"test-cert".as_slice()),
    );
    let sa = s.server_authentication.as_ref().unwrap();
    let ca = sa.ca_certs.as_ref().unwrap();
    let certs = &ca.inline_definition.as_ref().unwrap().certificate;
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].name, "ca1");
    assert_eq!(certs[0].cert_data, b"test-cert");
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
    assert!(err.to_string().contains("duplicate server address+port"), "unexpected error: {err}");
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
                    "shared-secret": "a2V5"
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
    assert!(err.to_string().contains("at least one entry"), "unexpected error: {err}");
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
                    "shared-secret": "a2V5"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("unknown variant"), "unexpected error: {err}");
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
                    "shared-secret": "a2V5"
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).unwrap();
    assert_eq!(config.server[0].timeout, 5);
}

#[test]
fn credential_references_preserved_for_roundtrip() {
    let json = r#"{
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
    }"#;

    let config = parse_yang_json(json).unwrap();
    let s = &config.server[0];

    let ci = s.client_identity.as_ref().unwrap();
    assert!(ci.credentials_reference.is_some());
    assert_eq!(ci.credentials_reference.as_deref(), Some("corp-cert"));
    assert!(ci.certificate.is_none());

    let sa = s.server_authentication.as_ref().unwrap();
    assert!(sa.credentials_reference.is_some());
    assert_eq!(sa.credentials_reference.as_deref(), Some("corp-ca"));
    assert!(sa.ca_certs.is_none());
}

#[test]
fn reject_missing_credential_reference() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "needs-resolution",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 4949,
                    "server-authentication": {
                        "credentials-reference": "nonexistent"
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("nonexistent"), "unexpected error: {err}");
}

#[test]
fn reject_no_security() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bare",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("security requires one of [tls, obfuscation]"),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_tls_and_obfuscation() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "conflict",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "a2V5",
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [{"name": "ca1", "cert-data": "dGVzdC1jZXJ0"}]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("security allows only one of [tls, obfuscation]"),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_missing_inline_or_keystore_choice() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-cert-choice",
                    "server-type": "accounting",
                    "address": "10.0.0.5",
                    "port": 49,
                    "client-identity": {
                        "certificate": {}
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("client-identity/certificate requires one of [inline, central-keystore]"),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_missing_inline_or_truststore_choice() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-ca-choice",
                    "server-type": "accounting",
                    "address": "10.0.0.6",
                    "port": 49,
                    "server-authentication": {
                        "ca-certs": {}
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string().contains(
            "server-authentication/ca-certs requires one of [inline, central-truststore]"
        ),
        "unexpected error: {err}",
    );
}

#[test]
fn accept_tls13_epsk_config_without_runtime_psk_support() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "epsk-server",
                    "server-type": "accounting",
                    "address": "10.0.0.7",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "cleartext-symmetric-key": "dG9wc2VjcmV0"
                            },
                            "external-identity": "client@example.com"
                        }
                    }
                }
            ]
        }
    }"#;

    let config =
        parse_yang_json(json).expect("tls13-epsk config should parse without runtime PSK support");
    assert_eq!(config.server.len(), 1);
    assert_eq!(config.server[0].name, "epsk-server");
}

#[test]
fn yang_types_support_round_trip_serialization() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "roundtrip",
                    "server-type": "authentication authorization accounting",
                    "address": "192.0.2.2",
                    "port": 49,
                    "shared-secret": "secret123"
                }
            ]
        }
    }"#;

    let root: YangConfigRoot = serde_json::from_str(json).expect("root should deserialize");
    let serialized = serde_json::to_string(&root).expect("root should serialize");

    assert!(serialized.contains("\"ietf-system-tacacs-plus:tacacs-plus\""));
    assert!(serialized.contains("\"server-type\":\"authentication authorization accounting\""));
}

#[test]
fn parse_yang_json_file_parses_and_validates_config() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "from_file",
                    "server-type": "accounting",
                    "address": "10.0.0.9",
                    "port": 49,
                    "shared-secret": "secret123"
                }
            ]
        }
    }"#;

    let path = write_temp_json_file(json);
    let result = parse_yang_json_file(&path);
    let _ = std::fs::remove_file(&path);

    let config = result.expect("file-based parse should succeed");
    assert_eq!(config.server.len(), 1);
    assert_eq!(config.server[0].name, "from_file");
}

#[test]
fn pipeline_parse_root_json_file_reads_root_without_validation() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "root_only",
                    "server-type": "accounting",
                    "address": "10.0.0.15",
                    "port": 49,
                    "shared-secret": "abc"
                }
            ]
        }
    }"#;

    let path = write_temp_json_file(json);
    let result = pipeline::parse_root_json_file(&path);
    let _ = std::fs::remove_file(&path);

    let root = result.expect("root parse from file should succeed");
    assert_eq!(root.tacacs_plus.server.len(), 1);
    assert_eq!(root.tacacs_plus.server[0].name, "root_only");
}

#[test]
fn pipeline_parse_root_json_file_reports_missing_file() {
    let mut missing = std::env::temp_dir();
    missing.push("tacacsrs-config-test-does-not-exist.json");

    let err = pipeline::parse_root_json_file(&missing).unwrap_err();
    assert!(err.to_string().contains("failed to read config file"), "unexpected error: {err}");
}

#[test]
fn resolve_server_finds_server_by_name() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "exists",
                        "server-type": "accounting",
                        "address": "10.0.0.16",
                        "port": 49,
                        "shared-secret": "secret"
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let result = resolve_server(&config, "exists");
    assert!(result.is_ok(), "expected successful lookup");
}

#[test]
fn resolve_server_rejects_unknown_name() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "exists",
                        "server-type": "accounting",
                        "address": "10.0.0.17",
                        "port": 49,
                        "shared-secret": "secret"
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    let err = resolve_server(&config, "missing").unwrap_err();
    assert!(err.to_string().contains("server 'missing' not found"), "unexpected error: {err}");
}

#[test]
fn validate_credential_references_returns_ok_for_simple_config() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "s1",
                        "server-type": "accounting",
                        "address": "10.0.0.18",
                        "port": 49,
                        "shared-secret": "secret"
                    }
                ]
            }
        }"#,
    )
    .expect("config should parse");

    validate_credential_references(&config)
        .expect("validate_credential_references should return Ok for simple config");
}

#[test]
fn reject_empty_server_type_bitflags() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-type",
                    "server-type": "",
                    "address": "10.0.0.21",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("at least one bit must be set"), "unexpected error: {err}");
}

#[test]
fn reject_duplicate_client_credentials_ids() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {"id": "dup"},
                {"id": "dup"}
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.22",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("duplicate client-credentials id"));
}

#[test]
fn reject_duplicate_server_credentials_ids() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server-credentials": [
                {"id": "dup"},
                {"id": "dup"}
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.23",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("duplicate server-credentials id"));
}

#[test]
fn reject_missing_client_credential_reference() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "missing-client-ref",
                    "server-type": "accounting",
                    "address": "10.0.0.24",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "missing-client"
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("credentials-reference 'missing-client' not found"),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_raw_private_key_without_choice() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "raw-key-empty",
                    "server-type": "accounting",
                    "address": "10.0.0.25",
                    "port": 49,
                    "client-identity": {
                        "raw-private-key": {}
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("client-identity/raw-private-key requires one of [inline, central-keystore]"),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_raw_private_key_with_multiple_choices() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "raw-key-both",
                    "server-type": "accounting",
                    "address": "10.0.0.26",
                    "port": 49,
                    "client-identity": {
                        "raw-private-key": {
                            "inline-definition": {
                                "cleartext-private-key": "a2V5"
                            },
                            "central-keystore-reference": "keyref"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string().contains(
            "client-identity/raw-private-key allows only one of [inline, central-keystore]"
        ),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_raw_public_keys_without_choice() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "raw-pub-empty",
                    "server-type": "accounting",
                    "address": "10.0.0.27",
                    "port": 49,
                    "server-authentication": {
                        "raw-public-keys": {}
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string().contains(
            "server-authentication/raw-public-keys requires one of [inline, central-truststore]"
        ),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_raw_public_keys_with_multiple_choices() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "raw-pub-both",
                    "server-type": "accounting",
                    "address": "10.0.0.28",
                    "port": 49,
                    "server-authentication": {
                        "raw-public-keys": {
                            "inline-definition": {
                                "public-key": []
                            },
                            "central-truststore-reference": "ref"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string().contains(
            "server-authentication/raw-public-keys allows only one of [inline, central-truststore]"
        ),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_source_ip_and_source_interface_together() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-source-choice",
                    "server-type": "accounting",
                    "address": "10.0.0.60",
                    "port": 49,
                    "shared-secret": "secret",
                    "source-ip": "192.0.2.10",
                    "source-interface": "Ethernet0"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("source-type allows only one of [source-ip, source-interface]"),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_client_identity_reference_and_explicit_together() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "corp-cert",
                    "certificate": {
                        "inline-definition": {
                            "cert-data": "Y2VydA==",
                            "cleartext-private-key": "a2V5"
                        }
                    }
                }
            ],
            "server": [
                {
                    "name": "bad-ref-explicit",
                    "server-type": "accounting",
                    "address": "10.0.0.61",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "corp-cert",
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "Y2VydA==",
                                "cleartext-private-key": "a2V5"
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("client-identity allows only one of [ref, explicit/auth-type]"),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_server_auth_reference_and_explicit_together() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server-credentials": [
                {
                    "id": "corp-ca",
                    "ca-certs": {
                        "inline-definition": {
                            "certificate": [
                                {"name": "ca1", "cert-data": "Y2EtY2VydC0x"}
                            ]
                        }
                    }
                }
            ],
            "server": [
                {
                    "name": "bad-sa-ref-explicit",
                    "server-type": "accounting",
                    "address": "10.0.0.62",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "Y2VydA=="
                            }
                        }
                    },
                    "server-authentication": {
                        "credentials-reference": "corp-ca",
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "Y2EtY2VydC0x"}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("server-authentication allows only one of [ref, explicit]"),
        "unexpected error: {err}",
    );
}

#[test]
fn accept_server_authentication_with_ee_certs_only() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "ee-only",
                    "server-type": "accounting",
                    "address": "10.0.0.64",
                    "port": 49,
                    "server-authentication": {
                        "ee-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ee1", "cert-data": "ZWUtY2VydA=="}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("ee-certs explicit mode should be accepted");
    assert_eq!(config.server.len(), 1);
    assert_eq!(config.server[0].name, "ee-only");
}

#[test]
fn reject_client_credentials_with_multiple_auth_types() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "dup-auth-type",
                    "certificate": {
                        "inline-definition": {
                            "cert-data": "Y2VydA==",
                            "cleartext-private-key": "a2V5"
                        }
                    },
                    "raw-private-key": {
                        "inline-definition": {
                            "cleartext-private-key": "KEY2"
                        }
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.63",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("client-credentials/auth-type allows only one of [certificate, raw-public-key, tls13-epsk]"),
        "unexpected error: {err}",
    );
}

#[test]
fn accept_client_credentials_with_certificate_auth_type() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "cert-only",
                    "certificate": {
                        "inline-definition": {
                            "cert-data": "Y2VydA==",
                            "cleartext-private-key": "a2V5"
                        }
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.65",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("certificate auth-type should be accepted");
    assert_eq!(config.client_credentials.len(), 1);
    assert_eq!(config.client_credentials[0].id, "cert-only");
}

#[test]
fn accept_client_credentials_with_raw_private_key_auth_type() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "rpk-only",
                    "raw-private-key": {
                        "inline-definition": {
                            "cleartext-private-key": "a2V5"
                        }
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.66",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("raw-private-key auth-type should be accepted");
    assert_eq!(config.client_credentials.len(), 1);
    assert_eq!(config.client_credentials[0].id, "rpk-only");
}

#[test]
fn accept_client_credentials_with_tls13_epsk_auth_type() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "epsk-only",
                    "tls13-epsk": {
                        "inline-definition": {
                            "cleartext-symmetric-key": "dG9wc2VjcmV0"
                        },
                        "external-identity": "client@example.com"
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.67",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("tls13-epsk auth-type should be accepted with psk");
    assert_eq!(config.client_credentials.len(), 1);
    assert_eq!(config.client_credentials[0].id, "epsk-only");
}

#[test]
fn validation_maps_all_tacacs_plus_choice_mandatory_constants_to_expected_validators() {
    let generated = include_str!("../src/generated.rs");
    let validation = include_str!("../src/validation.rs");

    let tacacs_plus_start = generated
        .find("pub mod tacacs_plus {")
        .expect("generated.rs should contain tacacs_plus module");
    let keystore_start = generated
        .find("/// Types from `ietf-keystore`.")
        .expect("generated.rs should contain keystore module marker");
    let tacacs_plus_block = &generated[tacacs_plus_start..keystore_start];
    let generated_constants = generated_tacacs_plus_choice_mandatory_constants(tacacs_plus_block);
    let expected_mappings = expected_choice_mandatory_mappings();

    let expected_constants: std::collections::BTreeSet<&str> = expected_mappings
        .iter()
        .map(|(qualified_name, _)| *qualified_name)
        .collect();

    let generated_constant_refs: std::collections::BTreeSet<&str> =
        generated_constants.iter().map(String::as_str).collect();

    assert_eq!(
        generated_constant_refs, expected_constants,
        "generated choice mandatory constants changed; update this validator mapping test",
    );

    let normalized_validation = normalize_whitespace(validation);
    for (qualified_name, snippets) in expected_mappings {
        for snippet in snippets {
            let normalized_snippet = normalize_whitespace(snippet);
            assert!(
                normalized_validation.contains(&normalized_snippet),
                "validation.rs does not map {qualified_name} to expected validate_choice call: {snippet}",
            );
        }
    }
}

fn generated_tacacs_plus_choice_mandatory_constants(
    tacacs_plus_block: &str,
) -> std::collections::BTreeSet<String> {
    let generated_lines: Vec<&str> = tacacs_plus_block.lines().collect();

    generated_lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();
            if !trimmed.starts_with("pub const CHOICE_") || !trimmed.contains("_MANDATORY") {
                return None;
            }

            let constant_name = trimmed
                .split_whitespace()
                .nth(2)
                .map(|name| name.trim_end_matches(':').to_owned())?;
            let owner = generated_lines[..index]
                .iter()
                .rev()
                .find_map(|candidate| {
                    candidate
                        .trim()
                        .strip_prefix("impl ")
                        .and_then(|value| value.strip_suffix(" {"))
                })
                .expect("choice constant should be declared inside an impl block");

            Some(format!("{owner}::{constant_name}"))
        })
        .collect()
}

fn expected_choice_mandatory_mappings() -> Vec<(&'static str, &'static [&'static str])> {
    let mut mappings = Vec::new();
    mappings.extend(expected_server_choice_mappings());
    mappings.extend(expected_client_identity_choice_mappings());
    mappings.extend(expected_server_auth_choice_mappings());
    mappings.extend(expected_client_credentials_choice_mappings());
    mappings
}

fn expected_server_choice_mappings() -> [(&'static str, &'static [&'static str]); 2] {
    [
        (
            "TacacsPlusServer::CHOICE_SECURITY_MANDATORY",
            &[r#"
                validate_choice(
                    &server.name,
                    "security",
                    TacacsPlusServer::CHOICE_SECURITY,
                    TacacsPlusServer::CHOICE_SECURITY_MANDATORY,
                "#],
        ),
        (
            "TacacsPlusServer::CHOICE_SOURCE_TYPE_MANDATORY",
            &[r#"
                validate_choice(
                    &server.name,
                    "source-type",
                    TacacsPlusServer::CHOICE_SOURCE_TYPE,
                    TacacsPlusServer::CHOICE_SOURCE_TYPE_MANDATORY,
                "#],
        ),
    ]
}

fn expected_client_identity_choice_mappings() -> [(&'static str, &'static [&'static str]); 4] {
    [
        (
            "TlsClientClientIdentity::CHOICE_REF_OR_EXPLICIT_MANDATORY",
            &[r#"
                validate_choice(
                    &server.name,
                    "client-identity",
                    TlsClientClientIdentity::CHOICE_REF_OR_EXPLICIT,
                    TlsClientClientIdentity::CHOICE_REF_OR_EXPLICIT_MANDATORY,
                "#],
        ),
        (
            "ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE_MANDATORY",
            &[
                r#"
                validate_choice(
                    &server.name,
                    "client-identity/certificate",
                    ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE,
                    ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
                "#,
                r#"
                validate_choice(
                    &credentials.id,
                    "client-credentials/certificate",
                    ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE,
                    ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
                "#,
            ],
        ),
        (
            "RawPrivateKey::CHOICE_INLINE_OR_KEYSTORE_MANDATORY",
            &[
                r#"
                validate_choice(
                    &server.name,
                    "client-identity/raw-private-key",
                    RawPrivateKey::CHOICE_INLINE_OR_KEYSTORE,
                    RawPrivateKey::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
                "#,
                r#"
                validate_choice(
                    &credentials.id,
                    "client-credentials/raw-private-key",
                    RawPrivateKey::CHOICE_INLINE_OR_KEYSTORE,
                    RawPrivateKey::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
                "#,
            ],
        ),
        (
            "Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE_MANDATORY",
            &[
                r#"
                validate_choice(
                    &server.name,
                    "client-identity/tls13-epsk",
                    Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE,
                    Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
                "#,
                r#"
                validate_choice(
                    &credentials.id,
                    "client-credentials/tls13-epsk",
                    Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE,
                    Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE_MANDATORY,
                "#,
            ],
        ),
    ]
}

fn expected_server_auth_choice_mappings() -> [(&'static str, &'static [&'static str]); 3] {
    [
        (
            "TlsClientServerAuthentication::CHOICE_REF_OR_EXPLICIT_MANDATORY",
            &[r#"
                validate_choice(
                    &server.name,
                    "server-authentication",
                    TlsClientServerAuthentication::CHOICE_REF_OR_EXPLICIT,
                    TlsClientServerAuthentication::CHOICE_REF_OR_EXPLICIT_MANDATORY,
                "#],
        ),
        (
            "ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY",
            &[r#"
                validate_choice(
                    &server.name,
                    "server-authentication/ca-certs",
                    ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE,
                    ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY,
                "#],
        ),
        (
            "ServerAuthenticationRawPublicKeys::CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY",
            &[r#"
                validate_choice(
                    &server.name,
                    "server-authentication/raw-public-keys",
                    ServerAuthenticationRawPublicKeys::CHOICE_INLINE_OR_TRUSTSTORE,
                    ServerAuthenticationRawPublicKeys::CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY,
                "#],
        ),
    ]
}

fn expected_client_credentials_choice_mappings() -> [(&'static str, &'static [&'static str]); 1] {
    [(
        "ClientCredentials::CHOICE_AUTH_TYPE_MANDATORY",
        &[r#"
                validate_choice(
                    &credentials.id,
                    "client-credentials/auth-type",
                    ClientCredentials::CHOICE_AUTH_TYPE,
                    ClientCredentials::CHOICE_AUTH_TYPE_MANDATORY,
                "#],
    )]
}

fn normalize_whitespace(input: &str) -> String {
    input.split_whitespace().collect()
}

#[test]
fn reject_tls_version_min_below_13() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "tls-min-bad",
                    "server-type": "accounting",
                    "address": "10.0.0.29",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "Y2VydA=="
                            }
                        }
                    },
                    "hello-params": {
                        "tls-versions": {
                            "min": "ietf-tls-common:tls12"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err
        .to_string()
        .contains("minimum TLS version must be >= 1.3"));
}

#[test]
fn reject_tls_version_max_below_13() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "tls-max-bad",
                    "server-type": "accounting",
                    "address": "10.0.0.30",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "Y2VydA=="
                            }
                        }
                    },
                    "hello-params": {
                        "tls-versions": {
                            "max": "ietf-tls-common:tls12"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err
        .to_string()
        .contains("maximum TLS version must be >= 1.3"));
}

#[test]
fn accept_tls_versions_at_or_above_13() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "tls-bounds-ok",
                    "server-type": "accounting",
                    "address": "10.0.0.31",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "Y2VydA=="
                            }
                        }
                    },
                    "hello-params": {
                        "tls-versions": {
                            "min": "ietf-tls-common:tls13",
                            "max": "ietf-tls-common:tls13"
                        }
                    }
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("tls version bounds should be accepted");
    assert_eq!(config.server.len(), 1);
    assert_eq!(config.server[0].name, "tls-bounds-ok");
}

#[test]
fn accept_tls_hello_params_without_tls_versions() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "tls-empty-hello",
                    "server-type": "accounting",
                    "address": "10.0.0.33",
                    "port": 49,
                    "hello-params": {}
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("empty hello-params should be accepted");
    assert_eq!(config.server.len(), 1);
    assert_eq!(config.server[0].name, "tls-empty-hello");
    assert!(config.server[0].hello_params.is_some());
}

#[test]
fn accept_tls13_epsk_when_present() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "epsk-ok",
                    "server-type": "accounting",
                    "address": "10.0.0.32",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "cleartext-symmetric-key": "dG9wc2VjcmV0"
                            },
                            "external-identity": "client@example.com"
                        }
                    }
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("tls13-epsk should parse");
    assert_eq!(config.server.len(), 1);
    assert_eq!(config.server[0].name, "epsk-ok");
}

#[test]
fn reject_tls13_epsk_with_multiple_choice_sources() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "epsk-bad-choice",
                    "server-type": "accounting",
                    "address": "10.0.0.34",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "cleartext-symmetric-key": "dG9wc2VjcmV0"
                            },
                            "central-keystore-reference": "keyref",
                            "external-identity": "client@example.com"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).expect_err("tls13-epsk with multiple choices must fail");
    assert!(
        err.to_string()
            .contains("client-identity/tls13-epsk allows only one of [inline, central-keystore]"),
        "unexpected error: {err}",
    );
}

// ---------------------------------------------------------------------------
// Key-format identityref validation
// ---------------------------------------------------------------------------

#[test]
fn accept_valid_private_key_format() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "tls1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "domain-name": "tacacs.example.com",
                    "sni-enabled": true,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "public-key-format": "ietf-crypto-types:subject-public-key-info-format",
                                "public-key": "dGVzdA==",
                                "private-key-format": "ietf-crypto-types:rsa-private-key-format",
                                "cleartext-private-key": "dGVzdA==",
                                "cert-data": "dGVzdA=="
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "dGVzdC1jZXJ0"}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    parse_yang_json(json).expect("valid key formats should be accepted");
}

#[test]
fn reject_invalid_private_key_format() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "tls1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "domain-name": "tacacs.example.com",
                    "sni-enabled": true,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "private-key-format": "bogus-format",
                                "cleartext-private-key": "dGVzdA==",
                                "cert-data": "dGVzdA=="
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "dGVzdC1jZXJ0"}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("unknown variant `bogus-format`"), "unexpected error: {message}");
}

#[test]
fn reject_invalid_public_key_format() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "tls1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "domain-name": "tacacs.example.com",
                    "sni-enabled": true,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "public-key-format": "not-a-real-format",
                                "public-key": "dGVzdA==",
                                "private-key-format": "ietf-crypto-types:rsa-private-key-format",
                                "cleartext-private-key": "dGVzdA==",
                                "cert-data": "dGVzdA=="
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "dGVzdC1jZXJ0"}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("unknown variant `not-a-real-format`"), "unexpected error: {message}");
}

#[test]
fn reject_invalid_symmetric_key_format() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "epsk-cred",
                    "tls13-epsk": {
                        "inline-definition": {
                            "key-format": "bad-format",
                            "cleartext-symmetric-key": "dGVzdA=="
                        },
                        "external-identity": "test-id",
                        "hash": "sha-256"
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "epsk-cred"
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "dGVzdC1jZXJ0"}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("unknown variant `bad-format`"), "unexpected error: {message}");
}

#[test]
fn accept_valid_symmetric_key_format() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "epsk-cred",
                    "tls13-epsk": {
                        "inline-definition": {
                            "key-format": "ietf-crypto-types:octet-string-key-format",
                            "cleartext-symmetric-key": "dGVzdA=="
                        },
                        "external-identity": "test-id",
                        "hash": "sha-256"
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "epsk-cred"
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "dGVzdC1jZXJ0"}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    parse_yang_json(json).expect("valid symmetric key format should be accepted");
}

// ---------------------------------------------------------------------------
// Inline key material validation
// ---------------------------------------------------------------------------

#[test]
fn reject_invalid_base64_in_private_key() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-key",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "cleartext-private-key": "not valid base64!!!",
                                "cert-data": "dGVzdA=="
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "dGVzdA=="}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("Invalid symbol"), "unexpected error: {message}");
}

#[test]
fn reject_invalid_base64_in_cert_data() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-cert",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "!!!not-base64!!!"}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("Invalid symbol"), "unexpected error: {message}");
}

#[test]
fn reject_empty_private_key() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "empty-key",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "cleartext-private-key": "",
                                "cert-data": "dGVzdA=="
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "dGVzdA=="}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("cleartext-private-key must not be empty"),
        "unexpected error: {err}",
    );
}

#[test]
fn reject_pem_certificate_data() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "pem-server",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----"}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("Invalid symbol"), "unexpected error: {message}");
}

#[test]
fn reject_pem_without_end_marker() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-pem",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "-----BEGIN CERTIFICATE-----\ndGVzdA=="}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("Invalid symbol"), "unexpected error: {message}");
}

#[test]
fn reject_invalid_base64_in_symmetric_key() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "bad-epsk",
                    "tls13-epsk": {
                        "inline-definition": {
                            "cleartext-symmetric-key": "not!!!valid!!!base64"
                        },
                        "external-identity": "test-id",
                        "hash": "sha-256"
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "bad-epsk"
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ca1", "cert-data": "dGVzdA=="}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("Invalid symbol"), "unexpected error: {message}");
}

// ---------------------------------------------------------------------------
// Unsupported inline key feature validation
// ---------------------------------------------------------------------------

#[test]
fn reject_hidden_private_key_in_server_certificate() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "hidden-key",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "hidden-private-key": true,
                                "cert-data": "dGVzdA=="
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("hidden-private-key"), "unexpected error: {err}");
}

#[test]
fn reject_encrypted_private_key_in_server_certificate() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "enc-key",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "encrypted-private-key": {
                                    "encrypted-value-format": "ietf-crypto-types:cms-encrypted-data-format",
                                    "encrypted-value": "dGVzdA=="
                                },
                                "cert-data": "dGVzdA=="
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("encrypted-private-key"), "unexpected error: {err}");
}

#[test]
fn reject_hidden_private_key_in_raw_private_key() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "hidden-rpk",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "raw-private-key": {
                            "inline-definition": {
                                "hidden-private-key": true
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("hidden-private-key"), "unexpected error: {err}");
}

#[test]
fn reject_hidden_symmetric_key_in_epsk() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "hidden-epsk",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "hidden-symmetric-key": true
                            },
                            "external-identity": "id"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("hidden-symmetric-key"), "unexpected error: {err}");
}

#[test]
fn reject_encrypted_symmetric_key_in_epsk() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "enc-epsk",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "encrypted-symmetric-key": {
                                    "encrypted-value-format": "ietf-crypto-types:cms-encrypted-data-format",
                                    "encrypted-value": "dGVzdA=="
                                }
                            },
                            "external-identity": "id"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("encrypted-symmetric-key"), "unexpected error: {err}");
}

#[test]
fn reject_epsk_context_derivation() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "epsk-ctx",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "cleartext-symmetric-key": "dG9wc2VjcmV0"
                            },
                            "external-identity": "id",
                            "context": "some-context"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("context"), "unexpected error: {err}");
}

#[test]
fn reject_epsk_target_protocol() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "epsk-proto",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "cleartext-symmetric-key": "dG9wc2VjcmV0"
                            },
                            "external-identity": "id",
                            "target-protocol": 1
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("target-protocol"), "unexpected error: {err}");
}

#[test]
fn reject_epsk_target_kdf() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "epsk-kdf",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "cleartext-symmetric-key": "dG9wc2VjcmV0"
                            },
                            "external-identity": "id",
                            "target-kdf": 1
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("target-kdf"), "unexpected error: {err}");
}

#[test]
fn reject_hidden_private_key_in_client_credentials() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "hidden-cred",
                    "certificate": {
                        "inline-definition": {
                            "hidden-private-key": true,
                            "cert-data": "dGVzdA=="
                        }
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("hidden-private-key"), "unexpected error: {err}");
}

#[test]
fn reject_encrypted_private_key_in_client_credentials_rpk() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "enc-cred",
                    "raw-private-key": {
                        "inline-definition": {
                            "encrypted-private-key": {
                                "encrypted-value-format": "ietf-crypto-types:cms-encrypted-data-format",
                                "encrypted-value": "dGVzdA=="
                            }
                        }
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("encrypted-private-key"), "unexpected error: {err}");
}

#[test]
fn reject_epsk_context_in_client_credentials() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "epsk-ctx-cred",
                    "tls13-epsk": {
                        "inline-definition": {
                            "cleartext-symmetric-key": "dG9wc2VjcmV0"
                        },
                        "external-identity": "id",
                        "context": "some-ctx"
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("context"), "unexpected error: {err}");
}

// ---------------------------------------------------------------------------
// Key-format validation in additional code paths
// ---------------------------------------------------------------------------

#[test]
fn reject_invalid_key_format_in_client_credentials_rpk() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "bad-rpk-fmt",
                    "raw-private-key": {
                        "inline-definition": {
                            "private-key-format": "bogus-format",
                            "cleartext-private-key": "dGVzdA=="
                        }
                    }
                }
            ],
            "server": [
                {
                    "name": "s1",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "secret"
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("unknown variant `bogus-format`"), "unexpected error: {message}");
}

#[test]
fn reject_invalid_rpk_public_key_format_in_server_auth() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-rpk-sa",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "server-authentication": {
                        "raw-public-keys": {
                            "inline-definition": {
                                "public-key": [
                                    {
                                        "name": "pk1",
                                        "public-key-format": "bad-format",
                                        "public-key": "dGVzdA=="
                                    }
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("unknown variant `bad-format`"), "unexpected error: {message}");
}

#[test]
fn reject_invalid_ee_cert_data() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-ee",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "server-authentication": {
                        "ee-certs": {
                            "inline-definition": {
                                "certificate": [
                                    {"name": "ee1", "cert-data": "!!!not-base64!!!"}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("Invalid symbol"), "unexpected error: {message}");
}

#[test]
fn reject_invalid_key_format_in_server_rpk() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-srv-rpk",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "raw-private-key": {
                            "inline-definition": {
                                "private-key-format": "invalid",
                                "cleartext-private-key": "dGVzdA=="
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("unknown variant `invalid`"), "unexpected error: {message}");
}

#[test]
fn reject_invalid_symmetric_key_format_in_server_epsk() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "bad-srv-epsk",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "key-format": "bogus",
                                "cleartext-symmetric-key": "dGVzdA=="
                            },
                            "external-identity": "id"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("unknown variant `bogus`"), "unexpected error: {message}");
}
