use std::path::PathBuf;

use crate::{
    get_resolved_server, parse_yang_json, parse_yang_json_file, pipeline,
    validate_credential_references, CredentialRefType, CredentialResolver, YangConfigRoot,
    TacacsPlusServerType,
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
                                "cert-data": "MIIB-client",
                                "cleartext-private-key": "MIIEv-client"
                            }
                        }
                    },
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
            ]
        }
    }"#;

    let config = parse_yang_json(json).unwrap();
    let s = &config.server[0];
    assert_eq!(s.server_type, TacacsPlusServerType::ACCOUNTING);
    assert_eq!(s.domain_name.as_deref(), Some("tacacs.example.com"));
    assert_eq!(s.sni_enabled, Some(true));
    assert!(s.single_connection);
    assert_eq!(s.timeout, 5); // default

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
        Some("MIIB-client"),
    );
    let sa = s.server_authentication.as_ref().unwrap();
    let ca = sa.ca_certs.as_ref().unwrap();
    let certs = &ca.inline_definition.as_ref().unwrap().certificate;
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].name, "ca1");
    assert_eq!(certs[0].cert_data, "MIIB...");
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
                    "shared-secret": "key"
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
                    "shared-secret": "key"
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
    }"#;

    let config = parse_yang_json(json).unwrap();
    let s = &config.server[0];

    let ci = s.client_identity.as_ref().unwrap();
    // References are preserved (NOT cleared) for round-tripping
    assert!(ci.credentials_reference.is_some());
    assert_eq!(ci.credentials_reference.as_deref(), Some("corp-cert"));
    // Inline material is NOT populated during parsing
    assert!(ci.certificate.is_none());

    // Server auth reference is also preserved
    let sa = s.server_authentication.as_ref().unwrap();
    assert!(sa.credentials_reference.is_some());
    assert_eq!(sa.credentials_reference.as_deref(), Some("corp-ca"));
    // Inline material is NOT populated during parsing
    assert!(sa.ca_certs.is_none());
}

#[test]
fn reject_missing_credential_reference() {
    // A server cannot reference a credential ID that doesn't exist in the config.
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
    assert!(
        err.to_string().contains("nonexistent"),
        "unexpected error: {err}",
    );
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
    assert!(err.to_string().contains("security choice is mandatory"), "unexpected error: {err}",);
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
                    "shared-secret": "key",
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [{"name": "ca1", "cert-data": "MIIB..."}]
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
            .contains("cannot use both TLS and shared-secret"),
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

#[cfg(not(feature = "psk"))]
#[test]
fn reject_tls13_epsk_without_psk_feature() {
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
                                "cleartext-symmetric-key": "topsecret"
                            },
                            "external-identity": "client@example.com"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("TLS 1.3 PSK requires the 'psk' feature flag"),
        "unexpected error: {err}",
    );
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
    assert!(
        err.to_string().contains("failed to read config file"),
        "unexpected error: {err}",
    );
}

#[test]
fn get_resolved_server_finds_server_by_name() {
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

    let resolvers: Vec<Box<dyn CredentialResolver>> = vec![];
    let result = get_resolved_server(&config, "exists", &resolvers);
    assert!(result.is_ok(), "expected successful lookup");
}

#[test]
fn get_resolved_server_rejects_unknown_name() {
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

    let resolvers: Vec<Box<dyn CredentialResolver>> = vec![];
    let err = get_resolved_server(&config, "missing", &resolvers).unwrap_err();
    assert!(
        err.to_string().contains("server 'missing' not found"),
        "unexpected error: {err}",
    );
}

#[test]
fn validate_credential_references_placeholder_returns_ok() {
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

    let resolvers: Vec<Box<dyn CredentialResolver>> = vec![];
    validate_credential_references(&config, &resolvers)
        .expect("placeholder validate_credential_references should return Ok");
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
    assert!(
        err.to_string().contains("at least one bit must be set"),
        "unexpected error: {err}",
    );
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
            .contains("client-credentials reference 'missing-client' not found"),
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
                                "cleartext-private-key": "KEY"
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
        err.to_string()
            .contains("client-identity/raw-private-key allows only one of [inline, central-keystore]"),
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
                                "cert-data": "CERT"
                            }
                        }
                    },
                    "hello-params": {
                        "tls-versions": {
                            "min": "tls12"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("minimum TLS version must be >= 1.3"));
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
                                "cert-data": "CERT"
                            }
                        }
                    },
                    "hello-params": {
                        "tls-versions": {
                            "max": "tls11"
                        }
                    }
                }
            ]
        }
    }"#;

    let err = parse_yang_json(json).unwrap_err();
    assert!(err.to_string().contains("maximum TLS version must be >= 1.3"));
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
                                "cert-data": "CERT"
                            }
                        }
                    },
                    "hello-params": {
                        "tls-versions": {
                            "min": "tls13",
                            "max": "tls13"
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

#[cfg(feature = "psk")]
#[test]
fn accept_tls13_epsk_when_psk_feature_enabled() {
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
                                "cleartext-symmetric-key": "topsecret"
                            },
                            "external-identity": "client@example.com"
                        }
                    }
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("tls13-epsk should parse with psk feature");
    assert_eq!(config.server.len(), 1);
    assert_eq!(config.server[0].name, "epsk-ok");
}

struct DummyResolver;

impl CredentialResolver for DummyResolver {
    fn resolve(
        &self,
        _key: &str,
        _ref_type: CredentialRefType,
    ) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
}

#[test]
fn credential_resolver_default_validate_calls_resolve() {
    let resolver = DummyResolver;
    resolver
        .validate("some-key", CredentialRefType::ClientCredential)
        .expect("default validate should succeed when resolver returns None");
}
