use tacacsrs_config::crypto_types::{PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat};
use tacacsrs_config::{parse_yang_json, PskDheKeSupportedGroup, TacacsPlusServerType};

// ---------------------------------------------------------------------------
// PublicKeyFormat identity enum
// ---------------------------------------------------------------------------

#[test]
fn public_key_format_from_rfc7951_str_valid() {
    assert_eq!(
        PublicKeyFormat::from_rfc7951_str("ietf-crypto-types:ssh-public-key-format"),
        Some(PublicKeyFormat::SshPublicKeyFormat),
    );
    assert_eq!(
        PublicKeyFormat::from_rfc7951_str("ietf-crypto-types:subject-public-key-info-format"),
        Some(PublicKeyFormat::SubjectPublicKeyInfoFormat),
    );
}

#[test]
fn public_key_format_from_rfc7951_str_invalid() {
    assert_eq!(PublicKeyFormat::from_rfc7951_str("bogus"), None);
    assert_eq!(PublicKeyFormat::from_rfc7951_str(""), None);
}

#[test]
fn public_key_format_as_rfc7951_str() {
    assert_eq!(
        PublicKeyFormat::SshPublicKeyFormat.as_rfc7951_str(),
        "ietf-crypto-types:ssh-public-key-format",
    );
    assert_eq!(
        PublicKeyFormat::SubjectPublicKeyInfoFormat.as_rfc7951_str(),
        "ietf-crypto-types:subject-public-key-info-format",
    );
}

#[test]
fn public_key_format_is_valid() {
    assert!(PublicKeyFormat::is_valid("ietf-crypto-types:ssh-public-key-format"));
    assert!(PublicKeyFormat::is_valid("ietf-crypto-types:subject-public-key-info-format"));
    assert!(!PublicKeyFormat::is_valid("bogus"));
}

#[test]
fn public_key_format_all_and_allowed_values() {
    assert_eq!(PublicKeyFormat::ALL.len(), 2);
    assert_eq!(PublicKeyFormat::ALLOWED_VALUES.len(), 2);
    for variant in PublicKeyFormat::ALL {
        assert!(PublicKeyFormat::ALLOWED_VALUES.contains(&variant.as_rfc7951_str()));
    }
}

// ---------------------------------------------------------------------------
// PrivateKeyFormat identity enum
// ---------------------------------------------------------------------------

#[test]
fn private_key_format_from_rfc7951_str_valid() {
    assert_eq!(
        PrivateKeyFormat::from_rfc7951_str("ietf-crypto-types:rsa-private-key-format"),
        Some(PrivateKeyFormat::RsaPrivateKeyFormat),
    );
    assert_eq!(
        PrivateKeyFormat::from_rfc7951_str("ietf-crypto-types:ec-private-key-format"),
        Some(PrivateKeyFormat::EcPrivateKeyFormat),
    );
    assert_eq!(
        PrivateKeyFormat::from_rfc7951_str("ietf-crypto-types:one-asymmetric-key-format"),
        Some(PrivateKeyFormat::OneAsymmetricKeyFormat),
    );
}

#[test]
fn private_key_format_from_rfc7951_str_invalid() {
    assert_eq!(PrivateKeyFormat::from_rfc7951_str("unknown"), None);
}

#[test]
fn private_key_format_as_rfc7951_str() {
    assert_eq!(
        PrivateKeyFormat::RsaPrivateKeyFormat.as_rfc7951_str(),
        "ietf-crypto-types:rsa-private-key-format",
    );
    assert_eq!(
        PrivateKeyFormat::EcPrivateKeyFormat.as_rfc7951_str(),
        "ietf-crypto-types:ec-private-key-format",
    );
    assert_eq!(
        PrivateKeyFormat::OneAsymmetricKeyFormat.as_rfc7951_str(),
        "ietf-crypto-types:one-asymmetric-key-format",
    );
}

#[test]
fn private_key_format_is_valid() {
    assert!(PrivateKeyFormat::is_valid("ietf-crypto-types:rsa-private-key-format"));
    assert!(PrivateKeyFormat::is_valid("ietf-crypto-types:ec-private-key-format"));
    assert!(PrivateKeyFormat::is_valid("ietf-crypto-types:one-asymmetric-key-format"));
    assert!(!PrivateKeyFormat::is_valid("bogus"));
}

#[test]
fn private_key_format_all_and_allowed_values() {
    assert_eq!(PrivateKeyFormat::ALL.len(), 3);
    assert_eq!(PrivateKeyFormat::ALLOWED_VALUES.len(), 3);
    for variant in PrivateKeyFormat::ALL {
        assert!(PrivateKeyFormat::ALLOWED_VALUES.contains(&variant.as_rfc7951_str()));
    }
}

// ---------------------------------------------------------------------------
// SymmetricKeyFormat identity enum
// ---------------------------------------------------------------------------

#[test]
fn symmetric_key_format_from_rfc7951_str_valid() {
    assert_eq!(
        SymmetricKeyFormat::from_rfc7951_str("ietf-crypto-types:octet-string-key-format"),
        Some(SymmetricKeyFormat::OctetStringKeyFormat),
    );
    assert_eq!(
        SymmetricKeyFormat::from_rfc7951_str("ietf-crypto-types:one-symmetric-key-format"),
        Some(SymmetricKeyFormat::OneSymmetricKeyFormat),
    );
}

#[test]
fn symmetric_key_format_from_rfc7951_str_invalid() {
    assert_eq!(SymmetricKeyFormat::from_rfc7951_str("nope"), None);
}

#[test]
fn symmetric_key_format_as_rfc7951_str() {
    assert_eq!(
        SymmetricKeyFormat::OctetStringKeyFormat.as_rfc7951_str(),
        "ietf-crypto-types:octet-string-key-format",
    );
    assert_eq!(
        SymmetricKeyFormat::OneSymmetricKeyFormat.as_rfc7951_str(),
        "ietf-crypto-types:one-symmetric-key-format",
    );
}

#[test]
fn symmetric_key_format_is_valid() {
    assert!(SymmetricKeyFormat::is_valid("ietf-crypto-types:octet-string-key-format"));
    assert!(SymmetricKeyFormat::is_valid("ietf-crypto-types:one-symmetric-key-format"));
    assert!(!SymmetricKeyFormat::is_valid("bad"));
}

#[test]
fn symmetric_key_format_all_and_allowed_values() {
    assert_eq!(SymmetricKeyFormat::ALL.len(), 2);
    assert_eq!(SymmetricKeyFormat::ALLOWED_VALUES.len(), 2);
    for variant in SymmetricKeyFormat::ALL {
        assert!(SymmetricKeyFormat::ALLOWED_VALUES.contains(&variant.as_rfc7951_str()));
    }
}

// ---------------------------------------------------------------------------
// TacacsPlusServerType serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn server_type_serialize_single_flag() {
    let root = tacacsrs_config::model::YangConfigRoot {
        tacacs_plus: tacacsrs_config::TacacsPlus {
            client_credentials: vec![],
            server_credentials: vec![],
            server: vec![tacacsrs_config::TacacsPlusServer {
                name: "s".to_owned(),
                server_type: TacacsPlusServerType::AUTHORIZATION,
                address: "10.0.0.1".to_owned(),
                port: 49,
                domain_name: None,
                sni_enabled: None,
                single_connection: false,
                timeout: 5,
                source_ip: None,
                source_interface: None,
                shared_secret: Some("key".to_owned()),
                client_identity: None,
                server_authentication: None,
                vrf_instance: None,
            }],
        },
    };

    let serialized = serde_json::to_string(&root).expect("should serialize");
    assert!(serialized.contains("\"server-type\":\"authorization\""));
}

#[test]
fn server_type_serialize_two_flags() {
    let root = tacacsrs_config::model::YangConfigRoot {
        tacacs_plus: tacacsrs_config::TacacsPlus {
            client_credentials: vec![],
            server_credentials: vec![],
            server: vec![tacacsrs_config::TacacsPlusServer {
                name: "s".to_owned(),
                server_type: TacacsPlusServerType::AUTHENTICATION
                    | TacacsPlusServerType::ACCOUNTING,
                address: "10.0.0.1".to_owned(),
                port: 49,
                domain_name: None,
                sni_enabled: None,
                single_connection: false,
                timeout: 5,
                source_ip: None,
                source_interface: None,
                shared_secret: Some("key".to_owned()),
                client_identity: None,
                server_authentication: None,
                vrf_instance: None,
            }],
        },
    };

    let serialized = serde_json::to_string(&root).expect("should serialize");
    assert!(serialized.contains("\"server-type\":\"authentication accounting\""));
}

#[test]
fn server_type_deserialize_partial_flags() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "partial",
                    "server-type": "authentication accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "shared-secret": "key"
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).unwrap();
    let st = config.server[0].server_type;
    assert!(st.contains(TacacsPlusServerType::AUTHENTICATION));
    assert!(!st.contains(TacacsPlusServerType::AUTHORIZATION));
    assert!(st.contains(TacacsPlusServerType::ACCOUNTING));
}

// ---------------------------------------------------------------------------
// EpskSupportedHash: explicit sha-384 selection
// ---------------------------------------------------------------------------

#[test]
fn epsk_hash_sha384_explicit() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "sha384-epsk",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "cleartext-symmetric-key": "dG9wc2VjcmV0"
                            },
                            "external-identity": "id@example.com",
                            "hash": "sha-384"
                        }
                    }
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("sha-384 should be accepted");
    let epsk = config.server[0]
        .client_identity
        .as_ref()
        .unwrap()
        .tls13_epsk
        .as_ref()
        .unwrap();
    assert!(matches!(epsk.hash, tacacsrs_config::EpskSupportedHash::Sha384));
}

// ---------------------------------------------------------------------------
// PSK DHE supported groups augmentation
// ---------------------------------------------------------------------------

#[test]
fn psk_dhe_groups_deserializes_rfc7951_augmented_leaf_list() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "dhe-group",
                    "server-type": "accounting",
                    "address": "10.0.0.1",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "inline-definition": {
                                "cleartext-symmetric-key": "dG9wc2VjcmV0"
                            },
                            "external-identity": "id@example.com",
                            "tacacsrs-tls-psk-dhe:psk-dhe-ke-groups": [
                                "x25519",
                                "ffdhe3072"
                            ]
                        }
                    }
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("PSK DHE groups should deserialize");
    let groups = &config.server[0]
        .client_identity
        .as_ref()
        .and_then(|identity| identity.tls13_epsk.as_ref())
        .expect("tls13-epsk should be present")
        .psk_dhe_ke_groups;
    assert!(matches!(groups.first(), Some(PskDheKeSupportedGroup::X25519)));
    assert!(matches!(groups.get(1), Some(PskDheKeSupportedGroup::Ffdhe3072)));
}
