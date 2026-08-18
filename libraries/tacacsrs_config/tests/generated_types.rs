#![allow(clippy::assertions_on_constants)]

use tacacsrs_config::crypto_types::{PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat};
use tacacsrs_config::{parse_yang_json, PskDheKeSupportedGroup, TacacsPlusServerType};
use tacacsrs_config::{TacacsPlusBuilder, TacacsPlusServerBuilder};

const _: () =
    assert!(tacacsrs_config::ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE_MANDATORY);
const _: () = assert!(tacacsrs_config::Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE_MANDATORY);
const _: () =
    assert!(tacacsrs_config::ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE_MANDATORY);

#[test]
fn generated_central_certificate_shape_and_choice_metadata() {
    let certificate = tacacsrs_config::ClientIdentityCertificate {
        inline_definition: None,
        central_keystore_reference: Some(
            tacacsrs_config::keystore::EndEntityCertWithKeyCentralKeystoreReference {
                asymmetric_key: Some("opaque-asymmetric-key".to_owned()),
                certificate: Some("opaque-certificate".to_owned()),
            },
        ),
    };
    let bundle = tacacsrs_config::ClientCredentials {
        id: "bundle".to_owned(),
        certificate: Some(certificate),
        tls13_epsk: None,
    };

    assert_eq!(
        tacacsrs_config::ClientIdentityCertificate::CHOICE_INLINE_OR_KEYSTORE,
        &[
            ("inline", &["inline-definition"][..]),
            ("central-keystore", &["central-keystore-reference"][..]),
        ],
    );
    let serialized = serde_json::to_value(bundle).expect("central certificate must serialize");
    assert_eq!(
        serialized["certificate"]["central-keystore-reference"]["asymmetric-key"],
        "opaque-asymmetric-key",
    );
    assert_eq!(
        serialized["certificate"]["central-keystore-reference"]["certificate"],
        "opaque-certificate",
    );
}

#[test]
fn generated_central_epsk_shape_preserves_protocol_metadata() {
    let epsk = tacacsrs_config::Tls13Epsk {
        inline_definition: None,
        central_keystore_reference: Some("opaque-symmetric-key".to_owned()),
        external_identity: "client@example.test".to_owned(),
        hash: tacacsrs_config::EpskSupportedHash::Sha384,
        context: Some("role-context".to_owned()),
        target_protocol: Some(7),
        target_kdf: Some(9),
        psk_dhe_ke_groups: vec![PskDheKeSupportedGroup::Secp384r1],
    };
    let bundle = tacacsrs_config::ClientCredentials {
        id: "bundle".to_owned(),
        certificate: None,
        tls13_epsk: Some(epsk),
    };

    assert_eq!(
        tacacsrs_config::Tls13Epsk::CHOICE_INLINE_OR_KEYSTORE,
        &[
            ("inline", &["inline-definition"][..]),
            ("central-keystore", &["central-keystore-reference"][..]),
        ],
    );
    let serialized = serde_json::to_value(bundle).expect("central EPSK must serialize");
    let epsk = &serialized["tls13-epsk"];
    assert_eq!(epsk["central-keystore-reference"], "opaque-symmetric-key");
    assert_eq!(epsk["external-identity"], "client@example.test");
    assert_eq!(epsk["hash"], "sha-384");
    assert_eq!(epsk["context"], "role-context");
    assert_eq!(epsk["target-protocol"], 7);
    assert_eq!(epsk["target-kdf"], 9);
    assert_eq!(epsk["tacacsrs:psk-dhe-ke-groups"][0], "secp384r1");
}

#[test]
fn generated_central_trust_shape_is_shared_by_direct_and_bundle_ca_ee_fields() {
    let trust = tacacsrs_config::ServerAuthenticationCaCerts {
        inline_definition: None,
        central_truststore_reference: Some("opaque-certificate-bag".to_owned()),
    };
    let bundle = tacacsrs_config::ServerCredentials {
        id: "bundle".to_owned(),
        ca_certs: Some(trust.clone()),
        ee_certs: Some(trust),
        tls13_epsks: None,
    };

    assert_eq!(
        tacacsrs_config::ServerAuthenticationCaCerts::CHOICE_INLINE_OR_TRUSTSTORE,
        &[
            ("inline", &["inline-definition"][..]),
            ("central-truststore", &["central-truststore-reference"][..]),
        ],
    );
    let serialized = serde_json::to_value(bundle).expect("central trust must serialize");
    assert_eq!(serialized["ca-certs"]["central-truststore-reference"], "opaque-certificate-bag",);
    assert_eq!(serialized["ee-certs"]["central-truststore-reference"], "opaque-certificate-bag",);
}

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
                shared_secret: Some(tacacsrs_secrets::SecretString::new("key".to_owned())),
                client_identity: None,
                server_authentication: None,
                vrf_instance: None,
            }],
        },
    };

    let serialized = serde_json::to_string(&root).expect("root must serialize");
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
                shared_secret: Some(tacacsrs_secrets::SecretString::new("key".to_owned())),
                client_identity: None,
                server_authentication: None,
                vrf_instance: None,
            }],
        },
    };

    let serialized = serde_json::to_string(&root).expect("root must serialize");
    assert!(serialized.contains("\"server-type\":\"authentication accounting\""));
}

#[test]
fn serialization_omits_absent_optionals_and_empty_lists() {
    let root = tacacsrs_config::model::YangConfigRoot {
        tacacs_plus: TacacsPlusBuilder::new()
            .with_server(
                TacacsPlusServerBuilder::new(
                    "tls",
                    TacacsPlusServerType::ACCOUNTING,
                    "127.0.0.1",
                    4449,
                )
                .with_tls_server_authentication()
                .build(),
            )
            .build()
            .expect("builder root must be valid"),
    };

    let serialized = serde_json::to_string(&root).expect("root must serialize");

    assert!(!serialized.contains(":null"), "serialized JSON must omit null fields: {serialized}");
    assert!(
        !serialized.contains("\"client-credentials\":[]"),
        "serialized JSON must omit the empty client-credentials list: {serialized}"
    );
    assert!(
        !serialized.contains("\"server-credentials\":[]"),
        "serialized JSON must omit the empty server-credentials list: {serialized}"
    );
    assert!(
        serialized.contains("\"server-authentication\":{}"),
        "serialized JSON must preserve the empty TLS choice container: {serialized}"
    );
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

    let config = parse_yang_json(json).expect("sha-384 must be accepted");
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
fn psk_dhe_group_from_str_uses_rfc7951_values() {
    assert!(matches!(
        "secp384r1".parse::<PskDheKeSupportedGroup>(),
        Ok(PskDheKeSupportedGroup::Secp384r1),
    ));
    assert_eq!(PskDheKeSupportedGroup::X25519.as_rfc7951_str(), "x25519");
    assert!(PskDheKeSupportedGroup::ALLOWED_VALUES.contains(&"ffdhe8192"));
}

#[test]
fn psk_dhe_group_from_str_rejects_unknown_values() {
    let error = "secp224r1"
        .parse::<PskDheKeSupportedGroup>()
        .expect_err("unknown group must fail");

    assert!(error.contains("secp224r1"));
    assert!(error.contains("secp384r1"));
}

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
                            "tacacsrs:psk-dhe-ke-groups": [
                                "x25519",
                                "ffdhe3072"
                            ]
                        }
                    }
                }
            ]
        }
    }"#;

    let config = parse_yang_json(json).expect("PSK-DHE groups must deserialize");
    let groups = &config.server[0]
        .client_identity
        .as_ref()
        .and_then(|identity| identity.tls13_epsk.as_ref())
        .expect("tls13-epsk must be present")
        .psk_dhe_ke_groups;
    assert!(matches!(groups.first(), Some(PskDheKeSupportedGroup::X25519)));
    assert!(matches!(groups.get(1), Some(PskDheKeSupportedGroup::Ffdhe3072)));
}

#[test]
fn generated_parent_debug_and_serialization_redact_all_secret_fields() {
    let config = protected_config();

    let debug = format!("{config:?}");
    let serialized =
        serde_json::to_string(&config).expect("protected configuration must serialize");

    for raw_secret in ["shared-secret-sentinel", "private-secret", "epsk-secret"] {
        assert!(!debug.contains(raw_secret));
        assert!(!serialized.contains(raw_secret));
    }
    for encoded_secret in ["cHJpdmF0ZS1zZWNyZXQ=", "ZXBzay1zZWNyZXQ="] {
        assert!(!serialized.contains(encoded_secret));
    }
    assert_eq!(debug.matches("<redacted>").count(), 3);
    assert_eq!(serialized.matches("<redacted>").count(), 3);
}

#[test]
fn generated_parent_equality_compares_actual_secret_values() {
    let config = protected_config();

    let mut changed_shared_secret = config.clone();
    changed_shared_secret.server[0].shared_secret =
        Some(tacacsrs_secrets::SecretString::new("replacement-shared-secret".to_owned()));
    assert_ne!(config, changed_shared_secret);

    let mut changed_epsk = config.clone();
    changed_epsk.server[1]
        .client_identity
        .as_mut()
        .unwrap()
        .tls13_epsk
        .as_mut()
        .unwrap()
        .inline_definition
        .as_mut()
        .unwrap()
        .cleartext_symmetric_key =
        Some(tacacsrs_secrets::SecretBytes::new(b"replacement-epsk-secret".to_vec()));
    assert_ne!(config, changed_epsk);

    let mut changed_private_key = config.clone();
    changed_private_key.client_credentials[0]
        .certificate
        .as_mut()
        .unwrap()
        .inline_definition
        .as_mut()
        .unwrap()
        .cleartext_private_key =
        Some(tacacsrs_secrets::SecretBytes::new(b"replacement-private-secret".to_vec()));
    assert_ne!(config, changed_private_key);
}

fn protected_config() -> tacacsrs_config::TacacsPlus {
    parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [
                    {
                        "id": "client-certificate",
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "Y2VydGlmaWNhdGU=",
                                "cleartext-private-key": "cHJpdmF0ZS1zZWNyZXQ="
                            }
                        }
                    }
                ],
                "server": [
                    {
                        "name": "shared-secret",
                        "server-type": "authentication",
                        "address": "192.0.2.1",
                        "port": 49,
                        "shared-secret": "shared-secret-sentinel"
                    },
                    {
                        "name": "epsk",
                        "server-type": "accounting",
                        "address": "192.0.2.2",
                        "port": 49,
                        "client-identity": {
                            "tls13-epsk": {
                                "inline-definition": {
                                    "cleartext-symmetric-key": "ZXBzay1zZWNyZXQ="
                                },
                                "external-identity": "client@example.test"
                            }
                        }
                    }
                ]
            }
        }"#,
    )
    .expect("protected configuration must parse")
}
