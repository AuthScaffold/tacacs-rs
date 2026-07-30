use serde_json::{Value, json};
use tacacsrs_config::parse_yang_json;

fn root(
    servers: Vec<Value>,
    client_credentials: Vec<Value>,
    server_credentials: Vec<Value>,
) -> Value {
    json!({
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": Value::Array(client_credentials),
            "server-credentials": Value::Array(server_credentials),
            "server": Value::Array(servers),
        }
    })
}

fn plain_server(name: &str, address: &str) -> Value {
    json!({
        "name": name,
        "server-type": "accounting",
        "address": address,
        "port": 49,
        "shared-secret": "test-secret",
    })
}

fn assert_validation_error(value: &Value, expected_path: &str, expected_rule: &str) {
    let error = parse_yang_json(&value.to_string()).expect_err("configuration should be rejected");
    let message = error.to_string();
    assert!(message.contains(expected_path), "missing path {expected_path}: {message}");
    assert!(message.contains(expected_rule), "missing rule {expected_rule}: {message}");
}

fn inline_certificate() -> Value {
    json!({
        "cleartext-private-key": "a2V5",
        "cert-data": "Y2VydA==",
    })
}

fn central_certificate() -> Value {
    json!({
        "asymmetric-key": "opaque-asymmetric-key",
        "certificate": "opaque-certificate",
    })
}

fn inline_epsk() -> Value {
    json!({"cleartext-symmetric-key": "c2VjcmV0"})
}

fn inline_trust() -> Value {
    json!({
        "certificate": [{
            "name": "trust-anchor",
            "cert-data": "Y2VydA==",
        }]
    })
}

#[test]
fn central_only_choices_validate_for_direct_and_bundle_usages() {
    let config = root(
        vec![
            json!({
                "name": "direct-certificate",
                "server-type": "accounting",
                "address": "10.0.1.1",
                "port": 49,
                "client-identity": {
                    "certificate": {
                        "central-keystore-reference": central_certificate(),
                    }
                }
            }),
            json!({
                "name": "direct-epsk",
                "server-type": "accounting",
                "address": "10.0.1.2",
                "port": 49,
                "client-identity": {
                    "tls13-epsk": {
                        "central-keystore-reference": "opaque-symmetric-key",
                        "external-identity": "client@example.test",
                        "hash": "sha-384",
                        "context": "provider-context",
                        "target-protocol": 7,
                        "target-kdf": 9,
                        "tacacsrs:psk-dhe-ke-groups": ["secp384r1"],
                    }
                }
            }),
            json!({
                "name": "direct-trust",
                "server-type": "accounting",
                "address": "10.0.1.3",
                "port": 49,
                "server-authentication": {
                    "ca-certs": {
                        "central-truststore-reference": "opaque-ca-bag",
                    },
                    "ee-certs": {
                        "central-truststore-reference": "opaque-ee-bag",
                    }
                }
            }),
            json!({
                "name": "bundled",
                "server-type": "accounting",
                "address": "10.0.1.4",
                "port": 49,
                "client-identity": {"credentials-reference": "client-certificate-bundle"},
                "server-authentication": {"credentials-reference": "server-trust-bundle"},
            }),
        ],
        vec![
            json!({
                "id": "client-certificate-bundle",
                "certificate": {
                    "central-keystore-reference": central_certificate(),
                }
            }),
            json!({
                "id": "client-epsk-bundle",
                "tls13-epsk": {
                    "central-keystore-reference": "opaque-bundle-symmetric-key",
                    "external-identity": "bundle@example.test",
                }
            }),
        ],
        vec![json!({
            "id": "server-trust-bundle",
            "ca-certs": {"central-truststore-reference": "opaque-bundle-ca"},
            "ee-certs": {"central-truststore-reference": "opaque-bundle-ee"},
        })],
    );

    parse_yang_json(&config.to_string()).expect("all central-only usages should validate");
}

#[test]
#[allow(clippy::too_many_lines)] // The table intentionally keeps direct and bundle cases together.
fn inline_and_central_cases_are_rejected_for_every_usage() {
    let dual_certificate = json!({
        "inline-definition": inline_certificate(),
        "central-keystore-reference": central_certificate(),
    });
    let dual_epsk = json!({
        "inline-definition": inline_epsk(),
        "central-keystore-reference": "opaque-symmetric-key",
        "external-identity": "client@example.test",
    });
    let dual_trust = json!({
        "inline-definition": inline_trust(),
        "central-truststore-reference": "opaque-bag",
    });

    let cases = [
        (
            root(
                vec![json!({
                    "name": "direct-certificate",
                    "server-type": "accounting",
                    "address": "10.0.2.1",
                    "port": 49,
                    "client-identity": {"certificate": dual_certificate},
                })],
                vec![],
                vec![],
            ),
            "client-identity/certificate",
            "inline, central-keystore",
        ),
        (
            root(
                vec![json!({
                    "name": "direct-epsk",
                    "server-type": "accounting",
                    "address": "10.0.2.2",
                    "port": 49,
                    "client-identity": {"tls13-epsk": dual_epsk},
                })],
                vec![],
                vec![],
            ),
            "client-identity/tls13-epsk",
            "inline, central-keystore",
        ),
        (
            root(
                vec![json!({
                    "name": "direct-ca",
                    "server-type": "accounting",
                    "address": "10.0.2.3",
                    "port": 49,
                    "server-authentication": {"ca-certs": dual_trust},
                })],
                vec![],
                vec![],
            ),
            "server-authentication/ca-certs",
            "inline, central-truststore",
        ),
        (
            root(
                vec![json!({
                    "name": "direct-ee",
                    "server-type": "accounting",
                    "address": "10.0.2.4",
                    "port": 49,
                    "server-authentication": {"ee-certs": dual_trust},
                })],
                vec![],
                vec![],
            ),
            "server-authentication/ee-certs",
            "inline, central-truststore",
        ),
        (
            root(
                vec![plain_server("client-certificate-bundle", "10.0.2.5")],
                vec![json!({"id": "client-certificate", "certificate": dual_certificate})],
                vec![],
            ),
            "client-credentials/certificate",
            "inline, central-keystore",
        ),
        (
            root(
                vec![plain_server("client-epsk-bundle", "10.0.2.6")],
                vec![json!({"id": "client-epsk", "tls13-epsk": dual_epsk})],
                vec![],
            ),
            "client-credentials/tls13-epsk",
            "inline, central-keystore",
        ),
        (
            root(
                vec![plain_server("server-ca-bundle", "10.0.2.7")],
                vec![],
                vec![json!({"id": "server-ca", "ca-certs": dual_trust})],
            ),
            "server-credentials/ca-certs",
            "inline, central-truststore",
        ),
        (
            root(
                vec![plain_server("server-ee-bundle", "10.0.2.8")],
                vec![],
                vec![json!({"id": "server-ee", "ee-certs": dual_trust})],
            ),
            "server-credentials/ee-certs",
            "inline, central-truststore",
        ),
    ];

    for (config, expected_path, expected_cases) in cases {
        assert_validation_error(&config, expected_path, expected_cases);
    }
}

#[test]
#[allow(clippy::too_many_lines)] // The table intentionally keeps direct and bundle cases together.
fn mandatory_choices_are_enforced_for_every_direct_and_bundle_usage() {
    let cases = [
        (
            root(
                vec![json!({
                    "name": "direct-certificate",
                    "server-type": "accounting",
                    "address": "10.0.3.1",
                    "port": 49,
                    "client-identity": {"certificate": {}},
                })],
                vec![],
                vec![],
            ),
            "client-identity/certificate",
            "requires one of",
        ),
        (
            root(
                vec![json!({
                    "name": "direct-epsk",
                    "server-type": "accounting",
                    "address": "10.0.3.2",
                    "port": 49,
                    "client-identity": {"tls13-epsk": {"external-identity": "client"}},
                })],
                vec![],
                vec![],
            ),
            "client-identity/tls13-epsk",
            "requires one of",
        ),
        (
            root(
                vec![json!({
                    "name": "direct-ca",
                    "server-type": "accounting",
                    "address": "10.0.3.3",
                    "port": 49,
                    "server-authentication": {"ca-certs": {}},
                })],
                vec![],
                vec![],
            ),
            "server-authentication/ca-certs",
            "requires one of",
        ),
        (
            root(
                vec![json!({
                    "name": "direct-ee",
                    "server-type": "accounting",
                    "address": "10.0.3.4",
                    "port": 49,
                    "server-authentication": {"ee-certs": {}},
                })],
                vec![],
                vec![],
            ),
            "server-authentication/ee-certs",
            "requires one of",
        ),
        (
            root(
                vec![plain_server("client-certificate-bundle", "10.0.3.5")],
                vec![json!({"id": "client-certificate", "certificate": {}})],
                vec![],
            ),
            "client-credentials/certificate",
            "requires one of",
        ),
        (
            root(
                vec![plain_server("client-epsk-bundle", "10.0.3.6")],
                vec![json!({
                    "id": "client-epsk",
                    "tls13-epsk": {"external-identity": "client"},
                })],
                vec![],
            ),
            "client-credentials/tls13-epsk",
            "requires one of",
        ),
        (
            root(
                vec![plain_server("server-ca-bundle", "10.0.3.7")],
                vec![],
                vec![json!({"id": "server-ca", "ca-certs": {}})],
            ),
            "server-credentials/ca-certs",
            "requires one of",
        ),
        (
            root(
                vec![plain_server("server-ee-bundle", "10.0.3.8")],
                vec![],
                vec![json!({"id": "server-ee", "ee-certs": {}})],
            ),
            "server-credentials/ee-certs",
            "requires one of",
        ),
    ];

    for (config, expected_path, expected_rule) in cases {
        assert_validation_error(&config, expected_path, expected_rule);
    }
}
