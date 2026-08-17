use serde_json::{Value, json};
use tacacsrs_config::{YangConfigRoot, parse_yang_json};

fn round_trip(input: &str) -> Value {
    let parsed = parse_yang_json(input).expect("initial central configuration must parse");
    let serialized = serde_json::to_value(YangConfigRoot {
        tacacs_plus: parsed,
    })
    .expect("central configuration must serialize");
    let reparsed = parse_yang_json(
        &serde_json::to_string(&serialized).expect("serialized configuration must be JSON"),
    )
    .expect("serialized central configuration must parse again");
    let reserialized = serde_json::to_value(YangConfigRoot {
        tacacs_plus: reparsed,
    })
    .expect("reparsed central configuration must serialize");
    assert_eq!(reserialized, serialized);
    serialized
}

#[test]
fn direct_central_references_round_trip_with_exact_values() {
    let value = round_trip(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "certificate-and-trust",
                        "server-type": "accounting",
                        "address": "192.0.2.21",
                        "port": 49,
                        "client-identity": {
                            "certificate": {
                                "central-keystore-reference": {
                                    "asymmetric-key": "../opaque asymmetric key",
                                    "certificate": "opaque certificate value"
                                }
                            }
                        },
                        "server-authentication": {
                            "ca-certs": {
                                "central-truststore-reference": "opaque CA bag/value"
                            },
                            "ee-certs": {
                                "central-truststore-reference": "opaque EE bag value"
                            }
                        }
                    },
                    {
                        "name": "epsk",
                        "server-type": "accounting",
                        "address": "192.0.2.22",
                        "port": 49,
                        "client-identity": {
                            "tls13-epsk": {
                                "central-keystore-reference": "opaque symmetric key/value",
                                "external-identity": "client@example.test",
                                "hash": "sha-384",
                                "context": "opaque provider context",
                                "target-protocol": 7,
                                "target-kdf": 9,
                                "tacacsrs:psk-dhe-ke-groups": ["secp384r1", "x25519"]
                            }
                        }
                    }
                ]
            }
        }"#,
    );
    let servers = value["ietf-system-tacacs-plus:tacacs-plus"]["server"]
        .as_array()
        .expect("serialized servers");

    assert_eq!(
        servers[0]["client-identity"]["certificate"]["central-keystore-reference"],
        json!({
            "asymmetric-key": "../opaque asymmetric key",
            "certificate": "opaque certificate value",
        })
    );
    assert_eq!(
        servers[0]["server-authentication"]["ca-certs"]["central-truststore-reference"],
        "opaque CA bag/value"
    );
    assert_eq!(
        servers[0]["server-authentication"]["ee-certs"]["central-truststore-reference"],
        "opaque EE bag value"
    );
    assert_eq!(
        servers[1]["client-identity"]["tls13-epsk"],
        json!({
            "central-keystore-reference": "opaque symmetric key/value",
            "external-identity": "client@example.test",
            "hash": "sha-384",
            "context": "opaque provider context",
            "target-protocol": 7,
            "target-kdf": 9,
            "tacacsrs:psk-dhe-ke-groups": ["secp384r1", "x25519"],
        })
    );
}

#[test]
fn bundled_central_references_round_trip_with_exact_values() {
    let value = round_trip(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [
                    {
                        "id": "certificate-bundle",
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "bundle asymmetric key",
                                "certificate": "bundle certificate"
                            }
                        }
                    },
                    {
                        "id": "epsk-bundle",
                        "tls13-epsk": {
                            "central-keystore-reference": "bundle symmetric key",
                            "external-identity": "bundle@example.test",
                            "hash": "sha-384",
                            "context": "bundle context",
                            "target-protocol": 11,
                            "target-kdf": 13,
                            "tacacsrs:psk-dhe-ke-groups": ["x25519"]
                        }
                    }
                ],
                "server-credentials": [{
                    "id": "trust-bundle",
                    "ca-certs": {
                        "central-truststore-reference": "bundle CA bag"
                    },
                    "ee-certs": {
                        "central-truststore-reference": "bundle EE bag"
                    }
                }],
                "server": [
                    {
                        "name": "certificate-server",
                        "server-type": "accounting",
                        "address": "192.0.2.23",
                        "port": 49,
                        "client-identity": {"credentials-reference": "certificate-bundle"},
                        "server-authentication": {"credentials-reference": "trust-bundle"}
                    },
                    {
                        "name": "epsk-server",
                        "server-type": "accounting",
                        "address": "192.0.2.24",
                        "port": 49,
                        "client-identity": {"credentials-reference": "epsk-bundle"}
                    }
                ]
            }
        }"#,
    );
    let config = &value["ietf-system-tacacs-plus:tacacs-plus"];
    let clients = config["client-credentials"]
        .as_array()
        .expect("client bundles");
    let servers = config["server-credentials"]
        .as_array()
        .expect("server bundles");

    assert_eq!(
        clients[0]["certificate"]["central-keystore-reference"],
        json!({
            "asymmetric-key": "bundle asymmetric key",
            "certificate": "bundle certificate",
        })
    );
    assert_eq!(
        clients[1]["tls13-epsk"],
        json!({
            "central-keystore-reference": "bundle symmetric key",
            "external-identity": "bundle@example.test",
            "hash": "sha-384",
            "context": "bundle context",
            "target-protocol": 11,
            "target-kdf": 13,
            "tacacsrs:psk-dhe-ke-groups": ["x25519"],
        })
    );
    assert_eq!(servers[0]["ca-certs"]["central-truststore-reference"], "bundle CA bag");
    assert_eq!(servers[0]["ee-certs"]["central-truststore-reference"], "bundle EE bag");
}
