use tacacsrs_config::{
    parse_yang_json, TacacsPlusServerBuilder, TacacsPlusServerType,
    prepare::{prepare_endpoint, PrepareOptions},
    tacacsrs::BindingPolicy,
};
use tacacsrs_networking::SourceBinding;

#[test]
fn canonical_binding_round_trips_and_prepares_without_host_resources() {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [{
                "name": "management",
                "server-type": "authentication authorization accounting",
                "address": "192.0.2.49",
                "port": 49,
                "shared-secret": "test-only-obfuscation",
                "source-ip": "192.0.2.1",
                "vrf-instance": "mgmt-vrf",
                "tacacsrs:egress-interface": "mgmt0",
                "tacacsrs:binding-policy": "strict"
            }]
        }
    }"#;
    let config = parse_yang_json(json).unwrap();
    let server = &config.server[0];
    let original = server.clone();
    let endpoint = prepare_endpoint(server, PrepareOptions::default()).unwrap();
    assert_eq!(
        endpoint.local_binding().source(),
        Some(&SourceBinding::Ip("192.0.2.1".parse().unwrap()))
    );
    assert_eq!(endpoint.local_binding().egress_interface(), Some("mgmt0"));
    assert_eq!(endpoint.local_binding().vrf(), Some("mgmt-vrf"));
    assert_eq!(endpoint.local_binding().policy(), tacacsrs_networking::BindingPolicy::Strict);
    let serialized = serde_json::to_value(server).unwrap();
    assert_eq!(serialized["tacacsrs:egress-interface"], "mgmt0");
    assert_eq!(serialized["tacacsrs:binding-policy"], "strict");
    assert_eq!(*server, original);
}

#[test]
fn all_transports_share_derived_binding_and_best_effort_default() {
    let base = || {
        TacacsPlusServerBuilder::new("management", TacacsPlusServerType::all(), "192.0.2.49", 49)
            .with_egress_interface("mgmt0")
            .with_vrf_instance("mgmt-vrf")
    };
    for server in [
        base().with_shared_secret("test-only-obfuscation").build(),
        base().with_tls_server_authentication().build(),
        base()
            .with_tls13_epsk_psk_only("test-client", b"test-only-psk-material".to_vec())
            .build(),
        base()
            .with_tls13_epsk("test-client", b"test-only-psk-material".to_vec())
            .build(),
    ] {
        let endpoint = prepare_endpoint(&server, PrepareOptions::default()).unwrap();
        assert_eq!(endpoint.local_binding().egress_interface(), Some("mgmt0"));
        assert_eq!(endpoint.local_binding().source(), None);
        assert_eq!(
            endpoint.local_binding().policy(),
            tacacsrs_networking::BindingPolicy::BestEffort
        );
    }
}

#[test]
fn malformed_bindings_fail_before_execution_even_with_best_effort() {
    for change in [
        serde_json::json!({"source-ip": "not-an-address"}),
        serde_json::json!({"source-ip": "::1"}),
        serde_json::json!({"source-ip": "0.0.0.0"}),
        serde_json::json!({"source-interface": "../private"}),
        serde_json::json!({"source-interface": "lo", "source-ip": "127.0.0.1"}),
        serde_json::json!({"tacacsrs:egress-interface": "0123456789abcdef"}),
        serde_json::json!({"vrf-instance": "bad/name"}),
        serde_json::json!({"tacacsrs:binding-policy": "ignore-everything"}),
    ] {
        let mut server = serde_json::json!({
            "name": "invalid", "server-type": "authentication",
            "address": "192.0.2.49", "port": 49, "shared-secret": "test-only-obfuscation"
        });
        server
            .as_object_mut()
            .unwrap()
            .extend(change.as_object().unwrap().clone());
        let root = serde_json::json!({"ietf-system-tacacs-plus:tacacs-plus": {"server": [server]}});
        assert!(parse_yang_json(&root.to_string()).is_err(), "{change}");
    }
    let server =
        TacacsPlusServerBuilder::new("invalid", TacacsPlusServerType::all(), "192.0.2.49", 49)
            .with_shared_secret("test-only-obfuscation")
            .with_egress_interface("bad/name")
            .with_binding_policy(BindingPolicy::BestEffort)
            .build();
    assert!(prepare_endpoint(&server, PrepareOptions::default()).is_err());
}
