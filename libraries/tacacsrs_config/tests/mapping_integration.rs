use std::time::Duration;

use anyhow::Result;

use tacacsrs_config::{
    parse_yang_json, pipeline, resolve_servers, validate_credential_references,
    CredentialRefType, CredentialResolver, ResolvedServer, TacacsPlusServer,
};

#[test]
fn resolve_servers_maps_inline_tls_material() {
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

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);

    let server = &servers[0];
    assert_eq!(server.name, "tls_inline");
    assert_eq!(server.address, "10.0.0.10");
    assert_eq!(server.port, 4949);
    assert!(server.is_tls());

    // Client cert should be preserved inline
    let ci = server
        .client_identity
        .as_ref()
        .expect("client_identity should be set");
    let cert = ci.certificate.as_ref().expect("certificate should be set");
    let inline = cert
        .inline_definition
        .as_ref()
        .expect("inline should be set");
    assert_eq!(inline.cert_data.as_deref(), Some("CLIENT_CERT_PEM"));
    assert_eq!(inline.cleartext_private_key.as_deref(), Some("CLIENT_KEY_PEM"));

    // CA certs should be preserved inline
    let sa = server
        .server_authentication
        .as_ref()
        .expect("server_authentication should be set");
    let ca = sa.ca_certs.as_ref().expect("ca_certs should be set");
    let ca_inline = ca
        .inline_definition
        .as_ref()
        .expect("ca inline should be set");
    assert_eq!(ca_inline.certificate.len(), 2);
    assert_eq!(ca_inline.certificate[0].cert_data, "CA_CERT_1");
    assert_eq!(ca_inline.certificate[1].cert_data, "CA_CERT_2");
}

#[test]
fn resolve_servers_maps_tls13_epsk() {
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

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);
    assert!(servers[0].is_tls());

    let epsk = servers[0]
        .client_identity
        .as_ref()
        .and_then(|ci| ci.tls13_epsk.as_ref())
        .expect("tls13_epsk should be set");
    assert_eq!(epsk.external_identity, "client@example.com");
    assert_eq!(
        epsk.inline_definition
            .as_ref()
            .and_then(|d| d.cleartext_symmetric_key.as_deref()),
        Some("topsecret"),
    );
}

#[test]
fn resolve_servers_resolves_credential_references() {
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

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);

    let server = &servers[0];
    assert_eq!(server.name, "tls_server");
    assert!(server.is_tls());

    // Client identity should have been resolved from the bundle
    let ci = server
        .client_identity
        .as_ref()
        .expect("client_identity should be set");
    assert!(ci.credentials_reference.is_none(), "reference should be cleared after resolution");
    let cert = ci
        .certificate
        .as_ref()
        .expect("certificate should be populated from bundle");
    let inline = cert
        .inline_definition
        .as_ref()
        .expect("inline should be set");
    assert_eq!(inline.cert_data.as_deref(), Some("MIIB..."));
    assert_eq!(inline.cleartext_private_key.as_deref(), Some("MIIEv..."));

    // Server authentication should have been resolved from the bundle
    let sa = server
        .server_authentication
        .as_ref()
        .expect("server_authentication should be set");
    assert!(sa.credentials_reference.is_none(), "reference should be cleared");
    let ca = sa
        .ca_certs
        .as_ref()
        .expect("ca_certs should be populated from bundle");
    let ca_inline = ca
        .inline_definition
        .as_ref()
        .expect("ca inline should be set");
    assert_eq!(ca_inline.certificate.len(), 1);
    assert_eq!(ca_inline.certificate[0].cert_data, "MIIB...");
}

#[test]
fn resolve_servers_maps_shared_secret_obfuscation() {
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

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);

    let server = &servers[0];
    assert_eq!(server.name, "obf_server");
    assert!(server.is_obfuscation());
    assert_eq!(server.shared_secret.as_deref(), Some("corp-shared-secret"));
    assert_eq!(server.obfuscation_key(), Some(b"corp-shared-secret".to_vec()));
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

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers[0].socket_address(), "192.0.2.10:4049");
}

#[test]
fn resolve_servers_maps_tls_hello_only_server() {
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

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);
    assert!(servers[0].is_tls());
    assert!(servers[0].hello_params.is_some());
}

#[test]
fn resolve_servers_maps_tls_server_auth_only() {
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

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);
    assert!(servers[0].is_tls());

    let sa = servers[0]
        .server_authentication
        .as_ref()
        .expect("server_authentication");
    let ca = sa.ca_certs.as_ref().expect("ca_certs");
    let inline = ca.inline_definition.as_ref().expect("inline");
    assert_eq!(inline.certificate.len(), 1);
    assert_eq!(inline.certificate[0].cert_data, "CA_CERT");
}

#[test]
fn resolve_servers_maps_none_obfuscation_for_unvalidated_bare_server() {
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

    let servers = resolve_servers(&root.tacacs_plus, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);
    assert!(servers[0].is_obfuscation());
    assert!(servers[0].shared_secret.is_none());
}

// ---------------------------------------------------------------------------
// ResolvedServer helper methods
// ---------------------------------------------------------------------------

#[test]
fn resolved_server_from_raw_wraps_without_resolution() {
    let server = TacacsPlusServer {
        name: "raw".to_owned(),
        server_type: tacacsrs_config::TacacsPlusServerType::ACCOUNTING,
        address: "10.0.0.99".to_owned(),
        port: 4949,
        timeout: 30,
        ..default_bare_server()
    };

    let resolved = ResolvedServer::from_raw(server);
    assert_eq!(resolved.name, "raw");
    assert_eq!(resolved.port, 4949);
}

#[test]
fn resolved_server_into_inner_returns_original() {
    let server = TacacsPlusServer {
        name: "inner".to_owned(),
        server_type: tacacsrs_config::TacacsPlusServerType::ACCOUNTING,
        address: "10.0.0.98".to_owned(),
        port: 49,
        timeout: 5,
        ..default_bare_server()
    };

    let resolved = ResolvedServer::from_raw(server);
    let inner = resolved.into_inner();
    assert_eq!(inner.name, "inner");
    assert_eq!(inner.address, "10.0.0.98");
}

#[test]
fn resolved_server_timeout_duration() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "td",
                    "server-type": "accounting",
                    "address": "10.0.0.70",
                    "port": 49,
                    "timeout": 42,
                    "shared-secret": "secret"
                }]
            }
        }"#,
    )
    .unwrap();

    let servers = resolve_servers(&config, None).unwrap();
    assert_eq!(servers[0].timeout_duration(), Duration::from_secs(42));
}

#[test]
fn resolved_server_obfuscation_key_returns_none_without_shared_secret() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "nokey",
                    "server-type": "accounting",
                    "address": "10.0.0.71",
                    "port": 49
                }]
            }
        }"#,
    )
    .unwrap();

    let servers = resolve_servers(&root.tacacs_plus, None).unwrap();
    assert!(servers[0].obfuscation_key().is_none());
}

#[test]
fn resolved_server_sni_enabled_defaults_to_false() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "nosni",
                    "server-type": "accounting",
                    "address": "10.0.0.72",
                    "port": 49,
                    "shared-secret": "secret"
                }]
            }
        }"#,
    )
    .unwrap();

    let servers = resolve_servers(&config, None).unwrap();
    assert!(!servers[0].sni_enabled());
}

#[test]
fn resolved_server_sni_enabled_returns_true_when_set() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "sni",
                    "server-type": "accounting",
                    "address": "10.0.0.73",
                    "port": 49,
                    "domain-name": "tacacs.example.com",
                    "sni-enabled": true,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "CERT",
                                "cleartext-private-key": "KEY"
                            }
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let servers = resolve_servers(&config, None).unwrap();
    assert!(servers[0].sni_enabled());
}

#[test]
fn resolved_server_debug_redacts_secrets() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "debug_test",
                    "server-type": "accounting",
                    "address": "10.0.0.74",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "PRIVATE_CERT",
                                "cleartext-private-key": "PRIVATE_KEY"
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [{"name": "ca1", "cert-data": "CA"}]
                            }
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let servers = resolve_servers(&config, None).unwrap();
    let debug_output = format!("{:?}", servers[0]);
    assert!(debug_output.contains("debug_test"));
    assert!(debug_output.contains("<redacted>"));
    assert!(!debug_output.contains("PRIVATE_KEY"));
    assert!(!debug_output.contains("PRIVATE_CERT"));
}

#[test]
fn resolved_server_debug_redacts_shared_secret() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "debug_obf",
                    "server-type": "accounting",
                    "address": "10.0.0.75",
                    "port": 49,
                    "shared-secret": "SUPER_SECRET_VALUE"
                }]
            }
        }"#,
    )
    .unwrap();

    let servers = resolve_servers(&config, None).unwrap();
    let debug_output = format!("{:?}", servers[0]);
    assert!(debug_output.contains("debug_obf"));
    assert!(debug_output.contains("<redacted>"));
    assert!(!debug_output.contains("SUPER_SECRET_VALUE"));
}

// ---------------------------------------------------------------------------
// External credential resolution via CredentialResolver
// ---------------------------------------------------------------------------

/// Test resolver that returns fixed material keyed by reference name.
struct TestResolver {
    entries: Vec<(String, CredentialRefType, String)>,
}

impl TestResolver {
    fn new(entries: Vec<(&str, CredentialRefType, &str)>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .map(|(k, t, v)| (k.to_owned(), t, v.to_owned()))
                .collect(),
        }
    }
}

impl CredentialResolver for TestResolver {
    fn resolve(&self, key: &str, ref_type: CredentialRefType) -> Result<Option<String>> {
        Ok(self
            .entries
            .iter()
            .find(|(k, t, _)| k == key && *t == ref_type)
            .map(|(_, _, v)| v.clone()))
    }
}

/// Test resolver that always fails.
struct FailingResolver;

impl CredentialResolver for FailingResolver {
    fn resolve(&self, key: &str, _ref_type: CredentialRefType) -> Result<Option<String>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }
}

#[test]
fn resolve_certificate_central_keystore_reference() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ks-cert",
                    "server-type": "accounting",
                    "address": "10.0.1.1",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "my-key",
                                "certificate": "my-cert"
                            }
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let resolver = TestResolver::new(vec![(
        "my-key",
        CredentialRefType::Keystore,
        "RESOLVED_KEY_PEM",
    )]);

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let ci = servers[0].client_identity.as_ref().unwrap();
    let cert = ci.certificate.as_ref().unwrap();
    assert!(
        cert.central_keystore_reference.is_none(),
        "keystore ref should be cleared"
    );
    let inline = cert.inline_definition.as_ref().unwrap();
    assert_eq!(
        inline.cleartext_private_key.as_deref(),
        Some("RESOLVED_KEY_PEM")
    );
    assert_eq!(inline.cert_data.as_deref(), Some("my-cert"));
}

#[test]
fn resolve_raw_private_key_central_keystore_reference() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ks-rpk",
                    "server-type": "accounting",
                    "address": "10.0.1.2",
                    "port": 49,
                    "client-identity": {
                        "raw-private-key": {
                            "central-keystore-reference": "rpk-ref"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let resolver = TestResolver::new(vec![(
        "rpk-ref",
        CredentialRefType::Keystore,
        "RPK_MATERIAL",
    )]);

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let ci = servers[0].client_identity.as_ref().unwrap();
    let rpk = ci.raw_private_key.as_ref().unwrap();
    assert!(rpk.central_keystore_reference.is_none());
    let inline = rpk.inline_definition.as_ref().unwrap();
    assert_eq!(
        inline.cleartext_private_key.as_deref(),
        Some("RPK_MATERIAL")
    );
}

#[test]
fn resolve_tls13_epsk_central_keystore_reference() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ks-epsk",
                    "server-type": "accounting",
                    "address": "10.0.1.3",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "epsk-ref",
                            "external-identity": "client@example.com"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let resolver = TestResolver::new(vec![(
        "epsk-ref",
        CredentialRefType::Keystore,
        "EPSK_SECRET",
    )]);

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let ci = servers[0].client_identity.as_ref().unwrap();
    let epsk = ci.tls13_epsk.as_ref().unwrap();
    assert!(epsk.central_keystore_reference.is_none());
    let inline = epsk.inline_definition.as_ref().unwrap();
    assert_eq!(
        inline.cleartext_symmetric_key.as_deref(),
        Some("EPSK_SECRET")
    );
}

#[test]
fn resolve_ca_certs_central_truststore_reference() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ts-ca",
                    "server-type": "accounting",
                    "address": "10.0.1.4",
                    "port": 49,
                    "server-authentication": {
                        "ca-certs": {
                            "central-truststore-reference": "ca-ref"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let resolver = TestResolver::new(vec![(
        "ca-ref",
        CredentialRefType::Truststore,
        "CA_CERT_PEM",
    )]);

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let sa = servers[0].server_authentication.as_ref().unwrap();
    let ca = sa.ca_certs.as_ref().unwrap();
    assert!(ca.central_truststore_reference.is_none());
    let inline = ca.inline_definition.as_ref().unwrap();
    assert_eq!(inline.certificate.len(), 1);
    assert_eq!(inline.certificate[0].name, "ca-ref");
    assert_eq!(inline.certificate[0].cert_data, "CA_CERT_PEM");
}

#[test]
fn resolve_ee_certs_central_truststore_reference() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ts-ee",
                    "server-type": "accounting",
                    "address": "10.0.1.5",
                    "port": 49,
                    "server-authentication": {
                        "ee-certs": {
                            "central-truststore-reference": "ee-ref"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let resolver = TestResolver::new(vec![(
        "ee-ref",
        CredentialRefType::Truststore,
        "EE_CERT_PEM",
    )]);

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let sa = servers[0].server_authentication.as_ref().unwrap();
    let ee = sa.ee_certs.as_ref().unwrap();
    assert!(ee.central_truststore_reference.is_none());
    let inline = ee.inline_definition.as_ref().unwrap();
    assert_eq!(inline.certificate.len(), 1);
    assert_eq!(inline.certificate[0].cert_data, "EE_CERT_PEM");
}

#[test]
fn resolve_raw_public_keys_central_truststore_reference() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ts-rpk",
                    "server-type": "accounting",
                    "address": "10.0.1.6",
                    "port": 49,
                    "server-authentication": {
                        "raw-public-keys": {
                            "central-truststore-reference": "rpk-ref"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let resolver = TestResolver::new(vec![(
        "rpk-ref",
        CredentialRefType::Truststore,
        "PUB_KEY_DATA",
    )]);

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let sa = servers[0].server_authentication.as_ref().unwrap();
    let rpk = sa.raw_public_keys.as_ref().unwrap();
    assert!(rpk.central_truststore_reference.is_none());
    let inline = rpk.inline_definition.as_ref().unwrap();
    assert_eq!(inline.public_key.len(), 1);
    assert_eq!(inline.public_key[0].public_key, "PUB_KEY_DATA");
}

#[test]
fn resolve_server_errors_on_failing_external_resolver() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "fail-ks",
                    "server-type": "accounting",
                    "address": "10.0.1.7",
                    "port": 49,
                    "client-identity": {
                        "raw-private-key": {
                            "central-keystore-reference": "bad-ref"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = resolve_servers(&config, Some(&FailingResolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("fail-ks"), "error should name the server: {msg}");
    assert!(
        msg.contains("resolution failed"),
        "error should include resolver failure: {msg}"
    );
}

#[test]
fn resolve_server_errors_on_failing_truststore_resolver() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "fail-ts",
                    "server-type": "accounting",
                    "address": "10.0.1.8",
                    "port": 49,
                    "server-authentication": {
                        "ca-certs": {
                            "central-truststore-reference": "bad-ts-ref"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = resolve_servers(&config, Some(&FailingResolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("fail-ts"), "error should name the server: {msg}");
    assert!(
        msg.contains("resolution failed"),
        "error should include resolver failure: {msg}"
    );
}

#[test]
fn resolve_noop_when_external_resolver_returns_none() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop",
                    "server-type": "accounting",
                    "address": "10.0.1.9",
                    "port": 49,
                    "client-identity": {
                        "raw-private-key": {
                            "central-keystore-reference": "unknown-ref"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    // Resolver that handles nothing (returns None)
    let resolver = TestResolver::new(vec![]);
    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let rpk = servers[0]
        .client_identity
        .as_ref()
        .unwrap()
        .raw_private_key
        .as_ref()
        .unwrap();
    // When resolver returns None, the reference stays in place
    assert!(rpk.central_keystore_reference.is_some());
    assert!(rpk.inline_definition.is_none());
}

// ---------------------------------------------------------------------------
// validate_credential_references — error collection paths
// ---------------------------------------------------------------------------

#[test]
fn validate_credential_references_collects_missing_client_bundle_ref() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "vcr-client",
                    "server-type": "accounting",
                    "address": "10.0.2.1",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "nonexistent-client"
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("nonexistent-client"), "error: {msg}");
    assert!(
        msg.contains("client-identity credentials-reference"),
        "error: {msg}"
    );
}

#[test]
fn validate_credential_references_collects_missing_server_bundle_ref() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "vcr-server",
                    "server-type": "accounting",
                    "address": "10.0.2.2",
                    "port": 49,
                    "server-authentication": {
                        "credentials-reference": "nonexistent-server"
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("nonexistent-server"), "error: {msg}");
    assert!(
        msg.contains("server-authentication credentials-reference"),
        "error: {msg}"
    );
}

#[test]
fn validate_credential_references_collects_multiple_errors() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "s1",
                        "server-type": "accounting",
                        "address": "10.0.2.3",
                        "port": 49,
                        "client-identity": {
                            "credentials-reference": "missing-ci"
                        }
                    },
                    {
                        "name": "s2",
                        "server-type": "accounting",
                        "address": "10.0.2.4",
                        "port": 50,
                        "server-authentication": {
                            "credentials-reference": "missing-sa"
                        }
                    }
                ]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("missing-ci"), "error should mention first ref: {msg}");
    assert!(msg.contains("missing-sa"), "error should mention second ref: {msg}");
}

#[test]
fn validate_credential_references_collects_external_keystore_errors() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ext-ks",
                    "server-type": "accounting",
                    "address": "10.0.2.5",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "bad-key"
                            }
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("certificate central-keystore-reference"),
        "error: {msg}"
    );
}

#[test]
fn validate_credential_references_collects_external_rpk_keystore_error() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ext-rpk-ks",
                    "server-type": "accounting",
                    "address": "10.0.2.6",
                    "port": 49,
                    "client-identity": {
                        "raw-private-key": {
                            "central-keystore-reference": "bad-rpk"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("raw-private-key central-keystore-reference"),
        "error: {msg}"
    );
}

#[test]
fn validate_credential_references_collects_external_epsk_keystore_error() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ext-epsk-ks",
                    "server-type": "accounting",
                    "address": "10.0.2.7",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "bad-epsk",
                            "external-identity": "id@example.com"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("tls13-epsk central-keystore-reference"),
        "error: {msg}"
    );
}

#[test]
fn validate_credential_references_collects_external_ca_truststore_error() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ext-ca-ts",
                    "server-type": "accounting",
                    "address": "10.0.2.8",
                    "port": 49,
                    "server-authentication": {
                        "ca-certs": {
                            "central-truststore-reference": "bad-ca"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("ca-certs central-truststore-reference"),
        "error: {msg}"
    );
}

#[test]
fn validate_credential_references_collects_external_ee_truststore_error() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ext-ee-ts",
                    "server-type": "accounting",
                    "address": "10.0.2.9",
                    "port": 49,
                    "server-authentication": {
                        "ee-certs": {
                            "central-truststore-reference": "bad-ee"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("ee-certs central-truststore-reference"),
        "error: {msg}"
    );
}

#[test]
fn validate_credential_references_collects_external_rpk_truststore_error() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ext-rpk-ts",
                    "server-type": "accounting",
                    "address": "10.0.2.10",
                    "port": 49,
                    "server-authentication": {
                        "raw-public-keys": {
                            "central-truststore-reference": "bad-rpk-ts"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("raw-public-keys central-truststore-reference"),
        "error: {msg}"
    );
}

#[test]
fn resolve_certificate_keystore_ref_error_has_context() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ctx-cert",
                    "server-type": "accounting",
                    "address": "10.0.1.10",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "err-key"
                            }
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = resolve_servers(&config, Some(&FailingResolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("ctx-cert"), "error should mention server: {msg}");
    assert!(
        msg.contains("central-keystore-reference for certificate"),
        "error should have context: {msg}"
    );
}

#[test]
fn resolve_epsk_keystore_ref_error_has_context() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ctx-epsk",
                    "server-type": "accounting",
                    "address": "10.0.1.11",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "err-epsk",
                            "external-identity": "fail@example.com"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = resolve_servers(&config, Some(&FailingResolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("ctx-epsk"), "error should mention server: {msg}");
    assert!(
        msg.contains("central-keystore-reference for tls13-epsk"),
        "error should have context: {msg}"
    );
}

#[test]
fn resolve_raw_public_keys_truststore_ref_error_has_context() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ctx-rpk-ts",
                    "server-type": "accounting",
                    "address": "10.0.1.12",
                    "port": 49,
                    "server-authentication": {
                        "raw-public-keys": {
                            "central-truststore-reference": "err-rpk"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = resolve_servers(&config, Some(&FailingResolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("ctx-rpk-ts"), "error should mention server: {msg}");
    assert!(
        msg.contains("central-truststore-reference for raw-public-keys"),
        "error should have context: {msg}"
    );
}

#[test]
fn resolve_ee_certs_truststore_ref_error_has_context() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "ctx-ee-ts",
                    "server-type": "accounting",
                    "address": "10.0.1.13",
                    "port": 49,
                    "server-authentication": {
                        "ee-certs": {
                            "central-truststore-reference": "err-ee"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = resolve_servers(&config, Some(&FailingResolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("ctx-ee-ts"), "error should mention server: {msg}");
}

// ---------------------------------------------------------------------------
// Bundle + external resolution combined
// ---------------------------------------------------------------------------

#[test]
fn resolve_bundle_ref_then_external_keystore_ref() {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [{
                    "id": "bundle-with-ks-ref",
                    "raw-private-key": {
                        "central-keystore-reference": "ext-key"
                    }
                }],
                "server": [{
                    "name": "combo",
                    "server-type": "accounting",
                    "address": "10.0.3.1",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "bundle-with-ks-ref"
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let resolver = TestResolver::new(vec![(
        "ext-key",
        CredentialRefType::Keystore,
        "FULLY_RESOLVED",
    )]);

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let ci = servers[0].client_identity.as_ref().unwrap();
    assert!(ci.credentials_reference.is_none());
    let rpk = ci.raw_private_key.as_ref().unwrap();
    assert!(rpk.central_keystore_reference.is_none());
    let inline = rpk.inline_definition.as_ref().unwrap();
    assert_eq!(
        inline.cleartext_private_key.as_deref(),
        Some("FULLY_RESOLVED")
    );
}

// ---------------------------------------------------------------------------
// Helper to create a bare TacacsPlusServer for from_raw tests
// ---------------------------------------------------------------------------

fn default_bare_server() -> TacacsPlusServer {
    TacacsPlusServer {
        name: String::new(),
        server_type: tacacsrs_config::TacacsPlusServerType::ACCOUNTING,
        address: String::new(),
        port: 49,
        domain_name: None,
        sni_enabled: None,
        single_connection: false,
        timeout: 5,
        source_ip: None,
        source_interface: None,
        shared_secret: None,
        client_identity: None,
        server_authentication: None,
        hello_params: None,
        vrf_instance: None,
    }
}
