use tacacsrs_config::{parse_yang_json, pipeline, resolve_servers};

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
