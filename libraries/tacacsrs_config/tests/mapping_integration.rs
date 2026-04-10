use std::time::Duration;

use anyhow::Result;

use tacacsrs_config::{
    parse_yang_json, pipeline, resolve_servers, validate_credential_references,
    AsymmetricKeyMaterial, CertificateEntry, CredentialResolver, ResolvedServer,
    SymmetricKeyMaterial, TacacsPlusServer, TruststorePublicKeyMaterial, X509CertificateMaterial,
};
use tacacsrs_config::crypto_types::{PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat};

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
                                    "cert-data": "Y2xpZW50LWNlcnQ=",
                                    "cleartext-private-key": "Y2xpZW50LWtleQ=="
                                }
                            }
                        },
                        "server-authentication": {
                            "ca-certs": {
                                "inline-definition": {
                                    "certificate": [
                                        {"name": "ca1", "cert-data": "Y2EtY2VydC0x"},
                                        {"name": "ca2", "cert-data": "Y2EtY2VydC0y"}
                                    ]
                                }
                            }
                        }
                    }
                ]
            }
        }"#,
        None,
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
    assert_eq!(inline.cert_data.as_deref(), Some("Y2xpZW50LWNlcnQ="));
    assert_eq!(inline.cleartext_private_key.as_deref(), Some("Y2xpZW50LWtleQ=="));

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
    assert_eq!(ca_inline.certificate[0].cert_data, "Y2EtY2VydC0x");
    assert_eq!(ca_inline.certificate[1].cert_data, "Y2EtY2VydC0y");
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
                                    "cleartext-symmetric-key": "dG9wc2VjcmV0"
                                },
                                "external-identity": "client@example.com"
                            }
                        }
                    }
                ]
            }
        }"#,
        None,
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
        Some("dG9wc2VjcmV0"),
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
        }"#,
        None,
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
    assert_eq!(inline.cert_data.as_deref(), Some("dGVzdC1jZXJ0"));
    assert_eq!(inline.cleartext_private_key.as_deref(), Some("dGVzdC1rZXk="));

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
    assert_eq!(ca_inline.certificate[0].cert_data, "dGVzdC1jZXJ0");
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
        None,
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
        None,
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
        None,
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
                                        {"name": "ca1", "cert-data": "Y2EtY2VydA=="}
                                    ]
                                }
                            }
                        }
                    }
                ]
            }
        }"#,
        None,
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
    assert_eq!(inline.certificate[0].cert_data, "Y2EtY2VydA==");
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
        None,
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
        None,
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
                                "cert-data": "Y2VydA==",
                                "cleartext-private-key": "a2V5"
                            }
                        }
                    }
                }]
            }
        }"#,
        None,
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
                                "cert-data": "cHJpdmF0ZS1jZXJ0",
                                "cleartext-private-key": "cHJpdmF0ZS1rZXk="
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [{"name": "ca1", "cert-data": "Y2E="}]
                            }
                        }
                    }
                }]
            }
        }"#,
        None,
    )
    .unwrap();

    let servers = resolve_servers(&config, None).unwrap();
    let debug_output = format!("{:?}", servers[0]);
    assert!(debug_output.contains("debug_test"));
    assert!(debug_output.contains("<redacted>"));
    assert!(!debug_output.contains("cHJpdmF0ZS1rZXk="));
    assert!(!debug_output.contains("cHJpdmF0ZS1jZXJ0"));
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
        None,
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
    keystore_certs: Vec<(String, X509CertificateMaterial)>,
    certificate_bags: Vec<(String, Vec<CertificateEntry>)>,
    asymmetric_keys: Vec<(String, AsymmetricKeyMaterial)>,
    symmetric_keys: Vec<(String, SymmetricKeyMaterial)>,
}

impl TestResolver {
    fn new() -> Self {
        Self {
            keystore_certs: Vec::new(),
            certificate_bags: Vec::new(),
            asymmetric_keys: Vec::new(),
            symmetric_keys: Vec::new(),
        }
    }

    fn with_keystore_certificate(mut self, key: &str, material: X509CertificateMaterial) -> Self {
        self.keystore_certs.push((key.to_owned(), material));
        self
    }

    fn with_certificate_bag(mut self, key: &str, entries: Vec<CertificateEntry>) -> Self {
        self.certificate_bags.push((key.to_owned(), entries));
        self
    }

    fn with_asymmetric_key(mut self, key: &str, material: AsymmetricKeyMaterial) -> Self {
        self.asymmetric_keys.push((key.to_owned(), material));
        self
    }

    fn with_symmetric_key(mut self, key: &str, material: SymmetricKeyMaterial) -> Self {
        self.symmetric_keys.push((key.to_owned(), material));
        self
    }
}

impl CredentialResolver for TestResolver {
    fn resolve_keystore_certificate(&self, key: &str) -> Result<Option<X509CertificateMaterial>> {
        Ok(self
            .keystore_certs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone()))
    }

    fn resolve_certificate_bag(&self, key: &str) -> Result<Option<Vec<CertificateEntry>>> {
        Ok(self
            .certificate_bags
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone()))
    }

    fn resolve_asymmetric_key(&self, key: &str) -> Result<Option<AsymmetricKeyMaterial>> {
        Ok(self
            .asymmetric_keys
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone()))
    }

    fn resolve_symmetric_key(&self, key: &str) -> Result<Option<SymmetricKeyMaterial>> {
        Ok(self
            .symmetric_keys
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone()))
    }

    fn resolve_public_key_bag(
        &self,
        key: &str,
    ) -> Result<Option<Vec<TruststorePublicKeyMaterial>>> {
        // Fall back: use certificate bag name/data as public key entries
        let bag = self.resolve_certificate_bag(key)?;
        Ok(bag.map(|entries| {
            entries
                .into_iter()
                .map(|entry| TruststorePublicKeyMaterial {
                    name: entry.name,
                    public_key: entry.cert_data,
                    public_key_format: PublicKeyFormat::SubjectPublicKeyInfoFormat,
                })
                .collect()
        }))
    }

    fn validate_keystore_certificate(&self, key: &str) -> Result<()> {
        self.resolve_keystore_certificate(key)?.ok_or_else(|| {
            anyhow::anyhow!("test resolver has no keystore certificate for '{key}'")
        })?;
        Ok(())
    }

    fn validate_asymmetric_key(&self, key: &str) -> Result<()> {
        self.resolve_asymmetric_key(key)?
            .ok_or_else(|| anyhow::anyhow!("test resolver has no asymmetric key for '{key}'"))?;
        Ok(())
    }

    fn validate_symmetric_key(&self, key: &str) -> Result<()> {
        self.resolve_symmetric_key(key)?
            .ok_or_else(|| anyhow::anyhow!("test resolver has no symmetric key for '{key}'"))?;
        Ok(())
    }

    fn validate_certificate_bag(&self, key: &str) -> Result<()> {
        self.resolve_certificate_bag(key)?
            .ok_or_else(|| anyhow::anyhow!("test resolver has no certificate bag for '{key}'"))?;
        Ok(())
    }

    fn validate_public_key_bag(&self, key: &str) -> Result<()> {
        self.resolve_public_key_bag(key)?
            .ok_or_else(|| anyhow::anyhow!("test resolver has no public key bag for '{key}'"))?;
        Ok(())
    }
}

/// Test resolver that always fails.
struct FailingResolver;

impl CredentialResolver for FailingResolver {
    fn resolve_keystore_certificate(&self, key: &str) -> Result<Option<X509CertificateMaterial>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn resolve_certificate_bag(&self, key: &str) -> Result<Option<Vec<CertificateEntry>>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn resolve_asymmetric_key(&self, key: &str) -> Result<Option<AsymmetricKeyMaterial>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn resolve_symmetric_key(&self, key: &str) -> Result<Option<SymmetricKeyMaterial>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn resolve_public_key_bag(
        &self,
        key: &str,
    ) -> Result<Option<Vec<TruststorePublicKeyMaterial>>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn validate_keystore_certificate(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn validate_asymmetric_key(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn validate_symmetric_key(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn validate_certificate_bag(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn validate_public_key_bag(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }
}

#[test]
fn resolve_certificate_central_keystore_reference() {
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new().with_keystore_certificate(
        "my-cert",
        X509CertificateMaterial {
            cert_data: "RESOLVED_CERT_PEM".to_owned(),
            key_material: AsymmetricKeyMaterial {
                cleartext_private_key: "RESOLVED_KEY_PEM".to_owned(),
                public_key: None,
                private_key_format: None,
                public_key_format: None,
            },
        },
    );

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let ci = servers[0].client_identity.as_ref().unwrap();
    let cert = ci.certificate.as_ref().unwrap();
    assert!(cert.central_keystore_reference.is_none(), "keystore ref should be cleared");
    let inline = cert.inline_definition.as_ref().unwrap();
    assert_eq!(inline.cleartext_private_key.as_deref(), Some("RESOLVED_KEY_PEM"));
    assert_eq!(inline.cert_data.as_deref(), Some("RESOLVED_CERT_PEM"));
}

#[test]
fn resolve_raw_private_key_central_keystore_reference() {
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new().with_asymmetric_key(
        "rpk-ref",
        AsymmetricKeyMaterial {
            cleartext_private_key: "RPK_PRIVATE_KEY".to_owned(),
            public_key: Some("RPK_PUBLIC_KEY".to_owned()),
            private_key_format: Some(PrivateKeyFormat::OneAsymmetricKeyFormat),
            public_key_format: Some(PublicKeyFormat::SubjectPublicKeyInfoFormat),
        },
    );

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let ci = servers[0].client_identity.as_ref().unwrap();
    let rpk = ci.raw_private_key.as_ref().unwrap();
    assert!(rpk.central_keystore_reference.is_none());
    let inline = rpk.inline_definition.as_ref().unwrap();
    assert_eq!(inline.cleartext_private_key.as_deref(), Some("RPK_PRIVATE_KEY"));
    assert_eq!(inline.public_key.as_deref(), Some("RPK_PUBLIC_KEY"));
    assert_eq!(
        inline.private_key_format.as_deref(),
        Some("ietf-crypto-types:one-asymmetric-key-format")
    );
    assert_eq!(
        inline.public_key_format.as_deref(),
        Some("ietf-crypto-types:subject-public-key-info-format")
    );
}

#[test]
fn resolve_tls13_epsk_central_keystore_reference() {
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new().with_symmetric_key(
        "epsk-ref",
        SymmetricKeyMaterial {
            cleartext_symmetric_key: "EPSK_SECRET".to_owned(),
            key_format: Some(SymmetricKeyFormat::OctetStringKeyFormat),
        },
    );

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let ci = servers[0].client_identity.as_ref().unwrap();
    let epsk = ci.tls13_epsk.as_ref().unwrap();
    assert!(epsk.central_keystore_reference.is_none());
    let inline = epsk.inline_definition.as_ref().unwrap();
    assert_eq!(inline.cleartext_symmetric_key.as_deref(), Some("EPSK_SECRET"));
    assert_eq!(inline.key_format.as_deref(), Some("ietf-crypto-types:octet-string-key-format"));
}

#[test]
fn resolve_ca_certs_central_truststore_reference() {
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new().with_certificate_bag(
        "ca-ref",
        vec![CertificateEntry {
            name: "ca-ref".to_owned(),
            cert_data: "CA_CERT_PEM".to_owned(),
        }],
    );

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
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new().with_certificate_bag(
        "ee-ref",
        vec![CertificateEntry {
            name: "ee-ref".to_owned(),
            cert_data: "EE_CERT_PEM".to_owned(),
        }],
    );

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
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new().with_certificate_bag(
        "rpk-ref",
        vec![CertificateEntry {
            name: "rpk-ref".to_owned(),
            cert_data: "PUB_KEY_DATA".to_owned(),
        }],
    );

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let sa = servers[0].server_authentication.as_ref().unwrap();
    let rpk = sa.raw_public_keys.as_ref().unwrap();
    assert!(rpk.central_truststore_reference.is_none());
    let inline = rpk.inline_definition.as_ref().unwrap();
    assert_eq!(inline.public_key.len(), 1);
    assert_eq!(inline.public_key[0].public_key, "PUB_KEY_DATA");
    assert_eq!(
        inline.public_key[0].public_key_format,
        "ietf-crypto-types:subject-public-key-info-format"
    );
}

#[test]
fn resolve_server_errors_on_failing_external_resolver() {
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    let err = resolve_servers(&config, Some(&FailingResolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("fail-ks"), "error should name the server: {msg}");
    assert!(msg.contains("resolution failed"), "error should include resolver failure: {msg}");
}

#[test]
fn resolve_server_errors_on_failing_truststore_resolver() {
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    let err = resolve_servers(&config, Some(&FailingResolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("fail-ts"), "error should name the server: {msg}");
    assert!(msg.contains("resolution failed"), "error should include resolver failure: {msg}");
}

#[test]
fn resolve_noop_when_external_resolver_returns_none() {
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    // Resolver that handles nothing (returns None)
    let resolver = TestResolver::new();
    let err = resolve_servers(&config, Some(&resolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("did not resolve"), "error should indicate unresolved reference: {msg}");
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
    assert!(msg.contains("client-identity credentials-reference"), "error: {msg}");
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
    assert!(msg.contains("server-authentication credentials-reference"), "error: {msg}");
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

    let err =
        validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("certificate central-keystore-reference"), "error: {msg}");
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

    let err =
        validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("raw-private-key central-keystore-reference"), "error: {msg}");
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

    let err =
        validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("tls13-epsk central-keystore-reference"), "error: {msg}");
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

    let err =
        validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("ca-certs central-truststore-reference"), "error: {msg}");
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

    let err =
        validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("ee-certs central-truststore-reference"), "error: {msg}");
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

    let err =
        validate_credential_references(&root.tacacs_plus, Some(&FailingResolver)).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("raw-public-keys central-truststore-reference"), "error: {msg}");
}

#[test]
fn resolve_certificate_keystore_ref_error_has_context() {
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

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
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

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
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

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
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    let err = resolve_servers(&config, Some(&FailingResolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("ctx-ee-ts"), "error should mention server: {msg}");
}

// ---------------------------------------------------------------------------
// Bundle + external resolution combined
// ---------------------------------------------------------------------------

#[test]
fn resolve_bundle_ref_then_external_keystore_ref() {
    let config = pipeline::parse_root_json(
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
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new().with_asymmetric_key(
        "ext-key",
        AsymmetricKeyMaterial {
            cleartext_private_key: "FULLY_RESOLVED".to_owned(),
            public_key: None,
            private_key_format: None,
            public_key_format: None,
        },
    );

    let servers = resolve_servers(&config, Some(&resolver)).unwrap();
    let ci = servers[0].client_identity.as_ref().unwrap();
    assert!(ci.credentials_reference.is_none());
    let rpk = ci.raw_private_key.as_ref().unwrap();
    assert!(rpk.central_keystore_reference.is_none());
    let inline = rpk.inline_definition.as_ref().unwrap();
    assert_eq!(inline.cleartext_private_key.as_deref(), Some("FULLY_RESOLVED"));
}

// ---------------------------------------------------------------------------
// IPv6 socket_address
// ---------------------------------------------------------------------------

#[test]
fn socket_address_wraps_ipv6_in_brackets() {
    let server = TacacsPlusServer {
        name: "ipv6".to_owned(),
        server_type: tacacsrs_config::TacacsPlusServerType::ACCOUNTING,
        address: "2001:db8::1".to_owned(),
        port: 49,
        timeout: 5,
        ..default_bare_server()
    };

    let resolved = ResolvedServer::from_raw(server);
    assert_eq!(resolved.socket_address(), "[2001:db8::1]:49");
}

// ---------------------------------------------------------------------------
// NoOpResolver paths (resolver=None with external refs)
// ---------------------------------------------------------------------------

#[test]
fn resolve_fails_with_noop_resolver_for_certificate_keystore_ref() {
    let config = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop-cert",
                    "server-type": "accounting",
                    "address": "10.0.4.1",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "k",
                                "certificate": "c"
                            }
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap()
    .tacacs_plus;

    let err = resolve_servers(&config, None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("no credential resolver configured"),
        "expected NoOpResolver error, got: {msg}",
    );
}

#[test]
fn resolve_fails_with_noop_resolver_for_epsk_keystore_ref() {
    let config = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop-epsk",
                    "server-type": "accounting",
                    "address": "10.0.4.2",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "some-ref",
                            "external-identity": "id@example.com"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap()
    .tacacs_plus;

    let err = resolve_servers(&config, None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("no credential resolver configured"),
        "expected NoOpResolver error, got: {msg}",
    );
}

#[test]
fn resolve_fails_with_noop_resolver_for_ca_truststore_ref() {
    let config = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop-ca",
                    "server-type": "accounting",
                    "address": "10.0.4.3",
                    "port": 49,
                    "server-authentication": {
                        "ca-certs": {
                            "central-truststore-reference": "ts-ref"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap()
    .tacacs_plus;

    let err = resolve_servers(&config, None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("no credential resolver configured"),
        "expected NoOpResolver error, got: {msg}",
    );
}

#[test]
fn resolve_fails_with_noop_resolver_for_rpk_truststore_ref() {
    let config = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop-rpk-ts",
                    "server-type": "accounting",
                    "address": "10.0.4.4",
                    "port": 49,
                    "server-authentication": {
                        "raw-public-keys": {
                            "central-truststore-reference": "rpk-ts-ref"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap()
    .tacacs_plus;

    let err = resolve_servers(&config, None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("no credential resolver configured"),
        "expected NoOpResolver error, got: {msg}",
    );
}

// ---------------------------------------------------------------------------
// Resolver returns Ok(None) — "did not resolve" paths
// ---------------------------------------------------------------------------

#[test]
fn resolve_certificate_keystore_returns_none_errors() {
    let config = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "none-cert",
                    "server-type": "accounting",
                    "address": "10.0.5.1",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "k",
                                "certificate": "unknown-cert"
                            }
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new(); // empty — returns None for everything
    let err = resolve_servers(&config, Some(&resolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("did not resolve"), "expected not-resolved error: {msg}");
}

#[test]
fn resolve_epsk_keystore_returns_none_errors() {
    let config = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "none-epsk",
                    "server-type": "accounting",
                    "address": "10.0.5.2",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "unknown-epsk",
                            "external-identity": "id@example.com"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new();
    let err = resolve_servers(&config, Some(&resolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("did not resolve"), "expected not-resolved error: {msg}");
}

#[test]
fn resolve_ca_certs_truststore_returns_none_errors() {
    let config = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "none-ca",
                    "server-type": "accounting",
                    "address": "10.0.5.3",
                    "port": 49,
                    "server-authentication": {
                        "ca-certs": {
                            "central-truststore-reference": "unknown-ca"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new();
    let err = resolve_servers(&config, Some(&resolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("did not resolve"), "expected not-resolved error: {msg}");
}

#[test]
fn resolve_ee_certs_truststore_returns_none_errors() {
    let config = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "none-ee",
                    "server-type": "accounting",
                    "address": "10.0.5.4",
                    "port": 49,
                    "server-authentication": {
                        "ee-certs": {
                            "central-truststore-reference": "unknown-ee"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new();
    let err = resolve_servers(&config, Some(&resolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("did not resolve"), "expected not-resolved error: {msg}");
}

#[test]
fn resolve_rpk_truststore_returns_none_errors() {
    let config = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "none-rpk-ts",
                    "server-type": "accounting",
                    "address": "10.0.5.5",
                    "port": 49,
                    "server-authentication": {
                        "raw-public-keys": {
                            "central-truststore-reference": "unknown-rpk"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap()
    .tacacs_plus;

    let resolver = TestResolver::new();
    let err = resolve_servers(&config, Some(&resolver)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("did not resolve"), "expected not-resolved error: {msg}");
}

// ---------------------------------------------------------------------------
// validate_credential_references with NoOp resolver (external refs, resolver=None)
// ---------------------------------------------------------------------------

#[test]
fn validate_credential_references_noop_resolver_rejects_external_refs() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop-val",
                    "server-type": "accounting",
                    "address": "10.0.6.1",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "central-keystore-reference": {
                                "asymmetric-key": "k",
                                "certificate": "c"
                            }
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("no credential resolver configured"), "error: {msg}",);
}

#[test]
fn validate_credential_references_noop_rejects_rpk_keystore_ref() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop-rpk",
                    "server-type": "accounting",
                    "address": "10.0.6.2",
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

    let err = validate_credential_references(&root.tacacs_plus, None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("no credential resolver configured"), "error: {msg}");
}

#[test]
fn validate_credential_references_noop_rejects_epsk_keystore_ref() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop-epsk",
                    "server-type": "accounting",
                    "address": "10.0.6.3",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "epsk-ref",
                            "external-identity": "id"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("no credential resolver configured"), "error: {msg}");
}

#[test]
fn validate_credential_references_noop_rejects_ca_truststore_ref() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop-ca",
                    "server-type": "accounting",
                    "address": "10.0.6.4",
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

    let err = validate_credential_references(&root.tacacs_plus, None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("no credential resolver configured"), "error: {msg}");
}

#[test]
fn validate_credential_references_noop_rejects_ee_truststore_ref() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop-ee",
                    "server-type": "accounting",
                    "address": "10.0.6.5",
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

    let err = validate_credential_references(&root.tacacs_plus, None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("no credential resolver configured"), "error: {msg}");
}

#[test]
fn validate_credential_references_noop_rejects_rpk_truststore_ref() {
    let root = pipeline::parse_root_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "noop-rpk-ts",
                    "server-type": "accounting",
                    "address": "10.0.6.6",
                    "port": 49,
                    "server-authentication": {
                        "raw-public-keys": {
                            "central-truststore-reference": "rpk-ts-ref"
                        }
                    }
                }]
            }
        }"#,
    )
    .unwrap();

    let err = validate_credential_references(&root.tacacs_plus, None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("no credential resolver configured"), "error: {msg}");
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
