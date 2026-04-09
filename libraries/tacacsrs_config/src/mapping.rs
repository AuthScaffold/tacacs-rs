use std::time::Duration;

use crate::generated::tacacs_plus::{TacacsPlus, TacacsPlusServer, TacacsPlusServerType};

/// Resolved per-server connection parameters ready for the runtime.
#[derive(Debug, Clone)]
pub struct ServerConnectionConfig {
    /// Unique configuration name for this server.
    pub name: String,
    /// What AAA operations this server handles.
    pub server_type: TacacsPlusServerType,
    /// IP address or hostname of the TACACS+ server.
    pub address: String,
    /// Port number of the TACACS+ server.
    pub port: u16,
    /// Resolved security mechanism for this server.
    pub security: ResolvedSecurity,
    /// Connection timeout.
    pub timeout: Duration,
    /// Whether to use single-connection mode.
    pub single_connection: bool,
    /// Optional domain name for TLS SNI.
    pub domain_name: Option<String>,
    /// Whether SNI is enabled.
    pub sni_enabled: bool,
}

impl ServerConnectionConfig {
    /// Returns the `address:port` socket address string.
    #[must_use]
    pub fn socket_address(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

/// Resolved security mechanism for an upstream connection.
#[derive(Debug, Clone)]
pub enum ResolvedSecurity {
    /// Legacy TACACS+ obfuscation (RFC 8907).
    Obfuscation {
        /// The shared secret key. If `None`, no obfuscation is applied.
        shared_secret: Option<String>,
    },
    /// TLS-secured connection with X.509 certificate authentication.
    Tls {
        /// PEM-encoded client certificate chain (None = no client auth).
        client_cert_pem: Option<String>,
        /// PEM-encoded client private key (None = no client auth).
        client_key_pem: Option<String>,
        /// PEM-encoded CA certificates for server verification.
        ca_certs_pem: Vec<String>,
        /// Disable certificate verification (development only).
        insecure_disable_certificate_verification: bool,
    },
    /// TLS 1.3 Pre-Shared Key (feature-gated, requires OpenSSL).
    Psk {
        /// PSK identity string.
        identity: String,
        /// Pre-shared key bytes.
        key: String,
    },
}

/// Convert a validated config into a list of runtime connection configurations.
///
/// # Errors
///
/// Returns an error if any server entry cannot be mapped to runtime parameters.
pub fn to_connection_configs(config: &TacacsPlus) -> anyhow::Result<Vec<ServerConnectionConfig>> {
    config
        .server
        .iter()
        .map(|entry| {
            let security = resolve_security(entry);
            Ok(ServerConnectionConfig {
                name: entry.name.clone(),
                server_type: entry.server_type,
                address: entry.address.clone(),
                port: entry.port,
                security,
                timeout: Duration::from_secs(u64::from(entry.timeout)),
                single_connection: entry.single_connection,
                domain_name: entry.domain_name.clone(),
                sni_enabled: entry.sni_enabled.unwrap_or(false),
            })
        })
        .collect()
}

fn resolve_security(server: &TacacsPlusServer) -> ResolvedSecurity {
    let has_tls = server.client_identity.is_some()
        || server.server_authentication.is_some()
        || server.hello_params.is_some();

    if has_tls {
        let (client_cert_pem, client_key_pem) = if let Some(ref ci) = server.client_identity {
            if let Some(ref cert) = ci.certificate {
                if let Some(ref inline) = cert.inline_definition {
                    (inline.cert_data.clone(), inline.cleartext_private_key.clone())
                } else {
                    (None, None)
                }
            } else if let Some(ref epsk) = ci.tls13_epsk {
                let key = epsk
                    .inline_definition
                    .as_ref()
                    .and_then(|d| d.cleartext_symmetric_key.clone())
                    .unwrap_or_default();
                return ResolvedSecurity::Psk {
                    identity: epsk.external_identity.clone(),
                    key,
                };
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let ca_certs_pem = if let Some(ref sa) = server.server_authentication {
            if let Some(ref ca) = sa.ca_certs {
                if let Some(ref inline) = ca.inline_definition {
                    inline
                        .certificate
                        .iter()
                        .map(|c| c.cert_data.clone())
                        .collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        ResolvedSecurity::Tls {
            client_cert_pem,
            client_key_pem,
            ca_certs_pem,
            insecure_disable_certificate_verification: false,
        }
    } else if let Some(ref secret) = server.shared_secret {
        ResolvedSecurity::Obfuscation {
            shared_secret: Some(secret.clone()),
        }
    } else {
        ResolvedSecurity::Obfuscation {
            shared_secret: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve_security, to_connection_configs, ResolvedSecurity};
    use crate::generated::tacacs_plus::TacacsPlusServer;
    use crate::parse_yang_json;

    #[test]
    fn resolve_security_extracts_tls_certificate_and_ca_material() {
        let config = parse_yang_json(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [
                        {
                            "name": "tls-server",
                            "server-type": "accounting",
                            "address": "10.0.0.1",
                            "port": 49,
                            "client-identity": {
                                "certificate": {
                                    "inline-definition": {
                                        "cert-data": "CLIENT_CERT",
                                        "cleartext-private-key": "CLIENT_KEY"
                                    }
                                }
                            },
                            "server-authentication": {
                                "ca-certs": {
                                    "inline-definition": {
                                        "certificate": [
                                            { "name": "ca1", "cert-data": "CA_CERT_1" },
                                            { "name": "ca2", "cert-data": "CA_CERT_2" }
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

        let security = resolve_security(&config.server[0]);
        assert!(matches!(security, ResolvedSecurity::Tls { .. }));
        if let ResolvedSecurity::Tls {
            client_cert_pem,
            client_key_pem,
            ca_certs_pem,
            insecure_disable_certificate_verification,
        } = security
        {
            assert_eq!(client_cert_pem.as_deref(), Some("CLIENT_CERT"));
            assert_eq!(client_key_pem.as_deref(), Some("CLIENT_KEY"));
            assert_eq!(ca_certs_pem, vec!["CA_CERT_1".to_owned(), "CA_CERT_2".to_owned()]);
            assert!(!insecure_disable_certificate_verification);
        }
    }

    #[cfg(feature = "psk")]
    #[test]
    fn resolve_security_maps_tls13_epsk_to_psk() {
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

        let security = resolve_security(&config.server[0]);
        assert!(matches!(security, ResolvedSecurity::Psk { .. }));
        if let ResolvedSecurity::Psk { identity, key } = security {
            assert_eq!(identity, "client@example.com");
            assert_eq!(key, "topsecret");
        }
    }

    #[test]
    fn to_connection_configs_accepts_reference_based_tls_server() {
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

        let servers = to_connection_configs(&config).expect("mapping should succeed");
        assert_eq!(servers.len(), 1);

        let server = &servers[0];
        assert_eq!(server.name, "tls_server");
        assert_eq!(server.address, "10.0.0.1");
        assert_eq!(server.port, 4949);

        assert!(matches!(&server.security, ResolvedSecurity::Tls { .. }));
        if let ResolvedSecurity::Tls {
            client_cert_pem,
            client_key_pem,
            ca_certs_pem,
            ..
        } = &server.security
        {
            // References are preserved at parse time; mapping currently only
            // projects inline material into runtime TLS fields.
            assert!(client_cert_pem.is_none());
            assert!(client_key_pem.is_none());
            assert!(ca_certs_pem.is_empty());
        }
    }

    #[test]
    fn to_connection_configs_maps_inline_tls_material() {
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

        let servers = to_connection_configs(&config).expect("mapping should succeed");
        assert_eq!(servers.len(), 1);

        let server = &servers[0];
        assert_eq!(server.name, "tls_inline");
        assert_eq!(server.address, "10.0.0.10");
        assert_eq!(server.port, 4949);

        assert!(matches!(&server.security, ResolvedSecurity::Tls { .. }));
        if let ResolvedSecurity::Tls {
            client_cert_pem,
            client_key_pem,
            ca_certs_pem,
            insecure_disable_certificate_verification,
        } = &server.security
        {
            assert_eq!(client_cert_pem.as_deref(), Some("CLIENT_CERT_PEM"));
            assert_eq!(client_key_pem.as_deref(), Some("CLIENT_KEY_PEM"));
            assert_eq!(
                ca_certs_pem,
                &vec!["CA_CERT_1".to_owned(), "CA_CERT_2".to_owned()],
            );
            assert!(!insecure_disable_certificate_verification);
        }
    }

    #[test]
    fn to_connection_configs_maps_shared_secret_obfuscation_literal() {
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

        let servers = to_connection_configs(&config).expect("mapping should succeed");
        assert_eq!(servers.len(), 1);

        let server = &servers[0];
        assert_eq!(server.name, "obf_server");
        assert_eq!(server.address, "10.0.0.20");
        assert_eq!(server.port, 49);

        assert!(matches!(&server.security, ResolvedSecurity::Obfuscation { .. }));
        if let ResolvedSecurity::Obfuscation { shared_secret } = &server.security {
            assert_eq!(shared_secret.as_deref(), Some("corp-shared-secret"));
        }
    }

    #[test]
    fn to_connection_configs_maps_tls_security_without_inline_material() {
        let config = parse_yang_json(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [
                        {
                            "name": "tls_keystore_refs",
                            "server-type": "accounting",
                            "address": "10.0.0.11",
                            "port": 49,
                            "client-identity": {
                                "certificate": {
                                    "central-keystore-reference": {
                                        "asymmetric-key": "key-1",
                                        "certificate": "cert-1"
                                    }
                                }
                            },
                            "server-authentication": {
                                "ca-certs": {
                                    "central-truststore-reference": "truststore-ca-id"
                                }
                            }
                        }
                    ]
                }
            }"#,
        )
        .expect("config should parse");

        let servers = to_connection_configs(&config).expect("mapping should succeed");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "tls_keystore_refs");

        assert!(matches!(&servers[0].security, ResolvedSecurity::Tls { .. }));
        if let ResolvedSecurity::Tls {
            client_cert_pem,
            client_key_pem,
            ca_certs_pem,
            ..
        } = &servers[0].security
        {
            assert!(client_cert_pem.is_none());
            assert!(client_key_pem.is_none());
            assert!(ca_certs_pem.is_empty());
        }
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

        let servers = to_connection_configs(&config).expect("mapping should succeed");
        assert_eq!(servers[0].socket_address(), "192.0.2.10:4049");
    }

    #[test]
    fn resolve_security_returns_none_obfuscation_without_security_fields() {
        let server: TacacsPlusServer = serde_json::from_str(
            r#"{
                "name": "bare",
                "server-type": "accounting",
                "address": "10.0.0.30",
                "port": 49
            }"#,
        )
        .expect("server shape should deserialize");

        let security = resolve_security(&server);
        assert!(matches!(security, ResolvedSecurity::Obfuscation { .. }));
        if let ResolvedSecurity::Obfuscation { shared_secret } = security {
            assert!(shared_secret.is_none());
        }
    }

    #[test]
    fn resolve_security_handles_tls_without_server_authentication() {
        let config = parse_yang_json(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [
                        {
                            "name": "tls_no_sa",
                            "server-type": "accounting",
                            "address": "10.0.0.40",
                            "port": 49,
                            "client-identity": {
                                "certificate": {
                                    "inline-definition": {
                                        "cert-data": "CERT"
                                    }
                                }
                            }
                        }
                    ]
                }
            }"#,
        )
        .expect("config should parse");

        let security = resolve_security(&config.server[0]);
        assert!(matches!(security, ResolvedSecurity::Tls { .. }));
        if let ResolvedSecurity::Tls { ca_certs_pem, .. } = security {
            assert!(ca_certs_pem.is_empty());
        }
    }

    #[test]
    fn resolve_security_handles_tls_with_server_authentication_without_ca_certs() {
        let config = parse_yang_json(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [
                        {
                            "name": "tls_empty_sa",
                            "server-type": "accounting",
                            "address": "10.0.0.41",
                            "port": 49,
                            "client-identity": {
                                "certificate": {
                                    "inline-definition": {
                                        "cert-data": "CERT"
                                    }
                                }
                            },
                            "server-authentication": {
                                "credentials-reference": "corp-ca"
                            }
                        }
                    ],
                    "server-credentials": [
                        {
                            "id": "corp-ca",
                            "ca-certs": {
                                "inline-definition": {
                                    "certificate": [
                                        {"name": "ca1", "cert-data": "CA_CERT_1"}
                                    ]
                                }
                            }
                        }
                    ]
                }
            }"#,
        )
        .expect("config should parse");

        let security = resolve_security(&config.server[0]);
        assert!(matches!(security, ResolvedSecurity::Tls { .. }));
        if let ResolvedSecurity::Tls { ca_certs_pem, .. } = security {
            assert!(ca_certs_pem.is_empty());
        }
    }

    #[test]
    fn resolve_security_handles_tls_when_only_hello_params_are_present() {
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

        let security = resolve_security(&config.server[0]);
        assert!(matches!(security, ResolvedSecurity::Tls { .. }));
        if let ResolvedSecurity::Tls {
            client_cert_pem,
            client_key_pem,
            ca_certs_pem,
            ..
        } = security
        {
            assert!(client_cert_pem.is_none());
            assert!(client_key_pem.is_none());
            assert!(ca_certs_pem.is_empty());
        }
    }
}
