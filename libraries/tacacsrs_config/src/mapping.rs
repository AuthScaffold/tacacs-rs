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
    use super::{resolve_security, ResolvedSecurity};
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

        match resolve_security(&config.server[0]) {
            ResolvedSecurity::Tls {
                client_cert_pem,
                client_key_pem,
                ca_certs_pem,
                insecure_disable_certificate_verification,
            } => {
                assert_eq!(client_cert_pem.as_deref(), Some("CLIENT_CERT"));
                assert_eq!(client_key_pem.as_deref(), Some("CLIENT_KEY"));
                assert_eq!(ca_certs_pem, vec!["CA_CERT_1".to_owned(), "CA_CERT_2".to_owned()]);
                assert!(!insecure_disable_certificate_verification);
            }
            other => panic!("expected TLS security, got {other:?}"),
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

        match resolve_security(&config.server[0]) {
            ResolvedSecurity::Psk { identity, key } => {
                assert_eq!(identity, "client@example.com");
                assert_eq!(key, "topsecret");
            }
            other => panic!("expected PSK security, got {other:?}"),
        }
    }
}
