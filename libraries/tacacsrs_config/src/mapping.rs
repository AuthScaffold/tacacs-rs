use std::time::Duration;

use crate::server::{Security, ServerType, TacacsPlusConfig};

/// Resolved per-server connection parameters ready for the runtime.
///
/// Produced from a YANG [`ServerEntry`](crate::ServerEntry) after credential
/// reference resolution and validation. All file paths, credential bundles,
/// and defaults have been applied — the runtime can use this directly to
/// establish connections without further config lookups.
#[derive(Debug, Clone)]
pub struct ServerConnectionConfig {
    /// Unique configuration name for this server.
    pub name: String,
    /// What AAA operations this server handles.
    pub server_type: ServerType,
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
///
/// This is the runtime-ready representation of the YANG `choice security`
/// node, with all credential references resolved to concrete values.
#[derive(Debug, Clone)]
pub enum ResolvedSecurity {
    /// Legacy TACACS+ obfuscation (RFC 8907). The shared secret is used as
    /// the MD5 XOR pad key.
    Obfuscation {
        /// The shared secret key. If `None`, no obfuscation is applied.
        shared_secret: Option<String>,
    },
    /// TLS-secured connection with X.509 certificate authentication.
    Tls {
        /// Path to the client certificate file for mTLS.
        client_certificate: Option<String>,
        /// Path to the client private key file for mTLS.
        client_key: Option<String>,
        /// Paths to CA certificate files for server verification.
        ca_cert_files: Vec<String>,
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

/// Convert a validated [`TacacsPlusConfig`] into a list of runtime
/// connection configurations, preserving the YANG-defined server order
/// (which determines failover priority).
///
/// # Errors
///
/// Returns an error if any server entry cannot be mapped to runtime
/// parameters (e.g., unsupported TLS identity type).
pub fn to_connection_configs(
    config: &TacacsPlusConfig,
) -> anyhow::Result<Vec<ServerConnectionConfig>> {
    config
        .server
        .iter()
        .map(|entry| {
            let security = match &entry.security {
                Security::Obfuscation(secret) => ResolvedSecurity::Obfuscation {
                    shared_secret: Some(secret.clone()),
                },
                Security::Tls(tls) => resolve_tls_security(tls, &entry.name)?,
            };

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

fn resolve_tls_security(
    tls: &crate::tls::TlsClientConfig,
    server_name: &str,
) -> anyhow::Result<ResolvedSecurity> {
    let (client_certificate, client_key) = if let Some(ref ci) = tls.client_identity {
        match &ci.inline {
            Some(crate::tls::ClientIdentity::Certificate(cert)) => {
                (cert.cert_file.clone(), cert.key_file.clone())
            }
            Some(crate::tls::ClientIdentity::Tls13Epsk(epsk)) => {
                return Ok(ResolvedSecurity::Psk {
                    identity: epsk.external_identity.clone(),
                    key: epsk.key.clone().unwrap_or_default(),
                });
            }
            Some(crate::tls::ClientIdentity::RawPublicKey(_)) => {
                anyhow::bail!(
                    "server '{server_name}': raw public key client identity is not yet supported",
                );
            }
            None => (None, None),
        }
    } else {
        (None, None)
    };

    let ca_cert_files = tls
        .server_authentication
        .inline
        .as_ref()
        .and_then(|sa| sa.ca_certs.as_ref())
        .and_then(|ca| ca.cert_files.as_ref())
        .cloned()
        .unwrap_or_default();

    Ok(ResolvedSecurity::Tls {
        client_certificate,
        client_key,
        ca_cert_files,
        insecure_disable_certificate_verification: false,
    })
}
