use serde::Deserialize;

use crate::credential_refs::{ClientCredentials, ServerCredentials};
use crate::serde_helpers;
use crate::statistics::ServerStatistics;
use crate::tls::TlsClientConfig;

bitflags::bitflags! {
    /// TACACS+ server type bitfield matching the YANG `tacacs-plus-server-type`.
    ///
    /// Any combination of authentication, authorization, and accounting.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ServerType: u8 {
        const AUTHENTICATION = 0b001;
        const AUTHORIZATION  = 0b010;
        const ACCOUNTING     = 0b100;
    }
}

impl<'de> Deserialize<'de> for ServerType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let mut bits = Self::empty();
        for token in s.split_whitespace() {
            match token {
                "authentication" => bits |= Self::AUTHENTICATION,
                "authorization" => bits |= Self::AUTHORIZATION,
                "accounting" => bits |= Self::ACCOUNTING,
                other => {
                    return Err(serde::de::Error::unknown_variant(
                        other,
                        &["authentication", "authorization", "accounting"],
                    ));
                }
            }
        }
        if bits.is_empty() {
            return Err(serde::de::Error::custom(
                "server-type must contain at least one of: authentication, authorization, accounting",
            ));
        }
        Ok(bits)
    }
}

/// Security mechanism choice between TLS and legacy obfuscation.
///
/// Maps to the YANG `choice security` node under each server entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Security {
    /// TLS-secured TACACS+ connection (RFC SSSS).
    #[serde(rename = "tls")]
    Tls(Box<TlsClientConfig>),

    /// Legacy MD5 XOR-pad obfuscation (RFC 8907).
    #[serde(rename = "shared-secret")]
    Obfuscation(String),
}

/// Source address type for outbound TACACS+ packets.
///
/// Maps to the YANG `choice source-type` node.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceType {
    SourceIp(String),
    SourceInterface(String),
}

/// A single TACACS+ server entry in the ordered server list.
///
/// Maps 1:1 to the YANG `list server` node keyed by `name`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerEntry {
    /// Unique configuration name for this server entry.
    pub name: String,

    /// What AAA operations this server handles.
    pub server_type: ServerType,

    /// Optional DNS domain name of the server.
    pub domain_name: Option<String>,

    /// Whether to include SNI in TLS `ClientHello`. Requires `domain_name`.
    pub sni_enabled: Option<bool>,

    /// IP address or hostname of the TACACS+ server (mandatory).
    pub address: String,

    /// Port number of the TACACS+ server (mandatory).
    pub port: u16,

    /// Security mechanism: TLS or legacy obfuscation.
    #[serde(flatten)]
    pub security: Security,

    /// Source address for outbound packets.
    #[serde(flatten)]
    pub source_type: Option<SourceType>,

    /// VRF instance name for routing.
    pub vrf_instance: Option<String>,

    /// Whether to use single-connection mode (RFC 8907 §4.3).
    #[serde(default)]
    pub single_connection: bool,

    /// Timeout in seconds waiting for server response.
    #[serde(default = "serde_helpers::default_timeout")]
    pub timeout: u16,

    /// Runtime statistics (read-only, not deserialized from config).
    #[serde(skip)]
    pub statistics: ServerStatistics,
}

/// Top-level TACACS+ configuration container.
///
/// Maps to the YANG `container tacacs-plus` node.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TacacsPlusConfig {
    /// Reusable TLS client credential bundles, keyed by `id`.
    #[serde(default)]
    pub client_credentials: Vec<ClientCredentials>,

    /// Reusable TLS server authentication bundles, keyed by `id`.
    #[serde(default)]
    pub server_credentials: Vec<ServerCredentials>,

    /// Ordered list of TACACS+ servers. Index order determines failover priority.
    pub server: Vec<ServerEntry>,
}
