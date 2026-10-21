//! Parses canonical startup listener configuration and prepares bind targets.
//!
//! Preparation performs no filesystem or network I/O and preserves the source.
//! Unix paths use Linux syntax, including when configuration is inspected elsewhere.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use serde::Deserialize;

use crate::tacacsrs::LocalServices;

/// A validated local listener target, independent of IPC transport libraries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerEndpoint {
    /// Filesystem Unix socket path.
    Unix(PathBuf),
    /// Numeric IP socket address. Port zero requests an ephemeral port.
    Tcp(SocketAddr),
}

impl ListenerEndpoint {
    /// Reports whether a resolved destination can reach this TCP listener.
    ///
    /// The host supplies its current interface addresses. IPv4-mapped addresses
    /// compare as IPv4. An IPv6 wildcard conservatively includes dual-stack binding.
    /// This check describes the supplied snapshot, not future DNS or interface changes.
    #[must_use]
    pub fn covers_tcp_destination(&self, target: SocketAddr, local_addresses: &[IpAddr]) -> bool {
        let Self::Tcp(listener) = self else {
            return false;
        };
        if listener.port() == 0 || listener.port() != target.port() {
            return false;
        }
        let target = target.ip().to_canonical();
        let listener = listener.ip().to_canonical();
        target == listener
            || (listener.is_unspecified()
                && (listener.is_ipv6() || target.is_ipv4())
                && (target.is_loopback()
                    || target.is_unspecified()
                    || local_addresses
                        .iter()
                        .any(|address| address.to_canonical() == target)))
    }
}

/// Immutable bind targets derived from canonical local-service configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLocalServices {
    client_api: Option<PathBuf>,
    tacacs_proxy: Option<ListenerEndpoint>,
    unix_socket_mode: u32,
    max_connections: usize,
    max_client_api_streams: u32,
    connection_lifetime: std::time::Duration,
}

impl PreparedLocalServices {
    /// Returns the maximum number of served connections per listener.
    #[must_use]
    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Returns the HTTP/2 stream limit for each client API connection.
    #[must_use]
    pub const fn max_client_api_streams(&self) -> u32 {
        self.max_client_api_streams
    }

    /// Returns the maximum local connection lifetime.
    #[must_use]
    pub const fn connection_lifetime(&self) -> std::time::Duration {
        self.connection_lifetime
    }

    /// Returns the client API socket path when that service is enabled.
    #[must_use]
    pub fn client_api(&self) -> Option<&Path> {
        self.client_api.as_deref()
    }

    /// Returns the proxy target when that service is enabled.
    #[must_use]
    pub const fn tacacs_proxy(&self) -> Option<&ListenerEndpoint> {
        self.tacacs_proxy.as_ref()
    }

    /// Returns validated Unix permission bits.
    #[must_use]
    pub const fn unix_socket_mode(&self) -> u32 {
        self.unix_socket_mode
    }
}

#[derive(Deserialize)]
struct LocalServicesResource {
    #[serde(rename = "tacacsrs:local-services")]
    services: LocalServices,
}

/// Parses a module-qualified RFC 7951 local-service resource.
///
/// # Errors
///
/// Returns an error for unknown fields, malformed JSON, or invalid bind targets.
pub fn parse_local_services(bytes: &[u8]) -> anyhow::Result<LocalServices> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let mut unknown = BTreeSet::new();
    let resource: LocalServicesResource = serde_ignored::deserialize(&mut deserializer, |path| {
        unknown.insert(path.to_string());
    })
    .context("decode YANG local-services resource")?;
    deserializer
        .end()
        .context("unexpected data after local-services resource")?;
    ensure!(
        unknown.is_empty(),
        "unknown local-services fields: {}",
        unknown.into_iter().collect::<Vec<_>>().join(", ")
    );
    prepare_local_services(&resource.services)?;
    Ok(resource.services)
}

/// Validates and prepares canonical listener controls without binding sockets.
///
/// # Errors
///
/// Returns an error for disabled services, invalid endpoints or permissions,
/// conflicting Unix paths, or a proxy endpoint inconsistent with service selection.
pub fn prepare_local_services(source: &LocalServices) -> anyhow::Result<PreparedLocalServices> {
    crate::proxy_policy::validate_proxy_source(source)?;
    ensure!(source.max_connections > 0, "local-services/max-connections must be greater than zero");
    ensure!(
        source.max_client_api_streams > 0,
        "local-services/max-client-api-streams must be greater than zero"
    );
    ensure!(
        source.connection_lifetime_seconds > 0,
        "local-services/connection-lifetime-seconds must be greater than zero"
    );
    ensure!(
        source.client_api_enabled || source.tacacs_proxy_enabled,
        "Enable at least one runtime service"
    );
    ensure!(source.unix_socket_mode <= 0o777, "local-services/unix-socket-mode must be in 0..=511");
    let client_path = unix_path(&source.client_api_endpoint)
        .context("invalid local-services/client-api-endpoint")?;
    ensure!(
        source.tacacs_proxy_enabled == source.tacacs_proxy_endpoint.is_some(),
        "The proxy endpoint must be present exactly when the TACACS+ proxy service is enabled"
    );
    let proxy = source
        .tacacs_proxy_endpoint
        .as_deref()
        .map(|value| {
            if value.starts_with('/') {
                unix_path(value).map(ListenerEndpoint::Unix)
            } else {
                value
                    .parse::<SocketAddr>()
                    .map(ListenerEndpoint::Tcp)
                    .context(
                        "proxy endpoint must be an absolute Unix path or numeric IP socket address",
                    )
            }
        })
        .transpose()
        .context("invalid local-services/tacacs-proxy-endpoint")?;
    ensure!(
        !source.client_api_enabled
            || proxy.as_ref() != Some(&ListenerEndpoint::Unix(client_path.clone())),
        "Client API and TACACS+ proxy endpoints must differ"
    );
    Ok(PreparedLocalServices {
        client_api: source.client_api_enabled.then_some(client_path),
        tacacs_proxy: proxy,
        unix_socket_mode: u32::from(source.unix_socket_mode),
        max_connections: usize::from(source.max_connections),
        max_client_api_streams: u32::from(source.max_client_api_streams),
        connection_lifetime: std::time::Duration::from_secs(u64::from(
            source.connection_lifetime_seconds,
        )),
    })
}

fn unix_path(value: &str) -> anyhow::Result<PathBuf> {
    ensure!(value.starts_with('/'), "Unix socket path must be absolute");
    ensure!(
        !value.contains('\0') && value.len() <= 107,
        "Unix socket path must contain at most 107 bytes and no NUL"
    );
    ensure!(!value.ends_with('/'), "Unix socket path must name a socket, not a directory");
    let mut components = Vec::new();
    for component in value.split('/') {
        ensure!(component != "..", "Unix socket path must not contain parent traversal");
        if !component.is_empty() && component != "." {
            components.push(component);
        }
    }
    ensure!(
        !components.is_empty() && !value.ends_with("/."),
        "Unix socket path must name a socket"
    );
    Ok(PathBuf::from(format!("/{}", components.join("/"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_listener_matching_preserves_host_port_and_address_family() {
        let local_addresses = [
            "192.0.2.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ];
        for (listener, destination, expected) in [
            ("0.0.0.0:49", "127.0.0.1:49", true),
            ("0.0.0.0:49", "192.0.2.10:49", true),
            ("[::ffff:0.0.0.0]:49", "192.0.2.10:49", true),
            ("0.0.0.0:49", "192.0.2.20:49", false),
            ("0.0.0.0:49", "[::1]:49", false),
            ("[::]:49", "127.0.0.1:49", true),
            ("[::]:49", "[2001:db8::10]:49", true),
            ("[::]:49", "[2001:db8::20]:49", false),
            ("127.0.0.1:49", "[::ffff:127.0.0.1]:49", true),
            ("127.0.0.1:49", "127.0.0.2:49", false),
            ("127.0.0.1:49", "[::1]:49", false),
            ("127.0.0.1:49", "127.0.0.1:50", false),
            ("127.0.0.1:0", "127.0.0.1:49", false),
        ] {
            let listener = ListenerEndpoint::Tcp(listener.parse().unwrap());
            assert_eq!(
                listener.covers_tcp_destination(destination.parse().unwrap(), &local_addresses),
                expected,
                "{listener:?} -> {destination}"
            );
        }
    }

    #[test]
    fn generated_defaults_prepare_without_source_mutation() {
        let source = parse_local_services(br#"{"tacacsrs:local-services":{}}"#).unwrap();
        assert_eq!(source, LocalServices::default());
        let original = source.clone();
        let prepared = prepare_local_services(&source).unwrap();
        assert_eq!(prepared.client_api(), Some(Path::new("/run/tacacs/tacacs.sock")));
        assert_eq!(prepared.tacacs_proxy(), None);
        assert_eq!(prepared.unix_socket_mode(), 0o660);
        assert_eq!(prepared.max_connections(), 64);
        assert_eq!(prepared.max_client_api_streams(), 64);
        assert_eq!(prepared.connection_lifetime(), std::time::Duration::from_secs(300));
        assert_eq!(source, original);
    }

    #[test]
    fn ingress_limits_reject_zero_and_preserve_explicit_values() {
        for field in [
            "max-connections",
            "max-client-api-streams",
            "connection-lifetime-seconds",
        ] {
            let input = serde_json::json!({"tacacsrs:local-services": {field: 0}});
            assert!(parse_local_services(&serde_json::to_vec(&input).unwrap()).is_err());
        }
        let source = parse_local_services(br#"{"tacacsrs:local-services":{"max-connections":2,"max-client-api-streams":3,"connection-lifetime-seconds":4}}"#).unwrap();
        let original = source.clone();
        let prepared = prepare_local_services(&source).unwrap();
        assert_eq!(prepared.max_connections(), 2);
        assert_eq!(prepared.max_client_api_streams(), 3);
        assert_eq!(prepared.connection_lifetime(), std::time::Duration::from_secs(4));
        assert_eq!(source, original);
    }

    #[test]
    fn supports_unix_and_numeric_tcp_proxy_targets() {
        for target in [
            "/run/tacacs/proxy.sock",
            "127.0.0.1:49",
            "[::1]:0",
            "0.0.0.0:49",
        ] {
            let source = LocalServices {
                client_api_enabled: false,
                tacacs_proxy_enabled: true,
                tacacs_proxy_endpoint: Some(target.to_owned()),
                unix_socket_mode: 0o600,
                ..LocalServices::default()
            };
            let prepared = prepare_local_services(&source).unwrap();
            assert!(prepared.client_api().is_none());
            assert!(prepared.tacacs_proxy().is_some());
            assert_eq!(prepared.unix_socket_mode(), 0o600);
        }
    }

    #[test]
    fn rejects_invalid_listener_resources() {
        for document in [
            "{}",
            r#"{"tacacsrs:local-services":{}} {}"#,
            r#"{"tacacsrs:local-services":{"unknown":true}}"#,
            r#"{"tacacsrs:local-services":{"client-api-enabled":false}}"#,
            r#"{"tacacsrs:local-services":{"tacacs-proxy-enabled":true}}"#,
            r#"{"tacacsrs:local-services":{"tacacs-proxy-endpoint":"127.0.0.1:49"}}"#,
            r#"{"tacacsrs:local-services":{"unix-socket-mode":512}}"#,
            r#"{"tacacsrs:local-services":{"client-api-endpoint":"127.0.0.1:49"}}"#,
            r#"{"tacacsrs:local-services":{"client-api-endpoint":"/tmp/../tmp/socket"}}"#,
            r#"{"tacacsrs:local-services":{"client-api-endpoint":"/tmp/socket\u0000"}}"#,
        ] {
            assert!(parse_local_services(document.as_bytes()).is_err(), "accepted {document}");
        }
    }

    #[test]
    fn rejects_programmatic_ranges_and_lexical_endpoint_collisions() {
        let mut source = LocalServices {
            tacacs_proxy_enabled: true,
            tacacs_proxy_endpoint: Some("/run//tacacs/./tacacs.sock".to_owned()),
            ..LocalServices::default()
        };
        assert!(prepare_local_services(&source).is_err());
        source.tacacs_proxy_endpoint = Some("/tmp/proxy.sock".to_owned());
        source.unix_socket_mode = 0o1000;
        assert!(prepare_local_services(&source).is_err());
        source.unix_socket_mode = 0o660;
        source.client_api_endpoint = format!("/{}", "x".repeat(107));
        assert!(prepare_local_services(&source).is_err());
    }
}
