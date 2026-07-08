//! Runtime TACACS+ configuration filters composed by the daemon entry point.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use futures_util::future::{BoxFuture, FutureExt};
use tacacsrs_agent::EnabledServices;
use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_config::{TacacsPlus, TacacsPlusServer};

/// Filters a validated TACACS+ configuration before it is applied to runtime state.
pub(crate) trait TacacsPlusFilter: Send + Sync {
    /// Return the configuration snapshot that should be applied to the daemon.
    fn filter(&self, tacacs_plus: TacacsPlus) -> BoxFuture<'_, TacacsPlus>;
}

/// Filter implementation that preserves every server unchanged.
#[derive(Debug, Default)]
pub(crate) struct NoopTacacsPlusFilter;

impl TacacsPlusFilter for NoopTacacsPlusFilter {
    fn filter(&self, tacacs_plus: TacacsPlus) -> BoxFuture<'_, TacacsPlus> {
        async move { tacacs_plus }.boxed()
    }
}

/// Filter that removes upstream servers targeting the local TCP proxy endpoint.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProxySelfLoopFilter {
    proxy_endpoint: SocketAddr,
}

impl ProxySelfLoopFilter {
    /// Create a filter for the local TCP proxy endpoint.
    #[must_use]
    pub(crate) const fn new(proxy_endpoint: SocketAddr) -> Self {
        Self { proxy_endpoint }
    }

    async fn filter_proxy_self_loop_servers(&self, mut tacacs_plus: TacacsPlus) -> TacacsPlus {
        let original_server_count = tacacs_plus.server.len();
        let mut retained = Vec::with_capacity(original_server_count);
        for server in tacacs_plus.server {
            if upstream_server_targets_proxy_endpoint(&server, self.proxy_endpoint).await {
                log::warn!(
                    "Ignoring upstream TACACS+ server '{}' at {}:{} because it resolves to the local TACACS+ proxy endpoint {}; keeping it would proxy client traffic back into this daemon",
                    server.name,
                    server.address,
                    server.port,
                    self.proxy_endpoint,
                );
            } else {
                retained.push(server);
            }
        }

        let filtered_count = original_server_count.saturating_sub(retained.len());
        tacacs_plus.server = retained;

        if filtered_count > 0 {
            log::info!(
                "Filtered {filtered_count} upstream TACACS+ server(s) that target the local proxy endpoint {}",
                self.proxy_endpoint,
            );
        }
        if original_server_count > 0 && tacacs_plus.server.is_empty() {
            log::warn!(
                "All configured upstream TACACS+ servers target the local proxy endpoint {}; waiting for a non-looping upstream configuration",
                self.proxy_endpoint,
            );
        }

        tacacs_plus
    }
}

impl TacacsPlusFilter for ProxySelfLoopFilter {
    fn filter(&self, tacacs_plus: TacacsPlus) -> BoxFuture<'_, TacacsPlus> {
        async move { self.filter_proxy_self_loop_servers(tacacs_plus).await }.boxed()
    }
}

/// Compose the runtime config filter for the selected daemon services.
#[must_use]
pub(crate) fn config_filter_from_runtime_options(
    enabled_services: EnabledServices,
    proxy_endpoint: Option<&IpcEndpoint>,
) -> Arc<dyn TacacsPlusFilter> {
    if !enabled_services.tacacs_proxy() {
        return Arc::new(NoopTacacsPlusFilter);
    }

    match proxy_endpoint {
        Some(IpcEndpoint::Tcp(address)) => Arc::new(ProxySelfLoopFilter::new(*address)),
        _ => Arc::new(NoopTacacsPlusFilter),
    }
}

async fn upstream_server_targets_proxy_endpoint(
    server: &TacacsPlusServer,
    proxy_endpoint: SocketAddr,
) -> bool {
    if server.port != proxy_endpoint.port() {
        return false;
    }

    if let Ok(address) = server.address.parse::<IpAddr>() {
        return SocketAddr::new(address, server.port) == proxy_endpoint;
    }

    match tokio::net::lookup_host((server.address.as_str(), server.port)).await {
        Ok(mut addresses) => addresses.any(|address| address == proxy_endpoint),
        Err(error) => {
            log::warn!(
                "Failed to resolve upstream TACACS+ server '{}' at {}:{} while checking for a local proxy self-loop: {error}; keeping the server",
                server.name,
                server.address,
                server.port,
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        config_filter_from_runtime_options, NoopTacacsPlusFilter, ProxySelfLoopFilter,
        TacacsPlusFilter,
    };
    use tacacsrs_agent::EnabledServices;
    use tacacsrs_agent_client::IpcEndpoint;
    use tacacsrs_config::{TacacsPlus, TacacsPlusBuilder, TacacsPlusServerBuilder};
    use tacacsrs_config::TacacsPlusServerType;

    fn test_config_from_host_ports(addresses: &[(&str, u16)]) -> TacacsPlus {
        addresses
            .iter()
            .enumerate()
            .map(|(index, (address, port))| {
                TacacsPlusServerBuilder::new(
                    format!("server-{index}"),
                    TacacsPlusServerType::AUTHENTICATION
                        | TacacsPlusServerType::AUTHORIZATION
                        | TacacsPlusServerType::ACCOUNTING,
                    (*address).to_owned(),
                    *port,
                )
                .with_shared_secret("test-secret".to_owned())
            })
            .fold(TacacsPlusBuilder::new(), TacacsPlusBuilder::with_server_builder)
            .build()
            .expect("test config should be valid")
    }

    #[tokio::test]
    async fn runtime_options_select_proxy_filter_for_enabled_tcp_proxy() {
        let endpoint = Some(
            "127.0.0.1:9050"
                .parse::<IpcEndpoint>()
                .expect("TCP endpoint should parse"),
        );
        let config = test_config_from_host_ports(&[("127.0.0.1", 9050), ("192.0.2.20", 49)]);
        let filter =
            config_filter_from_runtime_options(EnabledServices::TACACS_PROXY, endpoint.as_ref());

        let filtered = filter.filter(config).await;

        assert_eq!(filtered.server.len(), 1);
        assert_eq!(filtered.server[0].address, "192.0.2.20");
    }

    #[tokio::test]
    async fn runtime_options_select_noop_filter_when_proxy_is_disabled() {
        let endpoint = Some(
            "127.0.0.1:9050"
                .parse::<IpcEndpoint>()
                .expect("TCP endpoint should parse"),
        );
        let config = test_config_from_host_ports(&[("127.0.0.1", 9050)]);
        let filter =
            config_filter_from_runtime_options(EnabledServices::CLIENT_API, endpoint.as_ref());

        let filtered = filter.filter(config).await;

        assert_eq!(filtered.server.len(), 1);
        assert_eq!(filtered.server[0].address, "127.0.0.1");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_options_select_noop_filter_for_unix_proxy() {
        let endpoint = Some(
            "/run/tacacs/proxy.sock"
                .parse::<IpcEndpoint>()
                .expect("Unix endpoint should parse"),
        );
        let config = test_config_from_host_ports(&[("127.0.0.1", 9050)]);
        let filter =
            config_filter_from_runtime_options(EnabledServices::TACACS_PROXY, endpoint.as_ref());

        let filtered = filter.filter(config).await;

        assert_eq!(filtered.server.len(), 1);
        assert_eq!(filtered.server[0].address, "127.0.0.1");
    }

    #[tokio::test]
    async fn noop_filter_preserves_all_servers() {
        let config = test_config_from_host_ports(&[("127.0.0.1", 9050)]);

        let filtered = NoopTacacsPlusFilter.filter(config).await;

        assert_eq!(filtered.server.len(), 1);
        assert_eq!(filtered.server[0].address, "127.0.0.1");
    }

    #[tokio::test]
    async fn proxy_filter_removes_matching_ipv4_endpoint() {
        let config = test_config_from_host_ports(&[("127.0.0.1", 9050), ("192.0.2.20", 49)]);
        let filter =
            ProxySelfLoopFilter::new("127.0.0.1:9050".parse().expect("socket should parse"));

        let filtered = filter.filter(config).await;

        assert_eq!(filtered.server.len(), 1);
        assert_eq!(filtered.server[0].address, "192.0.2.20");
    }

    #[tokio::test]
    async fn proxy_filter_removes_matching_ipv6_endpoint() {
        let config = test_config_from_host_ports(&[("::1", 9050), ("192.0.2.20", 49)]);
        let filter = ProxySelfLoopFilter::new("[::1]:9050".parse().expect("socket should parse"));

        let filtered = filter.filter(config).await;

        assert_eq!(filtered.server.len(), 1);
        assert_eq!(filtered.server[0].address, "192.0.2.20");
    }

    #[tokio::test]
    async fn proxy_filter_resolves_localhost_hostname() {
        let proxy_endpoint = tokio::net::lookup_host(("localhost", 9050))
            .await
            .expect("localhost should resolve")
            .next()
            .expect("localhost should have at least one address");
        let config = test_config_from_host_ports(&[("localhost", 9050), ("192.0.2.20", 49)]);
        let filter = ProxySelfLoopFilter::new(proxy_endpoint);

        let filtered = filter.filter(config).await;

        assert_eq!(filtered.server.len(), 1);
        assert_eq!(filtered.server[0].address, "192.0.2.20");
    }

    #[tokio::test]
    async fn proxy_filter_preserves_different_loopback_port() {
        let config = test_config_from_host_ports(&[("127.0.0.1", 9051), ("192.0.2.20", 49)]);
        let filter =
            ProxySelfLoopFilter::new("127.0.0.1:9050".parse().expect("socket should parse"));

        let filtered = filter.filter(config).await;

        assert_eq!(filtered.server.len(), 2);
    }

    #[tokio::test]
    async fn proxy_filter_preserves_non_loopback_same_port() {
        let config = test_config_from_host_ports(&[("192.0.2.20", 9050)]);
        let filter =
            ProxySelfLoopFilter::new("127.0.0.1:9050".parse().expect("socket should parse"));

        let filtered = filter.filter(config).await;

        assert_eq!(filtered.server.len(), 1);
        assert_eq!(filtered.server[0].address, "192.0.2.20");
    }
}
