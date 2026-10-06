//! Runtime TACACS+ configuration filters composed by the daemon entry point.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use futures_util::future::{BoxFuture, FutureExt};
use tacacsrs_config::local_services::{prepare_local_services, ListenerEndpoint};
use tacacsrs_config::proxy_policy::{prepare_proxy_policy, PreparedProxyPolicy};
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_config::{TacacsPlus, TacacsPlusServer};

/// Filtered daemon configuration plus local proxy-only metadata derived from it.
pub(crate) struct FilteredTacacsPlus {
    /// TACACS+ configuration to apply to the upstream runtime state.
    pub(crate) tacacs_plus: TacacsPlus,
    /// Obfuscation policy expected on downstream raw TACACS+ proxy traffic.
    pub(crate) proxy_downstream_obfuscation: PreparedProxyPolicy,
}

/// Filters a validated TACACS+ configuration before it is applied to runtime state.
pub(crate) trait TacacsPlusFilter: Send + Sync {
    /// Returns the configuration snapshot to apply to the daemon.
    fn filter(&self, tacacs_plus: TacacsPlus) -> BoxFuture<'_, anyhow::Result<FilteredTacacsPlus>>;
}

/// Filter implementation that preserves every server unchanged.
#[derive(Debug, Default)]
pub(crate) struct NoopTacacsPlusFilter {
    source: LocalServices,
}

impl NoopTacacsPlusFilter {
    fn new(source: LocalServices) -> Self {
        Self { source }
    }
}

impl TacacsPlusFilter for NoopTacacsPlusFilter {
    fn filter(&self, tacacs_plus: TacacsPlus) -> BoxFuture<'_, anyhow::Result<FilteredTacacsPlus>> {
        async move {
            let proxy_downstream_obfuscation = prepare_proxy_policy(&self.source, None)?;
            Ok(FilteredTacacsPlus {
                tacacs_plus,
                proxy_downstream_obfuscation,
            })
        }
        .boxed()
    }
}

/// Filter that removes upstream servers targeting the local TCP proxy endpoint.
#[derive(Debug, Clone)]
pub(crate) struct ProxySelfLoopFilter {
    proxy_endpoint: SocketAddr,
    source: LocalServices,
}

impl ProxySelfLoopFilter {
    /// Create a filter for the local TCP proxy endpoint.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(proxy_endpoint: SocketAddr) -> Self {
        Self::new_with_policy(
            proxy_endpoint,
            LocalServices {
                tacacs_proxy_enabled: true,
                tacacs_proxy_endpoint: Some(proxy_endpoint.to_string()),
                proxy_credential_source:
                    tacacsrs_config::tacacsrs::ProxyCredentialSource::LocalProxyRow,
                ..LocalServices::default()
            },
        )
    }

    #[must_use]
    pub(crate) fn new_with_policy(proxy_endpoint: SocketAddr, source: LocalServices) -> Self {
        Self {
            proxy_endpoint,
            source,
        }
    }

    async fn filter_proxy_self_loop_servers(
        &self,
        mut tacacs_plus: TacacsPlus,
    ) -> anyhow::Result<FilteredTacacsPlus> {
        let original_server_count = tacacs_plus.server.len();
        let enumerated_servers = tacacsrs_config::enumerate_servers(&tacacs_plus)?;
        let mut filtered_names = HashSet::new();
        let mut selected_proxy_server: Option<TacacsPlusServer> = None;

        for server in &enumerated_servers {
            if upstream_server_targets_proxy_endpoint(server, self.proxy_endpoint).await {
                log::warn!(
                    "The daemon ignores upstream TACACS+ server '{}' at {}:{} because it resolves to the local TACACS+ proxy endpoint {}. If retained, this server sends client traffic back into the daemon.",
                    server.name,
                    server.address,
                    server.port,
                    self.proxy_endpoint,
                );
                filtered_names.insert(server.name.clone());
                if selected_proxy_server.is_none() {
                    selected_proxy_server = Some(server.clone());
                }
            }
        }

        let proxy_downstream_obfuscation =
            prepare_proxy_policy(&self.source, selected_proxy_server.as_ref())?;

        tacacs_plus
            .server
            .retain(|server| !filtered_names.contains(&server.name));

        let filtered_count = original_server_count.saturating_sub(tacacs_plus.server.len());

        if filtered_count > 0 {
            log::info!(
                "Filtered {filtered_count} upstream TACACS+ server(s) that target the local proxy endpoint {}",
                self.proxy_endpoint,
            );
        }
        if original_server_count > 0 && tacacs_plus.server.is_empty() {
            log::warn!(
                "All configured upstream TACACS+ servers target the local proxy endpoint {}. The daemon waits for a non-looping upstream configuration.",
                self.proxy_endpoint,
            );
        }
        Ok(FilteredTacacsPlus {
            tacacs_plus,
            proxy_downstream_obfuscation,
        })
    }
}

impl TacacsPlusFilter for ProxySelfLoopFilter {
    fn filter(&self, tacacs_plus: TacacsPlus) -> BoxFuture<'_, anyhow::Result<FilteredTacacsPlus>> {
        async move { self.filter_proxy_self_loop_servers(tacacs_plus).await }.boxed()
    }
}

/// Composes the runtime configuration filter for the selected daemon services.
pub(crate) fn config_filter_from_local_services(
    source: &LocalServices,
) -> anyhow::Result<Arc<dyn TacacsPlusFilter>> {
    let prepared = prepare_local_services(source)?;
    match prepared.tacacs_proxy() {
        Some(ListenerEndpoint::Tcp(address)) => {
            Ok(Arc::new(ProxySelfLoopFilter::new_with_policy(*address, source.clone())))
        }
        _ => Ok(Arc::new(NoopTacacsPlusFilter::new(source.clone()))),
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
                "The daemon failed to resolve upstream TACACS+ server '{}' at {}:{} during local proxy self-loop detection: {error}. The daemon keeps the server.",
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
        config_filter_from_local_services, NoopTacacsPlusFilter, ProxySelfLoopFilter,
        TacacsPlusFilter,
    };
    use std::sync::Arc;
    use tacacsrs_config::tacacsrs::{LocalServices, ProxyCredentialSource};
    use tacacsrs_config::proxy_policy::prepare_proxy_policy;
    use tacacsrs_agent::{EnabledServices, PreparedProxyPolicy};
    use tacacsrs_agent_client::IpcEndpoint;
    use tacacsrs_config::TacacsPlusServerType;
    use tacacsrs_config::{
        TacacsPlus, TacacsPlusBuilder, TacacsPlusServerBuilder, ValidationOptions,
        ValidationRelaxation,
    };
    use tacacsrs_secrets::SecretString;

    fn test_config_from_host_ports(addresses: &[(&str, u16)]) -> TacacsPlus {
        test_config_from_host_ports_and_secrets(
            &addresses
                .iter()
                .map(|(address, port)| (*address, *port, Some("test-secret")))
                .collect::<Vec<_>>(),
        )
    }

    fn test_config_from_host_ports_and_secrets(
        addresses: &[(&str, u16, Option<&str>)],
    ) -> TacacsPlus {
        addresses
            .iter()
            .enumerate()
            .map(|(index, (address, port, shared_secret))| {
                let builder = TacacsPlusServerBuilder::new(
                    format!("server-{index}"),
                    TacacsPlusServerType::AUTHENTICATION
                        | TacacsPlusServerType::AUTHORIZATION
                        | TacacsPlusServerType::ACCOUNTING,
                    (*address).to_owned(),
                    *port,
                );
                if let Some(shared_secret) = shared_secret {
                    builder.with_shared_secret((*shared_secret).to_owned())
                } else {
                    builder
                }
            })
            .fold(TacacsPlusBuilder::new(), TacacsPlusBuilder::with_server_builder)
            .build_with_options(
                &ValidationOptions::new()
                    .with_relaxation(ValidationRelaxation::AllowPlainTcpWithoutSharedSecret),
            )
            .expect("test configuration must be valid")
    }

    fn proxy_obfuscation(secret: Option<&str>) -> PreparedProxyPolicy {
        let source = credential_source(secret);
        prepare_proxy_policy(&source, None).unwrap()
    }

    fn credential_source(secret: Option<&str>) -> LocalServices {
        LocalServices {
            tacacs_proxy_enabled: true,
            proxy_credential_source: if secret.is_some() {
                ProxyCredentialSource::Inline
            } else {
                ProxyCredentialSource::Unobfuscated
            },
            proxy_shared_secret: secret.map(|value| SecretString::new(value.to_owned())),
            ..LocalServices::default()
        }
    }

    fn config_filter_from_runtime_options(
        enabled: EnabledServices,
        endpoint: Option<&IpcEndpoint>,
        secret: Option<&str>,
    ) -> Arc<dyn TacacsPlusFilter> {
        let mut source = credential_source(secret);
        source.client_api_enabled = enabled.client_api();
        source.tacacs_proxy_enabled = enabled.tacacs_proxy();
        source.tacacs_proxy_endpoint = enabled.tacacs_proxy().then(|| match endpoint.unwrap() {
            IpcEndpoint::Tcp(address) => address.to_string(),
            IpcEndpoint::Unix(path) => path.to_str().unwrap().to_owned(),
        });
        config_filter_from_local_services(&source).unwrap()
    }

    #[tokio::test]
    async fn runtime_options_select_proxy_filter_for_enabled_tcp_proxy() {
        let endpoint = Some(
            "127.0.0.1:9050"
                .parse::<IpcEndpoint>()
                .expect("TCP endpoint must parse"),
        );
        let config = test_config_from_host_ports(&[("127.0.0.1", 9050), ("192.0.2.20", 49)]);
        let filter = config_filter_from_runtime_options(
            EnabledServices::TACACS_PROXY,
            endpoint.as_ref(),
            None,
        );

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "192.0.2.20");
        assert_eq!(filtered.proxy_downstream_obfuscation, proxy_obfuscation(None));
    }

    #[tokio::test]
    async fn runtime_options_select_noop_filter_when_proxy_is_disabled() {
        let endpoint = Some(
            "127.0.0.1:9050"
                .parse::<IpcEndpoint>()
                .expect("TCP endpoint must parse"),
        );
        let config = test_config_from_host_ports(&[("127.0.0.1", 9050)]);
        let filter = config_filter_from_runtime_options(
            EnabledServices::CLIENT_API,
            endpoint.as_ref(),
            None,
        );

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "127.0.0.1");
        assert_eq!(filtered.proxy_downstream_obfuscation, PreparedProxyPolicy::unobfuscated());
    }

    #[tokio::test]
    async fn runtime_options_select_noop_filter_for_unix_proxy() {
        let endpoint = Some(
            "/run/tacacs/proxy.sock"
                .parse::<IpcEndpoint>()
                .expect("Unix endpoint must parse"),
        );
        let config = test_config_from_host_ports(&[("127.0.0.1", 9050)]);
        let filter = config_filter_from_runtime_options(
            EnabledServices::TACACS_PROXY,
            endpoint.as_ref(),
            None,
        );

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "127.0.0.1");
        assert_eq!(filtered.proxy_downstream_obfuscation, PreparedProxyPolicy::unobfuscated());
    }

    #[tokio::test]
    async fn noop_filter_preserves_all_servers() {
        let config = test_config_from_host_ports(&[("127.0.0.1", 9050)]);

        let filtered = NoopTacacsPlusFilter::default()
            .filter(config)
            .await
            .expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "127.0.0.1");
        assert_eq!(filtered.proxy_downstream_obfuscation, PreparedProxyPolicy::unobfuscated());
    }

    #[tokio::test]
    async fn proxy_filter_removes_matching_ipv4_endpoint() {
        let config = test_config_from_host_ports(&[("127.0.0.1", 9050), ("192.0.2.20", 49)]);
        let filter = ProxySelfLoopFilter::new("127.0.0.1:9050".parse().expect("socket must parse"));

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "192.0.2.20");
        assert_eq!(filtered.proxy_downstream_obfuscation, proxy_obfuscation(Some("test-secret")));
    }

    #[tokio::test]
    async fn proxy_filter_removes_matching_ipv6_endpoint() {
        let config = test_config_from_host_ports(&[("::1", 9050), ("192.0.2.20", 49)]);
        let filter = ProxySelfLoopFilter::new("[::1]:9050".parse().expect("socket must parse"));

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "192.0.2.20");
        assert_eq!(filtered.proxy_downstream_obfuscation, proxy_obfuscation(Some("test-secret")));
    }

    #[tokio::test]
    async fn proxy_filter_resolves_localhost_hostname() {
        let proxy_endpoint = tokio::net::lookup_host(("localhost", 9050))
            .await
            .expect("localhost must resolve")
            .next()
            .expect("localhost must have at least one address");
        let config = test_config_from_host_ports(&[("localhost", 9050), ("192.0.2.20", 49)]);
        let filter = ProxySelfLoopFilter::new(proxy_endpoint);

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "192.0.2.20");
        assert_eq!(filtered.proxy_downstream_obfuscation, proxy_obfuscation(Some("test-secret")));
    }

    #[tokio::test]
    async fn proxy_filter_preserves_different_loopback_port() {
        let config = test_config_from_host_ports(&[("127.0.0.1", 9051), ("192.0.2.20", 49)]);
        let filter = ProxySelfLoopFilter::new_with_policy(
            "127.0.0.1:9050".parse().unwrap(),
            credential_source(None),
        );

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 2);
        assert_eq!(filtered.proxy_downstream_obfuscation, PreparedProxyPolicy::unobfuscated());
    }

    #[tokio::test]
    async fn proxy_filter_preserves_non_loopback_same_port() {
        let config = test_config_from_host_ports(&[("192.0.2.20", 9050)]);
        let filter = ProxySelfLoopFilter::new_with_policy(
            "127.0.0.1:9050".parse().unwrap(),
            credential_source(None),
        );

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "192.0.2.20");
        assert_eq!(filtered.proxy_downstream_obfuscation, PreparedProxyPolicy::unobfuscated());
    }

    #[tokio::test]
    async fn runtime_options_use_cli_proxy_secret_when_no_local_proxy_row_matches() {
        let endpoint = Some(
            "127.0.0.1:9050"
                .parse::<IpcEndpoint>()
                .expect("TCP endpoint must parse"),
        );
        let config = test_config_from_host_ports(&[("192.0.2.20", 49)]);
        let filter = config_filter_from_runtime_options(
            EnabledServices::TACACS_PROXY,
            endpoint.as_ref(),
            Some("cli-proxy-secret"),
        );

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(
            filtered.proxy_downstream_obfuscation,
            proxy_obfuscation(Some("cli-proxy-secret"))
        );
    }

    #[tokio::test]
    async fn proxy_filter_preserves_explicit_secret_despite_matching_local_row() {
        let config = test_config_from_host_ports_and_secrets(&[
            ("127.0.0.1", 9050, Some("local-row-secret")),
            ("192.0.2.20", 49, Some("upstream-secret")),
        ]);
        let filter = ProxySelfLoopFilter::new_with_policy(
            "127.0.0.1:9050".parse().expect("socket must parse"),
            credential_source(Some("cli-proxy-secret")),
        );

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(
            filtered.proxy_downstream_obfuscation,
            proxy_obfuscation(Some("cli-proxy-secret"))
        );
    }

    #[tokio::test]
    async fn proxy_filter_uses_highest_priority_matching_proxy_secret() {
        let config = test_config_from_host_ports_and_secrets(&[
            ("127.0.0.1", 9050, Some("highest-priority-secret")),
            ("localhost", 9050, Some("lower-priority-secret")),
            ("192.0.2.20", 49, Some("upstream-secret")),
        ]);
        let filter = ProxySelfLoopFilter::new("127.0.0.1:9050".parse().expect("socket must parse"));

        let filtered = filter.filter(config).await.expect("filter must succeed");

        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "192.0.2.20");
        assert_eq!(
            filtered.proxy_downstream_obfuscation,
            proxy_obfuscation(Some("highest-priority-secret"))
        );
    }

    #[tokio::test]
    async fn proxy_filter_rejects_missing_highest_priority_secret_without_downgrade() {
        let config = test_config_from_host_ports_and_secrets(&[
            ("127.0.0.1", 9050, None),
            ("localhost", 9050, Some("lower-priority-secret")),
            ("192.0.2.20", 49, Some("upstream-secret")),
        ]);
        let filter = ProxySelfLoopFilter::new("127.0.0.1:9050".parse().expect("socket must parse"));

        assert!(filter.filter(config).await.is_err());
    }

    #[tokio::test]
    async fn row_policy_rejects_missing_and_empty_replacements_without_mutating_source() {
        let filter = ProxySelfLoopFilter::new("127.0.0.1:9050".parse().unwrap());
        let source = test_config_from_host_ports_and_secrets(&[
            ("127.0.0.1", 9050, Some("original-local-key")),
            ("192.0.2.20", 49, Some("upstream-key")),
        ]);
        let original = source.clone();
        let accepted = filter.filter(source.clone()).await.unwrap();
        let mut invalid = source.clone();
        invalid.server[0].shared_secret = Some(SecretString::new(String::new()));
        assert!(filter.filter(invalid).await.is_err());
        let missing = test_config_from_host_ports(&[("192.0.2.20", 49)]);
        assert!(filter.filter(missing).await.is_err());
        assert_eq!(source, original);
        assert_eq!(
            accepted
                .proxy_downstream_obfuscation
                .shared_secret()
                .unwrap(),
            source.server[0].shared_secret.as_ref()
        );
    }
}
