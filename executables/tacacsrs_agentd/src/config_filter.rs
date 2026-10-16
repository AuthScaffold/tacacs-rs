//! Runtime TACACS+ configuration filters composed by the daemon entry point.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, ensure};
use futures_util::future::{BoxFuture, FutureExt};
use tacacsrs_config::local_services::{prepare_local_services, ListenerEndpoint};
use tacacsrs_config::proxy_policy::{prepare_proxy_policy, PreparedProxyPolicy};
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_config::{TacacsPlus, TacacsPlusServer, TacacsPlusServerExt};

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
        let local_addresses = if self.proxy_endpoint.ip().to_canonical().is_unspecified() {
            if_addrs::get_if_addrs()
                .context("read local interfaces for proxy loop validation")?
                .into_iter()
                .map(|interface| interface.ip())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut filtered_names = HashSet::new();
        let mut selected_proxy_server: Option<TacacsPlusServer> = None;

        for server in &enumerated_servers {
            let resolution = async {
                tokio::net::lookup_host((server.address.as_str(), server.port))
                    .await
                    .map(Iterator::collect::<Vec<_>>)
            };
            if upstream_server_targets_proxy_endpoint(
                server,
                self.proxy_endpoint,
                &local_addresses,
                resolution,
            )
            .await?
            {
                ensure!(
                    !server.is_tls(),
                    "TLS upstream targets the local raw TACACS+ proxy endpoint"
                );
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
    local_addresses: &[IpAddr],
    resolution: impl std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send,
) -> anyhow::Result<bool> {
    if server.port != proxy_endpoint.port() {
        return Ok(false);
    }

    let listener = ListenerEndpoint::Tcp(proxy_endpoint);
    if let Ok(address) = server.address.parse::<IpAddr>() {
        ensure!(
            !address.to_canonical().is_unspecified(),
            "Upstream address must be specified during proxy loop validation"
        );
        return Ok(
            listener.covers_tcp_destination(SocketAddr::new(address, server.port), local_addresses)
        );
    }

    let addresses = tokio::time::timeout(server.timeout_duration(), resolution)
        .await
        .context("DNS lookup timed out during proxy loop validation")?
        .context("DNS lookup failed during proxy loop validation")?;
    ensure!(!addresses.is_empty(), "DNS returned no addresses during proxy loop validation");
    ensure!(
        addresses
            .iter()
            .all(|address| !address.ip().to_canonical().is_unspecified()),
        "DNS returned an unspecified address during proxy loop validation"
    );
    Ok(addresses
        .into_iter()
        .any(|address| listener.covers_tcp_destination(address, local_addresses)))
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
    async fn wildcard_proxy_filters_loopback_without_removing_remote_servers() {
        let source = LocalServices {
            tacacs_proxy_enabled: true,
            tacacs_proxy_endpoint: Some("0.0.0.0:9050".to_owned()),
            ..LocalServices::default()
        };
        let filter = config_filter_from_local_services(&source).unwrap();
        let upstream = test_config_from_host_ports(&[("127.0.0.1", 9050), ("192.0.2.20", 9050)]);
        let filtered = filter.filter(upstream).await.unwrap();
        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "192.0.2.20");
    }

    #[tokio::test]
    async fn sonic_local_row_survives_mapping_until_runtime_credential_preparation() {
        use std::collections::BTreeMap;
        use tacacsrs_sonic::{SonicTacacsTables, map_sonic_tables_to_tacacs_plus};

        let hash = |values: &[(&str, &str)]| {
            values
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect()
        };
        let tables = SonicTacacsTables::with_extended_tables(
            BTreeMap::new(),
            BTreeMap::from([
                (
                    "127.0.0.1".to_owned(),
                    hash(&[("priority", "64"), ("passkey", "local-test-key")]),
                ),
                (
                    "192.0.2.20".to_owned(),
                    hash(&[("priority", "16"), ("passkey", "remote-test-key")]),
                ),
            ]),
            BTreeMap::new(),
            hash(&[
                ("local_listen_address", "127.0.0.1"),
                ("local_listen_port", "49"),
            ]),
        );
        let canonical = map_sonic_tables_to_tacacs_plus(&tables).unwrap();
        assert_eq!(canonical.server.len(), 2);
        let original = canonical.clone();
        let filter = ProxySelfLoopFilter::new("127.0.0.1:49".parse().unwrap());
        let filtered = filter.filter(canonical.clone()).await.unwrap();
        assert_eq!(filtered.tacacs_plus.server.len(), 1);
        assert_eq!(filtered.tacacs_plus.server[0].address, "192.0.2.20");
        assert_eq!(
            filtered.proxy_downstream_obfuscation,
            proxy_obfuscation(Some("local-test-key"))
        );
        assert_eq!(canonical, original);
    }

    #[tokio::test(start_paused = true)]
    async fn loop_validation_rejects_failed_empty_and_timed_out_dns() {
        use super::upstream_server_targets_proxy_endpoint;
        use futures_util::future::{ready, pending};

        let source = test_config_from_host_ports(&[("upstream.example", 49)]);
        let server = &source.server[0];
        let endpoint = "127.0.0.1:49".parse().unwrap();
        assert!(upstream_server_targets_proxy_endpoint(
            server,
            endpoint,
            &[],
            ready(Err(std::io::Error::other("unavailable")))
        )
        .await
        .is_err());
        assert!(upstream_server_targets_proxy_endpoint(
            server,
            endpoint,
            &[],
            ready(Ok(Vec::new()))
        )
        .await
        .is_err());
        assert!(upstream_server_targets_proxy_endpoint(
            server,
            endpoint,
            &[],
            ready(Ok(vec!["0.0.0.0:49".parse().unwrap()]))
        )
        .await
        .is_err());
        assert!(upstream_server_targets_proxy_endpoint(server, endpoint, &[], pending())
            .await
            .is_err());
        assert!(!upstream_server_targets_proxy_endpoint(
            server,
            "127.0.0.1:50".parse().unwrap(),
            &[],
            pending()
        )
        .await
        .unwrap());
        for address in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
            let source = test_config_from_host_ports(&[(address, 49)]);
            assert!(upstream_server_targets_proxy_endpoint(
                &source.server[0],
                endpoint,
                &[],
                pending()
            )
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn loop_validation_checks_every_resolved_address_and_local_interface() {
        use super::upstream_server_targets_proxy_endpoint;
        use futures_util::future::ready;

        let source = test_config_from_host_ports(&[("upstream.example", 49)]);
        let server = &source.server[0];
        let local = "192.0.2.10:49".parse::<std::net::SocketAddr>().unwrap();
        let remote = "192.0.2.20:49".parse().unwrap();
        let endpoint = "0.0.0.0:49".parse().unwrap();
        assert!(upstream_server_targets_proxy_endpoint(
            server,
            endpoint,
            &[local.ip()],
            ready(Ok(vec![remote, local]))
        )
        .await
        .unwrap());
        assert!(!upstream_server_targets_proxy_endpoint(
            server,
            endpoint,
            &[local.ip()],
            ready(Ok(vec![remote]))
        )
        .await
        .unwrap());
        let mapped = "[::ffff:127.0.0.1]:49".parse().unwrap();
        assert!(upstream_server_targets_proxy_endpoint(
            server,
            "127.0.0.1:49".parse().unwrap(),
            &[],
            ready(Ok(vec![remote, mapped]))
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn tls_self_target_is_rejected_by_the_shared_runtime_filter() {
        let mut source = test_config_from_host_ports(&[("127.0.0.1", 49)]);
        source.server[0] =
            TacacsPlusServerBuilder::new("self", TacacsPlusServerType::all(), "127.0.0.1", 49)
                .with_tls_server_authentication()
                .build();
        let canonical = source.clone();
        let filter = ProxySelfLoopFilter::new_with_policy(
            "127.0.0.1:49".parse().unwrap(),
            credential_source(None),
        );
        assert!(filter.filter(source).await.is_err());
        assert!(canonical.server[0].client_identity.is_none());
        assert!(canonical.server[0].server_authentication.is_some());
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
