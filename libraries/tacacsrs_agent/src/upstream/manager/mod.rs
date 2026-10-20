//! Publishes prepared catalogs with service policy, admission, and health.
//!
//! Networking owns route selection, circuits, cached connections, and reconnect
//! serialization. The manager retains source metadata and projects YANG inputs.
//!
//! # Atomic publication commit
//!
//! The manager owns the active catalog (`active_snapshot`), its fields, and the
//! request-capture surface. Captured leases own admission. Every snapshot write lives in the
//! [`publication`] module:
//! [`publish_policy`](UpstreamManager::publish_policy),
//! [`publish_initial_health`](UpstreamManager::publish_initial_health), and
//! [`reload_shared_servers_with_retirement`](UpstreamManager::reload_shared_servers_with_retirement).
//! Each takes the `active_snapshot` write lock (the catalog reload also holds
//! `catalog_reload_lock` first and prepares the new server set), then commits
//! generation, server count, and health through the [`PublicationController`] in
//! one health mutation. The manager-supplied commit callback swaps the snapshot
//! and runs coordinator bookkeeping. It never awaits and never reacquires these
//! locks. Upstream retirement awaits only after the write lock is released, so a
//! cancelled retirement cannot leave bookkeeping behind the applied snapshot. See
//! the [`publication`] module for the full write-path and lock-order contract.

use std::sync::{Arc, RwLock as StdRwLock};
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_config::prepare::PrepareOptions;
use tacacsrs_networking::routed::EndpointConnector;

use self::publication::PublicationController;
use self::server_set::{RuntimeRoutingSnapshot, ServerSet};
use self::prepared_server::PreparedServer;
use crate::config::{PreparedProxyPolicy, RuntimePolicy};
#[cfg(test)]
use crate::config::{FailoverStrategy, OperationPolicies};
use crate::runtime::RuntimeHealthPublisher;
use crate::upstream::admission::AdmissionRegistry;
use crate::upstream::{OperationKind, ProxyTransportSettings};
#[cfg(test)]
use crate::upstream::UpstreamConnector;

pub(crate) use self::server_set::{BoundServer, RoutingLease};
#[cfg(test)]
pub(crate) use self::server_set::ServiceConnector;

mod server_set;
mod prepared_server;
mod publication;
pub(crate) use publication::PublicationCandidate;
mod binding;

/// Publishes catalogs and captures request policy for both local services.
///
/// Networking supplies the binding and records routing outcomes. This adapter
/// associates that binding with source metadata and generation-aware health.
pub(crate) struct UpstreamManager<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    closed: std::sync::atomic::AtomicBool,
    /// Serializes catalog preparation and the snapshot swap. It is the inner
    /// lock, held after the service publication lock.
    catalog_reload_lock: tokio::sync::Mutex<()>,
    /// Active routing snapshot for new requests. Readers clone the `Arc`;
    /// publication swaps it under the write lock.
    active_snapshot: StdRwLock<Arc<RuntimeRoutingSnapshot<Connector>>>,
    connect_options: PrepareOptions,
    /// Serializes generation publication and server-availability observations.
    publication: PublicationController,
    prepared_history:
        std::sync::Mutex<Vec<(tacacsrs_networking::routed::Endpoint, Arc<TacacsPlusServer>)>>,
}

#[cfg(test)]
impl UpstreamManager<ServiceConnector> {
    /// Creates shared failover state for the service runtime.
    ///
    /// The runtime can start without a configured server while it waits for
    /// external configuration. In this state, IPC requests immediately return
    /// a retriable configuration error.
    #[cfg(test)]
    pub(crate) fn new(
        servers: Vec<TacacsPlusServer>,
        connector: Arc<UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
        health: RuntimeHealthPublisher,
    ) -> Self {
        let servers = servers.into_iter().map(Arc::new).collect();
        Self::new_shared_with_proxy_downstream_obfuscation(
            servers,
            PreparedProxyPolicy::unobfuscated(),
            RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::default(),
                preferred_probe_interval,
            )
            .expect("test recovery interval must be nonzero"),
            connector,
            health,
            PrepareOptions::default(),
        )
        .expect("test endpoints must prepare")
    }

    #[cfg(test)]
    pub(crate) fn new_shared(
        servers: Vec<Arc<TacacsPlusServer>>,
        connector: Arc<UpstreamConnector>,
        preferred_probe_interval: std::time::Duration,
        health: RuntimeHealthPublisher,
    ) -> Self {
        Self::new_shared_with_proxy_downstream_obfuscation(
            servers,
            PreparedProxyPolicy::unobfuscated(),
            RuntimePolicy::new(
                FailoverStrategy::default(),
                FailoverStrategy::default(),
                OperationPolicies::default(),
                preferred_probe_interval,
            )
            .expect("test recovery interval must be nonzero"),
            connector,
            health,
            PrepareOptions::default(),
        )
        .expect("test endpoints must prepare")
    }

    pub(crate) fn new_shared_with_proxy_downstream_obfuscation(
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
        runtime_policy: RuntimePolicy,
        connector: Arc<UpstreamConnector>,
        health: RuntimeHealthPublisher,
        connect_options: PrepareOptions,
    ) -> anyhow::Result<Self> {
        Self::from_connector(
            servers,
            proxy_downstream_obfuscation,
            runtime_policy,
            ServiceConnector(connector),
            health,
            connect_options,
        )
    }
}

impl<Connector: EndpointConnector> UpstreamManager<Connector> {
    pub(crate) fn from_connector(
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
        runtime_policy: RuntimePolicy,
        connector: Connector,
        health: RuntimeHealthPublisher,
        connect_options: PrepareOptions,
    ) -> anyhow::Result<Self> {
        let servers = servers
            .into_iter()
            .map(|server| PreparedServer::new(server, connect_options.clone()).map(Arc::new))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let credential_lifetime = servers
            .iter()
            .try_fold(crate::runtime::CredentialLifetime::unbounded(), |lifetime, server| {
                lifetime.intersect(server.evidence_lifetime)
            })?;
        let server_set = Arc::new(ServerSet::new(servers, connector));
        let prepared_history = std::sync::Mutex::new(
            server_set
                .servers
                .iter()
                .map(|slot| (slot.endpoint.clone(), slot.server.clone()))
                .collect(),
        );
        Ok(Self {
            closed: std::sync::atomic::AtomicBool::new(false),
            catalog_reload_lock: tokio::sync::Mutex::new(()),
            active_snapshot: StdRwLock::new(Arc::new(RuntimeRoutingSnapshot {
                generation: 0,
                availability_generation: 0,
                server_set,
                proxy_downstream_obfuscation,
                admission: Arc::new(AdmissionRegistry::new(&runtime_policy)),
                runtime_policy: Arc::new(runtime_policy),
                credential_lifetime,
            })),
            connect_options,
            publication: PublicationController::new(health),
            prepared_history,
        })
    }

    fn current_runtime(&self) -> Arc<RuntimeRoutingSnapshot<Connector>> {
        Arc::clone(
            &self
                .active_snapshot
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub(crate) fn candidate_limits(&self) -> crate::config::RuntimeCandidateLimits {
        self.current_runtime().runtime_policy.candidate_limits()
    }

    pub(crate) fn statistics(&self) -> tacacsrs_config::OperationalStatistics {
        let runtime = self.current_runtime();
        Self::statistics_from_runtime(&runtime, None)
    }

    pub(crate) fn diagnostics_json(
        &self,
        filter: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<String> {
        let runtime = self.current_runtime();
        let mut count = 0;
        for server in runtime
            .server_set
            .servers
            .iter()
            .filter(|server| filter.is_none_or(|name| name == server.server.name))
        {
            count += 1;
            anyhow::ensure!(
                count <= 128,
                "Too many servers for one diagnostics response; select a server"
            );
            for text in [
                Some(server.server.name.as_str()),
                Some(server.server.address.as_str()),
                server.server.source_ip.as_deref(),
                server.server.vrf_instance.as_deref(),
            ] {
                anyhow::ensure!(
                    text.is_none_or(|text| text.len() <= 1024),
                    "Server metadata exceeds the diagnostics limit"
                );
            }
        }
        anyhow::ensure!(filter.is_none() || count != 0, "No server matches the requested name");
        Self::statistics_from_runtime(&runtime, filter).to_yang_json_bounded(limit)
    }

    fn statistics_from_runtime(
        runtime: &server_set::RuntimeRoutingSnapshot<Connector>,
        filter: Option<&str>,
    ) -> tacacsrs_config::OperationalStatistics {
        tacacsrs_config::OperationalStatistics {
            runtime_generation: runtime.generation,
            servers: runtime
                .server_set
                .servers
                .iter()
                .filter(|server| filter.is_none_or(|name| name == server.server.name))
                .map(|server| {
                    let snapshot = server.counters.snapshot();
                    tacacsrs_config::ServerOperationalStatistics {
                        name: server.server.name.clone(),
                        counter_epoch: snapshot.epoch,
                        diagnostics: Some(tacacsrs_config::ServerDiagnostics::new(
                            &server.server,
                            snapshot.diagnostics.clone(),
                            tacacsrs_networking::routed::OperationKind::ALL
                                .into_iter()
                                .map(|operation| {
                                    let circuit = runtime
                                        .server_set
                                        .client
                                        .circuit_open(&server.server.name, operation);
                                    tacacsrs_config::RoutingStatus {
                                        operation: operation.name(),
                                        eligible: circuit.is_some(),
                                        on_hold: circuit.unwrap_or(false),
                                    }
                                })
                                .collect(),
                        )),
                        statistics: snapshot.into(),
                    }
                })
                .collect(),
        }
    }

    pub(crate) fn retirement_deadline(
        &self,
    ) -> anyhow::Result<tacacsrs_networking::RequestDeadline> {
        let runtime = self.current_runtime();
        let budget = OperationKind::ALL
            .into_iter()
            .map(|operation| runtime.runtime_policy.limits(operation).request_timeout())
            .max()
            .unwrap_or_default();
        tacacsrs_networking::RequestDeadline::after(budget)
    }

    pub(crate) fn ensure_open(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.closed.load(std::sync::atomic::Ordering::Acquire),
            "The TACACS+ service is closed"
        );
        Ok(())
    }

    pub(crate) fn shutdown_timeout(&self) -> std::time::Duration {
        self.current_runtime().runtime_policy.shutdown_timeout()
    }

    pub(crate) fn source_stale_timeout(&self) -> std::time::Duration {
        self.current_runtime().runtime_policy.source_stale_timeout()
    }

    pub(crate) fn credential_stale_timeout(&self) -> std::time::Duration {
        self.current_runtime()
            .runtime_policy
            .credential_stale_timeout()
    }

    pub(crate) fn credential_refresh_interval(&self) -> std::time::Duration {
        self.current_runtime()
            .runtime_policy
            .credential_refresh_interval()
    }

    pub(crate) fn shutdown_deadline(&self) -> anyhow::Result<tacacsrs_networking::RequestDeadline> {
        let runtime = self.current_runtime();
        let requests = OperationKind::ALL
            .into_iter()
            .map(|operation| runtime.runtime_policy.limits(operation).request_timeout())
            .max()
            .unwrap_or_default();
        tacacsrs_networking::RequestDeadline::after(
            requests.min(runtime.runtime_policy.shutdown_timeout()),
        )
    }

    pub(crate) fn close(&self) {
        let runtime = self
            .active_snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        runtime.admission.close();
        runtime.server_set.client.close();
    }

    pub(crate) fn cancel(&self) {
        self.close();
        self.current_server_set().client.cancel();
    }

    pub(crate) async fn close_and_join(
        &self,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        self.close();
        self.current_server_set()
            .client
            .close_and_join(deadline)
            .await
    }

    fn current_server_set(&self) -> Arc<ServerSet<Connector>> {
        Arc::clone(&self.current_runtime().server_set)
    }

    pub(in crate::upstream) fn capture_request(
        &self,
        service: crate::config::PolicyService,
        operation: OperationKind,
    ) -> RoutingLease<Connector> {
        let lease = RoutingLease::new(self.current_runtime(), service, operation);
        log::debug!(
            "Captured {} request routing generation {}",
            operation.name(),
            lease.generation()
        );
        lease
    }

    pub(crate) fn proxy_transport_settings(&self) -> ProxyTransportSettings {
        let runtime = self.current_runtime();
        let read_timeout = runtime
            .server_set
            .servers
            .iter()
            .map(|server| server.config().timeout_duration())
            .max()
            .unwrap_or_else(|| std::time::Duration::from_secs(5));
        ProxyTransportSettings::new(read_timeout, runtime.proxy_downstream_obfuscation.clone())
    }

    /// Atomically replaces the runtime policy for new requests.
    #[cfg(test)]
    pub(crate) fn reload_runtime_policy(&self, runtime_policy: RuntimePolicy) -> bool {
        self.admit_policy()
            .and_then(|revision| self.publish_policy(revision, runtime_policy))
            .is_ok_and(|outcome| matches!(outcome, crate::PolicyUpdate::Applied(_)))
    }

    pub(crate) fn admit_policy(&self) -> anyhow::Result<crate::PolicyRevision> {
        let _runtime = self
            .active_snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_open()?;
        Ok(self.publication.admit_policy())
    }

    pub(crate) fn reject_policy(
        &self,
        revision: crate::PolicyRevision,
    ) -> anyhow::Result<crate::PolicyUpdate> {
        let _runtime = self
            .active_snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_open()?;
        Ok(self.publication.reject_policy(revision))
    }

    /// Records startup state without opening cross-operation probe sessions.
    pub(crate) fn warm_connections(&self) {
        let server_set = self.current_server_set();
        if server_set.server_count() == 0 {
            log::warn!("No TACACS+ server is configured; waiting for configuration");
            return;
        }
        log::info!(
            "Configured {} TACACS+ server(s); operation connections will open on first use",
            server_set.server_count()
        );
    }

    /// Returns the number of configured TACACS+ servers.
    pub(crate) fn server_count(&self) -> usize {
        self.current_server_set().server_count()
    }

    /// Returns the number of servers eligible for one operation.
    #[cfg(test)]
    pub(crate) fn eligible_server_count(&self, operation: OperationKind) -> usize {
        self.current_server_set().client.eligible_count(operation)
    }

    /// Atomically replaces the configured TACACS+ server set.
    ///
    /// New IPC requests use the new ordered server set. Bound requests continue
    /// to use their existing connections. The manager keeps cached connections
    /// for unchanged servers. Connections for removed or changed servers stop
    /// accepting new sessions and leave the active runtime state.
    #[cfg(test)]
    pub(crate) async fn reload_servers(
        &self,
        servers: Vec<TacacsPlusServer>,
    ) -> anyhow::Result<()> {
        self.reload_shared_servers(servers.into_iter().map(Arc::new).collect())
            .await
    }

    #[cfg(test)]
    pub(crate) async fn reload_shared_servers(
        &self,
        servers: Vec<Arc<TacacsPlusServer>>,
    ) -> anyhow::Result<()> {
        self.reload_shared_servers_with_retirement(self.capture_upstream_reload(servers), None)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn reload_shared_servers_with_proxy_downstream_obfuscation(
        &self,
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        self.reload_shared_servers_with_commit(servers, proxy_downstream_obfuscation, || None)
            .await
    }

    /// Commits caller bookkeeping with the catalog, before health readers see it.
    /// The callback must not block, fail, or acquire runtime or health locks.
    #[cfg(test)]
    pub(crate) async fn reload_shared_servers_with_commit(
        &self,
        servers: Vec<Arc<TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
        commit: impl FnOnce() -> Option<crate::runtime::MaterializationCommit> + Send,
    ) -> anyhow::Result<()> {
        self.reload_shared_servers_with_retirement(
            PublicationCandidate::new(servers, proxy_downstream_obfuscation, None, None, commit),
            None,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) fn pause_next_publication(&self) -> Arc<tokio::sync::Notify> {
        self.publication.pause_next_publication()
    }
}

#[cfg(test)]
mod tests;
