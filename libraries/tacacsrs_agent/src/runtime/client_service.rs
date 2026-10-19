//! Runtime orchestration for the central TACACS+ client service.
//!
//! This module owns the public [`TacacsClientService`] facade and the generic
//! [`ServiceRuntime`] engine. The facade exposes concrete native types. The
//! engine stays generic over the connector, and the crate validates that its
//! primary futures are `Send`. The module validates startup configuration,
//! applies datastore reloads, and controls graceful listener shutdown. It
//! delegates request handling and failover to
//! [`crate::upstream::manager::UpstreamManager`].
//!
//! # Startup sequence
//!
//! 1. [`TacacsClientService::new`] resolves the current upstream server set.
//! 2. [`TacacsClientService::serve_until`] warms connection state and binds
//!    each injected listener.
//! 3. The service accepts clients until the host requests shutdown.
//!
//! # Publication write path
//!
//! One reload travels through fixed owners in one direction:
//!
//! 1. The materialization coordinator or a direct reload calls one reload
//!    method on [`TacacsClientService`].
//! 2. The [`ServiceRuntime`] engine holds `reload_publication_lock`, so only
//!    one publication runs end to end. It validates and prepares the catalog.
//! 3. [`UpstreamManager`](crate::upstream::manager::UpstreamManager) holds
//!    `catalog_reload_lock`, prepares the new server set, and swaps the active
//!    snapshot.
//! 4. The publication controller commits the generation, server count, and
//!    health in one health mutation. That commit also swaps the snapshot and
//!    runs coordinator bookkeeping. The commit does not await.
//!
//! # Lock order
//!
//! Acquire locks only in this order:
//! `reload_publication_lock` (service) -> `catalog_reload_lock` (manager) ->
//! active snapshot write lock -> publication observation lock -> health watch.
//! Upstream retirement awaits only after the snapshot write lock is released.
//!
//! # Cancellation and stale completion
//!
//! The host drives shutdown through [`serve_until`](TacacsClientService::serve_until).
//! Publication is the last step, so a dropped reload future leaves the previous
//! generation active. A late availability observation for a replaced generation
//! is ignored. Source and credential expiry and recovery are documented in
//! [`crate::runtime`] configuration supervision.
//!
//! # Graceful shutdown
//!
//! Shutdown uses this sequence:
//!
//! 1. Each listener stops accepting connections.
//! 2. Admission closes and active request handlers drain under one deadline.
//! 3. Remaining listener tasks are cancelled and joined.
//! 4. Current and historical upstream resources close and join using that deadline.
//! 5. Owned Unix socket paths are removed before stopped state is published.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tacacsrs_config::TacacsPlus;

use super::{RuntimeHealthPublisher, RuntimeListenerService};
use crate::config::{PreparedProxyPolicy, RuntimePolicy, ServiceConfig};
use crate::services::client_api::{ClientApiHandle, UpstreamBridge};
use crate::upstream::NetworkUpstreamConnector;

mod engine;

use engine::ServiceRuntime;
/// Prepared settings for a host-composed runtime listener.
///
/// A host maps these transport-neutral values into its own listener options,
/// for example the IPC listener options. The agent runtime does not own the IPC
/// transport or protobuf schema.
#[derive(Debug, Clone, Copy)]
pub struct ListenerSettings {
    /// Unix socket file permission bits.
    pub socket_mode: u32,
    /// Maximum number of simultaneously accepted connections.
    pub max_connections: usize,
    /// Maximum number of concurrent client API streams per connection.
    pub max_client_api_streams: u32,
    /// Maximum lifetime of one accepted connection.
    pub connection_lifetime: std::time::Duration,
}

/// Long-lived local TACACS+ client service.
///
/// [`TacacsClientService`] connects operator configuration to shared runtime
/// state. Its constructor validates the configuration and creates the failover
/// state machine. [`serve_until`](TacacsClientService::serve_until) starts the listeners with host cancellation.
///
/// This type is not `Clone` because it owns the listener lifecycle. Share
/// [`ServiceConfig`] before you create the service.
///
/// # Service lifecycle
///
/// ```text
/// [start]
///    |
///    v
/// Configuring ──> Validating ──> WarmingUp ──> Serving
///                                                 |
///                                          shutdown signal
///                                                 |
///                                                 v
///                                              Draining ──> Cleanup ──> [end]
/// ```
pub struct TacacsClientService {
    runtime: ServiceRuntime<NetworkUpstreamConnector>,
}

/// Read-only access to operational snapshots. Cloning does not own listeners or initiate traffic.
#[derive(Clone)]
pub struct DiagnosticsHandle {
    manager: std::sync::Weak<crate::upstream::manager::UpstreamManager<NetworkUpstreamConnector>>,
}

impl DiagnosticsHandle {
    /// Reads bounded RFC 7951 operational JSON, optionally selecting an exact server name.
    /// # Errors
    /// Returns an error for an unknown server, oversized metadata, or an oversized response.
    pub fn statistics_json(&self, server: Option<&str>, limit: usize) -> anyhow::Result<String> {
        self.manager
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("The agent runtime is no longer available"))?
            .diagnostics_json(server, limit)
    }
}

impl TacacsClientService {
    /// Returns a read-only handle to the current published generation.
    #[must_use]
    pub fn diagnostics_handle(&self) -> DiagnosticsHandle {
        DiagnosticsHandle {
            manager: Arc::downgrade(&self.runtime.manager),
        }
    }

    /// Captures read-only server counters associated with one published runtime generation.
    /// Unchanged endpoints retain their counter epoch across reloads. Replacements start a new epoch.
    #[must_use]
    pub fn statistics(&self) -> tacacsrs_config::OperationalStatistics {
        self.runtime.manager.statistics()
    }
    #[cfg(test)]
    pub(crate) fn pause_next_publication(&self) -> Arc<tokio::sync::Notify> {
        self.runtime.manager.pause_next_publication()
    }

    #[cfg(test)]
    pub(crate) fn pause_native_preparation(
        &self,
    ) -> (Arc<tokio::sync::Notify>, std::sync::mpsc::Sender<()>) {
        self.runtime.manager.pause_native_preparation()
    }

    #[cfg(test)]
    pub(crate) async fn hold_publication(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.runtime.reload_publication_lock.lock().await
    }

    /// Builds a service with the concrete native connector.
    ///
    /// # Errors
    /// Returns a configuration or native preparation error.
    pub fn new(config: ServiceConfig, health: RuntimeHealthPublisher) -> anyhow::Result<Self> {
        Ok(Self {
            runtime: ServiceRuntime::from_config(
                config,
                health,
                true,
                NetworkUpstreamConnector::new,
            )?,
        })
    }

    /// Builds an empty service that waits for its first valid configuration.
    ///
    /// # Errors
    /// Returns an error for nonempty upstreams or invalid listener configuration.
    pub fn waiting_for_configuration(
        config: ServiceConfig,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.tacacs_plus.server.is_empty(),
            "Configuration for a waiting service must contain no TACACS+ servers"
        );
        Ok(Self {
            runtime: ServiceRuntime::from_config(
                config,
                health,
                false,
                NetworkUpstreamConnector::new,
            )?,
        })
    }

    /// Applies a complete validated upstream configuration.
    ///
    /// # Errors
    /// Returns a validation or preparation error without publishing a partial update.
    pub async fn reload_tacacs_plus(&self, source: TacacsPlus) -> anyhow::Result<()> {
        self.runtime.reload_tacacs_plus(source).await
    }

    /// Applies a validated policy to new requests.
    /// Returns `Superseded` when a newer policy was admitted before publication.
    ///
    /// # Errors
    /// Returns an error if the runtime has closed.
    pub async fn reload_runtime_policy(
        &self,
        policy: RuntimePolicy,
    ) -> anyhow::Result<super::PolicyUpdate> {
        self.runtime.reload_runtime_policy(policy).await
    }

    /// Applies an observed canonical policy or records a source rejection.
    /// `None` records a rejected observation. Invalid canonical values also return
    /// `Rejected` without replacing the applied policy. The source is borrowed unchanged.
    ///
    /// # Errors
    /// Returns an error if the runtime has closed.
    pub async fn apply_policy_candidate(
        &self,
        source: Option<&tacacsrs_config::tacacsrs::RuntimePolicy>,
    ) -> anyhow::Result<super::PolicyUpdate> {
        let revision = self.runtime.manager.admit_policy()?;
        match source.map(RuntimePolicy::try_from) {
            Some(Ok(policy)) => self.runtime.publish_policy(revision, policy).await,
            Some(Err(_)) | None => self.runtime.manager.reject_policy(revision),
        }
    }

    /// Applies upstream configuration with its prepared downstream policy.
    ///
    /// # Errors
    /// Returns an error if the complete update cannot be prepared and published.
    pub async fn reload_tacacs_plus_with_proxy_downstream_obfuscation(
        &self,
        source: TacacsPlus,
        policy: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        self.runtime
            .reload_tacacs_plus_with_proxy_downstream_obfuscation(source, policy)
            .await
    }

    /// Applies materialized upstreams with their prepared downstream policy.
    ///
    /// # Errors
    /// Returns an error if validation or native preparation fails.
    pub async fn reload_materialized_servers_with_proxy_downstream_obfuscation(
        &self,
        servers: Vec<Arc<tacacsrs_config::TacacsPlusServer>>,
        policy: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        self.runtime
            .reload_materialized_servers_with_proxy_downstream_obfuscation(servers, policy)
            .await
    }

    /// Applies materialized servers and coordinator bookkeeping in one commit.
    pub(crate) async fn publish_materialized_servers(
        &self,
        servers: Vec<Arc<tacacsrs_config::TacacsPlusServer>>,
        policy: PreparedProxyPolicy,
        validity: super::CredentialLifetime,
        preparation: Arc<super::candidate_preparation::Preparation>,
        commit: impl FnOnce() -> Option<super::MaterializationCommit> + Send,
    ) -> anyhow::Result<()> {
        self.runtime
            .publish_materialized_servers(
                servers,
                policy,
                Some(validity),
                Some(preparation),
                commit,
            )
            .await
    }

    /// Withdraws expired upstreams without closing the recoverable runtime.
    pub(crate) async fn withdraw_expired_material(
        &self,
        commit: impl FnOnce() -> Option<super::MaterializationCommit> + Send,
    ) -> anyhow::Result<()> {
        let _reload = self.runtime.reload_publication_lock.lock().await;
        let proxy = self
            .runtime
            .manager
            .proxy_transport_settings()
            .downstream_obfuscation()
            .clone();
        self.runtime
            .manager
            .reload_shared_servers_with_retirement(
                Vec::new(),
                proxy,
                Some(tacacsrs_networking::RequestDeadline::at(tokio::time::Instant::now())),
                None,
                None,
                commit,
            )
            .await
    }

    pub(crate) fn source_stale_timeout(&self) -> std::time::Duration {
        self.runtime.manager.source_stale_timeout()
    }

    pub(crate) fn credential_stale_timeout(&self) -> std::time::Duration {
        self.runtime.manager.credential_stale_timeout()
    }

    pub(crate) fn credential_refresh_interval(&self) -> std::time::Duration {
        self.runtime.manager.credential_refresh_interval()
    }

    pub(crate) fn candidate_limits(&self) -> crate::config::RuntimeCandidateLimits {
        self.runtime.manager.candidate_limits()
    }

    pub(crate) fn ensure_open(&self) -> anyhow::Result<()> {
        self.runtime.manager.ensure_open()
    }

    /// Returns the applied graceful shutdown budget for an embedding host.
    /// Capture it once when shutdown begins; later policy updates must not renew it.
    #[must_use]
    pub fn shutdown_timeout(&self) -> std::time::Duration {
        self.runtime.manager.shutdown_timeout()
    }

    /// Returns the current configured upstream count.
    #[must_use]
    pub fn server_count(&self) -> usize {
        self.runtime.server_count()
    }

    /// Returns a cloneable handle for local client API operations.
    ///
    /// A host adapts this handle to an IPC server. The handle shares the runtime
    /// upstream manager and routes each operation through the active generation.
    #[must_use]
    pub fn client_api_handle(&self) -> ClientApiHandle {
        ClientApiHandle::new(UpstreamBridge::new(Arc::clone(&self.runtime.manager)))
    }

    /// Returns the prepared client API Unix socket path, if client API is enabled.
    ///
    /// A host composes its client API listener on this path. The agent runtime
    /// does not own the IPC transport.
    #[must_use]
    pub fn client_api_socket_path(&self) -> Option<PathBuf> {
        self.runtime.listeners.client_api().map(Path::to_path_buf)
    }

    /// Returns the prepared listener settings for a host-composed client API listener.
    #[must_use]
    pub fn client_api_listener_settings(&self) -> ListenerSettings {
        let prepared = &self.runtime.listeners;
        ListenerSettings {
            socket_mode: prepared.unix_socket_mode(),
            max_connections: prepared.max_connections(),
            max_client_api_streams: prepared.max_client_api_streams(),
            connection_lifetime: prepared.connection_lifetime(),
        }
    }

    /// Serves until an embedding host requests shutdown, without installing signals.
    ///
    /// The host injects composed listener services, for example the local client
    /// API over IPC. The agent runtime drives each injected listener, the raw
    /// TACACS+ proxy, graceful drain, and upstream retirement under one deadline.
    ///
    /// # Errors
    /// Returns a listener or shutdown error after cleanup.
    pub async fn serve_until(
        &self,
        stop: impl std::future::Future<Output = ()> + Send,
        listeners: Vec<Box<dyn RuntimeListenerService>>,
    ) -> anyhow::Result<()> {
        self.runtime.serve_until(stop, listeners).await
    }

    /// Closes upstream resources without starting listeners.
    ///
    /// Stop an active listener run through its `serve_until` trigger and await it.
    ///
    /// # Errors
    /// Returns an upstream cleanup error after joining remaining resources.
    pub async fn close_and_join(
        &self,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        self.runtime.close_and_join(deadline).await
    }
}


#[cfg(all(test, unix))]
impl TacacsClientService {
    /// Serves with the composed client API listener until `stop` fires.
    async fn serve_until_for_test(
        &self,
        stop: impl std::future::Future<Output = ()> + Send,
    ) -> anyhow::Result<()> {
        self.runtime.serve_until_for_test(stop).await
    }
}

#[cfg(all(test, unix))]
mod tests;
