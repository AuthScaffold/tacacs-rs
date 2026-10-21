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
//! 1. [`TacacsClientService::new`] validates startup controls and starts empty.
//! 2. One retained [`ConfigSupervisor`](super::ConfigSupervisor) observes and prepares the canonical source.
//! 3. [`TacacsClientService::serve_until`] warms connection state and binds
//!    each injected listener.
//! 4. The host drives supervision and serving until shutdown, then joins both.
//!
//! # Publication write path
//!
//! One reload travels through fixed owners in one direction:
//!
//! 1. The supervisor's materialization coordinator prepares a candidate and
//!    calls the private publication method on [`TacacsClientService`].
//! 2. The engine validates and prepares the complete catalog before publication locks.
//!    Supervised work retains its registered preparation lease during native work.
//! 3. The engine holds `reload_publication_lock`. The manager then holds
//!    `catalog_reload_lock`, checks current catalog identity and final limits,
//!    and swaps the active snapshot.
//! 4. The publication controller commits the generation, server count, and
//!    health in one health mutation. That commit also swaps the snapshot and
//!    runs coordinator bookkeeping. The commit does not await.
//!
//! # Lock order
//!
//! Acquire locks only in this order:
//! coordinator state (supervised commit only) -> `reload_publication_lock`
//! (service) -> `catalog_reload_lock` (manager) ->
//! active snapshot write lock -> publication observation lock -> health watch.
//! Upstream retirement awaits only after the snapshot write lock is released.
//!
//! # Cancellation and stale completion
//!
//! The host drives shutdown through [`serve_until`](TacacsClientService::serve_until).
//! Cancellation before commit leaves the previous generation active. Cancellation
//! after commit cannot undo the published generation. A late availability observation for a replaced generation
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

use super::{RuntimeHealthPublisher, RuntimeListenerService};
use crate::config::{RuntimePolicy, ServiceConfig};
#[cfg(test)]
use crate::config::PreparedProxyPolicy;
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
/// [`TacacsClientService`] owns shared runtime state. Its constructor validates
/// startup controls and creates an empty failover state machine.
/// [`ConfigSupervisor`](super::ConfigSupervisor) owns the upstream source and
/// publication. [`serve_until`](TacacsClientService::serve_until) starts listeners with host cancellation.
///
/// This type is not `Clone` because it owns the listener lifecycle. Share
/// the service through [`Arc`] when the host composes supervisors and listeners.
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

    pub(crate) async fn prepare_materialized_servers<Commit: Send>(
        &self,
        candidate: crate::upstream::manager::PublicationCandidate<Commit>,
    ) -> anyhow::Result<crate::upstream::manager::PublicationCandidate<Commit>> {
        self.runtime.prepare_materialized_servers(candidate).await
    }

    #[cfg(test)]
    pub(crate) async fn hold_publication(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.runtime.reload_publication_lock.lock().await
    }

    #[cfg(test)]
    pub(crate) fn pause_client_preparation(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        self.runtime.manager.pause_client_preparation()
    }

    #[cfg(test)]
    pub(crate) fn native_preparation_counts(&self) -> (usize, usize) {
        self.runtime.manager.native_preparation_counts()
    }

    /// Builds a native service with no applied upstream configuration.
    ///
    /// Use [`ConfigSupervisor`](super::ConfigSupervisor) for initial server
    /// preparation and every later update. Retain that supervisor until shutdown.
    /// Use [`Self::apply_policy_candidate`] for canonical policy updates.
    ///
    /// # Errors
    /// Returns an error for invalid listener controls or inconsistent health services.
    pub fn new(config: ServiceConfig, health: RuntimeHealthPublisher) -> anyhow::Result<Self> {
        Ok(Self {
            runtime: ServiceRuntime::from_config(
                config,
                health,
                Vec::new(),
                false,
                NetworkUpstreamConnector::new,
            )?,
        })
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

    /// Applies materialized upstreams with their prepared downstream policy.
    ///
    /// # Errors
    /// Returns an error if validation or native preparation fails.
    #[cfg(test)]
    pub(crate) async fn reload_materialized_servers_with_proxy_downstream_obfuscation(
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
        candidate: crate::upstream::manager::PublicationCandidate<
            impl FnOnce() -> Option<super::MaterializationCommit> + Send,
        >,
    ) -> anyhow::Result<()> {
        self.runtime.publish_materialized_servers(candidate).await
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
                crate::upstream::manager::PublicationCandidate::new(
                    Vec::new(),
                    proxy,
                    None,
                    None,
                    commit,
                ),
                Some(tacacsrs_networking::RequestDeadline::at(tokio::time::Instant::now())),
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
