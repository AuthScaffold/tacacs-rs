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

use std::sync::Arc;

use super::{RuntimeHealthPublisher, RuntimeListenerService};
use crate::config::{RuntimePolicy, ServiceConfig};
#[cfg(test)]
use crate::config::PreparedProxyPolicy;
use crate::services::client_api::{ClientApiHandle, UpstreamBridge, UpstreamProbe};
use crate::upstream::NetworkUpstreamConnector;

mod engine;

use engine::ServiceRuntime;
/// Prepared settings for a host-composed runtime listener.
///
/// A host maps these transport-neutral values into its own listener options,
/// for example the IPC listener options. The agent runtime does not own the IPC
/// transport or protobuf schema.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

impl From<&tacacsrs_config::local_services::PreparedLocalServices> for ListenerSettings {
    fn from(prepared: &tacacsrs_config::local_services::PreparedLocalServices) -> Self {
        Self {
            socket_mode: prepared.unix_socket_mode(),
            max_connections: prepared.max_connections(),
            max_client_api_streams: prepared.max_client_api_streams(),
            connection_lifetime: prepared.connection_lifetime(),
        }
    }
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

    /// Captures the same server counters as [`TacacsClientService::statistics`].
    ///
    /// # Errors
    /// Returns an error when the agent runtime no longer exists.
    pub fn statistics(&self) -> anyhow::Result<tacacsrs_config::OperationalStatistics> {
        Ok(self
            .manager
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("The agent runtime is no longer available"))?
            .statistics())
    }
}

impl TacacsClientService {
    pub(crate) fn shutdown_deadlines(&self) -> anyhow::Result<super::shutdown::ShutdownDeadlines> {
        self.runtime.manager.shutdown_deadlines()
    }
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
        Self::with_revocation(config, health, crate::UpstreamRevocation::default())
    }

    /// Builds a native service with host-supplied revocation controls.
    ///
    /// The service publishes the revocation settings of each accepted change
    /// through `revocation`, and attaches its verifier to new certificate TLS
    /// connections.
    ///
    /// # Errors
    /// Returns an error for invalid listener controls.
    pub fn with_revocation(
        config: ServiceConfig,
        health: RuntimeHealthPublisher,
        revocation: crate::UpstreamRevocation,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            runtime: ServiceRuntime::from_config(
                config,
                health,
                Vec::new(),
                false,
                revocation,
                |guard, revocation, policy| {
                    NetworkUpstreamConnector::new(guard, revocation).with_runtime_policy(policy)
                },
            )?,
        })
    }

    /// Builds the raw TACACS+ proxy listener.
    ///
    /// The listener follows the active local services. A host passes the
    /// listener to [`Self::serve_until`] with its other listeners.
    #[must_use]
    pub fn tacacs_proxy_listener(&self) -> Box<dyn RuntimeListenerService> {
        self.runtime.tacacs_proxy_listener()
    }

    /// Returns a view of the active local services.
    ///
    /// A host listener uses the view to bind, move, or stop its endpoint when
    /// a datastore change publishes new local services.
    #[must_use]
    pub fn local_services(&self) -> super::LocalServicesView {
        self.runtime.local_services.view()
    }

    /// Returns a view of the accepted runtime policy.
    ///
    /// The view changes after a datastore change or a policy file change
    /// applies a new runtime policy.
    #[must_use]
    pub fn runtime_policy(&self) -> super::RuntimePolicyView {
        self.runtime.runtime_policy.view()
    }

    /// Applies the overlays to the local services of a datastore change and
    /// prepares the result.
    pub(crate) fn prepare_local_services_candidate(
        &self,
        source: &tacacsrs_config::tacacsrs::LocalServices,
    ) -> anyhow::Result<Arc<super::ActiveLocalServices>> {
        self.runtime.local_services.prepare_candidate(source)
    }

    /// Returns the active local services.
    pub(crate) fn active_local_services(&self) -> Arc<super::ActiveLocalServices> {
        self.runtime.local_services.current()
    }

    /// Admits a new runtime policy revision.
    ///
    /// A policy with this revision supersedes every policy admitted earlier.
    ///
    /// # Errors
    /// Returns an error if the runtime has closed.
    pub(crate) fn admit_policy(&self) -> anyhow::Result<super::PolicyRevision> {
        self.runtime.manager.admit_policy()
    }

    /// Publishes the configuration sections of an accepted datastore change
    /// that has no servers to publish.
    ///
    /// The runtime policy applies first. Then the listeners see the new local
    /// services. A newer policy from another source supersedes this policy.
    pub(crate) async fn publish_sections(&self, sections: &super::CandidateSections) {
        self.runtime.publish_sections(sections).await;
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
    ///
    /// The sections publish immediately after the server commit, before
    /// upstream retirement can yield. If the caller drops the future after the
    /// commit, the servers and the sections are both active.
    pub(crate) async fn publish_materialized_servers(
        &self,
        candidate: crate::upstream::manager::PublicationCandidate<
            impl FnOnce() -> Option<super::MaterializationCommit> + Send,
        >,
        sections: Option<&super::CandidateSections>,
    ) -> anyhow::Result<()> {
        self.runtime
            .publish_materialized_servers(candidate, sections)
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

    /// Returns a cloneable handle that sends upstream WATCHDOG probes.
    ///
    /// A host calls the probe on a schedule to learn upstream health before
    /// the first client request. Each probe result updates runtime health.
    #[must_use]
    pub fn upstream_probe(&self) -> UpstreamProbe {
        UpstreamProbe::new(self.client_api_handle(), self.runtime.health.clone())
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
