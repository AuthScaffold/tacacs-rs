//! Connector-generic runtime engine for the central TACACS+ client service.
//!
//! [`ServiceRuntime`] is the engine behind the concrete
//! [`TacacsClientService`](super::TacacsClientService) facade. The facade
//! exposes concrete native types while this engine stays generic over the
//! connector, and the crate validates that its primary futures are `Send`. The
//! engine validates startup configuration, applies datastore reloads, and
//! drives graceful listener shutdown. It delegates request handling and
//! failover to [`UpstreamManager`].
//!
//! See the [`client_service`](super) module documentation for the publication
//! write path, lock order, cancellation rules, and shutdown sequence.

use std::sync::Arc;

use futures_util::FutureExt;
#[cfg(test)]
use tacacsrs_config::TacacsPlus;
use tacacsrs_provider::LocalServicesOverlay;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::config::{PreparedProxyPolicy, RuntimePolicy, ServiceConfig};
use crate::runtime::{
    ActiveLocalServices, ConfigPublisher, LocalServicesState, ProxyLoopGuard,
    RuntimeHealthPublisher, RuntimeListenerService, ShutdownCoordinator,
};
#[cfg(test)]
use crate::runtime::enumerate_supported_servers;
use crate::services::tacacs_proxy::{TacacsProxyListener, TacacsProxyService};
#[cfg(test)]
use crate::upstream::NetworkUpstreamConnector;
#[cfg(test)]
use crate::upstream::UpstreamConnector;
use crate::upstream::UpstreamConnection;
use crate::upstream::manager::UpstreamManager;
#[cfg(test)]
use crate::upstream::manager::ServiceConnector;
use tacacsrs_networking::routed::EndpointConnector;

pub(crate) struct ServiceRuntime<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    /// Validated operator configuration.
    pub(super) config: ServiceConfig,
    /// Active local services, their overlays, and the proxy loop guard.
    pub(super) local_services: LocalServicesState,
    /// The accepted runtime policy for components.
    pub(super) runtime_policy: ConfigPublisher<RuntimePolicy>,
    /// Shared upstream manager. It owns the routing catalog, failover, and
    /// generation-aware health publication.
    pub(super) manager: Arc<UpstreamManager<Connector>>,
    /// Serializes one complete runtime-generation publication at the service
    /// layer. It is the outer lock, ahead of the manager catalog reload lock.
    pub(super) reload_publication_lock: Mutex<()>,
    /// Shared protocol-neutral runtime health publisher.
    pub(super) health: RuntimeHealthPublisher,
    #[cfg(test)]
    pub(super) implicit_reload_pause:
        std::sync::Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}

struct ServiceRunGuard<'service, Connector: EndpointConnector>(
    Option<&'service UpstreamManager<Connector>>,
);

impl<Connector: EndpointConnector> Drop for ServiceRunGuard<'_, Connector> {
    fn drop(&mut self) {
        if let Some(manager) = self.0 {
            manager.cancel();
        }
    }
}

#[cfg(test)]
impl ServiceRuntime<ServiceConnector> {
    /// Builds a TACACS+ client service with persistent server connections and
    /// ordered failover.
    ///
    /// # Errors
    ///
    /// Returns an error if schema validation, credential-reference expansion,
    /// capability checks, or native transport preparation fails.
    pub(super) fn new(
        config: super::tests::ServiceFixture,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<Self> {
        Self::build(config, health, true)
    }

    /// Builds a service that can bind listeners before it receives valid
    /// configuration from the datastore.
    ///
    /// The placeholder configuration must contain no servers. A successful call
    /// to
    /// [`Self::reload_tacacs_plus`]
    /// marks the first configuration as applied.
    ///
    /// # Errors
    ///
    /// Returns an error if the placeholder contains a TACACS+ server. It also
    /// returns an error for invalid IPC endpoint configuration or a health
    /// publisher with a different service selection.
    pub(super) fn waiting_for_configuration(
        config: super::tests::ServiceFixture,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<Self> {
        if !config.source.server.is_empty() {
            anyhow::bail!("Configuration for a waiting service must contain no TACACS+ servers");
        }

        Self::build(config, health, false)
    }

    fn build(
        config: super::tests::ServiceFixture,
        health: RuntimeHealthPublisher,
        configuration_applied: bool,
    ) -> anyhow::Result<Self> {
        let servers =
            enumerate_supported_servers(&config.source, &config.settings.validation_options)?;
        Self::from_config(
            config.settings,
            health,
            servers.into_iter().map(Arc::new).collect(),
            configuration_applied,
            Vec::new(),
            |guard| ServiceConnector(NetworkUpstreamConnector::new(guard).erased()),
        )
    }

    pub(super) fn new_with_connector(
        config: super::tests::ServiceFixture,
        connector: Arc<UpstreamConnector>,
        health: RuntimeHealthPublisher,
    ) -> anyhow::Result<Self> {
        let servers =
            enumerate_supported_servers(&config.source, &config.settings.validation_options)?;
        Self::from_config(
            config.settings,
            health,
            servers.into_iter().map(Arc::new).collect(),
            true,
            Vec::new(),
            |_| ServiceConnector(connector),
        )
    }
}

impl<Connector: EndpointConnector> ServiceRuntime<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    pub(super) fn from_config(
        config: ServiceConfig,
        health: RuntimeHealthPublisher,
        servers: Vec<Arc<tacacsrs_config::TacacsPlusServer>>,
        configuration_applied: bool,
        local_services_overlays: Vec<Arc<dyn LocalServicesOverlay>>,
        factory: impl FnOnce(ProxyLoopGuard) -> Connector,
    ) -> anyhow::Result<Self> {
        let local_services = LocalServicesState::new(
            ActiveLocalServices::new(config.local_services.clone())?,
            local_services_overlays,
        );
        let connector = factory(local_services.proxy_loop_guard().clone());
        let proxy_policy = if !configuration_applied
            && config.local_services.proxy_credential_source
                == tacacsrs_config::tacacsrs::ProxyCredentialSource::LocalProxyRow
        {
            PreparedProxyPolicy::unavailable()
        } else {
            tacacsrs_config::proxy_policy::prepare_proxy_policy(&config.local_services, None)?
        };
        let manager = Arc::new(UpstreamManager::from_connector(
            servers,
            proxy_policy,
            config.runtime_policy.clone(),
            connector,
            health.clone(),
            tacacsrs_config::prepare::PrepareOptions::default()
                .with_certificate_verification(config.certificate_verification),
        )?);
        manager.publish_initial_health(configuration_applied);

        Ok(Self {
            runtime_policy: ConfigPublisher::new(Arc::new(config.runtime_policy.clone())),
            config,
            local_services,
            manager,
            reload_publication_lock: Mutex::new(()),
            health,
            #[cfg(test)]
            implicit_reload_pause: std::sync::Mutex::new(None),
        })
    }

    /// Applies validated TACACS+ configuration to the running service.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, reference expansion, or native preparation
    /// fails. Failure leaves the active runtime generation unchanged.
    #[cfg(test)]
    pub(super) async fn reload_tacacs_plus(&self, tacacs_plus: TacacsPlus) -> anyhow::Result<()> {
        let servers = enumerate_supported_servers(&tacacs_plus, &self.config.validation_options)?;
        let candidate = self
            .manager
            .capture_upstream_reload(servers.into_iter().map(Arc::new).collect());
        self.wait_for_implicit_reload_pause().await;
        self.publish_materialized_servers(candidate, None).await
    }

    #[cfg(test)]
    async fn wait_for_implicit_reload_pause(&self) {
        let pause = self.implicit_reload_pause.lock().unwrap().take();
        if let Some((entered, release)) = pause {
            entered.notify_one();
            release.notified().await;
        }
    }

    /// Atomically applies a validated runtime policy to new requests.
    /// Newer admitted candidates supersede older updates waiting for publication.
    ///
    /// # Errors
    /// Returns an error if the runtime has closed.
    #[cfg(test)]
    pub(super) async fn reload_runtime_policy(
        &self,
        runtime_policy: RuntimePolicy,
    ) -> anyhow::Result<crate::runtime::PolicyUpdate> {
        let revision = self.manager.admit_policy()?;
        self.publish_policy(revision, runtime_policy).await
    }

    pub(super) async fn publish_policy(
        &self,
        revision: crate::runtime::PolicyRevision,
        runtime_policy: RuntimePolicy,
    ) -> anyhow::Result<crate::runtime::PolicyUpdate> {
        let _reload_guard = self.reload_publication_lock.lock().await;
        self.publish_policy_locked(revision, Arc::new(runtime_policy))
    }

    /// Publishes a policy. The caller must hold `reload_publication_lock`.
    fn publish_policy_locked(
        &self,
        revision: crate::runtime::PolicyRevision,
        accepted: Arc<RuntimePolicy>,
    ) -> anyhow::Result<crate::runtime::PolicyUpdate> {
        let update = self
            .manager
            .publish_policy(revision, RuntimePolicy::clone(&accepted))?;
        if matches!(update, crate::runtime::PolicyUpdate::Applied(_)) {
            self.runtime_policy.publish_with(accepted, |_| {
                log::info!("The runtime applies a new runtime policy");
            });
        }
        Ok(update)
    }

    /// Publishes the sections of an accepted datastore change that has no
    /// server publication.
    pub(super) async fn publish_sections(&self, sections: &crate::runtime::CandidateSections) {
        let _reload_guard = self.reload_publication_lock.lock().await;
        self.publish_sections_locked(sections);
    }

    /// Publishes the runtime policy and then the local services of a change.
    /// The caller must hold `reload_publication_lock`. This method does not
    /// await, so a cancelled caller cannot publish only part of the sections.
    fn publish_sections_locked(&self, sections: &crate::runtime::CandidateSections) {
        if let Some(source) = &sections.runtime_policy {
            match self.publish_policy_locked(source.revision, Arc::clone(&source.policy)) {
                Ok(crate::runtime::PolicyUpdate::Applied(_)) => {}
                Ok(update) => log::debug!("The source runtime policy was not applied: {update:?}"),
                Err(error) => log::debug!("The source runtime policy was not applied: {error:#}"),
            }
        }
        self.local_services
            .publish(Arc::clone(&sections.local_services));
    }

    #[cfg(test)]
    pub(super) async fn reload_tacacs_plus_with_proxy_downstream_obfuscation(
        &self,
        tacacs_plus: TacacsPlus,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        proxy_downstream_obfuscation.shared_secret()?;
        let servers = enumerate_supported_servers(&tacacs_plus, &self.config.validation_options)?;
        self.reload_materialized_servers_with_proxy_downstream_obfuscation(
            servers.into_iter().map(Arc::new).collect(),
            proxy_downstream_obfuscation,
        )
        .await?;
        Ok(())
    }

    /// Atomically applies materialized servers and the proxy policy.
    ///
    /// The caller must resolve credentials first. The service validates the full
    /// set and prepares native contexts before publication. New requests see only
    /// the complete replacement. Bound requests retain their previous server set.
    ///
    /// # Errors
    ///
    /// Returns an error if the service cannot apply the materialized server set.
    /// If it fails, the previous runtime state stays active.
    #[cfg(test)]
    pub(super) async fn reload_materialized_servers_with_proxy_downstream_obfuscation(
        &self,
        servers: Vec<Arc<tacacsrs_config::TacacsPlusServer>>,
        proxy_downstream_obfuscation: PreparedProxyPolicy,
    ) -> anyhow::Result<()> {
        self.publish_materialized_servers(
            crate::upstream::manager::PublicationCandidate::new(
                servers,
                proxy_downstream_obfuscation,
                None,
                None,
                || None,
            ),
            None,
        )
        .await
    }

    pub(super) async fn publish_materialized_servers(
        &self,
        candidate: crate::upstream::manager::PublicationCandidate<
            impl FnOnce() -> Option<crate::runtime::MaterializationCommit> + Send,
            Connector,
        >,
        sections: Option<&crate::runtime::CandidateSections>,
    ) -> anyhow::Result<()> {
        let candidate = self.prepare_materialized_servers(candidate).await?;
        let _reload_guard = if let Some(preparation) = candidate.preparation.as_ref() {
            preparation
                .admission
                .run(self.reload_publication_lock.lock())
                .await?
        } else {
            self.reload_publication_lock.lock().await
        };
        self.manager
            .reload_shared_servers_then(candidate, None, || {
                if let Some(sections) = sections {
                    self.publish_sections_locked(sections);
                }
            })
            .await
    }

    pub(super) async fn prepare_materialized_servers<Commit: Send>(
        &self,
        candidate: crate::upstream::manager::PublicationCandidate<Commit, Connector>,
    ) -> anyhow::Result<crate::upstream::manager::PublicationCandidate<Commit, Connector>> {
        tacacsrs_config::prepare::validate_materialized_servers(
            candidate.servers.iter().map(AsRef::as_ref),
            &self.config.validation_options,
        )?;
        self.manager.prepare_candidate(candidate).await
    }

    /// Returns the number of configured TACACS+ servers.
    #[must_use]
    pub(super) fn server_count(&self) -> usize {
        self.manager.server_count()
    }

    /// Runs listeners until an embedding host requests shutdown, without installing signal handlers.
    ///
    /// The maximum current operation budget supplies one deadline for listener
    /// drain and all upstream retirement. The service cannot reopen after exit.
    ///
    /// # Errors
    /// Returns a listener, task, or upstream cleanup error after shutdown.
    pub(super) async fn serve_until(
        &self,
        stop: impl std::future::Future<Output = ()> + Send,
        listeners: Vec<Box<dyn RuntimeListenerService>>,
    ) -> anyhow::Result<()> {
        self.manager.ensure_open()?;
        let shutdown = ShutdownCoordinator::new(self.health.clone());
        tokio::pin!(stop);
        if stop.as_mut().now_or_never().is_some() {
            drop(listeners);
            shutdown.initiate_shutdown();
            let result = self
                .manager
                .close_and_join(self.manager.shutdown_deadline()?)
                .await;
            if result.is_ok() {
                shutdown.mark_stopped();
            } else {
                shutdown.fail();
            }
            return result;
        }
        let serving = self.serve_with_shutdown(&shutdown, listeners);
        tokio::pin!(serving);
        tokio::select! {
            biased;
            () = &mut stop => { shutdown.initiate_shutdown(); serving.await }
            result = &mut serving => result,
        }
    }

    /// Builds the raw TACACS+ proxy listener.
    ///
    /// The listener follows the active local services. It reports
    /// `Disabled` while the local services disable the proxy.
    pub(super) fn tacacs_proxy_listener(&self) -> Box<dyn RuntimeListenerService>
    where
        Connector: 'static,
    {
        let service = TacacsProxyService::new(
            Arc::clone(&self.manager),
            self.local_services.proxy_loop_guard().clone(),
        );
        Box::new(TacacsProxyListener::new(service, self.local_services.view()))
    }

    /// Permanently closes admission and joins upstream resources without starting listeners.
    ///
    /// # Errors
    /// Returns an upstream cleanup error after joining the remaining resources.
    pub(super) async fn close_and_join(
        &self,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        self.manager.close_and_join(deadline).await
    }

    pub(super) async fn serve_with_shutdown(
        &self,
        shutdown: &ShutdownCoordinator,
        listeners: Vec<Box<dyn RuntimeListenerService>>,
    ) -> anyhow::Result<()> {
        self.manager.ensure_open()?;
        let mut run = ServiceRunGuard(Some(&self.manager));
        log::info!("Warming TACACS+ server connections");
        self.manager.warm_connections();
        let result = self.serve_enabled_services(shutdown, listeners).await;
        run.0 = None;
        if result.is_ok() {
            shutdown.mark_stopped();
        } else {
            shutdown.fail();
        }

        log::info!("TACACS+ client service has shut down");
        result
    }

    async fn serve_enabled_services(
        &self,
        shutdown: &ShutdownCoordinator,
        listeners: Vec<Box<dyn RuntimeListenerService>>,
    ) -> anyhow::Result<()> {
        let mut tasks = JoinSet::new();
        if listeners.is_empty() {
            anyhow::bail!("Enable at least one runtime service");
        }
        for service in [
            crate::RuntimeService::ClientApi,
            crate::RuntimeService::TacacsProxy,
        ] {
            if listeners
                .iter()
                .any(|listener| listener.service() == Some(service))
            {
                continue;
            }
            let report = crate::runtime::listener_reconciler::report_missing_listener(
                service,
                self.local_services.view().subscribe(),
                shutdown.subscribe(),
                self.health.clone(),
            );
            tasks.spawn(async move { ("missing listener report", report.await) });
        }
        for listener in listeners {
            let shutdown = shutdown.subscribe();
            let health = self.health.clone();
            let name = listener.name();
            tasks.spawn(async move { (name, listener.serve(shutdown, health).await) });
        }

        let stop = shutdown.subscribe().wait();
        tokio::pin!(stop);
        let mut failure = None;
        loop {
            tokio::select! {
                biased;
                () = &mut stop => break,
                Some(result) = tasks.join_next() => match result {
                    Ok((name, Ok(()))) => {
                        log::info!("The {name} listener completed before shutdown");
                    }
                    Ok((name, Err(error))) => {
                        failure = Some(error.context(format!("The {name} listener failed")));
                        shutdown.fail();
                        break;
                    }
                    Err(error) => {
                        failure = Some(error.into());
                        shutdown.fail();
                        break;
                    }
                },
            }
        }
        let deadline = self.manager.shutdown_deadline()?;
        self.manager.close();
        let draining = async {
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result
                    .map_err(anyhow::Error::from)
                    .and_then(|(_, result)| result)
                {
                    failure.get_or_insert(error);
                }
            }
        };
        if deadline.run(draining).await.is_err() {
            tasks.shutdown().await;
        }
        let upstream = self.manager.close_and_join(deadline).await;
        failure.map_or(upstream, Err)
    }
}

#[cfg(all(test, unix))]
impl<Connector: EndpointConnector + 'static> ServiceRuntime<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    /// Builds the injected client API listener(s) for a test service runtime.
    ///
    /// This mirrors how the daemon composes the IPC listener with the agent
    /// runtime. It returns one listener when the client API is enabled.
    fn test_client_api_listeners(&self) -> Vec<Box<dyn RuntimeListenerService>> {
        let mut listeners = vec![self.tacacs_proxy_listener()];
        listeners.extend(self.test_client_api_only());
        listeners
    }

    fn test_client_api_only(&self) -> Vec<Box<dyn RuntimeListenerService>> {
        let local = self.local_services.current();
        let prepared = local.prepared();
        match prepared.client_api() {
            Some(path) => vec![crate::test_support::TestClientApiListener::boxed(
                Arc::clone(&self.manager),
                path.to_path_buf(),
                tacacsrs_ipc::server::ListenerOptions {
                    socket_mode: prepared.unix_socket_mode(),
                    max_connections: prepared.max_connections(),
                    max_client_api_streams: prepared.max_client_api_streams(),
                    connection_lifetime: prepared.connection_lifetime(),
                },
            )],
            None => Vec::new(),
        }
    }

    /// Serves with the composed client API listener until `stop` fires.
    pub(super) async fn serve_until_for_test(
        &self,
        stop: impl std::future::Future<Output = ()> + Send,
    ) -> anyhow::Result<()> {
        let listeners = self.test_client_api_listeners();
        self.serve_until(stop, listeners).await
    }

    /// Serves with the composed client API listener under one shutdown coordinator.
    pub(super) async fn serve_with_shutdown_for_test(
        &self,
        shutdown: &ShutdownCoordinator,
    ) -> anyhow::Result<()> {
        let listeners = self.test_client_api_listeners();
        self.serve_with_shutdown(shutdown, listeners).await
    }
}
