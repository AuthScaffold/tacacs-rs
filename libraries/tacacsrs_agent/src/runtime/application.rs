//! Complete source-driven application assembly and lifecycle.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use futures_util::FutureExt;
use tokio_util::sync::CancellationToken;

use tacacsrs_config::local_services::{prepare_local_services, PreparedLocalServices};
use tacacsrs_config::source::{ConfigDatastore, InitialLoadPolicy};
use tacacsrs_config::source::policy::{
    FilePolicyObservation, PolicyChange, PolicyFile, PolicyObservation,
};
use tacacsrs_networking::CertificateVerification;
use tacacsrs_provider::{Companion, CompanionContext, SourceBundle};

use crate::{RuntimeHealthPublisher, RuntimePolicy, ServiceConfig, TacacsClientService};
use super::{ConfigSupervisor, PolicySupervisor, RuntimeListenerService};
use super::application_tasks::{CriticalTasks, PeerContext, RuntimePeer, supervise};
use super::source_filter::config_filter_from_local_services;

/// Canonical policy or an independently observed policy file.
pub enum PolicyInput {
    /// Static canonical policy.
    Canonical(tacacsrs_config::tacacsrs::RuntimePolicy),
    /// File with a canonical baseline and live updates.
    File(PathBuf),
}

/// Provider and common controls consumed by one application.
pub struct RuntimeInputs {
    /// Canonical source and its companions.
    pub source: SourceBundle,
    /// Initial policy and optional observation.
    pub policy: PolicyInput,
    /// Upstream certificate verification policy.
    pub certificate_verification: CertificateVerification,
}

/// A prepared application with no bound listeners or running companions.
pub struct AgentRuntime {
    service: Arc<TacacsClientService>,
    health: RuntimeHealthPublisher,
    local_services: PreparedLocalServices,
    datastore: Arc<dyn ConfigDatastore>,
    supervisor: ConfigSupervisor,
    policy_observation: Option<FilePolicyObservation>,
    companions: Vec<Box<dyn Companion>>,
}

impl AgentRuntime {
    /// Prepares canonical inputs without binding listeners or starting companions.
    ///
    /// Cancellation drops local resources. External mutations belong in companions.
    ///
    /// # Errors
    /// Returns an error for invalid services, policy, or source controls.
    pub async fn prepare(inputs: RuntimeInputs) -> anyhow::Result<Self> {
        let RuntimeInputs {
            source,
            policy,
            certificate_verification,
        } = inputs;
        let local_services = prepare_local_services(&source.local_services)?;
        let filter = config_filter_from_local_services(&source.local_services)?;
        let (runtime_policy, policy_observation) = match policy {
            PolicyInput::Canonical(policy) => (RuntimePolicy::try_from(&policy)?, None),
            PolicyInput::File(path) => {
                let mut observation = PolicyFile::new(&path)?.observe().await?;
                let Some(PolicyChange::Changed(policy)) = observation.next().await? else {
                    anyhow::bail!("Initial runtime policy was rejected");
                };
                (RuntimePolicy::try_from(policy.as_ref())?, Some(observation))
            }
        };
        let config = ServiceConfig {
            local_services: source.local_services,
            validation_options: source.datastore.validation_options(),
            runtime_policy,
            certificate_verification,
        };
        let health = RuntimeHealthPublisher::new(config.enabled_services());
        let service = Arc::new(
            TacacsClientService::new(config, health.clone())
                .context("Failed to build TACACS+ client service configuration")?,
        );
        let mut supervisor = ConfigSupervisor::new(
            source.datastore.clone(),
            service.clone(),
            health.clone(),
            filter,
        );
        let (resolver, changes) = source.credentials.into_parts();
        if let Some(resolver) = resolver {
            supervisor = supervisor.with_credential_resolver(resolver);
        }
        if let Some(changes) = changes {
            supervisor = supervisor.with_credential_changes(changes);
        }
        Ok(Self {
            service,
            health,
            local_services,
            datastore: source.datastore,
            supervisor,
            policy_observation,
            companions: source.companions,
        })
    }

    /// Returns the shared service for listener and diagnostics adapters.
    #[must_use]
    pub fn service(&self) -> &Arc<TacacsClientService> {
        &self.service
    }

    /// Returns the application's authoritative health publisher.
    #[must_use]
    pub fn health(&self) -> &RuntimeHealthPublisher {
        &self.health
    }

    /// Returns prepared listener settings for output-path protection.
    #[must_use]
    pub fn prepared_local_services(&self) -> &PreparedLocalServices {
        &self.local_services
    }

    /// Runs initialization, listeners, and critical services until shutdown.
    ///
    /// The first stop or failure captures the shared teardown deadline.
    /// Normal return follows domain cleanup and joins every critical task.
    /// Observation implementations retain their own drop-based cancellation contract.
    ///
    /// # Errors
    /// Returns an initialization, service, task, or cleanup error.
    pub async fn run_until(
        mut self,
        stop: impl Future<Output = ()> + Send,
        listeners: Vec<Box<dyn RuntimeListenerService>>,
        peers: Vec<RuntimePeer>,
    ) -> anyhow::Result<()> {
        let cancellation = CancellationToken::new();
        let _cancel_on_drop = cancellation.clone().drop_guard();
        tokio::pin!(stop);
        if self.datastore.runtime_policy().initial_load == InitialLoadPolicy::FailFast {
            let initialized = {
                let initialize = self.supervisor.initialize_until(cancellation.cancelled());
                tokio::pin!(initialize);
                tokio::select! {
                    biased;
                    () = &mut stop => {
                        cancellation.cancel();
                        initialize.await
                    },
                    result = &mut initialize => result,
                }
            };
            if initialized.is_err() || cancellation.is_cancelled() {
                let cleanup = self
                    .service
                    .close_and_join(self.service.shutdown_deadlines()?.requests)
                    .await;
                return initialized.and(cleanup);
            }
        }
        if stop.as_mut().now_or_never().is_some() {
            return self
                .service
                .close_and_join(self.service.shutdown_deadlines()?.requests)
                .await;
        }
        let mut tasks = CriticalTasks::new(cancellation.clone());
        let token = cancellation.clone();
        tasks.spawn("Configuration supervisor", self.supervisor.run_until(token.cancelled_owned()));
        if let Some(observation) = self.policy_observation {
            let supervisor = PolicySupervisor::new(observation, self.service.clone());
            let token = cancellation.clone();
            tasks.spawn("Runtime policy supervisor", async move {
                supervisor.run_until(token.cancelled()).await
            });
        }
        for companion in self.companions {
            let context = CompanionContext {
                ready: self.health.subscribe_readiness(),
                cancellation: cancellation.child_token(),
            };
            tasks.spawn(companion.name(), companion.run(context));
        }
        for peer in peers {
            peer.spawn(
                &mut tasks,
                PeerContext {
                    health: self.health.subscribe(),
                    cancellation: cancellation.child_token(),
                },
            );
        }
        let serving = self
            .service
            .serve_until(cancellation.cancelled(), listeners);
        let application = supervise(serving, tasks, cancellation.clone(), self.health, || {
            self.service.shutdown_deadlines()
        });
        tokio::pin!(application);
        tokio::select! {
            biased;
            () = &mut stop => {
                cancellation.cancel();
                application.await
            }
            result = &mut application => result,
        }
    }
}

#[cfg(test)]
mod tests;
