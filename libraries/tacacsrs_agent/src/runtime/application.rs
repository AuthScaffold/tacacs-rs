//! Complete source-driven application assembly and lifecycle.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use futures_util::FutureExt;
use tokio_util::sync::CancellationToken;

use tacacsrs_config::local_services::{prepare_local_services, PreparedLocalServices};
use tacacsrs_config::source::policy::{
    FilePolicyObservation, PolicyChange, PolicyFile, PolicyObservation,
};
use tacacsrs_networking::CertificateVerification;
use tacacsrs_lifecycle::{HostedService, ShutdownSignal};
use tacacsrs_provider::SourceBundle;

use crate::{RuntimeHealthPublisher, RuntimePolicy, ServiceConfig, TacacsClientService};
use super::{ConfigSupervisor, PolicySupervisor, RuntimeHealth, RuntimeListenerService};
use super::application_tasks::{CriticalTasks, supervise};
use super::source_filter::config_filter_from_local_services;

/// Canonical policy or an independently observed policy file.
#[derive(Clone, Debug)]
pub enum PolicyInput {
    /// Static canonical policy.
    Canonical(tacacsrs_config::tacacsrs::RuntimePolicy),
    /// File with a canonical baseline and live updates.
    File(PathBuf),
}

/// Provider and common controls consumed by one application.
pub struct RuntimeInputs {
    /// Canonical source capabilities.
    pub source: SourceBundle,
    /// Initial policy and optional observation.
    pub policy: PolicyInput,
    /// Upstream certificate verification policy.
    pub certificate_verification: CertificateVerification,
}

/// A prepared application with no bound listeners or running services.
pub struct AgentRuntime {
    service: Arc<TacacsClientService>,
    health: RuntimeHealthPublisher,
    local_services: PreparedLocalServices,
    supervisor: ConfigSupervisor,
    policy_observation: Option<FilePolicyObservation>,
}

impl AgentRuntime {
    /// Prepares canonical inputs without binding listeners or starting services.
    ///
    /// Cancellation drops local resources. External mutations belong in hosted services.
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
        let mut supervisor =
            ConfigSupervisor::new(source.datastore, service.clone(), health.clone(), filter);
        let (resolver, changes) = source.credentials.into_parts();
        if let Some(resolver) = resolver {
            supervisor = supervisor.with_credential_resolver(resolver);
        }
        if let Some(changes) = changes {
            supervisor = supervisor.with_credential_changes(changes);
        }
        supervisor.validate_provider()?;
        Ok(Self {
            service,
            health,
            local_services,
            supervisor,
            policy_observation,
        })
    }

    /// Returns the shared service for listener and diagnostics adapters.
    #[must_use]
    pub fn service(&self) -> &Arc<TacacsClientService> {
        &self.service
    }

    /// Returns a read-only view of the application health.
    #[must_use]
    pub fn health(&self) -> RuntimeHealth {
        RuntimeHealth::new(self.health.clone())
    }

    /// Returns prepared listener settings for output-path protection.
    #[must_use]
    pub fn prepared_local_services(&self) -> &PreparedLocalServices {
        &self.local_services
    }

    /// Runs the supervisors, listeners, and hosted services until shutdown.
    ///
    /// All parts start together. No part waits for the first configuration.
    /// Runtime health reports the configuration, listener, and upstream state.
    /// Requests before the first publication receive a retryable unavailable
    /// error. Each hosted service receives a shutdown observer. An early return from a service is fatal.
    /// The first stop or failure captures the shared teardown deadline.
    /// Normal return follows domain cleanup and joins every critical task.
    /// Observation implementations retain their own drop-based cancellation contract.
    ///
    /// # Errors
    /// Returns a service, task, or cleanup error.
    pub async fn run_until(
        self,
        stop: impl Future<Output = ()> + Send,
        listeners: Vec<Box<dyn RuntimeListenerService>>,
        services: Vec<Arc<dyn HostedService>>,
    ) -> anyhow::Result<()> {
        let cancellation = CancellationToken::new();
        let _cancel_on_drop = cancellation.clone().drop_guard();
        tokio::pin!(stop);
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
        for service in services {
            let shutdown = ShutdownSignal::from(&cancellation);
            tasks.spawn(service.name(), service.run(shutdown));
        }
        let serving = self
            .service
            .serve_until(cancellation.clone().cancelled_owned(), listeners);
        // Supervision publishes the draining state before it cancels the hosted services.
        supervise(stop, serving, tasks, cancellation, self.health, || {
            self.service.shutdown_deadlines()
        })
        .await
    }
}

#[cfg(test)]
mod tests;
