//! Composes the agent runtime from selected components.
//!
//! A host passes a list of [`Component`] values to [`run_until`]. Each
//! component prepares its input without side effects and then registers
//! values and roles in a [`Composition`]. The host checks the graph, builds the
//! [`AgentRuntime`], supplies the deferred values, runs each [`StartupCheck`],
//! and then starts the listeners and the hosted services.
//!
//! The crate [`components`](crate::components) module contains the standard
//! components. An executable selects the components and gives them settings.

use std::future::Future;
use std::sync::Arc;

use anyhow::Context;
use tokio_util::sync::CancellationToken;

use crate::{
    AgentReadinessCheck, AgentRuntime, DiagnosticsHandle, PolicyInput, RuntimeHealth,
    RuntimeInputs, UpstreamProbe,
};
use tacacsrs_composition::{prepare_all, register_all, Component, Composition, Graph};
use tacacsrs_config::local_services::PreparedLocalServices;
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_lifecycle::{ApplicationLifetime, ApplicationReadiness, HostedService};
use tacacsrs_networking::CertificateVerification;
use tacacsrs_provider::{
    CredentialLayer, CredentialProvider, LocalServicesOverlay, SourceBundle, SourceDatastore,
};

mod roles;
#[cfg(test)]
mod tests;

pub use roles::{ClientApiAccess, ListenerFactory, StartupCheck};

/// Declares the inputs, roles, and deferred values of the agent host.
///
/// Components must provide exactly one value of each input type:
/// [`SourceDatastore`], [`CredentialProvider`], [`LocalServices`],
/// [`PolicyInput`], and [`CertificateVerification`].
///
/// Components can inject these deferred values. The host supplies them after
/// it prepares the agent runtime: [`DiagnosticsHandle`], [`RuntimeHealth`],
/// [`ClientApiAccess`], [`UpstreamProbe`], [`PreparedLocalServices`],
/// [`ApplicationReadiness`], and [`ApplicationLifetime`].
///
/// # Errors
/// Returns an error when a component already registered one of the deferred
/// types.
pub fn declare(composition: &mut Composition) -> anyhow::Result<()> {
    composition.require::<SourceDatastore>();
    composition.require::<CredentialProvider>();
    composition.require::<LocalServices>();
    composition.require::<PolicyInput>();
    composition.require::<CertificateVerification>();
    composition.role::<dyn ListenerFactory>("listener");
    composition.role::<dyn StartupCheck>("startup check");
    composition.role::<dyn CredentialLayer>("credential layer");
    composition.role::<dyn LocalServicesOverlay>("local services overlay");
    composition.deferred::<DiagnosticsHandle>()?;
    composition.deferred::<RuntimeHealth>()?;
    composition.deferred::<ClientApiAccess>()?;
    composition.deferred::<UpstreamProbe>()?;
    composition.deferred::<PreparedLocalServices>()?;
    composition.deferred::<ApplicationReadiness>()?;
    composition.deferred::<ApplicationLifetime>()?;
    Ok(())
}

/// A prepared agent runtime with its constructed listeners and services.
///
/// No listener is bound and no hosted service runs.
pub struct PreparedHost {
    runtime: AgentRuntime,
    listeners: Vec<Box<dyn crate::RuntimeListenerService>>,
    services: Vec<Arc<dyn HostedService>>,
    lifetime: ApplicationLifetime,
}

impl PreparedHost {
    /// Prepares the agent runtime from a validated graph.
    ///
    /// The host reads the inputs, applies the credential layers and the local
    /// services overlays in registration order, and prepares the runtime.
    /// Then it supplies the deferred values and runs the startup checks in
    /// registration order. Last, it constructs the enabled listeners and the
    /// hosted services, and drops the graph.
    ///
    /// # Errors
    /// Returns an input, layer, overlay, runtime, startup check, or
    /// construction error.
    pub async fn prepare(graph: Graph) -> anyhow::Result<Self> {
        let inputs = read_inputs(&graph)?;
        let runtime = AgentRuntime::prepare(inputs).await?;
        let service = runtime.service();
        graph.supply(Arc::new(service.diagnostics_handle()))?;
        graph.supply(Arc::new(runtime.health()))?;
        graph.supply(Arc::new(ClientApiAccess {
            socket_path: service.client_api_socket_path(),
            settings: service.client_api_listener_settings(),
            handle: service.client_api_handle(),
        }))?;
        graph.supply(Arc::new(service.upstream_probe()))?;
        graph.supply(Arc::new(runtime.prepared_local_services().clone()))?;
        graph.supply(Arc::new(ApplicationReadiness::new(AgentReadinessCheck::new(
            runtime.health(),
        ))))?;
        let lifetime = ApplicationLifetime::new();
        graph.supply(Arc::new(lifetime.clone()))?;
        for check in graph.members::<dyn StartupCheck>(|check| check.name())? {
            check
                .check()
                .await
                .with_context(|| format!("The startup check {} failed", check.name()))?;
        }
        let listeners = graph
            .members::<dyn ListenerFactory>(|factory| factory.name())?
            .iter()
            .filter_map(|factory| factory.listener())
            .collect();
        let services = graph.hosted_services()?;
        graph.finish()?;
        Ok(Self {
            runtime,
            listeners,
            services,
            lifetime,
        })
    }

    /// Returns the prepared agent runtime.
    #[must_use]
    pub fn runtime(&self) -> &AgentRuntime {
        &self.runtime
    }

    /// Returns the application lifetime that the components can inject.
    #[must_use]
    pub fn lifetime(&self) -> &ApplicationLifetime {
        &self.lifetime
    }

    /// Runs the agent with its listeners and hosted services until `stop`
    /// completes or a component stops the application.
    ///
    /// # Errors
    /// Returns the error of [`AgentRuntime::run_until`]. If the runtime stops
    /// without an error, returns the first error of
    /// [`ApplicationLifetime::stop_with_error`].
    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) -> anyhow::Result<()> {
        let stopping = self.lifetime.stopping();
        let stop = async move {
            tokio::select! {
                () = stop => {}
                () = stopping.requested() => {}
            }
        };
        self.runtime
            .run_until(stop, self.listeners, self.services)
            .await?;
        self.lifetime.take_error().map_or(Ok(()), Err)
    }
}

fn read_inputs(graph: &Graph) -> anyhow::Result<RuntimeInputs> {
    let datastore = graph.one::<SourceDatastore>()?.0.clone();
    let mut credentials = (*graph.one::<CredentialProvider>()?).clone();
    for layer in graph.members::<dyn CredentialLayer>(|layer| layer.name())? {
        credentials = credentials
            .layer(|inner| layer.wrap(inner))
            .with_context(|| format!("Could not apply the credential layer {}", layer.name()))?;
    }
    let mut local_services = (*graph.one::<LocalServices>()?).clone();
    for overlay in graph.members::<dyn LocalServicesOverlay>(|overlay| overlay.name())? {
        local_services = overlay.apply(local_services).with_context(|| {
            format!("Could not apply the local services overlay {}", overlay.name())
        })?;
    }
    Ok(RuntimeInputs {
        source: SourceBundle {
            datastore,
            credentials,
            local_services,
        },
        policy: (*graph.one::<PolicyInput>()?).clone(),
        certificate_verification: *graph.one::<CertificateVerification>()?,
    })
}

/// Prepares the components and the agent runtime.
///
/// The components prepare in order. Then the host declares its inputs, the
/// components register, and the host validates the composition and calls
/// [`PreparedHost::prepare`].
///
/// # Errors
/// Returns a preparation, registration, validation, or runtime error.
pub async fn bootstrap(mut components: Vec<Box<dyn Component>>) -> anyhow::Result<PreparedHost> {
    prepare_all(&mut components).await?;
    let mut composition = Composition::default();
    declare(&mut composition)?;
    register_all(components, &mut composition)?;
    PreparedHost::prepare(composition.validate()?).await
}

/// Bootstraps the components and runs the agent until `stop` completes.
///
/// If `stop` completes during bootstrap, the host drops the bootstrap future
/// and returns the result of `stop`. No listener binds and no hosted service
/// starts before bootstrap is complete.
///
/// # Errors
/// Returns the error of `stop`, bootstrap, or the agent runtime.
pub async fn run_until(
    components: Vec<Box<dyn Component>>,
    stop: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let application = async {
        let host = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            prepared = bootstrap(components) => prepared?,
        };
        host.run_until(cancellation.cancelled()).await
    };
    tokio::pin!(application);
    tokio::select! {
        biased;
        signal = stop => {
            cancellation.cancel();
            signal.and(application.await)
        },
        result = &mut application => result,
    }
}
