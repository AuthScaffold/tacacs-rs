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

use crate::runtime::{LocalServicesView, RuntimePolicyView};
use crate::{
    AgentReadinessCheck, AgentRuntime, DiagnosticsHandle, PolicyInput, RuntimeHealth,
    RuntimeInputs, UpstreamProbe,
};
use tacacsrs_composition::{prepare_all, register_all, Component, Composition, Graph};
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_lifecycle::{ApplicationLifetime, ApplicationReadiness, HostedService};
use tacacsrs_networking::CertificateVerification;
use tacacsrs_provider::{
    CredentialLayer, CredentialProvider, LocalServicesOverlay, SourceBundle, SourceDatastore,
};

mod roles;
#[cfg(test)]
mod tests;

pub use roles::{ClientApiAccess, ListenerFactory, StartupCheck, TacacsProxyAccess};

/// Declares the inputs, roles, and deferred values of the agent host.
///
/// Components must provide exactly one value of each input type:
/// [`SourceDatastore`], [`CredentialProvider`], [`LocalServices`],
/// [`PolicyInput`], and [`CertificateVerification`]. The [`LocalServices`]
/// value is the bootstrap value. A datastore change can replace it at runtime.
/// A component can also provide one [`UpstreamRevocation`](crate::UpstreamRevocation).
/// Without that value, the agent rejects new certificate TLS connections while
/// the configured revocation enforcement is not `disabled`.
///
/// Components can inject these deferred values. The host supplies them after
/// it prepares the agent runtime: [`DiagnosticsHandle`], [`RuntimeHealth`],
/// [`ClientApiAccess`], [`TacacsProxyAccess`], [`UpstreamProbe`],
/// [`LocalServicesView`], [`RuntimePolicyView`], [`ApplicationReadiness`], and
/// [`ApplicationLifetime`].
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
    composition.deferred::<TacacsProxyAccess>()?;
    composition.deferred::<UpstreamProbe>()?;
    composition.deferred::<LocalServicesView>()?;
    composition.deferred::<RuntimePolicyView>()?;
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
    /// Each runtime service can have at most one selected listener. A service
    /// that the bootstrap local services enable must have one.
    ///
    /// # Errors
    /// Returns an input, layer, overlay, runtime, startup check, or
    /// construction error. Also returns an error when a runtime service has
    /// more than one listener, or when an enabled service has no listener.
    pub async fn prepare(graph: Graph) -> anyhow::Result<Self> {
        let inputs = read_inputs(&graph)?;
        let runtime = AgentRuntime::prepare(inputs).await?;
        let service = runtime.service();
        graph.supply(Arc::new(service.diagnostics_handle()))?;
        graph.supply(Arc::new(runtime.health()))?;
        graph.supply(Arc::new(ClientApiAccess {
            local_services: service.local_services(),
            handle: service.client_api_handle(),
        }))?;
        graph.supply(Arc::new(TacacsProxyAccess::new(Arc::clone(service))))?;
        graph.supply(Arc::new(service.upstream_probe()))?;
        graph.supply(Arc::new(runtime.local_services()))?;
        graph.supply(Arc::new(runtime.runtime_policy()))?;
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
        let listeners: Vec<_> = graph
            .members::<dyn ListenerFactory>(|factory| factory.name())?
            .iter()
            .filter_map(|factory| factory.listener())
            .collect();
        check_listeners(&runtime, &listeners)?;
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

fn check_listeners(
    runtime: &AgentRuntime,
    listeners: &[Box<dyn crate::RuntimeListenerService>],
) -> anyhow::Result<()> {
    let enabled = runtime.health().snapshot().enabled_services();
    for (service, label, is_enabled) in [
        (crate::RuntimeService::ClientApi, "client API", enabled.client_api()),
        (crate::RuntimeService::TacacsProxy, "TACACS+ proxy", enabled.tacacs_proxy()),
    ] {
        let count = listeners
            .iter()
            .filter(|listener| listener.service() == Some(service))
            .count();
        anyhow::ensure!(
            count <= 1,
            "The components supply {count} {label} listeners. Select at most one listener component for each service"
        );
        anyhow::ensure!(
            count == 1 || !is_enabled,
            "The configuration enables the {label}, but no component supplies its listener. \
             Select one listener component for each enabled service"
        );
    }
    Ok(())
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
    let local_services_overlays =
        graph.members::<dyn LocalServicesOverlay>(|overlay| overlay.name())?;
    for overlay in &local_services_overlays {
        local_services = overlay.apply(local_services).with_context(|| {
            format!("Could not apply the local services overlay {}", overlay.name())
        })?;
    }
    Ok(RuntimeInputs {
        source: SourceBundle {
            datastore,
            credentials,
            local_services,
            local_services_overlays,
        },
        policy: (*graph.one::<PolicyInput>()?).clone(),
        certificate_verification: *graph.one::<CertificateVerification>()?,
        revocation: if graph.contains::<crate::UpstreamRevocation>() {
            (*graph.one::<crate::UpstreamRevocation>()?).clone()
        } else {
            crate::UpstreamRevocation::without_verifier()
        },
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
