//! Stops the application when the source configuration cannot become valid.

use std::sync::Arc;

use dill::component;

use crate::{DegradationReason, RuntimeHealth};
use tacacsrs_composition::{Component, Composition, Named};
use tacacsrs_lifecycle::{ApplicationLifetime, HostedService, ShutdownSignal};

/// Selects the invalid source shutdown.
///
/// The runtime sets [`DegradationReason::SourceConfigurationInvalid`] when it
/// rejects the initial configuration of a datastore without change
/// notifications. This component then stops the application with an error, so
/// the process exits with a failure status. Without this component, the
/// process stays alive and reports that it is not ready.
pub struct InvalidSourceShutdownComponent;

impl Component for InvalidSourceShutdownComponent {
    fn name(&self) -> &'static str {
        InvalidSourceShutdown::NAME
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        composition.hosted_service(<InvalidSourceShutdown as dill::Component>::builder())
    }
}

/// Watches runtime health for the final source rejection.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct InvalidSourceShutdown {
    health: Arc<RuntimeHealth>,
    lifetime: Arc<ApplicationLifetime>,
}

impl Named for InvalidSourceShutdown {
    const NAME: &'static str = "Invalid source shutdown";
}

#[async_trait::async_trait]
impl HostedService for InvalidSourceShutdown {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn run(self: Arc<Self>, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        let mut health = self.health.subscribe();
        tokio::select! {
            biased;
            () = shutdown.requested() => return Ok(()),
            found = health.wait_for(|snapshot| {
                snapshot
                    .degradation_reasons()
                    .contains(&DegradationReason::SourceConfigurationInvalid)
            }) => {
                // A closed watch means that the runtime is stopping.
                if found.is_ok() {
                    self.lifetime.stop_with_error(anyhow::anyhow!(
                        "The source configuration is invalid, and the source cannot change it"
                    ));
                }
            }
        }
        shutdown.requested().await;
        Ok(())
    }
}
