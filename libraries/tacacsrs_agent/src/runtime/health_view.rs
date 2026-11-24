//! Read-only runtime health for hosted services and health groups.

use async_trait::async_trait;
use tokio::sync::watch;

use tacacsrs_lifecycle::{
    HealthCheck, HealthCheckContext, HealthCheckResult, HealthGroupKind, HealthMember,
};

use super::{RuntimeHealthPublisher, RuntimeHealthSnapshot};

/// Observes runtime health without the ability to change it.
#[derive(Clone, Debug)]
pub struct RuntimeHealth {
    publisher: RuntimeHealthPublisher,
}

impl RuntimeHealth {
    pub(crate) fn new(publisher: RuntimeHealthPublisher) -> Self {
        Self { publisher }
    }

    /// Subscribes to the current snapshot and later transitions.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<RuntimeHealthSnapshot> {
        self.publisher.subscribe()
    }

    /// Subscribes to readiness.
    #[must_use]
    pub fn subscribe_readiness(&self) -> watch::Receiver<bool> {
        self.publisher.subscribe_readiness()
    }

    /// Returns a copy of the current snapshot.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeHealthSnapshot {
        self.publisher.snapshot()
    }

    /// Returns the current readiness.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        *self.publisher.subscribe_readiness().borrow()
    }
}

/// Reports agent readiness as a member of any health group.
#[derive(Clone, Debug)]
pub struct AgentReadinessCheck {
    health: RuntimeHealth,
}

impl AgentReadinessCheck {
    /// Stable member name of this check.
    pub const NAME: &'static str = "agent-readiness";

    /// Creates a check that reads `health`.
    #[must_use]
    pub fn new(health: RuntimeHealth) -> Self {
        Self { health }
    }
}

#[async_trait]
impl HealthCheck for AgentReadinessCheck {
    async fn check(
        &self,
        context: &HealthCheckContext,
    ) -> Result<HealthCheckResult, tacacsrs_lifecycle::BoxError> {
        Ok(if self.health.is_ready() {
            HealthCheckResult::healthy()
        } else {
            HealthCheckResult::new(context.failure_status())
                .with_description("The agent is not ready")
        })
    }
}

impl<G: HealthGroupKind> HealthMember<G> for AgentReadinessCheck {
    fn name(&self) -> &'static str {
        Self::NAME
    }
}
