//! Application readiness for hosted services in other packages.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use health_checks::{BoxError, HealthCheck, HealthCheckContext, HealthCheckResult};

use crate::{HealthGroupKind, HealthMember};

/// Reports whether the application is ready to serve requests.
///
/// The host supplies this check. A component adds it to its own health group
/// without a dependency on the application package.
#[derive(Clone)]
pub struct ApplicationReadiness {
    check: Arc<dyn HealthCheck>,
}

impl ApplicationReadiness {
    /// Stable member name of this check.
    pub const NAME: &'static str = "application-readiness";

    /// Creates a readiness view over `check`.
    #[must_use]
    pub fn new(check: impl HealthCheck) -> Self {
        Self {
            check: Arc::new(check),
        }
    }
}

impl fmt::Debug for ApplicationReadiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationReadiness")
    }
}

#[async_trait]
impl HealthCheck for ApplicationReadiness {
    async fn check(&self, context: &HealthCheckContext) -> Result<HealthCheckResult, BoxError> {
        self.check.check(context).await
    }
}

impl<G: HealthGroupKind> HealthMember<G> for ApplicationReadiness {
    fn name(&self) -> &'static str {
        Self::NAME
    }
}
