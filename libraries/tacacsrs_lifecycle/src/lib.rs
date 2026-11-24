#![doc = include_str!("../README.md")]

mod health;
mod lifetime;
mod readiness;
mod service;
mod shutdown;

pub use health::{
    validate_member_names, ComponentHealth, EmptyGroup, GroupAssessment, HealthEntry, HealthGroup,
    HealthGroupKind, HealthMember, HealthRegistration, HealthRegistry, CHECK_TIMEOUT,
    FAILED_CHECK_DESCRIPTION, POLL_INTERVAL,
};
pub use health_checks::{
    async_trait, BoxError, HealthCheck, HealthCheckContext, HealthCheckResult, HealthStatus,
};
pub use lifetime::ApplicationLifetime;
pub use readiness::ApplicationReadiness;
pub use service::HostedService;
pub use shutdown::{ShutdownRequester, ShutdownSignal};
