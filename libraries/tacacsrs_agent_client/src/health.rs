//! Stable service names used with the standard gRPC health protocol.

/// Overall health service name. The empty name follows the gRPC health
/// protocol convention and maps to agent readiness.
pub const OVERALL_HEALTH_SERVICE: &str = "";

/// Business RPC service represented by agent readiness.
pub const TACACS_AGENT_HEALTH_SERVICE: &str = "tacacsrs.agent.v1.TacacsAgent";

/// Startup probe service name.
pub const STARTUP_HEALTH_SERVICE: &str = "tacacsrs.agent.health.v1.Startup";

/// Liveness probe service name.
pub const LIVENESS_HEALTH_SERVICE: &str = "tacacsrs.agent.health.v1.Liveness";

/// Readiness probe service name.
pub const READINESS_HEALTH_SERVICE: &str = "tacacsrs.agent.health.v1.Readiness";
