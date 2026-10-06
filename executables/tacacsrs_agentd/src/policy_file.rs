//! File adapter for the canonical YANG runtime-policy resource.

use std::path::{Path, PathBuf};

use anyhow::Context;
use tacacsrs_agent::RuntimePolicy;

/// Source for one live runtime-policy document.
#[derive(Debug, Clone)]
pub(crate) struct PolicyFile {
    path: PathBuf,
}

impl PolicyFile {
    /// Creates a policy-file source.
    #[must_use]
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the policy file path.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Loads and validates the complete policy document.
    pub(crate) async fn load(&self) -> anyhow::Result<RuntimePolicy> {
        let bytes = tokio::fs::read(&self.path)
            .await
            .with_context(|| format!("read runtime policy file {}", self.path.display()))?;
        parse_policy(&bytes)
            .with_context(|| format!("parse runtime policy file {}", self.path.display()))
    }
}

fn parse_policy(bytes: &[u8]) -> anyhow::Result<RuntimePolicy> {
    let policy = tacacsrs_config::policy::parse_runtime_policy(bytes)?;
    RuntimePolicy::try_from(&policy)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tacacsrs_agent::{FailoverStrategy, OperationKind};

    use super::*;

    #[test]
    fn canonical_yang_policy_maps_existing_runtime_behavior() {
        let policy = parse_policy(
            br#"{
                "tacacsrs:runtime-policy": {
                    "failover-recovery-interval-seconds": 12,
                    "client-api-failover-strategy": "ordered-safe-retry",
                    "authentication": {"max-body-length": 2048, "max-concurrent-requests": 8}
                }
            }"#,
        )
        .expect("canonical YANG policy must prepare");
        assert_eq!(policy.failover_recovery_interval(), Duration::from_secs(12));
        assert_eq!(
            policy.failover_strategy(tacacsrs_agent::PolicyService::ClientApi),
            FailoverStrategy::OrderedSafeRetry
        );
        assert_eq!(
            policy
                .limits(OperationKind::Authentication)
                .max_concurrent_requests(),
            8
        );
        assert_eq!(
            policy
                .limits(OperationKind::Authorization)
                .max_body_length(),
            16 * 1024
        );
    }

    #[test]
    fn empty_document_uses_safe_defaults() {
        let policy = parse_policy(br#"{"tacacsrs:runtime-policy":{}}"#).expect("default policy");

        assert_eq!(
            policy
                .limits(OperationKind::Authentication)
                .max_body_length(),
            4 * 1024
        );
        assert_eq!(
            policy
                .limits(OperationKind::Authorization)
                .max_concurrent_requests(),
            64
        );
    }

    #[test]
    fn document_maps_service_strategies_and_limits() {
        let policy = parse_policy(
            br#"{
                "tacacsrs:runtime-policy": {
                    "failover-recovery-interval-seconds": 12,
                    "client-api-failover-strategy": "ordered-safe-retry",
                    "authentication": {
                        "max-body-length": 2048,
                        "max-concurrent-requests": 8
                    }
                }
            }"#,
        )
        .expect("custom policy");

        assert_eq!(policy.failover_recovery_interval(), Duration::from_secs(12));
        assert_eq!(
            policy.failover_strategy(tacacsrs_agent::PolicyService::ClientApi),
            FailoverStrategy::OrderedSafeRetry
        );
        assert_eq!(
            policy
                .limits(OperationKind::Authentication)
                .max_concurrent_requests(),
            8
        );
    }

    #[test]
    fn document_rejects_unknown_fields_and_invalid_limits() {
        assert!(parse_policy(br#"{"unknown": true}"#).is_err());
        assert!(parse_policy(
            br#"{
                    "tacacsrs:runtime-policy": {
                    "authorization": {
                        "max-body-length": 0
                    }
                    }
                }"#
        )
        .is_err());
    }
}
