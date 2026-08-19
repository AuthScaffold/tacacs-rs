//! JSON adapter for the live agent runtime policy.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;
use tacacsrs_agent::{FailoverStrategy, OperationPolicies, RequestLimits, RuntimePolicy};

const DEFAULT_RECOVERY_INTERVAL_SECONDS: u64 = 30;
const DEFAULT_AUTHENTICATION_BODY_LENGTH: usize = 4 * 1024;
const DEFAULT_AUTHORIZATION_BODY_LENGTH: usize = 16 * 1024;
const DEFAULT_ACCOUNTING_BODY_LENGTH: usize = 16 * 1024;
const DEFAULT_CONCURRENT_REQUESTS: usize = 64;

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
    RuntimePolicyDocument::from_json(bytes)?.into_policy()
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct RuntimePolicyDocument {
    failover_recovery_interval_seconds: u64,
    client_api_failover_strategy: FailoverStrategyDocument,
    tacacs_proxy_failover_strategy: FailoverStrategyDocument,
    authentication: RequestLimitsDocument,
    authorization: RequestLimitsDocument,
    accounting: RequestLimitsDocument,
}

impl RuntimePolicyDocument {
    fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes).context("decode runtime policy JSON")
    }

    fn into_policy(self) -> anyhow::Result<RuntimePolicy> {
        RuntimePolicy::new(
            self.client_api_failover_strategy.into(),
            self.tacacs_proxy_failover_strategy.into(),
            OperationPolicies::new(
                self.authentication.into_limits()?,
                self.authorization.into_limits()?,
                self.accounting.into_limits()?,
            ),
            Duration::from_secs(self.failover_recovery_interval_seconds),
        )
    }
}

impl Default for RuntimePolicyDocument {
    fn default() -> Self {
        Self {
            failover_recovery_interval_seconds: DEFAULT_RECOVERY_INTERVAL_SECONDS,
            client_api_failover_strategy: FailoverStrategyDocument::DeferredFailover,
            tacacs_proxy_failover_strategy: FailoverStrategyDocument::DeferredFailover,
            authentication: RequestLimitsDocument::new(DEFAULT_AUTHENTICATION_BODY_LENGTH),
            authorization: RequestLimitsDocument::new(DEFAULT_AUTHORIZATION_BODY_LENGTH),
            accounting: RequestLimitsDocument::new(DEFAULT_ACCOUNTING_BODY_LENGTH),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FailoverStrategyDocument {
    #[default]
    DeferredFailover,
    OrderedSafeRetry,
}

impl From<FailoverStrategyDocument> for FailoverStrategy {
    fn from(value: FailoverStrategyDocument) -> Self {
        match value {
            FailoverStrategyDocument::DeferredFailover => Self::DeferredFailover,
            FailoverStrategyDocument::OrderedSafeRetry => Self::OrderedSafeRetry,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RequestLimitsDocument {
    max_body_length: usize,
    #[serde(default = "default_concurrent_requests")]
    max_concurrent_requests: usize,
}

impl RequestLimitsDocument {
    const fn new(max_body_length: usize) -> Self {
        Self {
            max_body_length,
            max_concurrent_requests: DEFAULT_CONCURRENT_REQUESTS,
        }
    }

    fn into_limits(self) -> anyhow::Result<RequestLimits> {
        RequestLimits::new(self.max_body_length, self.max_concurrent_requests)
    }
}

const fn default_concurrent_requests() -> usize {
    DEFAULT_CONCURRENT_REQUESTS
}

#[cfg(test)]
mod tests {
    use tacacsrs_agent::OperationKind;

    use super::*;

    #[test]
    fn empty_document_uses_safe_defaults() {
        let policy = parse_policy(b"{}").expect("default policy");

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
                "failover-recovery-interval-seconds": 12,
                "client-api-failover-strategy": "ordered-safe-retry",
                "authentication": {
                    "max-body-length": 2048,
                    "max-concurrent-requests": 8
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
                    "authorization": {
                        "max-body-length": 0
                    }
                }"#
        )
        .is_err());
    }
}
