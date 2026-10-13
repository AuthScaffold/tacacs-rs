//! Runtime routing and admission policy.

use std::time::Duration;

use tacacsrs_protocol::constants::TACACS_MAX_BODY_LENGTH;

use crate::upstream::OperationKind;

/// Default admission ceiling for concurrent requests of one operation.
///
/// Local queue depths align with this value so that a full queue reflects real
/// admission pressure.
pub(crate) fn default_concurrent_request_limit() -> usize {
    tacacsrs_config::tacacsrs::Authentication::default().max_concurrent_requests as usize
}

/// Failover behavior for one local service.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum FailoverStrategy {
    /// Record a failure and let the next request use the next server.
    #[default]
    DeferredFailover,
    /// Try the next eligible server during the current request when replay is safe.
    /// Unknown outcomes stop immediately for every operation kind.
    OrderedSafeRetry,
}

/// A local service that sends requests through the upstream manager.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum PolicyService {
    /// The protobuf client API.
    ClientApi,
    /// The raw TACACS+ proxy.
    TacacsProxy,
}

/// Admission limits shared by all clients of one operation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RequestLimits {
    max_body_length: usize,
    max_concurrent_requests: usize,
    request_timeout: Duration,
}

impl RequestLimits {
    /// Creates validated request limits.
    ///
    /// # Errors
    ///
    /// Returns an error if either limit is zero or the body limit exceeds the
    /// absolute TACACS+ protocol limit.
    pub fn new(max_body_length: usize, max_concurrent_requests: usize) -> anyhow::Result<Self> {
        if max_body_length == 0 {
            anyhow::bail!("The maximum request body length must be greater than zero");
        }
        if max_body_length > TACACS_MAX_BODY_LENGTH as usize {
            anyhow::bail!(
                "The maximum request body length {max_body_length} exceeds the absolute TACACS+ limit of {TACACS_MAX_BODY_LENGTH}"
            );
        }
        if max_concurrent_requests == 0 {
            anyhow::bail!("The maximum concurrent request count must be greater than zero");
        }
        Ok(Self {
            max_body_length,
            max_concurrent_requests,
            request_timeout: Duration::from_secs(u64::from(
                tacacsrs_config::tacacsrs::Authentication::default().request_timeout_seconds,
            )),
        })
    }

    /// Overrides the total request budget on a prepared policy.
    ///
    /// # Errors
    /// Returns an error for a zero budget or an unsupported clock range.
    pub fn with_request_timeout(mut self, timeout: Duration) -> anyhow::Result<Self> {
        anyhow::ensure!(!timeout.is_zero(), "The request timeout must be greater than zero");
        tacacsrs_networking::RequestDeadline::after(timeout)?;
        self.request_timeout = timeout;
        Ok(self)
    }

    /// Returns the total budget captured before admission.
    #[must_use]
    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }

    /// Returns the maximum encoded TACACS+ body length.
    #[must_use]
    pub const fn max_body_length(self) -> usize {
        self.max_body_length
    }

    /// Returns the maximum number of concurrent requests.
    #[must_use]
    pub const fn max_concurrent_requests(self) -> usize {
        self.max_concurrent_requests
    }
}

/// Operation limits shared by IPC and proxy clients.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OperationPolicies {
    authentication: RequestLimits,
    authorization: RequestLimits,
    accounting: RequestLimits,
}

impl OperationPolicies {
    /// Creates operation-specific admission policies.
    #[must_use]
    pub const fn new(
        authentication: RequestLimits,
        authorization: RequestLimits,
        accounting: RequestLimits,
    ) -> Self {
        Self {
            authentication,
            authorization,
            accounting,
        }
    }

    /// Returns the limits for an operation.
    #[must_use]
    pub const fn get(&self, operation: OperationKind) -> RequestLimits {
        match operation {
            OperationKind::Authentication => self.authentication,
            OperationKind::Authorization => self.authorization,
            OperationKind::Accounting => self.accounting,
        }
    }
}

impl Default for OperationPolicies {
    fn default() -> Self {
        RuntimePolicy::default().operations
    }
}

/// Complete live policy for the local TACACS+ services.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimePolicy {
    client_api_failover_strategy: FailoverStrategy,
    tacacs_proxy_failover_strategy: FailoverStrategy,
    operations: OperationPolicies,
    failover_recovery_interval: Duration,
    shutdown_timeout: Duration,
    source_stale_timeout: Duration,
    credential_stale_timeout: Duration,
    credential_refresh_interval: Duration,
}

impl RuntimePolicy {
    fn from_validated_yang(policy: &tacacsrs_config::tacacsrs::RuntimePolicy) -> Self {
        let authentication = policy.authentication.clone().unwrap_or_default();
        let authorization = policy.authorization.clone().unwrap_or_default();
        let accounting = policy.accounting.clone().unwrap_or_default();
        Self {
            client_api_failover_strategy: strategy_from_yang(policy.client_api_failover_strategy),
            tacacs_proxy_failover_strategy: strategy_from_yang(
                policy.tacacs_proxy_failover_strategy,
            ),
            operations: OperationPolicies::new(
                RequestLimits {
                    max_body_length: authentication.max_body_length as usize,
                    max_concurrent_requests: authentication.max_concurrent_requests as usize,
                    request_timeout: Duration::from_secs(u64::from(
                        authentication.request_timeout_seconds,
                    )),
                },
                RequestLimits {
                    max_body_length: authorization.max_body_length as usize,
                    max_concurrent_requests: authorization.max_concurrent_requests as usize,
                    request_timeout: Duration::from_secs(u64::from(
                        authorization.request_timeout_seconds,
                    )),
                },
                RequestLimits {
                    max_body_length: accounting.max_body_length as usize,
                    max_concurrent_requests: accounting.max_concurrent_requests as usize,
                    request_timeout: Duration::from_secs(u64::from(
                        accounting.request_timeout_seconds,
                    )),
                },
            ),
            failover_recovery_interval: Duration::from_secs(u64::from(
                policy.failover_recovery_interval_seconds,
            )),
            shutdown_timeout: Duration::from_secs(u64::from(policy.shutdown_timeout_seconds)),
            source_stale_timeout: Duration::from_secs(u64::from(
                policy.source_stale_timeout_seconds,
            )),
            credential_stale_timeout: Duration::from_secs(u64::from(
                policy.credential_stale_timeout_seconds,
            )),
            credential_refresh_interval: Duration::from_secs(u64::from(
                policy.credential_refresh_interval_seconds,
            )),
        }
    }

    /// Creates a validated runtime policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the recovery interval is zero.
    pub fn new(
        client_api_failover_strategy: FailoverStrategy,
        tacacs_proxy_failover_strategy: FailoverStrategy,
        operations: OperationPolicies,
        failover_recovery_interval: Duration,
    ) -> anyhow::Result<Self> {
        if failover_recovery_interval.is_zero() {
            anyhow::bail!("The failover recovery interval must be greater than zero");
        }
        Ok(Self {
            client_api_failover_strategy,
            tacacs_proxy_failover_strategy,
            operations,
            failover_recovery_interval,
            shutdown_timeout: Duration::from_secs(u64::from(
                tacacsrs_config::tacacsrs::RuntimePolicy::default().shutdown_timeout_seconds,
            )),
            source_stale_timeout: Duration::from_secs(u64::from(
                tacacsrs_config::tacacsrs::RuntimePolicy::default().source_stale_timeout_seconds,
            )),
            credential_stale_timeout: Duration::from_secs(u64::from(
                tacacsrs_config::tacacsrs::RuntimePolicy::default()
                    .credential_stale_timeout_seconds,
            )),
            credential_refresh_interval: Duration::from_secs(u64::from(
                tacacsrs_config::tacacsrs::RuntimePolicy::default()
                    .credential_refresh_interval_seconds,
            )),
        })
    }

    /// Returns the failover strategy for a local service.
    #[must_use]
    pub const fn failover_strategy(&self, service: PolicyService) -> FailoverStrategy {
        match service {
            PolicyService::ClientApi => self.client_api_failover_strategy,
            PolicyService::TacacsProxy => self.tacacs_proxy_failover_strategy,
        }
    }

    /// Projects the service strategy into an execution-only attempt budget.
    pub(crate) fn failover_plan(
        &self,
        service: PolicyService,
        eligible_servers: usize,
    ) -> tacacsrs_networking::retry::FailoverPlan {
        let attempts = match self.failover_strategy(service) {
            FailoverStrategy::DeferredFailover => 1,
            FailoverStrategy::OrderedSafeRetry => eligible_servers.max(1),
        };
        tacacsrs_networking::retry::FailoverPlan::new(attempts)
    }

    /// Returns the shared admission limits for an operation.
    #[must_use]
    pub const fn limits(&self, operation: OperationKind) -> RequestLimits {
        self.operations.get(operation)
    }

    /// Returns the interval before a failed route receives one recovery trial.
    #[must_use]
    pub const fn failover_recovery_interval(&self) -> Duration {
        self.failover_recovery_interval
    }

    /// Returns the graceful teardown budget captured when shutdown starts.
    #[must_use]
    pub const fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    /// Returns the grace interval captured when applied source configuration becomes stale.
    #[must_use]
    pub const fn source_stale_timeout(&self) -> Duration {
        self.source_stale_timeout
    }

    /// Returns the grace interval captured when referenced credentials become stale.
    #[must_use]
    pub const fn credential_stale_timeout(&self) -> Duration {
        self.credential_stale_timeout
    }

    /// Returns the maximum scheduled delay between provider refresh attempts.
    #[must_use]
    pub const fn credential_refresh_interval(&self) -> Duration {
        self.credential_refresh_interval
    }
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self::from_validated_yang(&tacacsrs_config::tacacsrs::RuntimePolicy::default())
    }
}

impl TryFrom<&tacacsrs_config::tacacsrs::RuntimePolicy> for RuntimePolicy {
    type Error = anyhow::Error;

    fn try_from(policy: &tacacsrs_config::tacacsrs::RuntimePolicy) -> Result<Self, Self::Error> {
        tacacsrs_config::policy::validate_runtime_policy(policy)?;
        Ok(Self::from_validated_yang(policy))
    }
}

const fn strategy_from_yang(
    strategy: tacacsrs_config::tacacsrs::FailoverStrategy,
) -> FailoverStrategy {
    match strategy {
        tacacsrs_config::tacacsrs::FailoverStrategy::DeferredFailover => {
            FailoverStrategy::DeferredFailover
        }
        tacacsrs_config::tacacsrs::FailoverStrategy::OrderedSafeRetry => {
            FailoverStrategy::OrderedSafeRetry
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_uses_safe_limits_and_deferred_failover() {
        let policy = RuntimePolicy::default();

        assert_eq!(
            policy.failover_strategy(PolicyService::ClientApi),
            FailoverStrategy::DeferredFailover
        );
        assert_eq!(
            policy
                .limits(OperationKind::Authentication)
                .max_body_length(),
            4 * 1024
        );
        assert_eq!(
            policy
                .limits(OperationKind::Authorization)
                .max_body_length(),
            16 * 1024
        );
        assert_eq!(
            policy
                .limits(OperationKind::Accounting)
                .max_concurrent_requests(),
            64
        );
    }

    #[test]
    fn request_limits_reject_zero_and_excessive_values() {
        assert!(RequestLimits::new(0, 1).is_err());
        assert!(RequestLimits::new(1, 0).is_err());
        assert!(RequestLimits::new(TACACS_MAX_BODY_LENGTH as usize + 1, 1).is_err());
        assert!(RequestLimits::new(1, 1)
            .unwrap()
            .with_request_timeout(Duration::ZERO)
            .is_err());
    }

    #[test]
    fn runtime_policy_rejects_zero_recovery_interval() {
        assert!(RuntimePolicy::new(
            FailoverStrategy::default(),
            FailoverStrategy::default(),
            OperationPolicies::default(),
            Duration::ZERO,
        )
        .is_err());
    }

    #[test]
    fn canonical_policy_preparation_preserves_source_and_generated_defaults() {
        let source = tacacsrs_config::policy::parse_runtime_policy(
            br#"{
            "tacacsrs:runtime-policy": {
                "client-api-failover-strategy": "ordered-safe-retry",
                "authentication": {},
                "authorization": {"max-body-length":8192,"max-concurrent-requests":16,"request-timeout-seconds":12}
            }
        }"#,
        )
        .unwrap();
        let original = source.clone();
        let prepared = RuntimePolicy::try_from(&source).unwrap();
        assert_eq!(source, original);
        assert_eq!(
            prepared
                .limits(OperationKind::Authorization)
                .request_timeout(),
            Duration::from_secs(12)
        );
        assert_eq!(
            prepared
                .limits(OperationKind::Authentication)
                .request_timeout(),
            Duration::from_secs(30)
        );
        assert_eq!(
            prepared.failover_strategy(PolicyService::ClientApi),
            FailoverStrategy::OrderedSafeRetry
        );
        assert_eq!(
            prepared.failover_strategy(PolicyService::TacacsProxy),
            FailoverStrategy::DeferredFailover
        );
        assert_eq!(prepared.failover_recovery_interval(), Duration::from_secs(30));
        assert_eq!(
            prepared
                .limits(OperationKind::Authentication)
                .max_body_length(),
            4096
        );
        assert_eq!(
            prepared.limits(OperationKind::Authorization),
            RequestLimits::new(8192, 16)
                .unwrap()
                .with_request_timeout(Duration::from_secs(12))
                .unwrap()
        );
        assert_eq!(prepared.limits(OperationKind::Accounting).max_body_length(), 16384);
        let mut invalid = source;
        invalid.failover_recovery_interval_seconds = 0;
        assert!(RuntimePolicy::try_from(&invalid).is_err());
    }
}
