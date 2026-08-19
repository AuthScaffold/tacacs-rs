//! Runtime routing and admission policy.

use std::time::Duration;

use tacacsrs_messages::constants::TACACS_MAX_BODY_LENGTH;

use crate::upstream::OperationKind;

const DEFAULT_AUTHENTICATION_BODY_LIMIT: usize = 4 * 1024;
const DEFAULT_AUTHORIZATION_BODY_LIMIT: usize = 16 * 1024;
const DEFAULT_ACCOUNTING_BODY_LIMIT: usize = 16 * 1024;
const DEFAULT_CONCURRENT_REQUEST_LIMIT: usize = 64;
const DEFAULT_RECOVERY_INTERVAL: Duration = Duration::from_secs(30);

/// Failover behavior for one local service.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum FailoverStrategy {
    /// Record a failure and let the next request use the next server.
    #[default]
    DeferredFailover,
    /// Try the next eligible server during the current request when replay is safe.
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
        })
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
        Self::new(
            RequestLimits {
                max_body_length: DEFAULT_AUTHENTICATION_BODY_LIMIT,
                max_concurrent_requests: DEFAULT_CONCURRENT_REQUEST_LIMIT,
            },
            RequestLimits {
                max_body_length: DEFAULT_AUTHORIZATION_BODY_LIMIT,
                max_concurrent_requests: DEFAULT_CONCURRENT_REQUEST_LIMIT,
            },
            RequestLimits {
                max_body_length: DEFAULT_ACCOUNTING_BODY_LIMIT,
                max_concurrent_requests: DEFAULT_CONCURRENT_REQUEST_LIMIT,
            },
        )
    }
}

/// Complete live policy for the local TACACS+ services.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimePolicy {
    client_api_failover_strategy: FailoverStrategy,
    tacacs_proxy_failover_strategy: FailoverStrategy,
    operations: OperationPolicies,
    failover_recovery_interval: Duration,
}

impl RuntimePolicy {
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
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            client_api_failover_strategy: FailoverStrategy::default(),
            tacacs_proxy_failover_strategy: FailoverStrategy::default(),
            operations: OperationPolicies::default(),
            failover_recovery_interval: DEFAULT_RECOVERY_INTERVAL,
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
}
