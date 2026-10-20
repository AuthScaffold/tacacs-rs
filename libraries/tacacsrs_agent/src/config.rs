//! Configuration types for local listeners and upstream failover.
//!
//! This module keeps parsing and defaults close to the configuration types.
//! Operators can use one module to see how the runtime interprets IPC endpoint
//! strings.
//!
//! # Configuration flow
//!
//! The host supplies listener and execution controls through [`ServiceConfig`].
//! [`TacacsClientService::new`](crate::TacacsClientService::new) validates these
//! controls and starts with no upstream servers. [`ConfigSupervisor`](crate::runtime::ConfigSupervisor)
//! observes the canonical datastore and owns every server publication.
pub use tacacsrs_config::proxy_policy::PreparedProxyPolicy;

pub use self::policy::{
    FailoverStrategy, OperationPolicies, PolicyService, RequestLimits, RuntimePolicy,
    RuntimeCandidateLimits,
};
pub(crate) use self::policy::default_concurrent_request_limit;

mod policy;

/// Runtime services hosted by the TACACS+ client service process.
///
/// The client API is the local gRPC/protobuf service. `tacon`,
/// `session-wrapper`, and other typed local clients use this service. The
/// TACACS+ proxy accepts raw TACACS+ packets and sends them to a server. Enable
/// at least one service.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EnabledServices {
    client_api: bool,
    tacacs_proxy: bool,
}

impl EnabledServices {
    /// Only host the local client API service.
    pub const CLIENT_API: Self = Self::new(true, false);

    /// Only host the raw TACACS+ proxy service.
    pub const TACACS_PROXY: Self = Self::new(false, true);

    /// Host both the local client API service and the raw TACACS+ proxy service.
    pub const BOTH: Self = Self::new(true, true);

    /// Host no runtime services.
    pub const NONE: Self = Self::new(false, false);

    /// Creates a runtime service selection.
    #[must_use]
    pub const fn new(client_api: bool, tacacs_proxy: bool) -> Self {
        Self {
            client_api,
            tacacs_proxy,
        }
    }

    /// Returns whether the local client API service is enabled.
    #[must_use]
    pub const fn client_api(self) -> bool {
        self.client_api
    }

    /// Returns whether all runtime services are disabled.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.client_api && !self.tacacs_proxy
    }

    /// Returns whether the raw TACACS+ proxy service is enabled.
    #[must_use]
    pub const fn tacacs_proxy(self) -> bool {
        self.tacacs_proxy
    }
}

/// Configuration for the long-lived TACACS+ client service process.
///
/// These startup controls do not contain an upstream source. The canonical
/// [`ConfigDatastore`](tacacsrs_config::source::ConfigDatastore) supplies servers
/// through [`ConfigSupervisor`](crate::runtime::ConfigSupervisor).
/// At least one local service must be enabled.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Canonical startup listener controls. Preparation validates these before binding.
    pub local_services: tacacsrs_config::tacacsrs::LocalServices,

    /// Schema validation policy for every runtime generation.
    ///
    /// Use the validation options of the supervised datastore.
    pub validation_options: tacacsrs_config::ValidationOptions,

    /// Live failover and request-admission policy.
    pub runtime_policy: RuntimePolicy,

    /// Selects TLS certificate verification for server connections.
    ///
    /// CAUTION: `DisabledForDevelopment` permits server impersonation. Use `Required` in production.
    pub certificate_verification: tacacsrs_networking::CertificateVerification,
}

impl ServiceConfig {
    /// Returns the service selection from the canonical listener source.
    #[must_use]
    pub const fn enabled_services(&self) -> EnabledServices {
        EnabledServices::new(
            self.local_services.client_api_enabled,
            self.local_services.tacacs_proxy_enabled,
        )
    }
}
