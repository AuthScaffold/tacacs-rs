//! Configuration types for local listeners and upstream failover.
//!
//! This module keeps parsing and defaults close to the configuration types.
//! Operators can use one module to see how the runtime interprets IPC endpoint
//! strings.
//!
//! # Configuration flow
//!
//! The executable, such as `tacacsrs_agentd`, parses CLI flags or a YANG JSON
//! configuration file into a [`ServiceConfig`]. It passes the result to
//! [`TacacsClientService::new`](crate::TacacsClientService::new) for
//! validation. It then calls
//! [`serve`](crate::TacacsClientService::serve) to start the runtime.

use tacacsrs_config::TacacsPlus;
use tacacsrs_secrets::SecretString;

pub use self::policy::{
    FailoverStrategy, OperationPolicies, PolicyService, RequestLimits, RuntimePolicy,
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

/// Downstream obfuscation policy for raw TACACS+ proxy clients.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub enum ProxyDownstreamObfuscation {
    /// Requires downstream proxy clients to send unobfuscated TACACS+ packets.
    #[default]
    Unobfuscated,

    /// Requires downstream proxy clients to use this shared secret for TACACS+
    /// message obfuscation.
    SharedSecret(SecretString),
}

/// Configuration for the long-lived TACACS+ client service process.
///
/// The service reads this configuration at startup. It validates related
/// fields, such as credential references, in
/// [`TacacsClientService::new`](crate::TacacsClientService::new).
///
/// # Required fields
///
/// - **`local_services`** — canonical listener configuration. At least one
///   service must be enabled.
/// - **`tacacs_plus`** — the YANG-modelled root configuration. The order of
///   `tacacs_plus.server` sets the failover priority. Index 0 is preferred.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Canonical startup listener controls. Preparation validates these before binding.
    pub local_services: tacacsrs_config::tacacsrs::LocalServices,

    /// Obfuscation policy expected from raw TACACS+ proxy clients.
    ///
    /// This policy is separate from the shared secrets for servers. The proxy
    /// deobfuscates and reobfuscates packets when it rewrites TACACS+ session
    /// IDs. A downstream client sends either unobfuscated packets or packets
    /// obfuscated with the local proxy shared secret.
    pub proxy_downstream_obfuscation: ProxyDownstreamObfuscation,

    /// Root TACACS+ configuration that contains servers and shared
    /// credential bundles.
    ///
    /// The service resolves `client-credentials` / `server-credentials`
    /// references at startup with [`tacacsrs_config::enumerate_servers`].
    /// [`tacacsrs_config::TacacsPlusBuilder`] usually puts security material
    /// directly in each server. In this case, the credential bundles are empty.
    pub tacacs_plus: TacacsPlus,

    /// Schema validation policy used by the source and every runtime generation.
    pub validation_options: tacacsrs_config::ValidationOptions,

    /// Live failover and request-admission policy.
    pub runtime_policy: RuntimePolicy,

    /// Disables TLS certificate verification for server connections.
    ///
    /// This option is dangerous. Use it only for development and tests. Always
    /// enable certificate verification in production.
    #[doc(hidden)]
    pub disable_certificate_verification: bool,
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
