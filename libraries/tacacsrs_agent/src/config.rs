//! Public configuration types for the local IPC listener and upstream failover.
//!
//! This module intentionally keeps parsing and defaults close to the config
//! structs so operators can see, in one place, how endpoint strings are
//! interpreted by the service runtime.
//!
//! # Configuration flow
//!
//! The executable (e.g. `tacacsrs_agentd`) parses CLI flags or a YANG JSON
//! config file into a [`ServiceConfig`], passes it to
//! [`TacacsClientService::new`](crate::TacacsClientService::new) for
//! validation, and then calls
//! [`serve`](crate::TacacsClientService::serve) to start the runtime.

use std::time::Duration;

use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_config::TacacsPlus;
use tacacsrs_secrets::SecretString;

/// Runtime services hosted by the TACACS+ client service process.
///
/// The client API is the local gRPC/protobuf service used by `tacon`,
/// `session-wrapper`, and other typed local consumers. The TACACS+ proxy is a
/// sibling service that accepts raw TACACS+ packets and forwards them upstream.
/// At least one service must be enabled for the process to do useful work.
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

    /// Returns a value indicating whether the local client API service is enabled.
    #[must_use]
    pub const fn client_api(self) -> bool {
        self.client_api
    }

    /// Returns a value indicating whether no runtime services are enabled.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.client_api && !self.tacacs_proxy
    }

    /// Returns a value indicating whether the raw TACACS+ proxy service is enabled.
    #[must_use]
    pub const fn tacacs_proxy(self) -> bool {
        self.tacacs_proxy
    }
}

/// Downstream obfuscation policy for raw TACACS+ proxy clients.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub enum ProxyDownstreamObfuscation {
    /// Expect downstream proxy clients to send unobfuscated TACACS+ packets.
    #[default]
    Unobfuscated,

    /// Expect downstream proxy clients to use this shared secret for TACACS+
    /// message obfuscation.
    SharedSecret(SecretString),
}

/// Configuration for the long-lived TACACS+ client service process.
///
/// The service consumes this once at startup. Validation that requires cross-
/// field context, such as credential-reference resolution, happens in
/// [`TacacsClientService::new`](crate::TacacsClientService::new).
///
/// # Required fields
///
/// - **`enabled_services`** — the local runtime services to host. At least one
///   service must be enabled.
/// - **`tacacs_plus`** — the YANG-modelled root configuration. The order of
///   `tacacs_plus.server` determines failover priority (index 0 is preferred)
///   when one or more accounting-capable servers are configured.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Runtime services to host in this process.
    pub enabled_services: EnabledServices,

    /// Local IPC endpoint exposed to local consumers when the client API
    /// service is enabled.
    ///
    /// Unix builds must use filesystem paths such as
    /// `/run/tacacs/tacacs.sock`. Non-Unix builds accept a loopback TCP socket
    /// address such as `127.0.0.1:9049` for developer workflows. Empty strings
    /// are rejected instead of defaulting.
    pub endpoint: IpcEndpoint,

    /// Optional local TACACS+ proxy endpoint.
    ///
    /// When the TACACS+ proxy service is enabled, this endpoint accepts raw
    /// TACACS+ client connections and proxies each downstream connection to
    /// one upstream TACACS+ session. TCP proxy endpoints must be loopback-only.
    pub proxy_endpoint: Option<IpcEndpoint>,

    /// Obfuscation policy expected from raw TACACS+ proxy clients.
    ///
    /// This is intentionally separate from upstream server shared secrets:
    /// the proxy has to deobfuscate and reobfuscate packets when rewriting
    /// TACACS+ session IDs across the downstream/upstream boundary, so the
    /// downstream client-facing choice is simply whether clients send
    /// unobfuscated packets or packets obfuscated with a local proxy secret.
    pub proxy_downstream_obfuscation: ProxyDownstreamObfuscation,

    /// Root TACACS+ configuration including upstream servers and any shared
    /// credential bundles.
    ///
    /// The service resolves `client-credentials` / `server-credentials`
    /// references at startup via
    /// [`tacacsrs_config::enumerate_servers`]. In-process construction via
    /// [`tacacsrs_config::TacacsPlusBuilder`] typically inlines all security
    /// material directly on each server and leaves the credential bundles
    /// empty.
    pub tacacs_plus: TacacsPlus,

    /// How often the preferred server should be reprobed while failed over.
    ///
    /// Only effective when more than one server is configured. A shorter
    /// interval detects recovery faster at the cost of more probe connections.
    pub preferred_probe_interval: Duration,

    #[cfg(unix)]
    /// File mode applied to the bound Unix socket path.
    ///
    /// Typical values: `0o660` (owner + group) or `0o666` (world-accessible).
    pub socket_mode: u32,

    /// Dangerously disable TLS certificate verification for upstream connections.
    ///
    /// This is intended for development and testing only. In production,
    /// certificate verification should always be enabled.
    #[doc(hidden)]
    pub disable_certificate_verification: bool,
}
