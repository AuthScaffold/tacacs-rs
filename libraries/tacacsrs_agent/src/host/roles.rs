//! Listener roles and the client API facet.

use std::sync::Arc;

use async_trait::async_trait;

use crate::runtime::LocalServicesView;
use crate::{ClientApiHandle, RuntimeListenerService, TacacsClientService};

/// Creates one owned listener for the agent runtime without I/O.
///
/// The listener binds its endpoint in `serve`.
pub trait ListenerFactory: Send + Sync {
    /// Returns a stable, secret-free name that is unique among listeners.
    fn name(&self) -> &'static str;

    /// Creates the listener, or returns `None` when the prepared runtime
    /// disables it.
    fn listener(&self) -> Option<Box<dyn RuntimeListenerService>>;
}

/// The client API of the prepared agent runtime.
///
/// The host supplies this value after it prepares the runtime. The value
/// serves requests. It cannot stop the agent.
#[derive(Clone)]
pub struct ClientApiAccess {
    /// The active local services. They select the client API socket and its
    /// settings.
    pub local_services: LocalServicesView,
    /// The handle that sends client API operations to the agent.
    pub handle: ClientApiHandle,
}

/// The raw TACACS+ proxy of the prepared agent runtime.
///
/// The host supplies this value after it prepares the runtime. The value
/// creates the proxy listener. It cannot stop the agent.
#[derive(Clone)]
pub struct TacacsProxyAccess {
    service: Arc<TacacsClientService>,
}

impl TacacsProxyAccess {
    pub(crate) fn new(service: Arc<TacacsClientService>) -> Self {
        Self { service }
    }

    /// Creates the proxy listener.
    ///
    /// The listener follows the active local services. It reports `Disabled`
    /// while the local services disable the proxy.
    #[must_use]
    pub fn listener(&self) -> Box<dyn RuntimeListenerService> {
        self.service.tacacs_proxy_listener()
    }
}

/// Registers protected output files on the prepared service.
#[derive(Clone)]
pub(crate) struct ListenerPathGuard {
    service: Arc<TacacsClientService>,
}

impl ListenerPathGuard {
    pub(crate) fn new(service: Arc<TacacsClientService>) -> Self {
        Self { service }
    }

    pub(crate) fn protect(&self, path: impl Into<std::path::PathBuf>) -> anyhow::Result<()> {
        self.service.protect_listener_path(path)
    }
}

/// Checks a prepared host before any listener binds or service starts.
///
/// A check can read deferred values. A failed check stops startup.
#[async_trait]
pub trait StartupCheck: Send + Sync {
    /// Returns a stable, secret-free name that is unique among checks.
    fn name(&self) -> &'static str;

    /// Runs the check.
    ///
    /// # Errors
    /// Returns an error that stops startup.
    async fn check(&self) -> anyhow::Result<()>;
}
