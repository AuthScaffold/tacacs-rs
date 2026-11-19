//! Listener roles and the client API facet.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::{ClientApiHandle, ListenerSettings, RuntimeListenerService};

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
    /// The client API socket path, or `None` when the client API is disabled.
    pub socket_path: Option<PathBuf>,
    /// The prepared client API listener settings.
    pub settings: ListenerSettings,
    /// The handle that sends client API operations to the agent.
    pub handle: ClientApiHandle,
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
