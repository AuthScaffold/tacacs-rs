//! Configuration sections that publish together with one datastore change.

use std::sync::Arc;

use crate::RuntimePolicy;

use super::ActiveLocalServices;

/// The prepared sections of one datastore change, other than the servers.
///
/// The runtime publishes these sections after the server set of the same
/// change.
#[derive(Debug)]
pub(crate) struct CandidateSections {
    /// The local services that the change activates.
    pub(crate) local_services: Arc<ActiveLocalServices>,
    /// The runtime policy of the change. `None` keeps the active policy.
    pub(crate) runtime_policy: Option<Arc<RuntimePolicy>>,
}

#[cfg(test)]
impl CandidateSections {
    /// Returns sections that change only the local services.
    pub(crate) const fn local_services(local_services: Arc<ActiveLocalServices>) -> Self {
        Self {
            local_services,
            runtime_policy: None,
        }
    }
}
