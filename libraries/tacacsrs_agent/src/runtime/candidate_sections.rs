//! Configuration sections that publish together with one datastore change.

use std::sync::Arc;

use crate::{PolicyRevision, RuntimePolicy};

use super::ActiveLocalServices;

/// The prepared sections of one datastore change, other than the servers.
///
/// The runtime publishes these sections in the same publication step as the
/// server set of the change. A credential refresh can publish the same
/// sections again.
#[derive(Debug)]
pub(crate) struct CandidateSections {
    /// The local services that the change activates.
    pub(crate) local_services: Arc<ActiveLocalServices>,
    /// The runtime policy of the change. `None` keeps the active policy.
    pub(crate) runtime_policy: Option<SourcePolicy>,
}

/// A runtime policy from a datastore change, with the revision that the
/// runtime admitted when it observed the change.
///
/// The revision stays the same when a credential refresh publishes the
/// sections again. A policy that the runtime admits later supersedes this
/// policy.
#[derive(Debug)]
pub(crate) struct SourcePolicy {
    pub(crate) revision: PolicyRevision,
    pub(crate) policy: Arc<RuntimePolicy>,
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
