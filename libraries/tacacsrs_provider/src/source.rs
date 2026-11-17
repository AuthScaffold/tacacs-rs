//! Canonical inputs prepared by a provider.

use std::sync::Arc;

use tacacsrs_config::source::ConfigDatastore;
use tacacsrs_config::tacacsrs::LocalServices;

use crate::{Companion, CredentialProvider};

/// Source components consumed by one agent runtime.
pub struct SourceBundle {
    /// Canonical configuration and its observation owner.
    pub datastore: Arc<dyn ConfigDatastore>,
    /// Credentials and optional change notifications.
    pub credentials: CredentialProvider,
    /// Canonical local listener configuration.
    pub local_services: LocalServices,
    /// Inert provider services started by the agent.
    pub companions: Vec<Box<dyn Companion>>,
}
