//! Canonical inputs prepared by a provider.

use std::fmt;
use std::sync::Arc;

use tacacsrs_config::source::ConfigDatastore;
use tacacsrs_config::tacacsrs::LocalServices;

use crate::CredentialProvider;

/// Source components consumed by one agent runtime.
pub struct SourceBundle {
    /// Canonical configuration and its observation owner.
    pub datastore: Arc<dyn ConfigDatastore>,
    /// Credentials and optional change notifications.
    pub credentials: CredentialProvider,
    /// Bootstrap local listener configuration.
    ///
    /// A datastore change that contains local services replaces this value
    /// at runtime.
    pub local_services: LocalServices,
}

/// The configuration datastore of the selected source.
///
/// A source shares this value so that a host can read the datastore by a
/// concrete type. Exactly one source supplies it.
#[derive(Clone)]
pub struct SourceDatastore(pub Arc<dyn ConfigDatastore>);

impl fmt::Debug for SourceDatastore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SourceDatastore")
            .field(&self.0.label())
            .finish()
    }
}
