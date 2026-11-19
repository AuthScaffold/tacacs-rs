//! The SONiC ConfigDB source component.

use std::sync::Arc;

use async_trait::async_trait;

use tacacsrs_composition::{Component, Composition};
use tacacsrs_config::local_services::LocalServicesPatch;
use tacacsrs_provider::SourceDatastore;

use crate::{SonicConfigDb, SonicConnection};

/// Supplies the datastore, credentials, and local services of SONiC ConfigDB.
///
/// The component does not read ConfigDB. It shares these values:
///
/// - a [`SourceDatastore`] that reads the forwarder row with each
///   configuration candidate and gives the local services of that row
/// - the SONiC [`CredentialProvider`](tacacsrs_provider::CredentialProvider)
/// - the bootstrap SONiC [`LocalServices`](tacacsrs_config::tacacsrs::LocalServices),
///   with the listener patch of the host and without a proxy endpoint
///
/// The client API and health serve at once. The proxy waits until a
/// forwarder row gives its endpoint. When the forwarder row changes, the
/// runtime moves the proxy to the new endpoint.
pub struct SonicSource {
    connection: SonicConnection,
    listener_patch: LocalServicesPatch,
}

impl SonicSource {
    /// Stable component name.
    pub const NAME: &'static str = "SONiC ConfigDB source";

    /// Creates a source for `connection`.
    #[must_use]
    pub fn new(connection: SonicConnection) -> Self {
        Self {
            connection,
            listener_patch: LocalServicesPatch::default(),
        }
    }

    /// Sets the host listener settings that apply to the forwarder row.
    ///
    /// The source checks the patch at once. If the patch sets a proxy
    /// endpoint, the datastore rejects a forwarder row with a different
    /// endpoint. See
    /// [`SonicForwarderSettings::local_services_with`](crate::SonicForwarderSettings::local_services_with).
    ///
    /// # Errors
    /// Returns an error when the patch disables a local service, sets an
    /// inline proxy shared secret, the proxy
    /// endpoint is not a loopback address with a nonzero port, or another
    /// patch value is invalid.
    pub fn with_listener_patch(mut self, patch: LocalServicesPatch) -> anyhow::Result<Self> {
        crate::mapping::check_listener_patch(&patch)?;
        self.listener_patch = patch;
        Ok(self)
    }
}

#[async_trait]
impl Component for SonicSource {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let (local_services, _) = crate::mapping::deferred_local_services(&self.listener_patch)?;
        composition.shared(Arc::new(crate::credentials(&self.connection)))?;
        composition.shared(Arc::new(local_services))?;
        composition.shared(Arc::new(SourceDatastore(Arc::new(SonicConfigDb::with_listener_patch(
            self.connection,
            self.listener_patch,
        )))))
    }
}
