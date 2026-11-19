//! The SONiC ConfigDB source component.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;

use tacacsrs_composition::{Component, Composition};
use tacacsrs_config::local_services::LocalServicesPatch;
use tacacsrs_provider::SourceDatastore;

use crate::{SonicConfigDb, SonicConnection, SonicForwarderSettings};

/// Supplies the datastore, credentials, and local services of SONiC ConfigDB.
///
/// Preparation waits until ConfigDB contains a valid forwarder row. The
/// component then shares these values:
///
/// - a [`SourceDatastore`] that compares later forwarder rows with the bound
///   row
/// - the SONiC [`CredentialProvider`](tacacsrs_provider::CredentialProvider)
/// - the [`LocalServices`](tacacsrs_config::tacacsrs::LocalServices) of the
///   forwarder row, with the listener patch of the host
pub struct SonicSource {
    connection: SonicConnection,
    listener_patch: LocalServicesPatch,
    forwarder: Option<SonicForwarderSettings>,
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
            forwarder: None,
        }
    }

    /// Sets the host listener settings that apply to the forwarder row.
    ///
    /// The source checks the patch at once, before it waits for ConfigDB. It
    /// compares the proxy endpoint with the forwarder row when the row is
    /// available. See [`SonicForwarderSettings::local_services_with`].
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

    async fn prepare(&mut self) -> anyhow::Result<()> {
        self.forwarder = Some(crate::wait_for_forwarder(&self.connection).await);
        Ok(())
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let forwarder = self
            .forwarder
            .context("The SONiC forwarder row is not prepared")?;
        let local_services = forwarder
            .local_services_with(&self.listener_patch)
            .context("The host listener settings conflict with the SONiC forwarder row")?;
        composition.shared(Arc::new(crate::credentials(&self.connection)))?;
        composition.shared(Arc::new(local_services))?;
        composition.shared(Arc::new(SourceDatastore(Arc::new(
            SonicConfigDb::with_bound_forwarder(self.connection, forwarder),
        ))))
    }
}
