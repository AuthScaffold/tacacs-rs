//! Canonical inputs prepared by a provider.

use std::fmt;
use std::sync::Arc;

use tacacsrs_config::source::ConfigDatastore;
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_credential_resolution::CredentialResolver;

use crate::CredentialProvider;

/// Source components consumed by one agent runtime.
pub struct SourceBundle {
    /// Canonical configuration and its observation owner.
    pub datastore: Arc<dyn ConfigDatastore>,
    /// Credentials and optional change notifications.
    pub credentials: CredentialProvider,
    /// Canonical local listener configuration.
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

/// Wraps the credential resolver of the source.
///
/// The host applies the layers in registration order. The first layer gets
/// the resolver of the source, and each later layer gets the result of the
/// layer before it.
pub trait CredentialLayer: Send + Sync {
    /// Returns a stable, secret-free name that is unique among layers.
    fn name(&self) -> &'static str;

    /// Returns the resolver that wraps `inner`.
    ///
    /// # Errors
    /// Returns an error when the layer cannot wrap the resolver, for example
    /// when the host applies it a second time.
    fn wrap(
        &self,
        inner: Option<Arc<dyn CredentialResolver>>,
    ) -> anyhow::Result<Arc<dyn CredentialResolver>>;
}

/// Changes the local services of the source before the runtime prepares them.
///
/// The host applies the overlays in registration order.
pub trait LocalServicesOverlay: Send + Sync {
    /// Returns a stable, secret-free name that is unique among overlays.
    fn name(&self) -> &'static str;

    /// Returns the changed local services.
    ///
    /// # Errors
    /// Returns an error when the change conflicts with the source.
    fn apply(&self, source: LocalServices) -> anyhow::Result<LocalServices>;
}
