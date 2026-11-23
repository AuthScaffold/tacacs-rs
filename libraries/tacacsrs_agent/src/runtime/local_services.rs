//! The local services that the runtime applies now.
//!
//! A datastore change can contain new local services. The runtime prepares
//! that value and publishes the candidate together with the upstream servers
//! of the same change. Then the listener reconcilers bind, move, or stop the
//! local listeners.

use std::sync::Arc;

use tacacsrs_config::local_services::{prepare_local_services, PreparedLocalServices};
use tacacsrs_config::tacacsrs::LocalServices;
use super::config_view::{ConfigPublisher, LocalServicesView};
use super::proxy_loop_guard::{ProxyGuardTarget, ProxyLoopGuard};

/// Local services with their prepared bind targets.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ActiveLocalServices {
    settings: LocalServices,
    prepared: PreparedLocalServices,
}

impl ActiveLocalServices {
    /// Prepares local services.
    ///
    /// # Errors
    /// Returns an error when the local services are not valid.
    pub fn new(settings: LocalServices) -> anyhow::Result<Self> {
        let prepared = prepare_local_services(&settings)?;
        Ok(Self { settings, prepared })
    }

    /// Returns the canonical local services.
    #[must_use]
    pub const fn settings(&self) -> &LocalServices {
        &self.settings
    }

    /// Returns the prepared bind targets.
    #[must_use]
    pub const fn prepared(&self) -> &PreparedLocalServices {
        &self.prepared
    }

    pub(crate) fn proxy_guard_target(&self) -> ProxyGuardTarget {
        match self.prepared.tacacs_proxy() {
            Some(endpoint) => ProxyGuardTarget::from_endpoint(Some(endpoint)),
            None if self.prepared.tacacs_proxy_enabled() => ProxyGuardTarget::Waiting,
            None => ProxyGuardTarget::Inactive,
        }
    }
}

/// Owns the active local services of the runtime.
pub(crate) struct LocalServicesState {
    publisher: ConfigPublisher<ActiveLocalServices>,
    proxy_loop_guard: ProxyLoopGuard,
}

impl LocalServicesState {
    pub(crate) fn new(initial: ActiveLocalServices) -> Self {
        let proxy_loop_guard = ProxyLoopGuard::with_target(initial.proxy_guard_target());
        Self {
            publisher: ConfigPublisher::new(Arc::new(initial)),
            proxy_loop_guard,
        }
    }

    pub(crate) fn proxy_loop_guard(&self) -> &ProxyLoopGuard {
        &self.proxy_loop_guard
    }

    pub(crate) fn view(&self) -> LocalServicesView {
        self.publisher.view()
    }

    pub(crate) fn current(&self) -> Arc<ActiveLocalServices> {
        self.publisher.current()
    }

    /// Prepares a candidate local-services snapshot.
    pub(crate) fn prepare_candidate(
        &self,
        source: &LocalServices,
    ) -> anyhow::Result<Arc<ActiveLocalServices>> {
        let _ = self;
        Ok(Arc::new(ActiveLocalServices::new(source.clone())?))
    }

    /// Publishes new local services. An unchanged value does nothing.
    ///
    /// The proxy loop guard receives the new target before the listeners do.
    pub(crate) fn publish(&self, next: Arc<ActiveLocalServices>) {
        self.publisher.publish_with(next, |next| {
            self.proxy_loop_guard.configure(next.proxy_guard_target());
            log::info!("The runtime applies new local services");
        });
    }
}
