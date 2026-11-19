//! The local services that the runtime applies now.
//!
//! A datastore change can contain new local services. The runtime applies the
//! local services overlays to that value and prepares it. The candidate is
//! published together with the upstream servers of the same change. Then the
//! listener reconcilers bind, move, or stop the local listeners.

use std::sync::Arc;

use anyhow::Context;
use tacacsrs_config::local_services::{prepare_local_services, PreparedLocalServices};
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_provider::LocalServicesOverlay;
use tokio::sync::watch;

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

    /// Returns the local services after the overlays.
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

/// A read-only view of the active local services.
///
/// Each clone sees each publication. A component reads the current value or
/// waits for the next change.
#[derive(Debug, Clone)]
pub struct LocalServicesView {
    receiver: watch::Receiver<Arc<ActiveLocalServices>>,
}

impl LocalServicesView {
    /// Returns the active local services.
    #[must_use]
    pub fn current(&self) -> Arc<ActiveLocalServices> {
        Arc::clone(&self.receiver.borrow())
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Arc<ActiveLocalServices>> {
        self.receiver.clone()
    }
}

/// Owns the active local services and the overlays of the runtime.
pub(crate) struct LocalServicesState {
    overlays: Vec<Arc<dyn LocalServicesOverlay>>,
    sender: watch::Sender<Arc<ActiveLocalServices>>,
    proxy_loop_guard: ProxyLoopGuard,
}

impl LocalServicesState {
    pub(crate) fn new(
        initial: ActiveLocalServices,
        overlays: Vec<Arc<dyn LocalServicesOverlay>>,
    ) -> Self {
        let proxy_loop_guard = ProxyLoopGuard::with_target(initial.proxy_guard_target());
        let (sender, _) = watch::channel(Arc::new(initial));
        Self {
            overlays,
            sender,
            proxy_loop_guard,
        }
    }

    pub(crate) fn proxy_loop_guard(&self) -> &ProxyLoopGuard {
        &self.proxy_loop_guard
    }

    pub(crate) fn view(&self) -> LocalServicesView {
        LocalServicesView {
            receiver: self.sender.subscribe(),
        }
    }

    pub(crate) fn current(&self) -> Arc<ActiveLocalServices> {
        Arc::clone(&self.sender.borrow())
    }

    /// Applies the overlays in order and prepares the result.
    pub(crate) fn prepare_candidate(
        &self,
        source: &LocalServices,
    ) -> anyhow::Result<Arc<ActiveLocalServices>> {
        let mut settings = source.clone();
        for overlay in &self.overlays {
            settings = overlay.apply(settings).with_context(|| {
                format!("Could not apply the local services overlay {}", overlay.name())
            })?;
        }
        Ok(Arc::new(ActiveLocalServices::new(settings)?))
    }

    /// Publishes new local services. An unchanged value does nothing.
    ///
    /// The proxy loop guard receives the new target before the listeners do.
    pub(crate) fn publish(&self, next: Arc<ActiveLocalServices>) {
        self.sender.send_if_modified(|current| {
            if **current == *next {
                return false;
            }
            self.proxy_loop_guard.configure(next.proxy_guard_target());
            log::info!("The runtime applies new local services");
            *current = next;
            true
        });
    }
}
