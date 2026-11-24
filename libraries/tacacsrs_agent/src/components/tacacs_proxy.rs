//! Serves the raw TACACS+ proxy.
//!
//! The component adds the proxy listener of the prepared agent runtime. The
//! listener follows the active local services. It binds, moves, or stops the
//! proxy endpoint when the local services change. If the local services enable
//! the proxy without an endpoint, the listener reports `Pending` until a
//! datastore change supplies the endpoint.

use std::sync::Arc;

use dill::component;

use crate::host::{ListenerFactory, TacacsProxyAccess};
use crate::RuntimeListenerService;
use tacacsrs_composition::{Component, Composition, Named};

/// Adds the raw TACACS+ proxy listener to the agent runtime.
pub struct TacacsProxyComponent;

impl Component for TacacsProxyComponent {
    fn name(&self) -> &'static str {
        TacacsProxyListenerFactory::NAME
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        composition.member::<dyn ListenerFactory, TacacsProxyListenerFactory, _>(
            <TacacsProxyListenerFactory as dill::Component>::builder(),
        )
    }
}

/// Creates the raw TACACS+ proxy listener for the agent service.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn ListenerFactory)]
struct TacacsProxyListenerFactory {
    access: Arc<TacacsProxyAccess>,
}

impl Named for TacacsProxyListenerFactory {
    const NAME: &'static str = "TACACS+ proxy";
}

impl ListenerFactory for TacacsProxyListenerFactory {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn listener(&self) -> Option<Box<dyn RuntimeListenerService>> {
        Some(self.access.listener())
    }
}
