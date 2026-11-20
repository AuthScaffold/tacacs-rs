//! The CRL revocation verifier for upstream TLS connections.
//!
//! The component creates one [`CrlVerifier`] and gives it to the agent as an
//! [`UpstreamRevocation`] input. The agent publishes the YANG
//! `certificate-revocation` policy to the verifier through a watch channel.
//! A hosted service runs the verifier's prefetch and refresh loop until
//! shutdown.
//!
//! The verifier checks revocation only when a connection is established. It
//! never closes an established connection.

use std::sync::Arc;

use dill::component;
use tokio::sync::watch;

use tacacsrs_agent::UpstreamRevocation;
use tacacsrs_composition::{Component, Composition, Named};
use tacacsrs_lifecycle::{HostedService, ShutdownSignal};
use tacacsrs_networking::{RevocationNetwork, RevocationSettings, RevocationVerifier};
use tacacsrs_revocation::CrlVerifier;

/// Supplies the CRL verifier and runs its refresh loop.
pub(crate) struct RevocationComponent;

impl Component for RevocationComponent {
    fn name(&self) -> &'static str {
        CrlRefresh::NAME
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let (sender, receiver) = watch::channel(RevocationSettings::default());
        let verifier = CrlVerifier::new(receiver);
        let shared: Arc<dyn RevocationVerifier> = Arc::new(verifier.clone());
        composition.shared(Arc::new(UpstreamRevocation::new(shared, sender)))?;
        composition.hosted_service(CrlRefresh::builder(verifier))
    }
}

/// Prefetches and refreshes the allowed CRLs until shutdown.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct CrlRefresh {
    #[component(explicit)]
    verifier: CrlVerifier,
}

impl Named for CrlRefresh {
    const NAME: &'static str = "CRL revocation refresh";
}

#[async_trait::async_trait]
impl HostedService for CrlRefresh {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn run(self: Arc<Self>, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        let refresh = self.verifier.spawn_refresh(RevocationNetwork::default());
        shutdown.requested().await;
        refresh.abort();
        Ok(())
    }
}
