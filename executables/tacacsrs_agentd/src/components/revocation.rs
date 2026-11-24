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
use std::time::Duration;

use dill::component;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use tacacsrs_agent::UpstreamRevocation;
use tacacsrs_composition::{Component, Composition, Named};
use tacacsrs_lifecycle::{HostedService, ShutdownSignal};
use tacacsrs_networking::{RevocationNetwork, RevocationSettings, RevocationVerifier};
use tacacsrs_revocation::CrlVerifier;

/// Delay before restarting the background CRL refresh task after an unexpected exit.
const REFRESH_RESTART_DELAY: Duration = Duration::from_secs(5);

/// Supplies the CRL verifier and runs its refresh loop.
pub(crate) struct RevocationComponent;

impl Component for RevocationComponent {
    fn name(&self) -> &'static str {
        CrlRefresh::NAME
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let (sender, receiver) = watch::channel(RevocationSettings::default());
        let (network_sender, network_receiver) = watch::channel(RevocationNetwork::default());
        let verifier = CrlVerifier::new(receiver);
        let shared: Arc<dyn RevocationVerifier> = Arc::new(verifier.clone());
        composition.shared(Arc::new(UpstreamRevocation::with_network(
            shared,
            sender,
            network_sender,
        )))?;
        composition.hosted_service(CrlRefresh::builder(verifier, network_receiver))
    }
}

/// Prefetches and refreshes the allowed CRLs until shutdown.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct CrlRefresh {
    #[component(explicit)]
    verifier: CrlVerifier,
    #[component(explicit)]
    network: watch::Receiver<RevocationNetwork>,
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
        supervise_refresh_until(
            || self.verifier.spawn_refresh_observed(self.network.clone()),
            shutdown,
            REFRESH_RESTART_DELAY,
        )
        .await
    }
}

async fn supervise_refresh_until(
    mut spawn_refresh: impl FnMut() -> JoinHandle<()>,
    shutdown: ShutdownSignal,
    restart_delay: Duration,
) -> anyhow::Result<()> {
    loop {
        let mut refresh = spawn_refresh();
        let outcome = tokio::select! {
            result = &mut refresh => result,
            () = shutdown.requested() => {
                refresh.abort();
                let _ = refresh.await;
                return Ok(());
            }
        };

        match outcome {
            Ok(()) => return Ok(()),
            Err(error) => {
                log::error!(
                    "CRL revocation refresh task terminated unexpectedly; restarting in {restart_delay:?}: {error}"
                );
                tokio::select! {
                    () = tokio::time::sleep(restart_delay) => {}
                    () = shutdown.requested() => return Ok(()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tacacsrs_lifecycle::ApplicationLifetime;

    use super::supervise_refresh_until;

    #[tokio::test]
    async fn refresh_task_panic_restarts_without_stopping_service() {
        let lifetime = ApplicationLifetime::new();
        let shutdown = lifetime.stopping();
        let spawns = Arc::new(AtomicUsize::new(0));
        let (restarted_tx, restarted_rx) = tokio::sync::oneshot::channel();
        let mut restarted_tx = Some(restarted_tx);

        let counter = Arc::clone(&spawns);
        let service = tokio::spawn(async move {
            supervise_refresh_until(
                move || {
                    let attempt = counter.fetch_add(1, Ordering::AcqRel);
                    if attempt == 0 {
                        tokio::spawn(async {
                            panic!("simulated refresh task panic");
                        })
                    } else {
                        if let Some(tx) = restarted_tx.take() {
                            let _ = tx.send(());
                        }
                        tokio::spawn(std::future::pending())
                    }
                },
                shutdown,
                Duration::from_millis(10),
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(1), restarted_rx)
            .await
            .expect("supervisor must restart panicking refresh task")
            .unwrap();
        assert_eq!(spawns.load(Ordering::Acquire), 2);

        lifetime.stop();
        service
            .await
            .expect("service task must not panic")
            .expect("service must exit cleanly on shutdown");
    }

    #[tokio::test]
    async fn natural_refresh_completion_ends_service_cleanly() {
        let lifetime = ApplicationLifetime::new();
        let spawns = AtomicUsize::new(0);
        supervise_refresh_until(
            || {
                spawns.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(async {})
            },
            lifetime.stopping(),
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert_eq!(spawns.load(Ordering::Acquire), 1);
    }
}
