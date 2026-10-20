//! One admitted deadline and capacity owner through configuration commit.

use std::future::Future;
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;
use tokio::time::Instant;

use tacacsrs_config::prepare::ConfigurationMaterialBudget;
use tacacsrs_credential_resolution::{WorkScope, WorkScopeControl};

use crate::config::RuntimeCandidateLimits;

#[derive(Debug, Clone, Copy)]
pub(crate) struct CandidateAdmission {
    pub(crate) admitted: Instant,
    pub(crate) deadline: Instant,
    pub(crate) limits: RuntimeCandidateLimits,
}

impl CandidateAdmission {
    pub(crate) fn new(limits: RuntimeCandidateLimits) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !limits.timeout.is_zero() && limits.requests > 0 && limits.material_bytes > 0,
            "candidate limits must be greater than zero"
        );
        let admitted = Instant::now();
        let deadline = admitted
            .checked_add(limits.timeout)
            .ok_or_else(|| anyhow::anyhow!("candidate deadline exceeds the clock range"))?;
        Ok(Self {
            admitted,
            deadline,
            limits,
        })
    }

    pub(crate) fn check(&self) -> anyhow::Result<()> {
        anyhow::ensure!(Instant::now() < self.deadline, "candidate preparation deadline exceeded");
        Ok(())
    }

    pub(crate) async fn run<Output>(
        &self,
        future: impl Future<Output = Output>,
    ) -> anyhow::Result<Output> {
        self.check()?;
        tokio::time::timeout_at(self.deadline, future)
            .await
            .map_err(|_| anyhow::anyhow!("candidate preparation deadline exceeded"))
    }

    pub(crate) async fn acquire(self, slot: &Arc<Semaphore>) -> anyhow::Result<Arc<Preparation>> {
        let permit = self.run(Arc::clone(slot).acquire_owned()).await??;
        self.check()?;
        let (control, scope) = WorkScope::new(permit);
        Ok(Arc::new(Preparation {
            admission: self,
            ledger: Arc::new(Mutex::new(ConfigurationMaterialBudget::new(
                self.limits.material_bytes,
                self.limits.requests,
            ))),
            scope,
            control,
            #[cfg(test)]
            release_probe: None,
        }))
    }
}

#[derive(Debug)]
pub(crate) struct Preparation {
    pub(crate) admission: CandidateAdmission,
    pub(crate) ledger: Arc<Mutex<ConfigurationMaterialBudget>>,
    pub(crate) scope: WorkScope,
    control: WorkScopeControl,
    #[cfg(test)]
    pub(crate) release_probe: Option<ReleaseProbe>,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ReleaseProbe {
    pub(crate) server: std::sync::Weak<tacacsrs_config::TacacsPlusServer>,
    pub(crate) slot: Arc<Semaphore>,
    pub(crate) live_at_release: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) available_at_release: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl Drop for ReleaseProbe {
    fn drop(&mut self) {
        self.available_at_release
            .store(self.slot.available_permits(), std::sync::atomic::Ordering::SeqCst);
        self.live_at_release
            .store(self.server.strong_count(), std::sync::atomic::Ordering::SeqCst);
    }
}

impl Preparation {
    pub(crate) fn payload_ledger(&self) -> Arc<dyn tacacsrs_networking::PreparationPayloadLedger> {
        Arc::new(PreparedPayloadLedger(Arc::clone(&self.ledger)))
    }
    pub(crate) fn with_ledger<Output>(
        &self,
        update: impl FnOnce(&mut ConfigurationMaterialBudget) -> anyhow::Result<Output>,
    ) -> anyhow::Result<Output> {
        update(
            &mut self
                .ledger
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub(crate) fn final_check(&self, current: RuntimeCandidateLimits) -> anyhow::Result<()> {
        let effective = self
            .admission
            .admitted
            .checked_add(self.admission.limits.timeout.min(current.timeout))
            .ok_or_else(|| anyhow::anyhow!("candidate deadline exceeds the clock range"))?;
        anyhow::ensure!(Instant::now() < effective, "candidate preparation deadline exceeded");
        self.with_ledger(|ledger| ledger.check(current.material_bytes, current.requests))
    }
}

#[derive(Debug)]
struct PreparedPayloadLedger(Arc<Mutex<ConfigurationMaterialBudget>>);

impl tacacsrs_networking::PreparationPayloadLedger for PreparedPayloadLedger {
    fn reserve(&self, bytes: u64) -> anyhow::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reserve_extra(bytes)
    }

    fn release(&self, bytes: u64) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release_extra(bytes);
    }
}

impl Drop for Preparation {
    fn drop(&mut self) {
        self.control.seal();
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use crate::upstream::manager::PublicationCandidate;
    use super::*;

    pub(crate) struct DisposalObservation {
        pub(crate) slot: Arc<Semaphore>,
        pub(crate) server: std::sync::Weak<tacacsrs_config::TacacsPlusServer>,
        pub(crate) live_at_release: Arc<AtomicUsize>,
        pub(crate) available_at_release: Arc<AtomicUsize>,
        permits_during_drop: Arc<AtomicUsize>,
        coordinator: Arc<tokio::sync::Mutex<()>>,
    }

    impl DisposalObservation {
        pub(crate) fn assert_disposed(&self, available: usize) {
            assert_eq!(self.permits_during_drop.load(Ordering::SeqCst), 0);
            assert_eq!(
                self.live_at_release.load(Ordering::SeqCst),
                0,
                "payload survived capacity release"
            );
            assert_eq!(self.available_at_release.load(Ordering::SeqCst), available);
            assert!(self.server.upgrade().is_none());
            assert_eq!(self.slot.available_permits(), available);
            assert!(self.coordinator.try_lock().is_ok());
        }
    }

    struct CapturedPublication {
        server: Arc<tacacsrs_config::TacacsPlusServer>,
        proxy: tacacsrs_config::proxy_policy::PreparedProxyPolicy,
        _coordinator: tokio::sync::OwnedMutexGuard<()>,
        slot: Arc<Semaphore>,
        permits_during_drop: Arc<AtomicUsize>,
    }

    impl Drop for CapturedPublication {
        fn drop(&mut self) {
            assert_eq!(self.server.name, "candidate-drop-test");
            assert!(self.proxy.shared_secret().unwrap().is_some());
            let available = std::thread::scope(|threads| {
                threads
                    .spawn(|| self.slot.available_permits())
                    .join()
                    .unwrap()
            });
            self.permits_during_drop.store(available, Ordering::SeqCst);
        }
    }

    pub(crate) async fn publication_candidate<
        Connector: tacacsrs_networking::routed::EndpointConnector,
    >() -> (
        PublicationCandidate<
            impl FnOnce() -> Option<crate::runtime::MaterializationCommit> + Send,
            Connector,
        >,
        DisposalObservation,
    ) {
        let slot = Arc::new(Semaphore::new(1));
        let mut preparation = CandidateAdmission::new(RuntimeCandidateLimits::default())
            .unwrap()
            .acquire(&slot)
            .await
            .unwrap();
        let server = Arc::new(
            tacacsrs_config::TacacsPlusServerBuilder::new(
                "candidate-drop-test",
                tacacsrs_config::TacacsPlusServerType::all(),
                "127.0.0.1",
                49,
            )
            .with_shared_secret("dummy-candidate-secret")
            .build(),
        );
        let proxy = tacacsrs_config::proxy_policy::prepare_proxy_policy(
            &tacacsrs_config::tacacsrs::LocalServices {
                tacacs_proxy_enabled: true,
                proxy_credential_source: tacacsrs_config::tacacsrs::ProxyCredentialSource::Inline,
                proxy_shared_secret: Some(tacacsrs_secrets::SecretString::new(
                    "dummy-proxy-secret".to_owned(),
                )),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let observation = DisposalObservation {
            slot: slot.clone(),
            server: Arc::downgrade(&server),
            live_at_release: Arc::new(AtomicUsize::new(usize::MAX)),
            available_at_release: Arc::new(AtomicUsize::new(usize::MAX)),
            permits_during_drop: Arc::new(AtomicUsize::new(usize::MAX)),
            coordinator: Arc::new(tokio::sync::Mutex::new(())),
        };
        Arc::get_mut(&mut preparation).unwrap().release_probe = Some(ReleaseProbe {
            server: observation.server.clone(),
            slot: slot.clone(),
            live_at_release: observation.live_at_release.clone(),
            available_at_release: observation.available_at_release.clone(),
        });
        let captured = CapturedPublication {
            server: server.clone(),
            proxy: proxy.clone(),
            _coordinator: observation.coordinator.clone().lock_owned().await,
            slot,
            permits_during_drop: observation.permits_during_drop.clone(),
        };
        (
            PublicationCandidate::new(vec![server], proxy, None, Some(preparation), move || {
                drop(captured);
                None
            }),
            observation,
        )
    }

    #[derive(Clone, Copy)]
    pub(crate) enum CancellationBoundary {
        Unpolled,
        Waiting,
        AdmissionTimeout,
        OuterTimeout,
    }

    impl CancellationBoundary {
        pub(crate) const ALL: [Self; 4] = [
            Self::Unpolled,
            Self::Waiting,
            Self::AdmissionTimeout,
            Self::OuterTimeout,
        ];
    }

    pub(crate) async fn cancel_publication(
        future: impl Future<Output = anyhow::Result<()>>,
        boundary: CancellationBoundary,
    ) {
        let mut pending = Box::pin(future);
        if !matches!(boundary, CancellationBoundary::Unpolled) {
            assert!(futures_util::poll!(&mut pending).is_pending());
        }
        match boundary {
            CancellationBoundary::Unpolled | CancellationBoundary::Waiting => drop(pending),
            CancellationBoundary::AdmissionTimeout => {
                tokio::time::advance(std::time::Duration::from_secs(30)).await;
                assert!(pending.await.is_err());
            }
            CancellationBoundary::OuterTimeout => {
                assert!(tokio::time::timeout(std::time::Duration::from_secs(1), pending)
                    .await
                    .is_err())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use super::*;

    #[test]
    fn candidate_deadline_rejects_unrepresentable_clock_range() {
        let mut limits = RuntimeCandidateLimits {
            timeout: Duration::MAX,
            ..RuntimeCandidateLimits::default()
        };
        assert!(CandidateAdmission::new(limits).is_err());
        limits.timeout = Duration::from_secs(u64::from(u32::MAX));
        assert!(CandidateAdmission::new(limits).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn candidate_deadline_uses_original_admission_and_tighter_policy() {
        let admission = CandidateAdmission::new(RuntimeCandidateLimits::default()).unwrap();
        let preparation = admission
            .acquire(&Arc::new(Semaphore::new(1)))
            .await
            .unwrap();
        tokio::time::advance(Duration::from_secs(25)).await;
        let mut policy = admission.limits;
        policy.timeout = Duration::from_secs(100);
        assert!(preparation.final_check(policy).is_ok());
        policy.timeout = Duration::from_secs(20);
        assert!(preparation.final_check(policy).is_err());
        tokio::time::advance(Duration::from_secs(5)).await;
        policy.timeout = Duration::from_secs(100);
        assert!(preparation.final_check(policy).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_registered_work_keeps_capacity_until_last_result_drop() {
        let slot = Arc::new(Semaphore::new(1));
        let admission = CandidateAdmission::new(RuntimeCandidateLimits::default()).unwrap();
        let preparation = admission.acquire(&slot).await.unwrap();
        let worker = preparation.scope.register().unwrap();
        drop(preparation);
        assert_eq!(slot.available_permits(), 0);
        let waiting = CandidateAdmission::new(RuntimeCandidateLimits::default())
            .unwrap()
            .acquire(&slot)
            .await;
        assert!(waiting.is_err());
        assert_eq!(slot.available_permits(), 0);
        drop(worker);
        assert_eq!(slot.available_permits(), 1);
        assert!(CandidateAdmission::new(RuntimeCandidateLimits::default())
            .unwrap()
            .acquire(&slot)
            .await
            .is_ok());
    }
}
