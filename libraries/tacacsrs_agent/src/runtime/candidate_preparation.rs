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
            ledger: Mutex::new(ConfigurationMaterialBudget::new(
                self.limits.material_bytes,
                self.limits.requests,
            )),
            scope,
            control,
        }))
    }
}

#[derive(Debug)]
pub(crate) struct Preparation {
    pub(crate) admission: CandidateAdmission,
    pub(crate) ledger: Mutex<ConfigurationMaterialBudget>,
    pub(crate) scope: WorkScope,
    control: WorkScopeControl,
}

impl Preparation {
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

impl Drop for Preparation {
    fn drop(&mut self) {
        self.control.seal();
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
