//! Canonical policy observation and runtime publication.
//!
//! The host supplies an owned observation and an explicit stop future. Rejected
//! candidates leave the applied policy unchanged. Observation failure returns
//! control to the host instead of silently retaining an unobserved policy.

use std::future::Future;
use std::sync::Arc;

use anyhow::Context;
use tacacsrs_config::source::policy::{PolicyChange, PolicyObservation};

use crate::{PolicyUpdate, TacacsClientService};

/// Applies canonical policy candidates until the host requests shutdown.
pub struct PolicySupervisor<Observation> {
    observation: Observation,
    service: Arc<TacacsClientService>,
}

impl<Observation: PolicyObservation> PolicySupervisor<Observation> {
    /// Takes ownership of an observation, including any unread baseline.
    #[must_use]
    pub fn new(observation: Observation, service: Arc<TacacsClientService>) -> Self {
        Self {
            observation,
            service,
        }
    }

    /// Applies updates until `stop` completes, then drops the observation.
    ///
    /// Cancellation can interrupt observation and publication lock acquisition.
    /// No process signal handlers or background tasks are installed.
    ///
    /// # Errors
    /// Returns an error if observation ends, observation fails, or the runtime closes.
    pub async fn run_until(mut self, stop: impl Future<Output = ()> + Send) -> anyhow::Result<()> {
        tokio::pin!(stop);
        loop {
            let change = tokio::select! {
                biased;
                () = &mut stop => return Ok(()),
                change = self.observation.next() => change?.context("Runtime policy observation ended")?,
            };
            let candidate = match change {
                PolicyChange::Changed(source) => Some(source),
                PolicyChange::CandidateRejected => None,
            };
            let result = tokio::select! {
                biased;
                () = &mut stop => return Ok(()),
                result = self.service.apply_policy_candidate(candidate.as_deref()) => result?,
            };
            match result {
                PolicyUpdate::Applied(_) => log::info!("Applied the updated runtime policy"),
                PolicyUpdate::Rejected(_) => log::warn!(
                    "Rejected the runtime policy update. Keeping the last-known-good policy"
                ),
                PolicyUpdate::Superseded => {
                    log::debug!("Skipped a superseded runtime policy candidate");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::sync::{mpsc, oneshot};
    use tacacsrs_config::TacacsPlus;
    use tacacsrs_networking::RequestDeadline;

    use crate::{
        DegradationReason, EnabledServices, RuntimeHealthPublisher, RuntimePolicy, ServiceConfig,
    };

    use super::*;

    struct Observation {
        events: mpsc::Receiver<PolicyChange>,
        dropped: Arc<AtomicBool>,
        entered: Option<oneshot::Sender<()>>,
    }

    #[async_trait]
    impl PolicyObservation for Observation {
        async fn next(&mut self) -> anyhow::Result<Option<PolicyChange>> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
            }
            Ok(self.events.recv().await)
        }
    }

    impl Drop for Observation {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    fn service(health: RuntimeHealthPublisher) -> Arc<TacacsClientService> {
        Arc::new(
            TacacsClientService::waiting_for_configuration(
                ServiceConfig {
                    local_services: tacacsrs_config::tacacsrs::LocalServices::default(),
                    tacacs_plus: TacacsPlus::empty(),
                    validation_options: tacacsrs_config::ValidationOptions::default(),
                    runtime_policy: RuntimePolicy::default(),
                    disable_certificate_verification: false,
                },
                health,
            )
            .expect("test service"),
        )
    }

    async fn wait_for_rejection(health: &RuntimeHealthPublisher, rejected: bool) {
        let mut changes = health.subscribe();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if changes
                    .borrow_and_update()
                    .degradation_reasons()
                    .contains(&DegradationReason::CandidatePolicyRejected)
                    == rejected
                {
                    return;
                }
                changes.changed().await.unwrap();
            }
        })
        .await
        .expect("policy health transition");
    }

    #[tokio::test]
    async fn delayed_policy_cannot_overwrite_a_newer_rejection() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let service = service(health.clone());
        let held = service.hold_publication().await;
        let (older_events, older_receiver) = mpsc::channel(1);
        older_events
            .send(PolicyChange::Changed(Arc::new(
                tacacsrs_config::tacacsrs::RuntimePolicy::default(),
            )))
            .await
            .unwrap();
        let older = PolicySupervisor::new(
            Observation {
                events: older_receiver,
                dropped: Arc::new(AtomicBool::new(false)),
                entered: None,
            },
            service.clone(),
        )
        .run_until(std::future::pending());
        tokio::pin!(older);
        assert!(futures_util::poll!(&mut older).is_pending());
        let generation = health.snapshot().runtime_generation();
        let (newer_events, newer_receiver) = mpsc::channel(1);
        newer_events
            .send(PolicyChange::CandidateRejected)
            .await
            .unwrap();
        let newer = PolicySupervisor::new(
            Observation {
                events: newer_receiver,
                dropped: Arc::new(AtomicBool::new(false)),
                entered: None,
            },
            service.clone(),
        )
        .run_until(std::future::pending());
        tokio::pin!(newer);
        assert!(futures_util::poll!(&mut newer).is_pending());
        assert!(health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CandidatePolicyRejected));
        drop(held);
        assert!(futures_util::poll!(&mut older).is_pending());
        assert!(
            health
                .snapshot()
                .degradation_reasons()
                .contains(&DegradationReason::CandidatePolicyRejected),
            "a delayed policy must not clear rejection of a newer candidate"
        );
        assert_eq!(health.snapshot().runtime_generation(), generation);
        drop(older_events);
        drop(newer_events);
    }

    #[tokio::test]
    async fn newer_valid_policy_supersedes_prepared_update_waiting_for_publication() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let service = service(health.clone());
        let held = service.hold_publication().await;
        let older = service.reload_runtime_policy(RuntimePolicy::default());
        tokio::pin!(older);
        assert!(futures_util::poll!(&mut older).is_pending());
        let source = tacacsrs_config::policy::parse_runtime_policy(
            br#"{"tacacsrs:runtime-policy":{"accounting":{"max-concurrent-requests":7}}}"#,
        )
        .unwrap();
        let original = source.clone();
        let newer = service.apply_policy_candidate(Some(&source));
        tokio::pin!(newer);
        assert!(futures_util::poll!(&mut newer).is_pending());
        drop(held);
        assert_eq!(older.await.unwrap(), PolicyUpdate::Superseded);
        let PolicyUpdate::Applied(revision) = newer.await.unwrap() else {
            panic!("new policy must apply");
        };
        assert_eq!(revision.value(), 2);
        let applied = health.snapshot();
        assert_eq!(applied.applied_policy_revision(), Some(revision));
        assert_eq!(applied.runtime_generation().unwrap().value(), 1);
        assert!(!applied.has_applied_configuration());
        assert_eq!(source, original);
    }

    #[tokio::test]
    async fn cancelled_policy_wait_keeps_previous_policy_and_rejection_health() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let service = service(health.clone());
        let policy = tacacsrs_config::tacacsrs::RuntimePolicy::default();
        service.apply_policy_candidate(Some(&policy)).await.unwrap();
        assert!(matches!(
            service.apply_policy_candidate(None).await.unwrap(),
            PolicyUpdate::Rejected(_)
        ));
        let previous = health.snapshot();
        let held = service.hold_publication().await;
        {
            let pending = service.apply_policy_candidate(Some(&policy));
            tokio::pin!(pending);
            assert!(futures_util::poll!(&mut pending).is_pending());
        }
        drop(held);
        assert_eq!(health.snapshot(), previous);
        let PolicyUpdate::Applied(revision) =
            service.apply_policy_candidate(Some(&policy)).await.unwrap()
        else {
            panic!("retry must apply");
        };
        assert_eq!(revision.value(), 4);
        assert!(!health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CandidatePolicyRejected));
    }

    #[tokio::test]
    async fn invalid_canonical_policy_preserves_applied_revision_and_generation() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let service = service(health.clone());
        let mut policy = tacacsrs_config::tacacsrs::RuntimePolicy::default();
        service.apply_policy_candidate(Some(&policy)).await.unwrap();
        let before = health.snapshot();
        policy.failover_recovery_interval_seconds = 0;
        assert!(matches!(
            service.apply_policy_candidate(Some(&policy)).await.unwrap(),
            PolicyUpdate::Rejected(_)
        ));
        let after = health.snapshot();
        assert_eq!(after.applied_policy_revision(), before.applied_policy_revision());
        assert_eq!(after.runtime_generation(), before.runtime_generation());
        assert!(after
            .degradation_reasons()
            .contains(&DegradationReason::CandidatePolicyRejected));
        service
            .close_and_join(RequestDeadline::after(Duration::from_secs(1)).unwrap())
            .await
            .unwrap();
        assert!(service.apply_policy_candidate(None).await.is_err());
        assert_eq!(health.snapshot(), after);
    }

    #[tokio::test]
    async fn invalid_update_keeps_policy_and_valid_update_clears_degradation() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let (events, receiver) = mpsc::channel(4);
        let dropped = Arc::new(AtomicBool::new(false));
        let supervisor = PolicySupervisor::new(
            Observation {
                events: receiver,
                dropped: dropped.clone(),
                entered: None,
            },
            service(health.clone()),
        );
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(supervisor.run_until(async {
            stopped.await.unwrap();
        }));
        events.send(PolicyChange::CandidateRejected).await.unwrap();
        wait_for_rejection(&health, true).await;
        let source = Arc::new(
            tacacsrs_config::policy::parse_runtime_policy(br#"{"tacacsrs:runtime-policy":{}}"#)
                .unwrap(),
        );
        events
            .send(PolicyChange::Changed(source.clone()))
            .await
            .unwrap();
        wait_for_rejection(&health, false).await;
        assert!(source.authentication.is_none());
        assert!(source.authorization.is_none());
        assert!(source.accounting.is_none());
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn closed_service_cannot_report_policy_as_applied() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let service = service(health.clone());
        service
            .close_and_join(RequestDeadline::after(Duration::from_secs(1)).unwrap())
            .await
            .unwrap();
        health.set_degraded(DegradationReason::CandidatePolicyRejected, true);
        let (events, receiver) = mpsc::channel(1);
        events
            .send(PolicyChange::Changed(Arc::new(
                tacacsrs_config::tacacsrs::RuntimePolicy::default(),
            )))
            .await
            .unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let supervisor = PolicySupervisor::new(
            Observation {
                events: receiver,
                dropped: dropped.clone(),
                entered: None,
            },
            service,
        );
        let result = supervisor.run_until(std::future::pending()).await;
        assert!(result.unwrap_err().to_string().contains("closed"));
        assert!(health
            .snapshot()
            .degradation_reasons()
            .contains(&DegradationReason::CandidatePolicyRejected));
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn observation_end_is_an_error_and_cancellation_drops_observation() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let (events, receiver) = mpsc::channel(1);
        drop(events);
        let dropped = Arc::new(AtomicBool::new(false));
        let supervisor = PolicySupervisor::new(
            Observation {
                events: receiver,
                dropped: dropped.clone(),
                entered: None,
            },
            service(health.clone()),
        );
        assert!(supervisor.run_until(std::future::pending()).await.is_err());
        assert!(dropped.load(Ordering::Acquire));
        let (_events, receiver) = mpsc::channel(1);
        dropped.store(false, Ordering::Release);
        let (entered, started) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        let supervisor = PolicySupervisor::new(
            Observation {
                events: receiver,
                dropped: dropped.clone(),
                entered: Some(entered),
            },
            service(health),
        );
        let task = tokio::spawn(supervisor.run_until(async {
            stopped.await.unwrap();
        }));
        started.await.unwrap();
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(dropped.load(Ordering::Acquire));
    }
}
