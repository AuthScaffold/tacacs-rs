//! Canonical policy observation and runtime publication.
//!
//! The host supplies an owned observation and an explicit stop future. Rejected
//! candidates leave the applied policy unchanged. Observation failure returns
//! control to the host instead of silently retaining an unobserved policy.

use std::future::Future;
use std::sync::Arc;

use anyhow::Context;
use tacacsrs_config::source::policy::{PolicyChange, PolicyObservation};

use crate::{DegradationReason, RuntimeHealthPublisher, RuntimePolicy, TacacsClientService};

/// Applies canonical policy candidates until the host requests shutdown.
pub struct PolicySupervisor<Observation> {
    observation: Observation,
    service: Arc<TacacsClientService>,
    health: RuntimeHealthPublisher,
}

impl<Observation: PolicyObservation> PolicySupervisor<Observation> {
    /// Takes ownership of an observation, including any unread baseline.
    #[must_use]
    pub fn new(
        observation: Observation,
        service: Arc<TacacsClientService>,
        health: RuntimeHealthPublisher,
    ) -> Self {
        Self {
            observation,
            service,
            health,
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
                PolicyChange::Changed(source) => RuntimePolicy::try_from(source.as_ref()).ok(),
                PolicyChange::CandidateRejected => None,
            };
            if let Some(policy) = candidate {
                tokio::select! {
                    biased;
                    () = &mut stop => return Ok(()),
                    applied = self.service.reload_runtime_policy(policy) => applied?,
                }
                self.health
                    .set_degraded(DegradationReason::CandidatePolicyRejected, false);
                log::info!("Applied the updated runtime policy");
            } else {
                self.health
                    .set_degraded(DegradationReason::CandidatePolicyRejected, true);
                log::warn!(
                    "Rejected the runtime policy update. Keeping the last-known-good policy"
                );
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

    use crate::{EnabledServices, ServiceConfig};

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
            health.clone(),
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
            health.clone(),
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
            health.clone(),
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
            service(health.clone()),
            health,
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
