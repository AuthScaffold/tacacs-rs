//! Shared process shutdown and listener lifecycle coordination.
//!
//! One coordinator waits for operating-system signals. Listener tasks hold
//! cloneable receivers and registration guards.
//!
//! ```text
//! SIGTERM / Ctrl-C
//!        |
//!        v
//! lifecycle=Draining -> broadcast -> stop accepting -> drain -> Stopped
//! ```

use tokio::sync::watch;

use super::{ListenerState, RuntimeHealthPublisher, RuntimeLifecycle, RuntimeService};

/// Broadcasts one ordered shutdown transition to all runtime tasks.
#[derive(Debug, Clone)]
pub(crate) struct ShutdownCoordinator {
    sender: watch::Sender<bool>,
    health: RuntimeHealthPublisher,
}

impl ShutdownCoordinator {
    /// Creates a coordinator for one service runtime.
    #[must_use]
    pub(crate) fn new(health: RuntimeHealthPublisher) -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender, health }
    }

    /// Returns a receiver for one listener or background task.
    #[must_use]
    pub(crate) fn subscribe(&self) -> ShutdownReceiver {
        ShutdownReceiver {
            receiver: self.sender.subscribe(),
        }
    }

    /// Starts the operating-system signal monitor.
    pub(crate) fn spawn_process_signal_monitor(&self) -> tokio::task::JoinHandle<()> {
        let coordinator = self.clone();
        tokio::spawn(async move {
            process_shutdown_signal().await;
            coordinator.initiate_shutdown();
        })
    }

    /// Withdraws health and then broadcasts graceful shutdown.
    pub(crate) fn initiate_shutdown(&self) {
        self.health.set_lifecycle(RuntimeLifecycle::Draining);
        self.sender.send_replace(true);
    }

    /// Publishes a fatal runtime failure and broadcasts cancellation.
    pub(crate) fn fail(&self) {
        self.health.set_lifecycle(RuntimeLifecycle::Failed);
        self.sender.send_replace(true);
    }

    /// Publishes the final stopped state after all listener tasks stop.
    pub(crate) fn mark_stopped(&self) {
        self.health.set_lifecycle(RuntimeLifecycle::Stopped);
    }
}

/// Cloneable shutdown subscription for one runtime task.
#[derive(Debug, Clone)]
pub(crate) struct ShutdownReceiver {
    receiver: watch::Receiver<bool>,
}

impl ShutdownReceiver {
    /// Waits until shutdown is broadcast or the coordinator is dropped.
    pub(crate) async fn wait(mut self) {
        if *self.receiver.borrow() {
            return;
        }

        while self.receiver.changed().await.is_ok() {
            if *self.receiver.borrow() {
                return;
            }
        }
    }
}

/// Publishes listener state and sets `Stopped` on each return path.
#[derive(Debug)]
pub(crate) struct ListenerRegistration {
    health: RuntimeHealthPublisher,
    service: RuntimeService,
}

impl ListenerRegistration {
    /// Registers an enabled listener and publishes `Binding` before bind work.
    #[must_use]
    pub(crate) fn new(health: RuntimeHealthPublisher, service: RuntimeService) -> Self {
        let accepted = health.set_listener(service, ListenerState::Binding);
        debug_assert!(accepted, "cannot register a disabled listener");
        Self { health, service }
    }

    /// Publishes that the IPC endpoint is bound and accepts work.
    pub(crate) fn mark_bound(&self) {
        let accepted = self.health.set_listener(self.service, ListenerState::Bound);
        debug_assert!(accepted, "cannot bind a disabled listener");
    }
}

impl Drop for ListenerRegistration {
    fn drop(&mut self) {
        let accepted = self
            .health
            .set_listener(self.service, ListenerState::Stopped);
        debug_assert!(accepted, "cannot stop a disabled listener");
    }
}

/// Waits for a termination signal that stops the service from accepting clients.
async fn process_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    if let Ok(mut terminate_signal) = signal(SignalKind::terminate()) {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                log::info!("Received Ctrl-C; starting graceful shutdown");
            }
            _ = terminate_signal.recv() => {
                log::info!("Received SIGTERM; starting graceful shutdown");
            }
        }
    } else {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("Received Ctrl-C; starting graceful shutdown");
    }
}

#[cfg(test)]
mod tests {
    use crate::EnabledServices;

    use super::*;

    #[tokio::test]
    async fn shutdown_withdraws_health_before_receiver_completes() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let coordinator = ShutdownCoordinator::new(health.clone());
        let receiver = coordinator.subscribe();

        coordinator.initiate_shutdown();
        receiver.wait().await;

        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Draining);
        assert!(!health.snapshot().is_liveness_serving());
    }

    #[test]
    fn listener_registration_publishes_stopped_on_drop() {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let registration = ListenerRegistration::new(health.clone(), RuntimeService::ClientApi);
        assert_eq!(health.snapshot().listener(RuntimeService::ClientApi), ListenerState::Binding,);

        registration.mark_bound();
        assert_eq!(health.snapshot().listener(RuntimeService::ClientApi), ListenerState::Bound,);

        drop(registration);
        assert_eq!(health.snapshot().listener(RuntimeService::ClientApi), ListenerState::Stopped,);
    }
}
