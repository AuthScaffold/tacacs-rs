//! Publishes agent health to the systemd service manager.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use dill::component;
use tokio::process::Command;
use tokio::sync::watch;

use crate::{DegradationReason, RuntimeHealth, RuntimeHealthSnapshot, RuntimeLifecycle};
use tacacsrs_composition::{Component, Composition, Named};
use tacacsrs_lifecycle::{HostedService, ShutdownSignal};

/// Selects how strictly the agent requires systemd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdMode {
    /// Notifies systemd only when `NOTIFY_SOCKET` is set. Failed
    /// notifications cause warnings.
    Auto,
    /// Requires `NOTIFY_SOCKET` and the `systemd-notify` helper. A failed
    /// notification stops the agent.
    Required,
}

/// Sends readiness, status, and stopping notifications to systemd.
///
/// The component reads the process environment in `prepare`. In
/// [`SystemdMode::Auto`] without `NOTIFY_SOCKET`, it registers nothing.
pub struct SystemdComponent {
    mode: SystemdMode,
    selected: Option<SystemdIntegration>,
}

impl SystemdComponent {
    /// Creates the component with the given mode.
    #[must_use]
    pub const fn new(mode: SystemdMode) -> Self {
        Self {
            mode,
            selected: None,
        }
    }
}

#[async_trait::async_trait]
impl Component for SystemdComponent {
    fn name(&self) -> &'static str {
        SystemdService::NAME
    }

    async fn prepare(&mut self) -> anyhow::Result<()> {
        self.selected = SystemdIntegration::from_environment(self.mode)?;
        Ok(())
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let Some(integration) = self.selected else {
            return Ok(());
        };
        composition.hosted_service(SystemdService::builder(integration))
    }
}

/// Publishes agent health to systemd until shutdown.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct SystemdService {
    #[component(explicit)]
    integration: SystemdIntegration,
    health: Arc<RuntimeHealth>,
}

impl Named for SystemdService {
    const NAME: &'static str = "Host integration";
}

#[async_trait::async_trait]
impl HostedService for SystemdService {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn run(self: Arc<Self>, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        self.integration
            .clone()
            .run(self.health.subscribe(), shutdown)
            .await
    }
}

#[async_trait::async_trait]
trait SystemdCommand: Send + Sync {
    fn is_available(&self) -> bool;
    async fn execute(&self, arguments: &[String]) -> anyhow::Result<()>;
}

#[derive(Debug)]
struct ProcessSystemdCommand;

#[async_trait::async_trait]
impl SystemdCommand for ProcessSystemdCommand {
    fn is_available(&self) -> bool {
        std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|directory| {
                std::fs::metadata(directory.join("systemd-notify")).is_ok_and(|metadata| {
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
            })
        })
    }

    async fn execute(&self, arguments: &[String]) -> anyhow::Result<()> {
        let status = Command::new("systemd-notify")
            .kill_on_drop(true)
            .args(arguments)
            .status()
            .await
            .map_err(|error| anyhow::anyhow!("Failed to run systemd-notify: {error}"))?;
        if !status.success() {
            anyhow::bail!("systemd-notify exited with an unsuccessful status: {status}");
        }
        Ok(())
    }
}

/// Backoff between retries of a systemd one-shot notification (`--ready` /
/// `--stopping`) that failed transiently in auto mode. Each wait is bounded.
/// The retry loop stays aware of cancellation. It resends a missed notification
/// without an unrelated health change. Cancellation never waits for a full retry period.
const SYSTEMD_RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Systemd notification state. Each run starts from a clone of the selected state.
#[derive(Clone)]
pub(crate) struct SystemdIntegration {
    command: Arc<dyn SystemdCommand>,
    strict: bool,
    ready_sent: bool,
    stopping_sent: bool,
    retry_backoff: Duration,
}

impl SystemdIntegration {
    /// Selects systemd integration from the mode and the process environment.
    ///
    /// Returns `None` for auto mode without a notification socket. Auto mode
    /// keeps the warn-and-continue helper behavior after it selects systemd.
    ///
    /// # Errors
    ///
    /// When `NOTIFY_SOCKET` or the helper is unavailable, required mode fails.
    fn from_environment(mode: SystemdMode) -> anyhow::Result<Option<Self>> {
        Self::select(
            mode,
            std::env::var_os("NOTIFY_SOCKET").is_some(),
            Arc::new(ProcessSystemdCommand),
        )
    }

    fn select(
        mode: SystemdMode,
        notify_socket_present: bool,
        command: Arc<dyn SystemdCommand>,
    ) -> anyhow::Result<Option<Self>> {
        match mode {
            SystemdMode::Auto if !notify_socket_present => Ok(None),
            SystemdMode::Auto => Ok(Some(Self {
                command,
                strict: false,
                ready_sent: false,
                stopping_sent: false,
                retry_backoff: SYSTEMD_RETRY_BACKOFF,
            })),
            SystemdMode::Required => {
                if !notify_socket_present {
                    anyhow::bail!(
                        "Required systemd integration needs the NOTIFY_SOCKET environment variable"
                    );
                }
                if !command.is_available() {
                    anyhow::bail!(
                        "Required systemd integration needs an executable systemd-notify helper"
                    );
                }
                Ok(Some(Self {
                    command,
                    strict: true,
                    ready_sent: false,
                    stopping_sent: false,
                    retry_backoff: SYSTEMD_RETRY_BACKOFF,
                }))
            }
        }
    }

    /// Consumes snapshots until daemon cancellation or a strict notification failure.
    pub(crate) async fn run(
        mut self,
        mut health: watch::Receiver<RuntimeHealthSnapshot>,
        shutdown: ShutdownSignal,
    ) -> anyhow::Result<()> {
        let snapshot = health.borrow().clone();
        let mut retry_pending = self.publish(&snapshot).await?;
        loop {
            let backoff = self.retry_backoff;
            // When a one-shot notification failed transiently, retry after a
            // bounded backoff even if health never changes again.
            let retry = async move {
                if retry_pending {
                    tokio::time::sleep(backoff).await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            tokio::pin!(retry);

            tokio::select! {
                biased;
                () = shutdown.requested() => {
                    let snapshot = health.borrow().clone();
                    self.publish(&snapshot).await?;
                    return Ok(());
                }
                () = &mut retry => {
                    let snapshot = health.borrow().clone();
                    retry_pending = self.publish(&snapshot).await?;
                }
                result = health.changed() => {
                    if result.is_err() {
                        return Ok(());
                    }
                    let snapshot = health.borrow().clone();
                    retry_pending = self.publish(&snapshot).await?;
                }
            }
        }
    }
}

impl SystemdIntegration {
    /// Publishes one systemd notification for `snapshot`.
    ///
    /// This method marks the one-shot `--ready` / `--stopping` flags as delivered
    /// only after the command succeeds. When a one-shot notification is still
    /// owed after a transient auto-mode failure, this method returns `true`.
    /// The caller must retry the notification.
    async fn publish(&mut self, snapshot: &RuntimeHealthSnapshot) -> anyhow::Result<bool> {
        let mut arguments = vec!["--pid=parent".to_owned()];
        arguments.push(format!("--status={}", status_text(snapshot)));

        // READY=1 reports that the process started and the listeners are bound.
        // Configuration and upstream health can arrive later. STATUS and the
        // health service report them, so a start timeout cannot stop the daemon
        // while its source is unavailable.
        let want_ready = snapshot.is_listening() && !self.ready_sent;
        let want_stopping =
            matches!(snapshot.lifecycle(), RuntimeLifecycle::Draining | RuntimeLifecycle::Stopped)
                && !self.stopping_sent;
        if want_ready {
            arguments.push("--ready".to_owned());
        }
        if want_stopping {
            arguments.push("--stopping".to_owned());
        }

        match self.command.execute(&arguments).await {
            Ok(()) => {
                if want_ready {
                    self.ready_sent = true;
                }
                if want_stopping {
                    self.stopping_sent = true;
                }
                Ok(false)
            }
            Err(error) => {
                if self.strict {
                    return Err(error);
                }
                log::warn!("Failed to publish automatic systemd notification");
                Ok(want_ready || want_stopping)
            }
        }
    }
}

fn status_text(snapshot: &RuntimeHealthSnapshot) -> &'static str {
    match snapshot.lifecycle() {
        RuntimeLifecycle::Draining => "Stopping local TACACS+ services",
        RuntimeLifecycle::Stopped => "Stopped",
        RuntimeLifecycle::Failed => "Fatal runtime failure",
        RuntimeLifecycle::Starting | RuntimeLifecycle::Serving
            if snapshot
                .degradation_reasons()
                .contains(&DegradationReason::SourceConfigurationInvalid) =>
        {
            "Stopping because the static configuration is invalid"
        }
        RuntimeLifecycle::Starting if !snapshot.has_applied_configuration() => {
            "Waiting for initial validated configuration"
        }
        RuntimeLifecycle::Starting => "Waiting for enabled listeners",
        RuntimeLifecycle::Serving
            if snapshot
                .degradation_reasons()
                .contains(&DegradationReason::UpstreamWatchdogFailed) =>
        {
            "Not ready because the upstream watchdog probe failed"
        }
        RuntimeLifecycle::Serving
            if snapshot.has_applied_configuration()
                && snapshot
                    .degradation_reasons()
                    .contains(&DegradationReason::UpstreamWatchdogPending) =>
        {
            "Waiting for the first upstream watchdog probe"
        }
        RuntimeLifecycle::Serving if !snapshot.degradation_reasons().is_empty() => {
            "Serving in degraded state"
        }
        RuntimeLifecycle::Serving if !snapshot.is_readiness_serving() => {
            "Serving local endpoints without an eligible upstream server"
        }
        RuntimeLifecycle::Serving => "Ready to serve local TACACS+ requests",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio_util::sync::CancellationToken;

    use crate::{
        DegradationReason, EnabledServices, ListenerState, RuntimeHealthPublisher, RuntimeService,
    };

    use super::*;

    #[derive(Default)]
    struct CapturingCommand {
        available: bool,
        fail: bool,
        fail_first: Mutex<usize>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl SystemdCommand for CapturingCommand {
        fn is_available(&self) -> bool {
            self.available
        }

        async fn execute(&self, arguments: &[String]) -> anyhow::Result<()> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(arguments.to_vec());
            let mut remaining = self.fail_first.lock().expect("fail_first lock");
            if *remaining > 0 {
                *remaining -= 1;
                anyhow::bail!("injected transient notification failure");
            }
            if self.fail {
                anyhow::bail!("injected notification failure");
            }
            Ok(())
        }
    }

    fn ready_publisher() -> RuntimeHealthPublisher {
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        health.set_applied_configuration(true);
        health.set_eligible_server_count(1);
        assert!(health.set_listener(RuntimeService::ClientApi, ListenerState::Bound));
        health
    }

    #[test]
    fn auto_without_socket_selects_no_integration() {
        assert!(SystemdIntegration::select(
            SystemdMode::Auto,
            false,
            Arc::new(CapturingCommand::default()),
        )
        .expect("auto selection")
        .is_none());
    }

    #[test]
    fn strict_systemd_requires_socket_and_helper() {
        let no_socket = SystemdIntegration::select(
            SystemdMode::Required,
            false,
            Arc::new(CapturingCommand {
                available: true,
                ..Default::default()
            }),
        );
        assert!(no_socket.is_err());

        let no_helper = SystemdIntegration::select(
            SystemdMode::Required,
            true,
            Arc::new(CapturingCommand::default()),
        );
        assert!(no_helper.is_err());
    }

    #[tokio::test]
    async fn systemd_publishes_ready_once_degraded_status_and_stopping() {
        let command = Arc::new(CapturingCommand {
            available: true,
            ..Default::default()
        });
        let health = ready_publisher();
        let integration = SystemdIntegration::select(
            SystemdMode::Required,
            true,
            Arc::clone(&command) as Arc<dyn SystemdCommand>,
        )
        .expect("systemd selection")
        .expect("systemd must be selected");
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task = tokio::spawn(integration.run(health.subscribe(), ShutdownSignal::from(&child)));
        tokio::task::yield_now().await;

        health.set_degraded(DegradationReason::UpstreamsUnavailable, true);
        tokio::task::yield_now().await;
        health.set_lifecycle(RuntimeLifecycle::Draining);
        tokio::task::yield_now().await;
        cancellation.cancel();
        task.await
            .expect("task must join")
            .expect("notifications must succeed");

        let calls = command.calls.lock().expect("calls lock");
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains(&"--ready".to_owned()))
                .count(),
            1,
        );
        assert!(calls.iter().any(|call| call
            .iter()
            .any(|arg| arg == "--status=Serving in degraded state")));
        assert!(calls
            .iter()
            .any(|call| call.contains(&"--stopping".to_owned())));
        let command_text = format!("{calls:?}");
        for forbidden in [
            "redis://",
            "unix://",
            "192.0.2.10",
            "credential-reference",
            "test-secret",
        ] {
            assert!(!command_text.contains(forbidden), "systemd arguments exposed {forbidden}");
        }
    }

    #[tokio::test]
    async fn systemd_sends_ready_when_listeners_bind_before_configuration() {
        let command = Arc::new(CapturingCommand {
            available: true,
            ..Default::default()
        });
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        assert!(health.set_listener(RuntimeService::ClientApi, ListenerState::Bound));
        assert!(!health.snapshot().is_readiness_serving());
        let integration = SystemdIntegration::select(
            SystemdMode::Required,
            true,
            Arc::clone(&command) as Arc<dyn SystemdCommand>,
        )
        .expect("systemd selection")
        .expect("systemd must be selected");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        integration
            .run(health.subscribe(), ShutdownSignal::from(&cancellation))
            .await
            .expect("notifications must succeed");

        let calls = command.calls.lock().expect("calls lock");
        assert!(calls
            .iter()
            .any(|call| call.contains(&"--ready".to_owned())));
        assert!(calls.iter().any(|call| call
            .iter()
            .any(|arg| arg == "--status=Waiting for initial validated configuration")));
    }

    #[tokio::test]
    async fn auto_ignores_notification_failure_but_strict_returns_it() {
        let health = ready_publisher();
        let auto = SystemdIntegration::select(
            SystemdMode::Auto,
            true,
            Arc::new(CapturingCommand {
                fail: true,
                ..Default::default()
            }),
        )
        .expect("auto systemd selection")
        .expect("systemd must be selected");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        auto.run(health.subscribe(), ShutdownSignal::from(&cancellation))
            .await
            .expect("auto mode must tolerate the failure");

        let strict = SystemdIntegration::select(
            SystemdMode::Required,
            true,
            Arc::new(CapturingCommand {
                available: true,
                fail: true,
                ..Default::default()
            }),
        )
        .expect("strict selection")
        .expect("systemd must be selected");
        assert!(strict
            .run(health.subscribe(), ShutdownSignal::from(&CancellationToken::new()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn publish_marks_ready_sent_only_after_the_command_succeeds() {
        let command = Arc::new(CapturingCommand {
            available: true,
            fail_first: Mutex::new(1),
            ..Default::default()
        });
        let mut integration = SystemdIntegration {
            command: Arc::clone(&command) as Arc<dyn SystemdCommand>,
            strict: false,
            ready_sent: false,
            stopping_sent: false,
            retry_backoff: Duration::from_millis(1),
        };
        let snapshot = ready_publisher().snapshot();

        let retry_pending = integration
            .publish(&snapshot)
            .await
            .expect("auto tolerates failure");
        assert!(retry_pending, "a failed one-shot must request a retry");
        assert!(!integration.ready_sent);

        let retry_pending = integration.publish(&snapshot).await.expect("auto succeeds");
        assert!(!retry_pending);
        assert!(integration.ready_sent);

        let retry_pending = integration.publish(&snapshot).await.expect("auto succeeds");
        assert!(!retry_pending, "a delivered one-shot must not request another retry");

        let ready_calls = command
            .calls
            .lock()
            .expect("calls lock")
            .iter()
            .filter(|call| call.contains(&"--ready".to_owned()))
            .count();
        assert_eq!(
            ready_calls, 2,
            "ready is attempted on the failure and the retry, then never again"
        );
    }

    #[tokio::test]
    async fn publish_marks_stopping_sent_only_after_the_command_succeeds() {
        let command = Arc::new(CapturingCommand {
            available: true,
            fail_first: Mutex::new(1),
            ..Default::default()
        });
        let mut integration = SystemdIntegration {
            command: Arc::clone(&command) as Arc<dyn SystemdCommand>,
            strict: false,
            ready_sent: true,
            stopping_sent: false,
            retry_backoff: Duration::from_millis(1),
        };
        let health = ready_publisher();
        health.set_lifecycle(RuntimeLifecycle::Draining);
        let snapshot = health.snapshot();

        let retry_pending = integration
            .publish(&snapshot)
            .await
            .expect("auto tolerates failure");
        assert!(retry_pending);
        assert!(!integration.stopping_sent);

        let retry_pending = integration.publish(&snapshot).await.expect("auto succeeds");
        assert!(!retry_pending);
        assert!(integration.stopping_sent);

        let stopping_calls = command
            .calls
            .lock()
            .expect("calls lock")
            .iter()
            .filter(|call| call.contains(&"--stopping".to_owned()))
            .count();
        assert_eq!(stopping_calls, 2);
    }

    #[tokio::test]
    async fn publish_retries_stopping_after_lifecycle_advances_to_stopped() {
        let command = Arc::new(CapturingCommand {
            available: true,
            fail_first: Mutex::new(1),
            ..Default::default()
        });
        let mut integration = SystemdIntegration {
            command: Arc::clone(&command) as Arc<dyn SystemdCommand>,
            strict: false,
            ready_sent: true,
            stopping_sent: false,
            retry_backoff: Duration::from_millis(1),
        };
        let health = ready_publisher();
        health.set_lifecycle(RuntimeLifecycle::Draining);

        assert!(integration
            .publish(&health.snapshot())
            .await
            .expect("auto tolerates failure"));
        health.set_lifecycle(RuntimeLifecycle::Stopped);
        assert!(!integration
            .publish(&health.snapshot())
            .await
            .expect("stopping retry succeeds"));
        assert!(integration.stopping_sent);

        let calls = command.calls.lock().expect("calls lock");
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains(&"--stopping".to_owned()))
                .count(),
            2,
        );
    }

    #[tokio::test(start_paused = true)]
    async fn auto_run_retries_a_failed_ready_without_a_health_change() {
        let command = Arc::new(CapturingCommand {
            available: true,
            fail_first: Mutex::new(1),
            ..Default::default()
        });
        let health = ready_publisher();
        let integration = SystemdIntegration {
            command: Arc::clone(&command) as Arc<dyn SystemdCommand>,
            strict: false,
            ready_sent: false,
            stopping_sent: false,
            retry_backoff: Duration::from_secs(1),
        };
        let cancellation = CancellationToken::new();
        let task =
            tokio::spawn(integration.run(health.subscribe(), ShutdownSignal::from(&cancellation)));

        let mut ready_calls = 0;
        for _ in 0..20 {
            tokio::task::yield_now().await;
            ready_calls = command
                .calls
                .lock()
                .expect("calls lock")
                .iter()
                .filter(|call| call.contains(&"--ready".to_owned()))
                .count();
            if ready_calls >= 2 {
                break;
            }
            tokio::time::advance(Duration::from_secs(1)).await;
        }

        cancellation.cancel();
        task.await
            .expect("join")
            .expect("auto tolerates the transient failure");

        assert_eq!(ready_calls, 2, "ready was retried after the backoff without any health change");
    }

    #[tokio::test(start_paused = true)]
    async fn auto_run_cancellation_is_bounded_while_a_retry_is_pending() {
        let command = Arc::new(CapturingCommand {
            available: true,
            fail: true,
            ..Default::default()
        });
        let health = ready_publisher();
        let integration = SystemdIntegration {
            command: Arc::clone(&command) as Arc<dyn SystemdCommand>,
            strict: false,
            ready_sent: false,
            stopping_sent: false,
            retry_backoff: Duration::from_secs(1),
        };
        let cancellation = CancellationToken::new();
        let task =
            tokio::spawn(integration.run(health.subscribe(), ShutdownSignal::from(&cancellation)));

        tokio::task::yield_now().await;
        cancellation.cancel();

        // A perpetually pending retry must still yield promptly to cancellation.
        task.await
            .expect("join")
            .expect("auto tolerates perpetual failure until canceled");
    }

    #[tokio::test(start_paused = true)]
    async fn auto_run_retries_stopping_when_stopped_and_cancelled_arrive_together() {
        let command = Arc::new(CapturingCommand {
            available: true,
            fail_first: Mutex::new(1),
            ..Default::default()
        });
        let health = ready_publisher();
        health.set_lifecycle(RuntimeLifecycle::Draining);
        let integration = SystemdIntegration {
            command: Arc::clone(&command) as Arc<dyn SystemdCommand>,
            strict: false,
            ready_sent: true,
            stopping_sent: false,
            retry_backoff: Duration::from_secs(1),
        };
        let cancellation = CancellationToken::new();
        let task =
            tokio::spawn(integration.run(health.subscribe(), ShutdownSignal::from(&cancellation)));

        tokio::task::yield_now().await;
        health.set_lifecycle(RuntimeLifecycle::Stopped);
        cancellation.cancel();
        task.await
            .expect("join")
            .expect("final stopping retry succeeds");

        let calls = command.calls.lock().expect("calls lock");
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains(&"--stopping".to_owned()))
                .count(),
            2,
        );
    }
}
