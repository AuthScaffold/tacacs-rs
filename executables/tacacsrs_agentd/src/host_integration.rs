//! Daemon-owned host process-manager integration.

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tacacsrs_agent::{RuntimeHealthSnapshot, RuntimeLifecycle};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::cli::HostIntegrationMode;

trait SystemdCommand: Send + Sync {
    fn is_available(&self) -> bool;
    fn execute(&self, arguments: &[String]) -> anyhow::Result<()>;
}

#[derive(Debug)]
struct ProcessSystemdCommand;

impl SystemdCommand for ProcessSystemdCommand {
    fn is_available(&self) -> bool {
        Command::new("systemd-notify")
            .arg("--version")
            .status()
            .is_ok_and(|status| status.success())
    }

    fn execute(&self, arguments: &[String]) -> anyhow::Result<()> {
        let status = Command::new("systemd-notify")
            .args(arguments)
            .status()
            .map_err(|error| anyhow::anyhow!("failed to execute systemd-notify: {error}"))?;
        if !status.success() {
            anyhow::bail!("systemd-notify returned unsuccessful status: {status}");
        }
        Ok(())
    }
}

/// Selected host adapter consuming common runtime health snapshots.
pub(crate) enum HostIntegration {
    None,
    Systemd(SystemdIntegration),
}

impl HostIntegration {
    /// Selects an adapter from CLI mode and process environment.
    ///
    /// # Errors
    ///
    /// Explicit systemd mode fails when `NOTIFY_SOCKET` or the helper is
    /// unavailable. Auto mode selects none without a notification socket and
    /// preserves warn-and-continue helper behavior after systemd selection.
    pub(crate) fn from_environment(mode: HostIntegrationMode) -> anyhow::Result<Self> {
        Self::select(
            mode,
            std::env::var_os("NOTIFY_SOCKET").is_some(),
            Arc::new(ProcessSystemdCommand),
        )
    }

    fn select(
        mode: HostIntegrationMode,
        notify_socket_present: bool,
        command: Arc<dyn SystemdCommand>,
    ) -> anyhow::Result<Self> {
        match mode {
            HostIntegrationMode::None => Ok(Self::None),
            HostIntegrationMode::Auto if !notify_socket_present => Ok(Self::None),
            HostIntegrationMode::Auto => Ok(Self::Systemd(SystemdIntegration {
                command,
                strict: false,
                ready_sent: false,
                stopping_sent: false,
                retry_backoff: SYSTEMD_RETRY_BACKOFF,
            })),
            HostIntegrationMode::Systemd => {
                if !notify_socket_present {
                    anyhow::bail!(
                        "--host-integration systemd requires the NOTIFY_SOCKET environment variable"
                    );
                }
                if !command.is_available() {
                    anyhow::bail!(
                        "--host-integration systemd requires an executable systemd-notify helper"
                    );
                }
                Ok(Self::Systemd(SystemdIntegration {
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
        cancellation: CancellationToken,
    ) -> anyhow::Result<()> {
        match &mut self {
            Self::None => {
                cancellation.cancelled().await;
                Ok(())
            }
            Self::Systemd(integration) => {
                let mut retry_pending = integration.publish(&health.borrow().clone())?;
                loop {
                    let backoff = integration.retry_backoff;
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
                        () = cancellation.cancelled() => return Ok(()),
                        () = &mut retry => {
                            retry_pending = integration.publish(&health.borrow().clone())?;
                        }
                        result = health.changed() => {
                            if result.is_err() {
                                return Ok(());
                            }
                            retry_pending = integration.publish(&health.borrow().clone())?;
                        }
                    }
                }
            }
        }
    }
}

/// Backoff between retries of a systemd one-shot notification (`--ready` /
/// `--stopping`) that failed transiently in auto mode. Each wait is bounded and
/// the retry loop stays cancellation-aware, so a missed notification is re-sent
/// without an unrelated health change and cancellation never waits a full period.
const SYSTEMD_RETRY_BACKOFF: Duration = Duration::from_secs(1);

pub(crate) struct SystemdIntegration {
    command: Arc<dyn SystemdCommand>,
    strict: bool,
    ready_sent: bool,
    stopping_sent: bool,
    retry_backoff: Duration,
}

impl SystemdIntegration {
    /// Publishes one systemd notification for `snapshot`.
    ///
    /// The one-shot `--ready` / `--stopping` flags are marked delivered only
    /// after the command succeeds. Returns `true` when a one-shot notification
    /// is still owed after a transient auto-mode failure and must be retried.
    fn publish(&mut self, snapshot: &RuntimeHealthSnapshot) -> anyhow::Result<bool> {
        let mut arguments = vec!["--pid=parent".to_owned()];
        arguments.push(format!("--status={}", status_text(snapshot)));

        let want_ready = snapshot.is_readiness_serving() && !self.ready_sent;
        let want_stopping =
            snapshot.lifecycle() == RuntimeLifecycle::Draining && !self.stopping_sent;
        if want_ready {
            arguments.push("--ready".to_owned());
        }
        if want_stopping {
            arguments.push("--stopping".to_owned());
        }

        match self.command.execute(&arguments) {
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
        RuntimeLifecycle::Starting if !snapshot.has_applied_configuration() => {
            "Waiting for initial validated configuration"
        }
        RuntimeLifecycle::Starting => "Waiting for enabled listeners",
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

    use tacacsrs_agent::{
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

    impl SystemdCommand for CapturingCommand {
        fn is_available(&self) -> bool {
            self.available
        }

        fn execute(&self, arguments: &[String]) -> anyhow::Result<()> {
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
    fn auto_without_socket_and_none_with_socket_select_no_integration() {
        assert!(matches!(
            HostIntegration::select(
                HostIntegrationMode::Auto,
                false,
                Arc::new(CapturingCommand::default()),
            )
            .expect("auto selection"),
            HostIntegration::None,
        ));
        assert!(matches!(
            HostIntegration::select(
                HostIntegrationMode::None,
                true,
                Arc::new(CapturingCommand::default()),
            )
            .expect("none selection"),
            HostIntegration::None,
        ));
    }

    #[test]
    fn strict_systemd_requires_socket_and_helper() {
        let no_socket = HostIntegration::select(
            HostIntegrationMode::Systemd,
            false,
            Arc::new(CapturingCommand {
                available: true,
                ..Default::default()
            }),
        );
        assert!(no_socket.is_err());

        let no_helper = HostIntegration::select(
            HostIntegrationMode::Systemd,
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
        let integration = HostIntegration::select(
            HostIntegrationMode::Systemd,
            true,
            Arc::clone(&command) as Arc<dyn SystemdCommand>,
        )
        .expect("systemd selection");
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task = tokio::spawn(integration.run(health.subscribe(), child));
        tokio::task::yield_now().await;

        health.set_degraded(DegradationReason::UpstreamsUnavailable, true);
        tokio::task::yield_now().await;
        health.set_lifecycle(RuntimeLifecycle::Draining);
        tokio::task::yield_now().await;
        cancellation.cancel();
        task.await
            .expect("task should join")
            .expect("notifications should succeed");

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
    async fn auto_ignores_notification_failure_but_strict_returns_it() {
        let health = ready_publisher();
        let auto = HostIntegration::select(
            HostIntegrationMode::Auto,
            true,
            Arc::new(CapturingCommand {
                fail: true,
                ..Default::default()
            }),
        )
        .expect("auto systemd selection");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        auto.run(health.subscribe(), cancellation)
            .await
            .expect("auto should tolerate failure");

        let strict = HostIntegration::select(
            HostIntegrationMode::Systemd,
            true,
            Arc::new(CapturingCommand {
                available: true,
                fail: true,
                ..Default::default()
            }),
        )
        .expect("strict selection");
        assert!(strict
            .run(health.subscribe(), CancellationToken::new())
            .await
            .is_err());
    }

    #[test]
    fn publish_marks_ready_sent_only_after_the_command_succeeds() {
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

        let retry_pending = integration.publish(&snapshot).expect("auto tolerates failure");
        assert!(retry_pending, "a failed one-shot must request a retry");
        assert!(!integration.ready_sent);

        let retry_pending = integration.publish(&snapshot).expect("auto succeeds");
        assert!(!retry_pending);
        assert!(integration.ready_sent);

        let retry_pending = integration.publish(&snapshot).expect("auto succeeds");
        assert!(!retry_pending, "a delivered one-shot must not request another retry");

        let ready_calls = command
            .calls
            .lock()
            .expect("calls lock")
            .iter()
            .filter(|call| call.contains(&"--ready".to_owned()))
            .count();
        assert_eq!(ready_calls, 2, "ready is attempted on the failure and the retry, then never again");
    }

    #[test]
    fn publish_marks_stopping_sent_only_after_the_command_succeeds() {
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

        let retry_pending = integration.publish(&snapshot).expect("auto tolerates failure");
        assert!(retry_pending);
        assert!(!integration.stopping_sent);

        let retry_pending = integration.publish(&snapshot).expect("auto succeeds");
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

    #[tokio::test(start_paused = true)]
    async fn auto_run_retries_a_failed_ready_without_a_health_change() {
        let command = Arc::new(CapturingCommand {
            available: true,
            fail_first: Mutex::new(1),
            ..Default::default()
        });
        let health = ready_publisher();
        let integration = HostIntegration::Systemd(SystemdIntegration {
            command: Arc::clone(&command) as Arc<dyn SystemdCommand>,
            strict: false,
            ready_sent: false,
            stopping_sent: false,
            retry_backoff: Duration::from_secs(1),
        });
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(integration.run(health.subscribe(), cancellation.clone()));

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
        task.await.expect("join").expect("auto tolerates the transient failure");

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
        let integration = HostIntegration::Systemd(SystemdIntegration {
            command: Arc::clone(&command) as Arc<dyn SystemdCommand>,
            strict: false,
            ready_sent: false,
            stopping_sent: false,
            retry_backoff: Duration::from_secs(1),
        });
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(integration.run(health.subscribe(), cancellation.clone()));

        tokio::task::yield_now().await;
        cancellation.cancel();

        // A perpetually pending retry must still yield promptly to cancellation.
        task.await.expect("join").expect("auto tolerates perpetual failure until cancelled");
    }
}
