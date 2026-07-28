//! Daemon-owned host process-manager integration.

use std::process::Command;
use std::sync::Arc;

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
            .map_err(|_| anyhow::anyhow!("systemd-notify could not be executed"))?;
        if !status.success() {
            anyhow::bail!("systemd-notify returned an unsuccessful status");
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
                integration.publish(&health.borrow().clone())?;
                loop {
                    tokio::select! {
                        biased;
                        result = health.changed() => {
                            if result.is_err() {
                                return Ok(());
                            }
                            integration.publish(&health.borrow().clone())?;
                        }
                        () = cancellation.cancelled() => return Ok(()),
                    }
                }
            }
        }
    }
}

pub(crate) struct SystemdIntegration {
    command: Arc<dyn SystemdCommand>,
    strict: bool,
    ready_sent: bool,
    stopping_sent: bool,
}

impl SystemdIntegration {
    fn publish(&mut self, snapshot: &RuntimeHealthSnapshot) -> anyhow::Result<()> {
        let mut arguments = vec!["--pid=parent".to_owned()];
        arguments.push(format!("--status={}", status_text(snapshot)));

        if snapshot.is_readiness_serving() && !self.ready_sent {
            arguments.push("--ready".to_owned());
            self.ready_sent = true;
        }
        if snapshot.lifecycle() == RuntimeLifecycle::Draining && !self.stopping_sent {
            arguments.push("--stopping".to_owned());
            self.stopping_sent = true;
        }

        if let Err(error) = self.command.execute(&arguments) {
            if self.strict {
                return Err(error);
            }
            log::warn!("Failed to publish automatic systemd notification");
        }
        Ok(())
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
}
