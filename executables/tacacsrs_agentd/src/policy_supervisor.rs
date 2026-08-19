//! Live runtime-policy file supervision.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tacacsrs_agent::{DegradationReason, RuntimeHealthPublisher, TacacsClientService};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::policy_file::PolicyFile;

const POLICY_RELOAD_DEBOUNCE: Duration = Duration::from_millis(100);

/// Applies valid policy-file updates to a running service.
pub(crate) struct PolicySupervisor {
    source: PolicyFile,
    service: Arc<TacacsClientService>,
    health: RuntimeHealthPublisher,
}

impl PolicySupervisor {
    /// Creates a live policy supervisor.
    #[must_use]
    pub(crate) fn new(
        source: PolicyFile,
        service: Arc<TacacsClientService>,
        health: RuntimeHealthPublisher,
    ) -> Self {
        Self {
            source,
            service,
            health,
        }
    }

    /// Watches and applies policy updates until shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the file watcher cannot start or stops unexpectedly.
    pub(crate) async fn run(self, cancellation: &CancellationToken) -> anyhow::Result<()> {
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut watcher = RecommendedWatcher::new(
            move |event| {
                if event_tx.blocking_send(event).is_err() {
                    log::debug!("Runtime policy watcher receiver dropped");
                }
            },
            Config::default(),
        )
        .context("create runtime policy watcher")?;
        let watch_directory = self
            .source
            .path()
            .parent()
            .unwrap_or_else(|| Path::new("."));
        watcher
            .watch(watch_directory, RecursiveMode::NonRecursive)
            .with_context(|| {
                format!("watch runtime policy directory {}", watch_directory.display())
            })?;

        loop {
            let event = tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                event = event_rx.recv() => event.context("runtime policy watcher stopped")?,
            };
            match event {
                Ok(event) if event_touches_path(&event, self.source.path()) => {
                    tokio::time::sleep(POLICY_RELOAD_DEBOUNCE).await;
                    while let Ok(Ok(_)) = event_rx.try_recv() {}
                    self.apply_candidate().await;
                }
                Ok(_) => {}
                Err(error) => {
                    log::warn!("Runtime policy watch event failed: {error:#}");
                }
            }
        }
    }

    async fn apply_candidate(&self) {
        match self.source.load().await {
            Ok(policy) => {
                self.service.reload_runtime_policy(policy).await;
                self.health
                    .set_degraded(DegradationReason::CandidatePolicyRejected, false);
                log::info!("Applied the updated runtime policy");
            }
            Err(error) => {
                self.health
                    .set_degraded(DegradationReason::CandidatePolicyRejected, true);
                log::warn!(
                    "Rejected the runtime policy update; keeping the last-known-good policy: {error:#}"
                );
            }
        }
    }
}

fn event_touches_path(event: &Event, watched_path: &Path) -> bool {
    event
        .paths
        .iter()
        .any(|event_path| paths_match(event_path, watched_path))
}

fn paths_match(event_path: &Path, watched_path: &Path) -> bool {
    if event_path == watched_path {
        return true;
    }
    event_path.file_name() == watched_path.file_name()
        && event_path.parent() == watched_path.parent()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tacacsrs_agent::{EnabledServices, ProxyDownstreamObfuscation, RuntimePolicy, ServiceConfig};
    use tacacsrs_agent_client::IpcEndpoint;
    use tacacsrs_config::TacacsPlus;

    use super::*;

    fn temp_policy(contents: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("tacacs-policy-{unique}.json"));
        fs::write(&path, contents).expect("write initial policy");
        path
    }

    fn service(health: RuntimeHealthPublisher) -> Arc<TacacsClientService> {
        Arc::new(
            TacacsClientService::waiting_for_configuration(
                ServiceConfig {
                    enabled_services: EnabledServices::CLIENT_API,
                    endpoint: IpcEndpoint::default_local(),
                    proxy_endpoint: None,
                    proxy_downstream_obfuscation: ProxyDownstreamObfuscation::default(),
                    tacacs_plus: TacacsPlus::empty(),
                    runtime_policy: RuntimePolicy::default(),
                    socket_mode: 0o660,
                    disable_certificate_verification: false,
                },
                health,
            )
            .expect("test service"),
        )
    }

    async fn wait_for_rejection(health: &RuntimeHealthPublisher, rejected: bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let active = health
                    .snapshot()
                    .degradation_reasons()
                    .contains(&DegradationReason::CandidatePolicyRejected);
                if active == rejected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("policy health transition");
    }

    #[tokio::test]
    async fn invalid_update_keeps_policy_and_valid_update_clears_degradation() {
        let path = temp_policy("{}");
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let cancellation = CancellationToken::new();
        let supervisor = PolicySupervisor::new(
            PolicyFile::new(path.clone()),
            service(health.clone()),
            health.clone(),
        );
        let task = {
            let cancellation = cancellation.clone();
            tokio::spawn(async move { supervisor.run(&cancellation).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;

        fs::write(&path, r#"{"unknown":true}"#).expect("write invalid policy");
        wait_for_rejection(&health, true).await;
        fs::write(&path, "{}").expect("write valid policy");
        wait_for_rejection(&health, false).await;

        cancellation.cancel();
        task.await
            .expect("policy supervisor joins")
            .expect("policy supervisor stops");
        fs::remove_file(path).ok();
    }
}
