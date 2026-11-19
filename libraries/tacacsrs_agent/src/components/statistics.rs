//! Writes operational statistics to a JSON file once each second.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, ensure};
use dill::component;
use tokio::io::AsyncWriteExt;

use crate::{DiagnosticsHandle, LocalServicesView};
use crate::host::StartupCheck;
use tacacsrs_composition::{Component, Composition, Named};
use tacacsrs_config::local_services::ListenerEndpoint;
use tacacsrs_lifecycle::{HostedService, ShutdownSignal};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

/// Publishes operational statistics to a file.
///
/// The component replaces the file atomically once each second. Startup stops
/// when the file path is equal to a protected input file or a listener socket
/// path.
pub struct StatisticsComponent {
    path: PathBuf,
    protected_inputs: Vec<PathBuf>,
    file: Option<StatisticsFile>,
}

impl StatisticsComponent {
    /// Creates the component for the file at `path`.
    ///
    /// The component never writes to a path in `protected_inputs`. A host
    /// gives its configuration and credential input files here.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, protected_inputs: Vec<PathBuf>) -> Self {
        Self {
            path: path.into(),
            protected_inputs,
            file: None,
        }
    }
}

#[async_trait::async_trait]
impl Component for StatisticsComponent {
    fn name(&self) -> &'static str {
        StatisticsService::NAME
    }

    async fn prepare(&mut self) -> anyhow::Result<()> {
        let protected: Vec<_> = self.protected_inputs.iter().map(PathBuf::as_path).collect();
        self.file = Some(StatisticsFile::new(&self.path, &protected).await?);
        Ok(())
    }

    fn register(self: Box<Self>, composition: &mut Composition) -> anyhow::Result<()> {
        let file = self.file.context("Statistics file is not prepared")?;
        composition.member::<dyn StartupCheck, ListenerProtection, _>(
            ListenerProtection::builder(file.clone()),
        )?;
        composition.hosted_service(StatisticsService::builder(file))
    }
}

/// Stops startup when the statistics file is a listener socket path.
///
/// The host runs this check before any listener binds. The check uses the
/// bootstrap local services.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn StartupCheck)]
struct ListenerProtection {
    #[component(explicit)]
    file: StatisticsFile,
    local_services: Arc<LocalServicesView>,
}

impl Named for ListenerProtection {
    const NAME: &'static str = "Statistics listener protection";
}

#[async_trait::async_trait]
impl StartupCheck for ListenerProtection {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn check(&self) -> anyhow::Result<()> {
        let active = self.local_services.current();
        let prepared = active.prepared();
        if let Some(path) = prepared.client_api() {
            self.file.protect_listener(path).await?;
        }
        if let Some(ListenerEndpoint::Unix(path)) = prepared.tacacs_proxy() {
            self.file.protect_listener(path).await?;
        }
        Ok(())
    }
}

/// Publishes operational statistics once each second until shutdown.
#[component]
#[dill::scope(dill::Singleton)]
#[dill::interface(dyn HostedService)]
struct StatisticsService {
    #[component(explicit)]
    file: StatisticsFile,
    diagnostics: Arc<DiagnosticsHandle>,
}

impl Named for StatisticsService {
    const NAME: &'static str = "Operational statistics";
}

#[async_trait::async_trait]
impl HostedService for StatisticsService {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn run(self: Arc<Self>, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        self.file.run(&self.diagnostics, &shutdown).await
    }
}

#[derive(Clone)]
pub(crate) struct StatisticsFile {
    path: PathBuf,
}

impl StatisticsFile {
    pub(crate) async fn new(path: &Path, protected: &[&Path]) -> anyhow::Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let parent =
            tokio::fs::canonicalize(absolute.parent().context("Statistics file has no parent")?)
                .await?;
        let path = parent.join(
            absolute
                .file_name()
                .context("Statistics file has no filename")?,
        );
        if let Ok(metadata) = tokio::fs::symlink_metadata(&path).await {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "Statistics destination must be a regular file"
            );
        }
        for input in protected {
            ensure!(
                !refers_to(input, &path).await?,
                "Statistics destination cannot overwrite a configuration input"
            );
        }
        Ok(Self { path })
    }

    async fn publish(
        &self,
        snapshot: &tacacsrs_config::OperationalStatistics,
    ) -> anyhow::Result<()> {
        if let Ok(metadata) = tokio::fs::symlink_metadata(&self.path).await {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "Statistics destination is no longer a regular file"
            );
        }
        let name = self
            .path
            .file_name()
            .context("Statistics filename is missing")?
            .to_string_lossy();
        let temporary = self.path.with_file_name(format!(
            ".{name}.{}-{}.tmp",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .await?;
        let cleanup = TemporaryFile(temporary);
        let data = snapshot.to_yang_json()?;
        file.write_all(data.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        drop(file);
        tokio::fs::rename(&cleanup.0, &self.path).await?;
        Ok(())
    }

    pub(crate) async fn protect_listener(&self, listener: &Path) -> anyhow::Result<()> {
        if let (Some(parent), Some(name)) = (listener.parent(), listener.file_name()) {
            if let Ok(parent) = tokio::fs::canonicalize(parent).await {
                ensure!(
                    parent.join(name) != self.path,
                    "Statistics destination cannot replace a listener socket"
                );
            }
        }
        Ok(())
    }

    async fn run(
        &self,
        diagnostics: &DiagnosticsHandle,
        stop: &ShutdownSignal,
    ) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = stop.requested() => return Ok(()),
                _ = interval.tick() => {
                    let snapshot = diagnostics.statistics()?;
                    tokio::select! {
                        biased;
                        () = stop.requested() => return Ok(()),
                        result = self.publish(&snapshot) => result.context("Could not publish operational statistics")?,
                    }
                }
            }
        }
    }
}

struct TemporaryFile(PathBuf);
impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Reports whether `input` names the canonical `path`.
///
/// A watched input can be absent at startup. For an absent input, the check
/// uses the canonical parent directory and the file name.
async fn refers_to(input: &Path, path: &Path) -> anyhow::Result<bool> {
    if let Ok(input) = tokio::fs::canonicalize(input).await {
        return Ok(input == path);
    }
    let absolute = if input.is_absolute() {
        input.to_path_buf()
    } else {
        std::env::current_dir()?.join(input)
    };
    let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) else {
        return Ok(false);
    };
    Ok(tokio::fs::canonicalize(parent)
        .await
        .is_ok_and(|parent| parent.join(name) == path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn absent_protected_input_is_still_protected() {
        let directory = std::env::temp_dir().join(format!(
            "agent-statistics-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let input = directory.join("config.json");
        let error = StatisticsFile::new(&input, &[input.as_path()])
            .await
            .err()
            .expect("an absent input is protected");
        assert!(error.to_string().contains("configuration input"));
        let other = directory.join("statistics.json");
        StatisticsFile::new(&other, &[input.as_path()])
            .await
            .unwrap();
        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }
}
