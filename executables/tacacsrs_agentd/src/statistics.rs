//! Owned periodic publication of generation-bound operational JSON.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, ensure};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

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
            if let Ok(input) = tokio::fs::canonicalize(input).await {
                ensure!(
                    input != path,
                    "Statistics destination cannot overwrite a configuration input"
                );
            }
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

    pub(crate) async fn run(
        self,
        service: std::sync::Arc<tacacsrs_agent::TacacsClientService>,
        stop: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = stop.cancelled() => return Ok(()),
                _ = interval.tick() => {
                    let snapshot = service.statistics();
                    tokio::select! {
                        biased;
                        () = stop.cancelled() => return Ok(()),
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
