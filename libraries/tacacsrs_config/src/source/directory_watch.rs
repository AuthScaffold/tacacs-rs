//! Platform-specific directory lifecycle checks for owned file observations.

#[cfg(windows)]
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(windows)]
use std::time::Duration;

use anyhow::Context;
#[cfg(windows)]
use same_file::Handle;
use tokio::sync::watch;
#[cfg(windows)]
use tokio::time::{Instant, Interval, MissedTickBehavior};

/// Bounds detection latency when a native watcher silently stops after directory loss.
#[cfg(windows)]
const DIRECTORY_CHECK_INTERVAL: Duration = Duration::from_millis(100);

#[cfg(not(windows))]
pub(crate) async fn wait_for_native_change(
    invalidations: &mut watch::Receiver<Option<Arc<notify::Error>>>,
    stopped_context: &'static str,
) -> anyhow::Result<()> {
    invalidations.changed().await.context(stopped_context)?;
    Ok(())
}

#[derive(Debug)]
#[cfg(windows)]
struct WatchedDirectory {
    path: PathBuf,
    identity: Handle,
}

/// Adds identity checks only where native watchers can stop silently.
#[derive(Debug)]
#[cfg(windows)]
pub(crate) struct DirectoryWatch {
    directories: Vec<WatchedDirectory>,
    checks: Interval,
}

#[cfg(windows)]
impl DirectoryWatch {
    pub(crate) fn new(directories: impl IntoIterator<Item = PathBuf>) -> anyhow::Result<Self> {
        let directories = directories
            .into_iter()
            .map(|path| {
                let identity = Handle::from_path(&path)
                    .with_context(|| format!("capture watched directory {}", path.display()))?;
                Ok(WatchedDirectory { path, identity })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut checks = tokio::time::interval_at(
            Instant::now() + DIRECTORY_CHECK_INTERVAL,
            DIRECTORY_CHECK_INTERVAL,
        );
        checks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Ok(Self {
            directories,
            checks,
        })
    }

    pub(crate) fn ensure_current(&self) -> anyhow::Result<()> {
        for directory in &self.directories {
            let current = Handle::from_path(&directory.path).with_context(|| {
                format!("access watched directory {}", directory.path.display())
            })?;
            anyhow::ensure!(
                current == directory.identity,
                "Watched directory was replaced: {}",
                directory.path.display()
            );
        }
        Ok(())
    }

    pub(crate) async fn wait_for_change(
        &mut self,
        invalidations: &mut watch::Receiver<Option<Arc<notify::Error>>>,
        stopped_context: &'static str,
    ) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                changed = invalidations.changed() => {
                    changed.context(stopped_context)?;
                    self.ensure_current()?;
                    return Ok(());
                }
                _ = self.checks.tick() => self.ensure_current()?,
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};
    use std::time::Duration;

    use super::*;

    const IDLE_ADVANCE_SECONDS: u64 = 24 * 60 * 60;

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_linux_observation_has_no_periodic_wake() {
        let (events, mut invalidations) = watch::channel(None);
        let update = wait_for_native_change(&mut invalidations, "test watcher stopped");
        tokio::pin!(update);
        let wake_counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(wake_counter.clone());
        let mut context = Context::from_waker(&waker);

        assert!(update.as_mut().poll(&mut context).is_pending());
        tokio::time::advance(Duration::new(IDLE_ADVANCE_SECONDS, 0)).await;
        tokio::task::yield_now().await;
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 0);

        events.send_replace(None);
        assert!(wake_counter.0.load(Ordering::Relaxed) > 0);
        assert!(update.as_mut().poll(&mut context).is_ready());
    }
}
