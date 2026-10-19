//! Owned observation of canonical runtime-policy resources.
//!
//! File sessions install observation before reading their baseline. The session
//! owns the watcher and pending read. Observation failure interrupts the read.
//! Reads use Tokio's blocking pool. A started operating-system read can finish
//! after session drop, but it cannot publish into a dropped session. Linux
//! observation remains passive while idle. Windows checks the directory identity
//! every 100 ms because a native watcher can stop silently. Directory removal,
//! rename, or replacement fails observation. Dropping the session stops
//! observation without a detached monitor.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use notify::event::ModifyKind;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::watch;

use crate::tacacsrs::RuntimePolicy;
#[cfg(windows)]
use crate::source::directory_watch::DirectoryWatch;
use super::file_observation::{FileObservationState, ObservationContext};

/// A complete source candidate or a rejected candidate that leaves applied state unchanged.
#[derive(Debug, Clone)]
pub enum PolicyChange {
    /// A validated canonical snapshot. Consumers must not mutate it during preparation.
    Changed(Arc<RuntimePolicy>),
    /// The current source could not be loaded or validated.
    CandidateRejected,
}

/// Owns an observation session, including its baseline and subsequent changes.
#[async_trait]
pub trait PolicyObservation: Send {
    /// Returns the next candidate, rejection, or end of observation.
    ///
    /// Implementations must retain unread changes when this future is cancelled.
    /// The first call supplies a baseline after observation is active. Changes can
    /// coalesce, but a later call must reconcile each invalidation received during a read.
    ///
    /// # Errors
    /// Returns an error when observation fails and must be re-established.
    async fn next(&mut self) -> anyhow::Result<Option<PolicyChange>>;
}

/// File source for a module-qualified RFC 7951 runtime-policy resource.
#[derive(Debug, Clone)]
pub struct PolicyFile {
    path: PathBuf,
}

impl PolicyFile {
    /// Captures an absolute source path without reading the file.
    ///
    /// # Errors
    /// Returns an error if the current directory cannot be resolved.
    pub fn new(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Ok(Self {
            path: std::path::absolute(path.as_ref()).context("resolve runtime policy path")?,
        })
    }

    /// Returns the captured source path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads and validates the complete canonical policy snapshot.
    ///
    /// # Errors
    /// Returns an I/O, JSON, or canonical policy validation error.
    pub async fn load(&self) -> anyhow::Result<RuntimePolicy> {
        let bytes = tokio::fs::read(&self.path)
            .await
            .with_context(|| format!("read runtime policy file {}", self.path.display()))?;
        crate::policy::parse_runtime_policy(&bytes)
            .with_context(|| format!("parse runtime policy file {}", self.path.display()))
    }

    /// Installs directory observation before the first baseline read.
    ///
    /// # Errors
    /// Returns an error if the parent directory or watcher cannot be established.
    pub async fn observe(&self) -> anyhow::Result<FilePolicyObservation> {
        let parent = self
            .path
            .parent()
            .context("runtime policy path has no parent")?;
        let parent = tokio::fs::canonicalize(parent)
            .await
            .context("resolve runtime policy directory")?;
        let path = parent.join(
            self.path
                .file_name()
                .context("runtime policy path has no file name")?,
        );
        let target = path.clone();
        let directory = parent.clone();
        #[cfg(windows)]
        let directory_watch = DirectoryWatch::new([parent.clone()])?;
        let (events, invalidations) = watch::channel(None::<Arc<notify::Error>>);
        let mut watcher = RecommendedWatcher::new(
            move |event: notify::Result<notify::Event>| {
                let error = match event {
                    Ok(event)
                        if event.paths.iter().any(|path| path == &directory)
                            && matches!(
                                event.kind,
                                EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(_))
                            ) =>
                    {
                        Some(Arc::new(notify::Error::generic(
                            "Runtime policy directory was removed or renamed",
                        )))
                    }
                    Ok(event) if event_touches_policy_path(&event, &target) => None,
                    Ok(_) => return,
                    Err(error) => Some(Arc::new(error)),
                };
                events.send_modify(|current| {
                    if current.is_none() {
                        *current = error;
                    }
                });
            },
            Config::default(),
        )
        .context("create runtime policy watcher")?;
        watcher
            .watch(&parent, RecursiveMode::NonRecursive)
            .with_context(|| format!("watch runtime policy directory {}", parent.display()))?;
        #[cfg(windows)]
        directory_watch.ensure_current()?;
        Ok(FilePolicyObservation {
            observation: FileObservationState::new(
                Some(watcher),
                #[cfg(windows)]
                Some(directory_watch),
                invalidations,
                POLICY_RELOAD_DEBOUNCE,
                ObservationContext {
                    failure: "Runtime policy observation failed",
                    stopped: "runtime policy watcher stopped",
                    reader_stopped: "runtime policy reader stopped",
                },
            ),
            source: Self { path },
        })
    }
}

/// Native file watcher and its cancellation-safe pending observation state.
pub struct FilePolicyObservation {
    observation: FileObservationState<RuntimePolicy>,
    source: PolicyFile,
}

/// Coalesces file replacement bursts without creating a queue of candidate documents.
const POLICY_RELOAD_DEBOUNCE: Duration = Duration::from_millis(100);

#[async_trait]
impl PolicyObservation for FilePolicyObservation {
    async fn next(&mut self) -> anyhow::Result<Option<PolicyChange>> {
        let source = &self.source;
        let Some(candidate) = self
            .observation
            .next(|| {
                let source = source.clone();
                tokio::task::spawn_blocking(move || {
                    let bytes = std::fs::read(source.path()).with_context(|| {
                        format!("read runtime policy file {}", source.path().display())
                    })?;
                    crate::policy::parse_runtime_policy(&bytes).with_context(|| {
                        format!("parse runtime policy file {}", source.path().display())
                    })
                })
            })
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(if let Ok(policy) = candidate {
            PolicyChange::Changed(Arc::new(policy))
        } else {
            log::warn!("Rejected runtime policy candidate from {}", self.source.path.display());
            PolicyChange::CandidateRejected
        }))
    }
}

fn event_touches_policy_path(event: &notify::Event, target: &Path) -> bool {
    event.need_rescan()
        || (!matches!(event.kind, EventKind::Access(_))
            && (event.paths.is_empty() || event.paths.iter().any(|path| path == target)))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn policy_event_filter_preserves_rescan_empty_and_access_rules() {
        use notify::event::{AccessKind, Flag};
        use notify::Event;

        let target = Path::new("policy.json");
        let access = Event::new(EventKind::Access(AccessKind::Read)).add_path(target.to_path_buf());
        assert!(!event_touches_policy_path(&access, target));
        assert!(event_touches_policy_path(&access.set_flag(Flag::Rescan), target));
        assert!(event_touches_policy_path(&Event::new(EventKind::Any), target));
        let unrelated = Event::new(EventKind::Any).add_path(PathBuf::from("other.json"));
        assert!(!event_touches_policy_path(&unrelated, target));
        let change = Event::new(EventKind::Any).add_path(target.to_path_buf());
        assert!(event_touches_policy_path(&change, target));
    }

    #[tokio::test]
    async fn delete_recreate_recovers_and_drop_releases_watcher() {
        let source = source();
        tokio::fs::write(source.path(), br#"{"tacacsrs:runtime-policy":{}}"#)
            .await
            .unwrap();
        let mut observation = source.observe().await.unwrap();
        let mut lifetime = observation.observation.invalidations.clone();
        assert!(matches!(observation.next().await.unwrap(), Some(PolicyChange::Changed(_))));
        tokio::fs::remove_file(source.path()).await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), observation.next())
                .await
                .unwrap()
                .unwrap(),
            Some(PolicyChange::CandidateRejected)
        ));
        tokio::fs::write(
            source.path(),
            br#"{"tacacsrs:runtime-policy":{"accounting":{"request-timeout-seconds":23}}}"#,
        )
        .await
        .unwrap();
        let Some(PolicyChange::Changed(policy)) =
            tokio::time::timeout(Duration::from_secs(1), observation.next())
                .await
                .unwrap()
                .unwrap()
        else {
            panic!("recreated policy must recover");
        };
        assert_eq!(policy.accounting.as_ref().unwrap().request_timeout_seconds, 23);
        drop(observation);
        tokio::time::timeout(Duration::from_secs(1), async {
            while lifetime.changed().await.is_ok() {}
        })
        .await
        .expect("drop must release the native watcher callback");
        tokio::fs::remove_file(source.path()).await.unwrap();
    }

    #[test]
    fn policy_observe_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        let source = source();
        assert_send(source.observe());
    }

    fn source() -> PolicyFile {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        PolicyFile::new(std::env::temp_dir().join(format!(
            "tacacs-policy-observation-{}-{time}-{sequence}.json",
            std::process::id()
        )))
        .unwrap()
    }

    #[tokio::test]
    async fn observation_reconciles_changes_before_start_and_atomic_replacement() {
        let source = source();
        tokio::fs::write(source.path(), br#"{"tacacsrs:runtime-policy":{}}"#)
            .await
            .unwrap();
        source.load().await.unwrap();
        tokio::fs::write(source.path(), br#"{"unknown":true}"#)
            .await
            .unwrap();
        let mut observation = source.observe().await.unwrap();
        assert!(matches!(observation.next().await.unwrap(), Some(PolicyChange::CandidateRejected)));
        let replacement = source.path().with_extension("new");
        tokio::fs::write(
            &replacement,
            br#"{"tacacsrs:runtime-policy":{"accounting":{"request-timeout-seconds":17}}}"#,
        )
        .await
        .unwrap();
        tokio::fs::rename(&replacement, source.path())
            .await
            .unwrap();
        let PolicyChange::Changed(policy) =
            tokio::time::timeout(Duration::from_secs(3), observation.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        else {
            panic!("replacement must produce a snapshot");
        };
        assert_eq!(policy.accounting.as_ref().unwrap().request_timeout_seconds, 17);
        assert!(policy.authentication.is_none());
        drop(observation);
        tokio::fs::remove_file(source.path()).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_debounce_retains_pending_candidate_and_coalesces_bursts() {
        let source = source();
        tokio::fs::write(source.path(), br#"{"tacacsrs:runtime-policy":{}}"#)
            .await
            .unwrap();
        let mut observation = source.observe().await.unwrap();
        observation.next().await.unwrap();
        let (events, invalidations) = watch::channel(None);
        observation.observation.failures = invalidations.clone();
        observation.observation.invalidations = invalidations;
        for _ in 0..10_000 {
            events.send_replace(None);
        }
        {
            let update = observation.next();
            tokio::pin!(update);
            assert!(futures_util::poll!(&mut update).is_pending());
        }
        tokio::fs::write(
            source.path(),
            br#"{"tacacsrs:runtime-policy":{"accounting":{"request-timeout-seconds":23}}}"#,
        )
        .await
        .unwrap();
        let current = tokio::time::timeout(Duration::from_secs(3), observation.next()).await;
        let Ok(Ok(Some(PolicyChange::Changed(current)))) = current else {
            panic!("cancelled observation must resume");
        };
        assert_eq!(current.accounting.as_ref().unwrap().request_timeout_seconds, 23);
        drop(observation);
        tokio::fs::remove_file(source.path()).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_pending_read_is_retained_and_concurrent_invalidation_is_not_lost() {
        let source = source();
        tokio::fs::write(
            source.path(),
            br#"{"tacacsrs:runtime-policy":{"accounting":{"request-timeout-seconds":17}}}"#,
        )
        .await
        .unwrap();
        let mut observation = source.observe().await.unwrap();
        let first = source.load().await.unwrap();
        let (release, stalled) = tokio::sync::oneshot::channel();
        observation.observation.read = Some(tokio::spawn(async move {
            stalled.await.unwrap();
            Ok(first)
        }));
        let (events, invalidations) = watch::channel(None);
        observation.observation.failures = invalidations.clone();
        observation.observation.invalidations = invalidations;
        {
            let next = observation.next();
            tokio::pin!(next);
            assert!(futures_util::poll!(&mut next).is_pending());
        }
        tokio::fs::write(
            source.path(),
            br#"{"tacacsrs:runtime-policy":{"accounting":{"request-timeout-seconds":23}}}"#,
        )
        .await
        .unwrap();
        events.send_replace(None);
        release.send(()).unwrap();

        let Some(PolicyChange::Changed(first)) = observation.next().await.unwrap() else {
            panic!("cancelled read must remain owned");
        };
        assert_eq!(first.accounting.as_ref().unwrap().request_timeout_seconds, 17);
        assert!(observation.observation.invalidations.has_changed().unwrap());
        let Some(PolicyChange::Changed(latest)) =
            tokio::time::timeout(Duration::from_secs(1), observation.next())
                .await
                .unwrap()
                .unwrap()
        else {
            panic!("invalidation during the read must trigger reconciliation");
        };
        assert_eq!(latest.accounting.as_ref().unwrap().request_timeout_seconds, 23);
        assert!(!observation.observation.invalidations.has_changed().unwrap());
        drop(observation);
        tokio::fs::remove_file(source.path()).await.unwrap();
    }

    #[tokio::test]
    async fn observation_failure_wins_when_a_read_is_ready() {
        let source = source();
        tokio::fs::write(source.path(), br#"{"tacacsrs:runtime-policy":{}}"#)
            .await
            .unwrap();
        let mut observation = source.observe().await.unwrap();
        let candidate = source.load().await.unwrap();
        observation.observation.read = Some(tokio::spawn(async move { Ok(candidate) }));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !observation.observation.read.as_ref().unwrap().is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("candidate read must be ready");
        let (events, invalidations) =
            watch::channel(Some(Arc::new(notify::Error::generic("test observation loss"))));
        observation.observation.failures = invalidations.clone();
        observation.observation.invalidations = invalidations;

        let error = observation.next().await.unwrap_err();
        assert!(error.to_string().contains("test observation loss"));

        drop(events);
        drop(observation);
        tokio::fs::remove_file(source.path()).await.unwrap();
    }

    #[tokio::test]
    async fn changes_after_baseline_before_supervision_are_observed() {
        let source = source();
        tokio::fs::write(source.path(), br#"{"tacacsrs:runtime-policy":{}}"#)
            .await
            .unwrap();
        let mut observation = source.observe().await.unwrap();
        assert!(matches!(observation.next().await.unwrap(), Some(PolicyChange::Changed(_))));
        tokio::fs::write(source.path(), br#"{"unknown":true}"#)
            .await
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(3), observation.next())
                .await
                .unwrap()
                .unwrap(),
            Some(PolicyChange::CandidateRejected)
        ));
        drop(observation);
        tokio::fs::remove_file(source.path()).await.unwrap();
    }

    #[tokio::test]
    async fn loss_of_watched_directory_ends_observation() {
        assert_loss_of_watched_directory_ends_observation(false).await;
    }

    #[tokio::test]
    async fn rename_of_watched_directory_ends_observation() {
        assert_loss_of_watched_directory_ends_observation(true).await;
    }

    #[tokio::test]
    async fn watched_directory_rename_interrupts_a_stalled_read() {
        let directory = source().path().with_extension("stalled-directory");
        tokio::fs::create_dir(&directory).await.unwrap();
        let source = PolicyFile::new(directory.join("policy.json")).unwrap();
        tokio::fs::write(source.path(), br#"{"tacacsrs:runtime-policy":{}}"#)
            .await
            .unwrap();
        let mut observation = source.observe().await.unwrap();
        let candidate = source.load().await.unwrap();
        let (release, stalled) = tokio::sync::oneshot::channel();
        observation.observation.read = Some(tokio::spawn(async move {
            stalled.await.unwrap();
            Ok(candidate)
        }));
        let renamed = directory.with_extension("stalled-renamed");
        {
            let next = observation.next();
            tokio::pin!(next);
            assert!(futures_util::poll!(&mut next).is_pending());
            tokio::fs::rename(&directory, &renamed).await.unwrap();
            tokio::fs::create_dir(&directory).await.unwrap();
            tokio::fs::write(source.path(), br#"{"tacacsrs:runtime-policy":{}}"#)
                .await
                .unwrap();
            let result = tokio::time::timeout(Duration::from_secs(1), &mut next)
                .await
                .expect("directory loss must interrupt the stalled read");
            assert!(result.is_err());
        }

        release.send(()).unwrap();
        let read = observation.observation.read.take().unwrap();
        read.await.unwrap().unwrap();
        drop(observation);
        tokio::fs::remove_dir_all(renamed).await.unwrap();
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }

    async fn assert_loss_of_watched_directory_ends_observation(rename: bool) {
        let directory = source().path().with_extension("directory");
        tokio::fs::create_dir(&directory).await.unwrap();
        let source = PolicyFile::new(directory.join("policy.json")).unwrap();
        tokio::fs::write(source.path(), br#"{"tacacsrs:runtime-policy":{}}"#)
            .await
            .unwrap();
        let mut observation = source.observe().await.unwrap();
        observation.next().await.unwrap();
        let renamed = directory.with_extension("renamed");
        if rename {
            tokio::fs::rename(&directory, &renamed).await.unwrap();
            tokio::fs::create_dir(&directory).await.unwrap();
            tokio::fs::write(source.path(), br#"{"tacacsrs:runtime-policy":{}}"#)
                .await
                .unwrap();
        } else {
            tokio::fs::remove_file(source.path()).await.unwrap();
            tokio::fs::remove_dir(&directory).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while observation.next().await.is_ok() {}
        })
        .await
        .expect("watch loss must not silently retain an unobserved policy");
        if rename {
            tokio::fs::remove_dir_all(renamed).await.unwrap();
            tokio::fs::remove_dir_all(directory).await.unwrap();
        }
    }
}
