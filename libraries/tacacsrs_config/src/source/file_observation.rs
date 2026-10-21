//! Shared ownership of file observation state, without source parsing or history.
//!
//! Cancellation retains the absolute debounce deadline and the same read task.
//! Separate receivers preserve invalidations received during a read. Failure checks
//! take priority over ready candidates and run again before candidate publication.
//! Drop aborts the owned task. A running blocking read can still finish, but it
//! cannot publish into the dropped observation.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use notify::RecommendedWatcher;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

#[cfg(windows)]
use super::directory_watch::DirectoryWatch;
use super::directory_watch::acknowledge_observation_active;
#[cfg(not(windows))]
use super::directory_watch::{wait_for_native_change, wait_for_observation_failure};

pub(super) struct FileObservationState<T> {
    watcher: Option<RecommendedWatcher>,
    #[cfg(windows)]
    directory_watch: Option<DirectoryWatch>,
    pub(super) failures: watch::Receiver<Option<Arc<notify::Error>>>,
    pub(super) invalidations: watch::Receiver<Option<Arc<notify::Error>>>,
    pending: bool,
    debounce_until: Option<Instant>,
    pub(super) read: Option<JoinHandle<anyhow::Result<T>>>,
    debounce: Duration,
    context: ObservationContext,
}

pub(super) struct ObservationContext {
    pub(super) failure: &'static str,
    pub(super) stopped: &'static str,
    pub(super) reader_stopped: &'static str,
}

impl<T> FileObservationState<T> {
    pub(super) fn new(
        watcher: Option<RecommendedWatcher>,
        #[cfg(windows)] directory_watch: Option<DirectoryWatch>,
        invalidations: watch::Receiver<Option<Arc<notify::Error>>>,
        debounce: Duration,
        context: ObservationContext,
    ) -> Self {
        Self {
            watcher,
            #[cfg(windows)]
            directory_watch,
            failures: invalidations.clone(),
            invalidations,
            pending: true,
            debounce_until: None,
            read: None,
            debounce,
            context,
        }
    }

    pub(super) async fn next(
        &mut self,
        start_read: impl FnOnce() -> JoinHandle<anyhow::Result<T>>,
    ) -> anyhow::Result<Option<anyhow::Result<T>>> {
        if !self.pending {
            if self.watcher.is_none() {
                return Ok(None);
            }
            #[cfg(windows)]
            self.directory_watch
                .as_mut()
                .context(self.context.failure)?
                .wait_for_change(&mut self.invalidations, self.context.stopped)
                .await?;
            #[cfg(not(windows))]
            wait_for_native_change(&mut self.invalidations, self.context.stopped).await?;
            self.pending = true;
            self.debounce_until = Some(Instant::now() + self.debounce);
        }
        if self.read.is_none() {
            if let Some(deadline) = self.debounce_until {
                tokio::select! {
                    biased;
                    error = observation_failure(
                        &mut self.failures,
                        #[cfg(windows)]
                        &mut self.directory_watch,
                        &self.context,
                    ) => return Err(error),
                    () = tokio::time::sleep_until(deadline) => {}
                }
            }
            if self.watcher.is_some() {
                acknowledge_observation_active(
                    &mut self.invalidations,
                    self.context.failure,
                    self.context.stopped,
                )?;
            }
            #[cfg(windows)]
            if let Some(directory_watch) = &self.directory_watch {
                directory_watch.ensure_current()?;
            }
            self.read = Some(start_read());
        }
        let read = self.read.as_mut().context(self.context.reader_stopped)?;
        let candidate = if self.watcher.is_some() {
            let candidate = tokio::select! {
                biased;
                error = observation_failure(
                    &mut self.failures,
                    #[cfg(windows)]
                    &mut self.directory_watch,
                    &self.context,
                ) => return Err(error),
                candidate = read => candidate,
            };
            acknowledge_observation_active(
                &mut self.failures,
                self.context.failure,
                self.context.stopped,
            )?;
            candidate
        } else {
            read.await
        };
        #[cfg(windows)]
        if let Some(directory_watch) = &self.directory_watch {
            directory_watch
                .ensure_current()
                .context(self.context.failure)?;
        }
        self.read = None;
        let candidate = candidate.context(self.context.reader_stopped)?;
        self.pending = false;
        self.debounce_until = None;
        Ok(Some(candidate))
    }
}

async fn observation_failure(
    failures: &mut watch::Receiver<Option<Arc<notify::Error>>>,
    #[cfg(windows)] directory_watch: &mut Option<DirectoryWatch>,
    context: &ObservationContext,
) -> anyhow::Error {
    #[cfg(windows)]
    {
        let Some(directory_watch) = directory_watch.as_mut() else {
            return anyhow::anyhow!(context.failure);
        };
        directory_watch
            .wait_for_observation_failure(failures, context.failure, context.stopped)
            .await
    }
    #[cfg(not(windows))]
    wait_for_observation_failure(failures, context.failure, context.stopped).await
}

impl<T> Drop for FileObservationState<T> {
    fn drop(&mut self) {
        if let Some(read) = &self.read {
            read.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use notify::{Config, Watcher};
    use tokio::sync::oneshot;

    use super::*;

    fn observation<T>(
        watched: bool,
        debounce: Duration,
    ) -> (FileObservationState<T>, watch::Sender<Option<Arc<notify::Error>>>) {
        let (events, invalidations) = watch::channel(None);
        let watcher = watched.then(|| RecommendedWatcher::new(|_| {}, Config::default()).unwrap());
        #[cfg(windows)]
        let directory_watch = watched.then(|| DirectoryWatch::new([]).unwrap());
        (
            FileObservationState::new(
                watcher,
                #[cfg(windows)]
                directory_watch,
                invalidations,
                debounce,
                ObservationContext {
                    failure: "test observation failed",
                    stopped: "test watcher stopped",
                    reader_stopped: "test reader stopped",
                },
            ),
            events,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn finite_baseline_has_no_debounce_and_then_ends() {
        let (mut observation, events) = observation(false, Duration::from_secs(60));
        drop(events);
        let started = Instant::now();
        assert_eq!(
            observation
                .next(|| tokio::spawn(async { Ok(7) }))
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            7,
        );
        assert_eq!(Instant::now(), started);
        assert!(observation
            .next(|| panic!("finite observation must end"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_debounce_keeps_absolute_deadline_and_lazy_loader() {
        let (mut observation, events) = observation(true, Duration::from_millis(100));
        observation
            .next(|| tokio::spawn(async { Ok(1) }))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let starts = Cell::new(0);
        events.send_replace(None);
        let deadline = Instant::now() + Duration::from_millis(100);
        for _ in 0..3 {
            {
                let next = observation.next(|| {
                    starts.set(starts.get() + 1);
                    tokio::spawn(async { Ok(2) })
                });
                tokio::pin!(next);
                assert!(futures_util::poll!(&mut next).is_pending());
            }
            assert_eq!(observation.debounce_until, Some(deadline));
            assert_eq!(starts.get(), 0);
            events.send_replace(None);
            tokio::time::advance(Duration::from_millis(30)).await;
        }
        tokio::time::advance(Duration::from_millis(10)).await;
        assert_eq!(
            observation
                .next(|| {
                    starts.set(starts.get() + 1);
                    tokio::spawn(async { Ok(2) })
                })
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            2,
        );
        assert_eq!(starts.get(), 1);
        assert!(!observation.invalidations.has_changed().unwrap());
    }

    #[tokio::test]
    async fn cancelled_read_keeps_one_task_and_reconciles_concurrent_invalidation() {
        let (mut observation, events) = observation(true, Duration::ZERO);
        let (release, ready) = oneshot::channel();
        let starts = Cell::new(0);
        {
            let next = observation.next(|| {
                starts.set(starts.get() + 1);
                tokio::spawn(async move {
                    ready.await.unwrap();
                    Ok(1)
                })
            });
            tokio::pin!(next);
            assert!(futures_util::poll!(&mut next).is_pending());
        }
        let task = observation.read.as_ref().unwrap().id();
        for _ in 0..3 {
            {
                let next = observation.next(|| panic!("pending read must not restart"));
                tokio::pin!(next);
                assert!(futures_util::poll!(&mut next).is_pending());
            }
            assert_eq!(observation.read.as_ref().unwrap().id(), task);
        }
        assert_eq!(starts.get(), 1);
        events.send_replace(None);
        release.send(()).unwrap();
        assert_eq!(
            observation
                .next(|| panic!("read must remain owned"))
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            1
        );
        assert!(observation.invalidations.has_changed().unwrap());
        assert_eq!(
            observation
                .next(|| tokio::spawn(async { Ok(2) }))
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            2
        );
        assert!(!observation.invalidations.has_changed().unwrap());
    }

    #[tokio::test]
    async fn pending_failure_wins_over_completed_read() {
        let (mut observation, events) = observation(true, Duration::ZERO);
        let read = tokio::spawn(async { Ok(1) });
        while !read.is_finished() {
            tokio::task::yield_now().await;
        }
        observation.read = Some(read);
        events.send_replace(Some(Arc::new(notify::Error::generic("lost observation"))));
        let error = observation
            .next(|| panic!("ready read must not restart"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("lost observation"));
        assert!(observation.pending);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_failure_wins_over_elapsed_debounce() {
        let (mut observation, events) = observation::<()>(true, Duration::from_millis(100));
        observation.pending = false;
        events.send_replace(None);
        {
            let next = observation.next(|| panic!("debounce must finish first"));
            tokio::pin!(next);
            assert!(futures_util::poll!(&mut next).is_pending());
        }
        events.send_replace(Some(Arc::new(notify::Error::generic("lost observation"))));
        tokio::time::advance(Duration::from_millis(100)).await;
        let error = observation
            .next(|| panic!("failure must prevent the read"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("lost observation"));
    }

    struct ReadDrop(Option<oneshot::Sender<()>>);

    impl Drop for ReadDrop {
        fn drop(&mut self) {
            if let Some(disposed) = self.0.take() {
                let _ = disposed.send(());
            }
        }
    }

    #[tokio::test]
    async fn drop_aborts_owned_pending_task() {
        let (mut observation, _events) = observation(false, Duration::ZERO);
        let (disposed, disposal) = oneshot::channel();
        let payload = ReadDrop(Some(disposed));
        {
            let next = observation.next(|| {
                tokio::spawn(async move {
                    let _payload = payload;
                    std::future::pending::<anyhow::Result<()>>().await
                })
            });
            tokio::pin!(next);
            assert!(futures_util::poll!(&mut next).is_pending());
        }
        drop(observation);
        disposal.await.unwrap();
    }

    #[tokio::test]
    async fn running_blocking_read_can_finish_after_drop_without_publication() {
        let (mut observation, _events) = observation(false, Duration::ZERO);
        let (entered, entry) = oneshot::channel();
        let (release, ready) = std::sync::mpsc::channel();
        let (disposed, disposal) = oneshot::channel();
        {
            let next = observation.next(|| {
                tokio::task::spawn_blocking(move || {
                    entered.send(()).unwrap();
                    ready.recv().unwrap();
                    Ok(ReadDrop(Some(disposed)))
                })
            });
            tokio::pin!(next);
            tokio::select! {
                result = entry => result.unwrap(),
                _ = &mut next => panic!("blocking read must wait for release"),
            }
        }
        drop(observation);
        release.send(()).unwrap();
        disposal.await.unwrap();
    }

    #[test]
    fn drop_aborts_queued_blocking_read_before_loader_entry() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (entered, entry) = oneshot::channel();
            let (release, ready) = std::sync::mpsc::channel();
            let occupied = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                ready.recv().unwrap();
            });
            entry.await.unwrap();
            let (mut observation, _events) = observation(false, Duration::ZERO);
            let (disposed, disposal) = oneshot::channel();
            let payload = ReadDrop(Some(disposed));
            let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let loader_started = started.clone();
            {
                let next = observation.next(|| {
                    tokio::task::spawn_blocking(move || {
                        loader_started.store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok(payload)
                    })
                });
                tokio::pin!(next);
                assert!(futures_util::poll!(&mut next).is_pending());
            }
            drop(observation);
            release.send(()).unwrap();
            occupied.await.unwrap();
            disposal.await.unwrap();
            assert!(!started.load(std::sync::atomic::Ordering::SeqCst));
        });
    }
}
