//! Cancellation-safe ownership of a single connection driver task.

use std::future::Future;

use tokio::sync::Mutex;
use tokio::task::{AbortHandle, JoinHandle};

use crate::RequestDeadline;

pub(crate) struct DriverTask {
    handle: Mutex<Option<JoinHandle<anyhow::Result<()>>>>,
    abort: AbortHandle,
}

impl DriverTask {
    pub(crate) fn spawn(future: impl Future<Output = anyhow::Result<()>> + Send + 'static) -> Self {
        Self::spawn_on(&tokio::runtime::Handle::current(), future)
    }

    pub(crate) fn spawn_on(
        runtime: &tokio::runtime::Handle,
        future: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> Self {
        let handle = runtime.spawn(future);
        Self {
            abort: handle.abort_handle(),
            handle: Mutex::new(Some(handle)),
        }
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.abort.is_finished()
    }

    pub(crate) fn abort(&self) {
        self.abort.abort();
    }

    pub(crate) async fn join_until(&self, deadline: RequestDeadline) -> anyhow::Result<()> {
        let mut slot = if let Ok(slot) = deadline.run(self.handle.lock()).await {
            slot
        } else {
            self.abort.abort();
            self.handle.lock().await
        };
        let Some(handle) = slot.as_mut() else {
            return Ok(());
        };
        let result = match deadline.run(&mut *handle).await {
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            Ok(result) => result
                .map_err(anyhow::Error::from)
                .and_then(std::convert::identity),
            Err(_) => {
                handle.abort();
                match handle.await {
                    Err(error) if error.is_cancelled() => Ok(()),
                    result => result
                        .map_err(anyhow::Error::from)
                        .and_then(std::convert::identity),
                }
            }
        };
        slot.take();
        result
    }
}

impl Drop for DriverTask {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.get_mut().take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    use super::*;

    struct Cleanup(Arc<AtomicBool>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn forced_join_waits_for_cleanup_and_can_be_repeated() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let cleanup = Cleanup(cleaned.clone());
        let task = DriverTask::spawn(async move {
            let _cleanup = cleanup;
            std::future::pending::<()>().await;
            Ok(())
        });
        task.join_until(RequestDeadline::after(Duration::from_secs(1)).unwrap())
            .await
            .unwrap();
        assert!(cleaned.load(Ordering::Acquire));
        task.join_until(RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_join_keeps_task_owned_for_another_join() {
        let task = DriverTask::spawn(std::future::pending());
        {
            let join = task.join_until(RequestDeadline::after(Duration::from_secs(10)).unwrap());
            tokio::pin!(join);
            assert!(futures::poll!(&mut join).is_pending());
        }
        task.join_until(RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        assert!(task.handle.lock().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_shorter_join_can_force_a_longer_waiter() {
        let task = Arc::new(DriverTask::spawn(std::future::pending()));
        let long_task = task.clone();
        let longer = tokio::spawn(async move {
            long_task
                .join_until(RequestDeadline::after(Duration::from_secs(60)).unwrap())
                .await
        });
        tokio::task::yield_now().await;
        let started = tokio::time::Instant::now();
        task.join_until(RequestDeadline::after(Duration::from_secs(1)).unwrap())
            .await
            .unwrap();
        longer.await.unwrap().unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    }
}
