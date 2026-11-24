//! Named tasks owned by one application run.
//!
//! A critical task must run until shutdown. An early return stops the
//! application. A background task follows the hosted service model: an early
//! `Ok(())` return is complete work, and the application continues. An error
//! or a panic from either kind stops the application.

use std::collections::HashMap;
use std::future::Future;

use anyhow::Context;
use tokio::task::{Id, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{RuntimeHealthPublisher, RuntimeLifecycle};

#[derive(Clone, Copy, PartialEq, Eq)]
enum TaskKind {
    Critical,
    Background,
}

pub(super) struct CriticalTasks {
    tasks: JoinSet<anyhow::Result<()>>,
    names: HashMap<Id, (&'static str, TaskKind)>,
    cancellation: CancellationToken,
}

impl CriticalTasks {
    pub(super) fn new(cancellation: CancellationToken) -> Self {
        Self {
            tasks: JoinSet::new(),
            names: HashMap::new(),
            cancellation,
        }
    }

    /// Spawns a task that must run until shutdown.
    pub(super) fn spawn(
        &mut self,
        name: &'static str,
        future: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) {
        self.spawn_kind(name, TaskKind::Critical, future);
    }

    /// Spawns a task that can complete before shutdown.
    pub(super) fn spawn_background(
        &mut self,
        name: &'static str,
        future: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) {
        self.spawn_kind(name, TaskKind::Background, future);
    }

    fn spawn_kind(
        &mut self,
        name: &'static str,
        kind: TaskKind,
        future: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) {
        let task = self.tasks.spawn(future);
        self.names.insert(task.id(), (name, kind));
    }

    pub(super) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Returns the result of the next task that affects the application.
    ///
    /// Before shutdown, the method logs a background task that returns
    /// `Ok(())` and waits for the next task.
    async fn next(&mut self, shutting_down: bool) -> Option<anyhow::Result<()>> {
        loop {
            let result = self.tasks.join_next_with_id().await?;
            let id = match &result {
                Ok((id, _)) => *id,
                Err(error) => error.id(),
            };
            let (name, kind) = self
                .names
                .remove(&id)
                .expect("every application task has a registered name");
            return Some(match result {
                Ok((_, Ok(()))) if shutting_down => Ok(()),
                Ok((_, Ok(()))) if kind == TaskKind::Background => {
                    log::info!("{name} completed");
                    continue;
                }
                Ok((_, Ok(()))) => Err(anyhow::anyhow!("{name} stopped unexpectedly")),
                Ok((_, result)) => result.with_context(|| format!("{name} failed")),
                Err(error) => {
                    Err(anyhow::Error::new(error).context(format!("{name} task panicked")))
                }
            });
        }
    }
}

impl Drop for CriticalTasks {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.tasks.abort_all();
    }
}

/// Drives the domain future in place so forced service cleanup cannot drop it.
pub(super) async fn supervise(
    stop: impl Future<Output = ()>,
    service: impl Future<Output = anyhow::Result<()>>,
    mut tasks: CriticalTasks,
    cancellation: CancellationToken,
    health: RuntimeHealthPublisher,
    deadline: impl FnOnce() -> anyhow::Result<super::shutdown::ShutdownDeadlines>,
) -> anyhow::Result<()> {
    tokio::pin!(service);
    let mut health_events = health.subscribe();
    let domain_stopping = async {
        loop {
            if matches!(
                health_events.borrow_and_update().lifecycle(),
                RuntimeLifecycle::Draining | RuntimeLifecycle::Failed | RuntimeLifecycle::Stopped
            ) {
                return;
            }
            if health_events.changed().await.is_err() {
                return;
            }
        }
    };
    let mut completed = false;
    let mut result = tokio::select! {
        biased;
        () = stop => Ok(()),
        () = cancellation.cancelled() => Ok(()),
        result = &mut service => { completed = true; result },
        Some(result) = tasks.next(false) => result,
        () = domain_stopping => Ok(()),
    };
    let overall = match deadline() {
        Ok(deadlines) => deadlines.overall.expires_at(),
        Err(error) => {
            if result.is_ok() {
                result = Err(error);
            }
            tokio::time::Instant::now()
        }
    };
    health.set_lifecycle(
        if result.is_err() || health.snapshot().lifecycle() == RuntimeLifecycle::Failed {
            RuntimeLifecycle::Failed
        } else {
            RuntimeLifecycle::Draining
        },
    );
    cancellation.cancel();
    let mut timed_out = false;
    let mut timeout_is_primary = false;
    loop {
        if completed && tasks.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            next = &mut service, if !completed => {
                completed = true;
                if result.is_ok() || (timeout_is_primary && next.is_err()) {
                    result = next;
                    timeout_is_primary = false;
                }
            },
            Some(next) = tasks.next(true), if !tasks.is_empty() => {
                if result.is_ok() { result = next; }
            },
            () = tokio::time::sleep_until(overall), if !timed_out && !tasks.is_empty() => {
                timed_out = true;
                tasks.tasks.abort_all();
                if result.is_ok() {
                    timeout_is_primary = true;
                    result = Err(anyhow::anyhow!("Shutdown deadline elapsed"));
                }
            },
        }
    }
    health.set_lifecycle(if result.is_err() {
        RuntimeLifecycle::Failed
    } else {
        RuntimeLifecycle::Stopped
    });
    result
}
