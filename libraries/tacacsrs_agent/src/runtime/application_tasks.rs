//! Named critical tasks owned by one application run.

use std::collections::HashMap;
use std::future::Future;

use anyhow::Context;
use futures_util::future::BoxFuture;
use tokio::sync::watch;
use tokio::task::{Id, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{RuntimeHealthPublisher, RuntimeHealthSnapshot, RuntimeLifecycle};

/// Health and cancellation supplied to a process-owned peer.
pub struct PeerContext {
    /// Read-only runtime health.
    pub health: watch::Receiver<RuntimeHealthSnapshot>,
    /// Cancelled when the application starts shutdown.
    /// Cancelling this child token does not stop the application.
    pub cancellation: CancellationToken,
}

/// An inert process service started by the agent runtime.
pub struct RuntimePeer {
    name: &'static str,
    start: Box<dyn FnOnce(PeerContext) -> BoxFuture<'static, anyhow::Result<()>> + Send>,
}

impl RuntimePeer {
    /// Registers a critical service without starting it.
    #[must_use]
    pub fn new<F, Fut>(name: &'static str, start: F) -> Self
    where
        F: FnOnce(PeerContext) -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        Self {
            name,
            start: Box::new(move |context| Box::pin(start(context))),
        }
    }

    pub(super) fn spawn(self, tasks: &mut CriticalTasks, context: PeerContext) {
        tasks.spawn(self.name, (self.start)(context));
    }
}

pub(super) struct CriticalTasks {
    tasks: JoinSet<anyhow::Result<()>>,
    names: HashMap<Id, &'static str>,
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

    pub(super) fn spawn(
        &mut self,
        name: &'static str,
        future: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) {
        let task = self.tasks.spawn(future);
        self.names.insert(task.id(), name);
    }

    async fn next(&mut self, shutting_down: bool) -> Option<anyhow::Result<()>> {
        let result = self.tasks.join_next_with_id().await?;
        let id = match &result {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        let name = self
            .names
            .remove(&id)
            .expect("every critical task has a registered name");
        Some(match result {
            Ok((_, Ok(()))) if !shutting_down => {
                Err(anyhow::anyhow!("{name} stopped unexpectedly"))
            }
            Ok((_, result)) => result.with_context(|| format!("{name} failed")),
            Err(error) => Err(anyhow::Error::new(error).context(format!("{name} task panicked"))),
        })
    }
}

impl Drop for CriticalTasks {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.tasks.abort_all();
    }
}

/// Drives the domain future in place so forced peer cleanup cannot drop it.
pub(super) async fn supervise(
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
        if completed && tasks.tasks.is_empty() {
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
            Some(next) = tasks.next(true), if !tasks.tasks.is_empty() => {
                if result.is_ok() { result = next; }
            },
            () = tokio::time::sleep_until(overall), if !timed_out && !tasks.tasks.is_empty() => {
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
