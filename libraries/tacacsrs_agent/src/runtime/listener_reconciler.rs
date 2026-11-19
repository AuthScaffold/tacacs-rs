//! Keeps one local listener in step with the active local services.
//!
//! A reconciler runs for each local service. It reads the active local
//! services and selects one of three states: disabled, waiting for an
//! endpoint, or ready with a bind target. For a new target, the reconciler
//! binds the new listener instance first. Then it stops the old instance. If
//! the two targets use the same socket, the reconciler stops the old instance
//! first.
//!
//! A bind failure keeps the old instance. The reconciler tries the bind again
//! after a delay that starts at 1 s and doubles up to 30 s. A different target
//! starts at once with the first delay. An error from a bound instance stops
//! the reconciler with that error.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tacacsrs_config::local_services::ListenerEndpoint;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

use super::local_services::ActiveLocalServices;
use super::{ListenerState, RuntimeHealthPublisher, RuntimeService, ShutdownReceiver};

/// The first delay after a bind failure.
const INITIAL_BIND_RETRY: Duration = Duration::from_secs(1);
/// The longest delay between bind attempts.
const MAXIMUM_BIND_RETRY: Duration = Duration::from_secs(30);

/// The state that the local services select for one listener.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum DesiredListener<Target> {
    /// The service is disabled.
    Disabled,
    /// The service is enabled, and its endpoint is not known yet.
    Waiting,
    /// The service is enabled with this bind target.
    Ready(Target),
}

/// Tells the reconciler that a listener instance accepts work.
#[derive(Debug)]
pub(crate) struct BindSignal(watch::Sender<bool>);

impl BindSignal {
    /// Records that the listener instance is bound.
    pub(crate) fn mark_bound(&self) {
        self.0.send_replace(true);
    }
}

/// Creates the listener instances of one local service.
pub(crate) trait ListenerInstances: Send + Sync + 'static {
    /// The bind target and the settings of one instance.
    type Target: Clone + Eq + fmt::Debug + Send + Sync + 'static;

    /// Returns the local service.
    fn service(&self) -> RuntimeService;

    /// Selects the listener state from the local services.
    fn desired(&self, local: &ActiveLocalServices) -> DesiredListener<Self::Target>;

    /// Returns whether the two targets use the same socket.
    fn conflicts(&self, active: &Self::Target, next: &Self::Target) -> bool;

    /// Starts one instance.
    ///
    /// The instance binds, calls [`BindSignal::mark_bound`], and serves until
    /// `shutdown` fires. An error before `mark_bound` is a bind failure.
    fn start(
        &self,
        target: Self::Target,
        shutdown: ShutdownReceiver,
        bound: BindSignal,
    ) -> BoxFuture<'static, anyhow::Result<()>>;
}

/// Returns whether two endpoints use the same socket.
pub(crate) fn endpoints_conflict(active: &ListenerEndpoint, next: &ListenerEndpoint) -> bool {
    match (active, next) {
        (ListenerEndpoint::Unix(active), ListenerEndpoint::Unix(next)) => active == next,
        (ListenerEndpoint::Tcp(active), ListenerEndpoint::Tcp(next)) => {
            active.port() != 0
                && active.port() == next.port()
                && (active.ip().to_canonical() == next.ip().to_canonical()
                    || active.ip().is_unspecified()
                    || next.ip().is_unspecified())
        }
        _ => false,
    }
}

struct Instance<Target> {
    target: Target,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<anyhow::Result<()>>,
}

impl<Target> Instance<Target> {
    fn stop(&self) {
        self.shutdown.send_replace(true);
    }
}

enum StartOutcome<Target> {
    Bound(Instance<Target>),
    Failed(anyhow::Error),
    Shutdown(Instance<Target>),
}

struct Reconciler<Instances: ListenerInstances> {
    instances: Instances,
    health: RuntimeHealthPublisher,
    active: Option<Instance<Instances::Target>>,
    retiring: JoinSet<anyhow::Result<()>>,
    retry_delay: Duration,
    retry_at: Option<Instant>,
    failed_target: Option<Instances::Target>,
}

/// Runs the listener of one service until `shutdown` fires.
///
/// # Errors
/// Returns the error of a bound listener instance after the reconciler stops
/// each other instance.
pub(crate) async fn reconcile<Instances: ListenerInstances>(
    instances: Instances,
    mut local: watch::Receiver<Arc<ActiveLocalServices>>,
    shutdown: ShutdownReceiver,
    health: RuntimeHealthPublisher,
) -> anyhow::Result<()> {
    let mut reconciler = Reconciler {
        instances,
        health,
        active: None,
        retiring: JoinSet::new(),
        retry_delay: INITIAL_BIND_RETRY,
        retry_at: None,
        failed_target: None,
    };
    let stop = shutdown.clone().wait();
    tokio::pin!(stop);
    let mut local_open = true;
    let result = loop {
        let desired = reconciler.instances.desired(&local.borrow_and_update());
        if reconciler.apply(desired, &shutdown, &mut stop).await {
            break Ok(());
        }
        let retry_at = reconciler.retry_at;
        let active = &mut reconciler.active;
        let retiring = &mut reconciler.retiring;
        let event = tokio::select! {
            biased;
            () = &mut stop => Event::Shutdown,
            changed = local.changed(), if local_open => Event::LocalServices(changed.is_ok()),
            exit = async {
                (&mut active.as_mut().expect("the branch needs an active instance").task).await
            }, if active.is_some() => Event::ActiveStopped(flatten(exit)),
            Some(exit) = retiring.join_next(), if !retiring.is_empty() => {
                Event::Retired(flatten(exit))
            }
            () = async {
                tokio::time::sleep_until(retry_at.expect("the branch needs a retry time")).await;
            }, if retry_at.is_some() => Event::Retry,
        };
        match event {
            Event::Shutdown => break Ok(()),
            Event::LocalServices(open) => local_open = open,
            Event::ActiveStopped(exit) => {
                reconciler.active = None;
                if let Err(error) = exit {
                    break Err(error);
                }
                log::info!("The {} listener stopped before shutdown", label(reconciler.service()));
                reconciler.set_state(ListenerState::Stopped);
            }
            Event::Retired(exit) => {
                if let Err(error) = exit {
                    log::warn!(
                        "A retired {} listener stopped with an error: {error:#}",
                        label(reconciler.service())
                    );
                }
            }
            Event::Retry => reconciler.retry_at = None,
        }
    };
    reconciler.stop_all().await;
    result
}

enum Event {
    Shutdown,
    LocalServices(bool),
    ActiveStopped(anyhow::Result<()>),
    Retired(anyhow::Result<()>),
    Retry,
}

impl<Instances: ListenerInstances> Reconciler<Instances> {
    fn service(&self) -> RuntimeService {
        self.instances.service()
    }

    fn set_state(&self, state: ListenerState) {
        self.health.set_listener(self.service(), state);
    }

    fn clear_retry(&mut self) {
        self.retry_delay = INITIAL_BIND_RETRY;
        self.retry_at = None;
        self.failed_target = None;
    }

    fn retire(&mut self, instance: Instance<Instances::Target>) {
        instance.stop();
        let task = instance.task;
        self.retiring.spawn(async move { flatten(task.await) });
    }

    /// Moves the listener toward `desired`. Returns `true` on shutdown.
    async fn apply(
        &mut self,
        desired: DesiredListener<Instances::Target>,
        shutdown: &ShutdownReceiver,
        stop: &mut (impl std::future::Future<Output = ()> + Unpin),
    ) -> bool {
        let target = match desired {
            DesiredListener::Disabled => {
                if let Some(active) = self.active.take() {
                    self.retire(active);
                }
                self.clear_retry();
                self.set_state(ListenerState::Disabled);
                return false;
            }
            DesiredListener::Waiting => {
                if let Some(active) = self.active.take() {
                    self.retire(active);
                }
                self.clear_retry();
                self.set_state(ListenerState::Pending);
                return false;
            }
            DesiredListener::Ready(target) => target,
        };
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.target == target)
        {
            self.clear_retry();
            return false;
        }
        if self.failed_target.as_ref() == Some(&target) {
            if self.retry_at.is_some_and(|at| at > Instant::now()) {
                return false;
            }
        } else {
            self.clear_retry();
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| self.instances.conflicts(&active.target, &target))
        {
            let active = self.active.take().expect("the active instance was checked");
            active.stop();
            if let Err(error) = flatten(active.task.await) {
                log::warn!(
                    "The {} listener stopped with an error before it moved: {error:#}",
                    label(self.service())
                );
            }
        }
        if self.active.is_none() {
            self.set_state(ListenerState::Binding);
        }
        match self.start(target.clone(), shutdown, stop).await {
            StartOutcome::Bound(instance) => {
                if let Some(previous) = self.active.replace(instance) {
                    self.retire(previous);
                }
                self.clear_retry();
                self.set_state(ListenerState::Bound);
                false
            }
            StartOutcome::Failed(error) => {
                log::warn!(
                    "The {} listener could not bind. The runtime tries again in {} s: {error:#}",
                    label(self.service()),
                    self.retry_delay.as_secs()
                );
                self.retry_at = Some(Instant::now() + self.retry_delay);
                self.retry_delay = (self.retry_delay * 2).min(MAXIMUM_BIND_RETRY);
                self.failed_target = Some(target);
                false
            }
            StartOutcome::Shutdown(instance) => {
                self.retire(instance);
                true
            }
        }
    }

    async fn start(
        &self,
        target: Instances::Target,
        shutdown: &ShutdownReceiver,
        stop: &mut (impl std::future::Future<Output = ()> + Unpin),
    ) -> StartOutcome<Instances::Target> {
        let (instance_shutdown, flag) = watch::channel(*shutdown.flag().borrow());
        let (bound, mut bound_receiver) = watch::channel(false);
        let task = tokio::spawn(self.instances.start(
            target.clone(),
            ShutdownReceiver::from_flag(flag),
            BindSignal(bound),
        ));
        let mut instance = Instance {
            target,
            shutdown: instance_shutdown,
            task,
        };
        tokio::select! {
            biased;
            () = &mut *stop => StartOutcome::Shutdown(instance),
            bound = async { bound_receiver.wait_for(|bound| *bound).await.is_ok() } => {
                if bound {
                    return StartOutcome::Bound(instance);
                }
                match flatten((&mut instance.task).await) {
                    Err(error) => StartOutcome::Failed(error),
                    Ok(()) => StartOutcome::Failed(anyhow::anyhow!("the listener stopped before it was bound")),
                }
            }
        }
    }

    async fn stop_all(&mut self) {
        if let Some(active) = self.active.take() {
            self.retire(active);
        }
        while let Some(exit) = self.retiring.join_next().await {
            if let Err(error) = flatten(exit) {
                log::warn!(
                    "A {} listener stopped with an error during shutdown: {error:#}",
                    label(self.service())
                );
            }
        }
        if self.health.snapshot().listener(self.service()) != ListenerState::Disabled {
            self.set_state(ListenerState::Stopped);
        }
    }
}

fn flatten(exit: Result<anyhow::Result<()>, tokio::task::JoinError>) -> anyhow::Result<()> {
    exit.map_err(anyhow::Error::from)
        .and_then(std::convert::identity)
}

fn label(service: RuntimeService) -> &'static str {
    match service {
        RuntimeService::ClientApi => "client API",
        RuntimeService::TacacsProxy => "TACACS+ proxy",
    }
}

#[cfg(test)]
mod tests;
