//! Terminal client state, setup ownership, and registered transport lifetimes.

use std::sync::{Arc, Mutex, Weak};

use anyhow::{Context, ensure};
use tokio::sync::oneshot;

use crate::{PreparedEndpoint, RequestDeadline};
use crate::runtime::task::DriverTask;
use crate::transport::BoxedTransport;
use crate::transport::managed::{TransportActivity, TransportControl};

#[derive(Default)]
struct State {
    closed: bool,
    setups: Vec<Arc<DriverTask>>,
    transports: Vec<Weak<TransportControl>>,
    expiries: Vec<Arc<DriverTask>>,
}

#[derive(Default)]
pub(super) struct ClientLifecycle {
    state: Mutex<State>,
    activity: Arc<TransportActivity>,
}

struct SetupRequest(Arc<DriverTask>);

impl Drop for SetupRequest {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl ClientLifecycle {
    pub(super) fn ensure_open(&self) -> anyhow::Result<()> {
        ensure!(
            !self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .closed,
            "The TACACS+ client is closed"
        );
        Ok(())
    }

    pub(super) fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed = true;
        for task in &state.setups {
            task.abort();
        }
    }

    fn register(&self, transport: BoxedTransport) -> anyhow::Result<BoxedTransport> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure!(!state.closed, "The TACACS+ client closed during connection setup");
        let (transport, control) = TransportControl::wrap(transport, self.activity.clone());
        state.expiries.retain(|task| !task.is_finished());
        if let Some(task) = control.expiry_task() {
            state.expiries.push(task);
        }
        state
            .transports
            .retain(|transport| transport.strong_count() > 0);
        state.transports.push(Arc::downgrade(&control));
        Ok(transport)
    }

    pub(super) async fn establish(
        self: &Arc<Self>,
        endpoint: PreparedEndpoint,
    ) -> anyhow::Result<BoxedTransport> {
        let (sender, receiver) = oneshot::channel();
        let task = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ensure!(!state.closed, "The TACACS+ client is closed");
            state.setups.retain(|task| !task.is_finished());
            let lifecycle = Arc::downgrade(self);
            let task = Arc::new(DriverTask::spawn(async move {
                let result = crate::establish::establish_stream(&endpoint)
                    .await
                    .with_context(|| {
                        format!("Failed to connect to TACACS+ server {}", endpoint.address())
                    })
                    .and_then(|transport| {
                        lifecycle
                            .upgrade()
                            .context("The TACACS+ client was dropped")?
                            .register(transport)
                    });
                let _delivered = sender.send(result);
                Ok(())
            }));
            state.setups.push(task.clone());
            task
        };
        let _request = SetupRequest(task);
        receiver
            .await
            .context("TACACS+ connection setup was cancelled")?
    }

    pub(super) async fn join_setups(&self, deadline: RequestDeadline) -> anyhow::Result<()> {
        let setups = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .setups
            .clone();
        let mut failure = None;
        for task in setups {
            if let Err(error) = task.join_until(deadline).await {
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .setups
            .retain(|task| !task.is_finished());
        failure.map_or(Ok(()), Err)
    }

    pub(super) async fn wait_for_transports(&self) {
        self.activity.wait_for_close().await;
    }

    pub(super) async fn join_expiries(&self, deadline: RequestDeadline) -> anyhow::Result<()> {
        let tasks = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expiries
            .clone();
        let mut failure = None;
        for task in tasks {
            if let Err(error) = task.join_until(deadline).await {
                failure.get_or_insert(error);
            }
        }
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expiries
            .retain(|task| !task.is_finished());
        failure.map_or(Ok(()), Err)
    }

    pub(super) fn force_close_transports(&self) {
        let transports = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut state.transports)
        };
        for transport in transports
            .into_iter()
            .filter_map(|transport| transport.upgrade())
        {
            transport.close();
        }
    }
}

impl Drop for ClientLifecycle {
    fn drop(&mut self) {
        self.close();
        self.force_close_transports();
    }
}
