//! Reusable fake upstream fixtures for routing and IPC tests.
//!
//! This module is only compiled under `#[cfg(test)]` and provides reusable
//! mock implementations of [`UpstreamConnection`] and [`UpstreamConnector`]
//! that the `state` and `coordinator` test suites share.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use tacacsrs_agent_client::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus,
    AuthorizationOperation, AuthorizationOperationResponse, AuthorizationResponseStatus,
};
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tokio::sync::Mutex;

use crate::upstream::{UpstreamConnection, UpstreamConnector};

#[derive(Debug)]
pub(crate) struct FakeConnection {
    pub address: String,
    pub usable: AtomicBool,
    pub fail_next_request: AtomicBool,
}

#[async_trait]
impl UpstreamConnection for FakeConnection {
    fn server_address(&self) -> &str {
        &self.address
    }

    async fn stop_accepting_new_sessions(&self) {
        self.usable.store(false, Ordering::Relaxed);
    }

    async fn send_accounting(
        &self,
        _request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        if self.fail_next_request.swap(false, Ordering::Relaxed) {
            self.usable.store(false, Ordering::Relaxed);
            anyhow::bail!("simulated failure from {}", self.address);
        }

        Ok(AccountingOperationResponse {
            server: self.address.clone(),
            status: AccountingResponseStatus::Success,
            server_message: format!("handled by {}", self.address),
            data: String::new(),
        })
    }

    async fn send_authorization(
        &self,
        _request: &AuthorizationOperation,
    ) -> anyhow::Result<AuthorizationOperationResponse> {
        if self.fail_next_request.swap(false, Ordering::Relaxed) {
            self.usable.store(false, Ordering::Relaxed);
            anyhow::bail!("simulated failure from {}", self.address);
        }

        Ok(AuthorizationOperationResponse {
            server: self.address.clone(),
            status: AuthorizationResponseStatus::PassAdd,
            server_message: format!("authorized by {}", self.address),
            args: Vec::new(),
            data: String::new(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct FakeConnector {
    pub connections: HashMap<String, Arc<FakeConnection>>,
    connect_attempts: Mutex<HashMap<String, usize>>,
    connect_delay: Duration,
    in_flight_connects: AtomicUsize,
    max_in_flight_connects: AtomicUsize,
}

impl FakeConnector {
    pub fn new(connections: HashMap<String, Arc<FakeConnection>>) -> Self {
        Self {
            connections,
            connect_attempts: Mutex::new(HashMap::new()),
            connect_delay: Duration::ZERO,
            in_flight_connects: AtomicUsize::new(0),
            max_in_flight_connects: AtomicUsize::new(0),
        }
    }

    pub fn with_connect_delay(mut self, connect_delay: Duration) -> Self {
        self.connect_delay = connect_delay;
        self
    }

    pub async fn connect_attempts_for(&self, address: &str) -> usize {
        *self
            .connect_attempts
            .lock()
            .await
            .get(address)
            .unwrap_or(&0)
    }

    pub fn max_in_flight_connects(&self) -> usize {
        self.max_in_flight_connects.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl UpstreamConnector for FakeConnector {
    async fn connect(
        &self,
        server: &TacacsPlusServer,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let address = server.socket_address();
        {
            let mut attempts = self.connect_attempts.lock().await;
            *attempts.entry(address.clone()).or_default() += 1;
        }

        let in_flight = self.in_flight_connects.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_in_flight_connects
            .fetch_max(in_flight, Ordering::Relaxed);
        if !self.connect_delay.is_zero() {
            tokio::time::sleep(self.connect_delay).await;
        }

        let connection = self
            .connections
            .get(&address)
            .with_context(|| format!("missing fake connection for {address}"))?;

        let result = if connection.usable.load(Ordering::Relaxed) {
            Ok(Arc::clone(connection) as Arc<dyn UpstreamConnection>)
        } else {
            Err(anyhow::anyhow!("{address} is currently down"))
        };

        self.in_flight_connects.fetch_sub(1, Ordering::Relaxed);
        result
    }
}
