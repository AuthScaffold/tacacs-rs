//! Shared fake types and helpers for service-layer tests.
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
};
use tokio::sync::{Mutex, Notify};

use crate::upstream::{UpstreamConnection, UpstreamConnector};

// ---------------------------------------------------------------------------
// FakeConnection / FakeConnector — configurable success/failure per server
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(super) struct FakeConnection {
    pub address: String,
    pub usable: AtomicBool,
    pub fail_next_request: AtomicBool,
}

#[async_trait]
impl UpstreamConnection for FakeConnection {
    fn server_address(&self) -> &str {
        &self.address
    }

    async fn is_usable_for_new_sessions(&self) -> bool {
        self.usable.load(Ordering::Relaxed)
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
}

#[derive(Debug)]
pub(super) struct FakeConnector {
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
    async fn connect(&self, address: &str) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        {
            let mut attempts = self.connect_attempts.lock().await;
            *attempts.entry(address.to_owned()).or_default() += 1;
        }

        let in_flight = self.in_flight_connects.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_in_flight_connects
            .fetch_max(in_flight, Ordering::Relaxed);
        if !self.connect_delay.is_zero() {
            tokio::time::sleep(self.connect_delay).await;
        }

        let connection = self
            .connections
            .get(address)
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

// ---------------------------------------------------------------------------
// SingleSessionConnection / SingleSessionConnector — marks itself unusable
// after one accounting call, forcing a reconnect on the next request.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(super) struct SingleSessionConnection {
    address: String,
    usable: AtomicBool,
}

#[async_trait]
impl UpstreamConnection for SingleSessionConnection {
    fn server_address(&self) -> &str {
        &self.address
    }

    async fn is_usable_for_new_sessions(&self) -> bool {
        self.usable.load(Ordering::Relaxed)
    }

    async fn send_accounting(
        &self,
        _request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        self.usable.store(false, Ordering::Relaxed);
        Ok(AccountingOperationResponse {
            server: self.address.clone(),
            status: AccountingResponseStatus::Success,
            server_message: "single-session upstream".to_owned(),
            data: String::new(),
        })
    }
}

#[derive(Debug)]
pub(super) struct SingleSessionConnector {
    pub address: String,
    pub connect_attempts: AtomicUsize,
}

#[async_trait]
impl UpstreamConnector for SingleSessionConnector {
    async fn connect(&self, address: &str) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        assert_eq!(address, self.address);
        self.connect_attempts.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(SingleSessionConnection {
            address: self.address.clone(),
            usable: AtomicBool::new(true),
        }))
    }
}

// ---------------------------------------------------------------------------
// BlockingConnection / BlockingConnector — blocks in send_accounting until
// an external Notify fires, useful for drain / shutdown tests.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(super) struct BlockingConnection {
    pub address: String,
    pub release: Arc<Notify>,
}

#[async_trait]
impl UpstreamConnection for BlockingConnection {
    fn server_address(&self) -> &str {
        &self.address
    }

    async fn is_usable_for_new_sessions(&self) -> bool {
        true
    }

    async fn send_accounting(
        &self,
        _request: &AccountingOperation,
    ) -> anyhow::Result<AccountingOperationResponse> {
        self.release.notified().await;
        Ok(AccountingOperationResponse {
            server: self.address.clone(),
            status: AccountingResponseStatus::Success,
            server_message: String::new(),
            data: String::new(),
        })
    }
}

#[derive(Debug)]
pub(super) struct BlockingConnector {
    pub connection: Arc<BlockingConnection>,
}

#[async_trait]
impl UpstreamConnector for BlockingConnector {
    async fn connect(&self, _address: &str) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        Ok(Arc::clone(&self.connection) as Arc<dyn UpstreamConnection>)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(super) fn build_request() -> AccountingOperation {
    AccountingOperation {
        user: "admin".to_owned(),
        port: "tty0".to_owned(),
        remote_address: "127.0.0.1".to_owned(),
        command: "show".to_owned(),
        command_arguments: vec!["users".to_owned()],
    }
}
