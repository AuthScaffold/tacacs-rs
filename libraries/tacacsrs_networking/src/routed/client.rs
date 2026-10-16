//! Endpoint selection, reconnect serialization, and binding outcomes.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::bail;

use super::{Endpoint, EndpointConnector, NativeConnector, OperationKind};
use super::catalog::{CachedConnection, Catalog, EndpointSlot};
use super::circuit::RecoveryPermit;
use super::lifecycle::{EndpointLifecycle, RoutingRuntime};

struct ConnectFailure {
    generation: u64,
    source: anyhow::Error,
}

/// A routed client with one immutable catalog and shared operation state.
///
/// Clones retain the catalog. [`Self::with_endpoints`] creates a replacement
/// without changing existing requests. No agent, listener, or schema is required.
pub struct RoutedClient<Connector: EndpointConnector = NativeConnector> {
    catalog: Arc<Catalog<Connector>>,
    connector: Arc<Connector>,
    runtime: Arc<RoutingRuntime<Connector>>,
}

impl<Connector: EndpointConnector> Clone for RoutedClient<Connector> {
    fn clone(&self) -> Self {
        Self {
            catalog: Arc::clone(&self.catalog),
            connector: Arc::clone(&self.connector),
            runtime: Arc::clone(&self.runtime),
        }
    }
}

impl RoutedClient {
    /// Creates a native routed client without opening connections.
    #[must_use]
    pub fn new(endpoints: Vec<Endpoint>) -> Self {
        Self::with_connector(endpoints, NativeConnector)
    }
}

impl<Connector: EndpointConnector> RoutedClient<Connector> {
    /// Creates a routed client with a host-supplied connection factory.
    pub fn with_connector(endpoints: Vec<Endpoint>, connector: Connector) -> Self {
        let connector = Arc::new(connector);
        let runtime = Arc::new(RoutingRuntime::default());
        let slots = endpoints
            .into_iter()
            .map(|endpoint| {
                let lifecycle = Arc::new(EndpointLifecycle::new(connector.clone()));
                runtime.register(lifecycle.clone());
                Arc::new(EndpointSlot::new(endpoint, lifecycle))
            })
            .collect();
        Self {
            catalog: Arc::new(Catalog::new(slots)),
            connector,
            runtime,
        }
    }

    /// Builds a replacement catalog, retaining state for cloned endpoint identities.
    pub async fn with_endpoints(&self, endpoints: Vec<Endpoint>) -> Self {
        let slots = endpoints
            .into_iter()
            .map(|endpoint| {
                self.catalog
                    .endpoints
                    .iter()
                    .find(|slot| slot.endpoint.same_identity(&endpoint))
                    .cloned()
                    .unwrap_or_else(|| {
                        let lifecycle = Arc::new(EndpointLifecycle::new(self.connector.clone()));
                        self.runtime.register(lifecycle.clone());
                        Arc::new(EndpointSlot::new(endpoint, lifecycle))
                    })
            })
            .collect();
        let replacement = Self {
            catalog: Arc::new(Catalog::new(slots)),
            connector: Arc::clone(&self.connector),
            runtime: Arc::clone(&self.runtime),
        };
        for operation in OperationKind::ALL {
            if let Some(previous) = self.active_endpoint(operation).await {
                let route = replacement.catalog.route(operation);
                if let Some(position) = route.indices.iter().position(|index| {
                    replacement.catalog.endpoints[*index].endpoint.name() == previous.name()
                }) {
                    *route
                        .active_position
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = position;
                }
            }
        }
        replacement
    }

    /// Returns the number of endpoints eligible for the operation.
    #[must_use]
    pub fn eligible_count(&self, operation: OperationKind) -> usize {
        self.catalog.route(operation).indices.len()
    }

    /// Returns the current preferred endpoint for the operation.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "Retain the async routing API while reading state without yielding."
    )]
    pub async fn active_endpoint(&self, operation: OperationKind) -> Option<&Endpoint> {
        let route = self.catalog.route(operation);
        let position = *route
            .active_position
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        route
            .indices
            .get(position)
            .map(|index| &self.catalog.endpoints[*index].endpoint)
    }

    /// Retires cached connections absent from a published replacement catalog.
    ///
    /// Existing bindings retain their connection handles and can finish.
    pub async fn retire_replaced(&self, replacement: &Self) {
        for slot in self.catalog.endpoints.iter().filter(|old| {
            !replacement
                .catalog
                .endpoints
                .iter()
                .any(|new| Arc::ptr_eq(old, new))
        }) {
            for operation in &slot.operations {
                let cached = operation
                    .connection
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(cached) = cached {
                    self.connector.retire(&cached.connection).await;
                }
            }
        }
    }

    /// Schedules terminal retirement of removed endpoints without delaying publication.
    /// Existing captured catalogs can use them only until the supplied deadline.
    pub fn retire_replaced_until(&self, replacement: &Self, deadline: crate::RequestDeadline) {
        for slot in self.catalog.endpoints.iter().filter(|old| {
            !replacement
                .catalog
                .endpoints
                .iter()
                .any(|new| Arc::ptr_eq(old, new))
        }) {
            slot.lifecycle.retire(deadline);
        }
    }

    /// Permanently rejects work in this client and all related replacement catalogs.
    pub fn close(&self) {
        self.runtime.close();
    }

    /// Rejects new work and schedules immediate owned cleanup without waiting.
    /// Use [`Self::close_and_join`] to confirm cleanup completion.
    pub fn cancel(&self) {
        self.runtime.cancel();
    }

    /// Closes and joins current and previously removed endpoints under one budget.
    ///
    /// # Errors
    /// Returns a connector or task failure after completing other cleanup.
    pub async fn close_and_join(&self, deadline: crate::RequestDeadline) -> anyhow::Result<()> {
        self.runtime.close_and_join(deadline).await
    }

    /// Selects an eligible endpoint and obtains its operation-isolated connection.
    ///
    /// # Errors
    /// Returns an error if no endpoint is eligible or available for the operation.
    pub async fn bind(
        &self,
        operation: OperationKind,
        recovery_interval: Duration,
    ) -> anyhow::Result<BoundEndpoint<Connector>> {
        self.runtime.ensure_open()?;
        let route = self.catalog.route(operation);
        if route.indices.is_empty() {
            bail!("No configured TACACS+ server supports {}", operation.name());
        }
        let start = *route
            .active_position
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for index in &route.indices {
            let slot = &self.catalog.endpoints[*index];
            let Some(permit) = slot
                .operation(operation)
                .circuit
                .try_begin_recovery(recovery_interval)
            else {
                continue;
            };
            match self.ensure_connection(slot, operation).await {
                Ok(cached) => return Ok(self.binding(*index, operation, cached, Some(permit))),
                Err(error) => {
                    log::warn!(
                        "{} recovery connection to {} failed: {:#}",
                        operation.name(),
                        slot.endpoint.prepared().address(),
                        error.source
                    );
                    self.note_failure(*index, operation, error.generation).await;
                }
            }
        }
        for offset in 0..route.indices.len() {
            let position = (start + offset) % route.indices.len();
            let index = route.indices[position];
            let slot = &self.catalog.endpoints[index];
            if slot.operation(operation).circuit.is_open() {
                continue;
            }
            match self.ensure_connection(slot, operation).await {
                Ok(cached) => {
                    *route
                        .active_position
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = position;
                    return Ok(self.binding(index, operation, cached, None));
                }
                Err(error) => {
                    log::warn!(
                        "{} connection to {} failed: {:#}",
                        operation.name(),
                        slot.endpoint.prepared().address(),
                        error.source
                    );
                    self.note_failure(index, operation, error.generation).await;
                }
            }
        }
        bail!("No TACACS+ server is available for {}", operation.name())
    }

    fn binding(
        &self,
        index: usize,
        operation: OperationKind,
        cached: CachedConnection<Connector::Connection>,
        recovery_permit: Option<RecoveryPermit>,
    ) -> BoundEndpoint<Connector> {
        BoundEndpoint {
            client: self.clone(),
            index,
            operation,
            cached,
            recovery_permit,
        }
    }

    async fn ensure_connection(
        &self,
        slot: &EndpointSlot<Connector>,
        operation: OperationKind,
    ) -> Result<CachedConnection<Connector::Connection>, ConnectFailure> {
        let state = slot.operation(operation);
        slot.lifecycle
            .ensure_open()
            .map_err(|source| ConnectFailure {
                generation: state.connection_generation.load(Ordering::Acquire),
                source,
            })?;
        if let Some(cached) = state
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            return Ok(CachedConnection {
                generation: cached.generation,
                connection: Arc::clone(&cached.connection),
            });
        }
        let previous = state.completed_connect_attempts.load(Ordering::Acquire);
        let _guard = state.connect_lock.lock().await;
        slot.lifecycle
            .ensure_open()
            .map_err(|source| ConnectFailure {
                generation: state.connection_generation.load(Ordering::Acquire),
                source,
            })?;
        if let Some(cached) = state
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            return Ok(CachedConnection {
                generation: cached.generation,
                connection: Arc::clone(&cached.connection),
            });
        }
        let completed = state.completed_connect_attempts.load(Ordering::Acquire);
        if completed != previous {
            return Err(ConnectFailure {
                generation: state.connection_generation.load(Ordering::Acquire),
                source: anyhow::anyhow!(
                    "Another {} connection attempt to {} completed for this request",
                    operation.name(),
                    slot.endpoint.prepared().address()
                ),
            });
        }
        let generation = {
            let _cache = state
                .connection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state
                .connection_generation
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1)
        };
        let result = slot
            .lifecycle
            .connect(slot.endpoint.prepared().clone(), operation)
            .await;
        let mut cache = state
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .completed_connect_attempts
            .fetch_add(1, Ordering::AcqRel);
        let pending = result.map_err(|source| ConnectFailure { generation, source })?;
        slot.lifecycle
            .ensure_open()
            .map_err(|source| ConnectFailure { generation, source })?;
        let connection = pending.adopt();
        *cache = Some(CachedConnection {
            generation,
            connection: Arc::clone(&connection),
        });
        Ok(CachedConnection {
            generation,
            connection,
        })
    }

    async fn note_failure(&self, index: usize, operation: OperationKind, failed_generation: u64) {
        if let Some(connection) = self.invalidate_failure(index, operation, failed_generation) {
            self.connector.retire(&connection).await;
        }
    }

    fn invalidate_failure(
        &self,
        index: usize,
        operation: OperationKind,
        failed_generation: u64,
    ) -> Option<Arc<Connector::Connection>> {
        let state = self.catalog.endpoints[index].operation(operation);
        let mut cache = state
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failed_generation != state.connection_generation.load(Ordering::Acquire) {
            return None;
        }
        if state.failed_generation.load(Ordering::Acquire) == failed_generation {
            return None;
        }
        state
            .failed_generation
            .store(failed_generation, Ordering::Release);
        let cached = cache.take();
        state.circuit.open();
        self.catalog.route(operation).advance_if_active(index);
        cached.map(|cached| cached.connection)
    }
}

/// Reports an interrupted upstream attempt unless explicitly disarmed.
///
/// Dropping this guard updates its captured connection generation synchronously.
/// Connector retirement remains owned by the endpoint lifecycle.
pub struct FailureObservation<Connector: EndpointConnector> {
    client: RoutedClient<Connector>,
    index: usize,
    operation: OperationKind,
    generation: u64,
    armed: bool,
}

impl<Connector: EndpointConnector> FailureObservation<Connector> {
    /// Marks a valid response or local validation failure as non-interrupted.
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<Connector: EndpointConnector> Drop for FailureObservation<Connector> {
    fn drop(&mut self) {
        if self.armed {
            if let Some(connection) =
                self.client
                    .invalidate_failure(self.index, self.operation, self.generation)
            {
                self.client.catalog.endpoints[self.index]
                    .lifecycle
                    .retire_failed(connection);
            }
        }
    }
}

/// Connection and outcome-reporting identity for one selected endpoint.
pub struct BoundEndpoint<Connector: EndpointConnector = NativeConnector> {
    client: RoutedClient<Connector>,
    index: usize,
    operation: OperationKind,
    cached: CachedConnection<Connector::Connection>,
    recovery_permit: Option<RecoveryPermit>,
}

impl<Connector: EndpointConnector> BoundEndpoint<Connector> {
    /// Arms cancellation-safe failure reporting for upstream I/O only.
    #[must_use]
    pub fn observe_failure(&self) -> FailureObservation<Connector> {
        FailureObservation {
            client: self.client.clone(),
            index: self.index,
            operation: self.operation,
            generation: self.cached.generation,
            armed: true,
        }
    }

    /// Returns the selected prepared endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.client.catalog.endpoints[self.index].endpoint
    }

    /// Returns the selected endpoint's catalog position.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Borrows the shared connection handle used to execute an exchange.
    #[must_use]
    pub fn connection(&self) -> &Arc<Connector::Connection> {
        &self.cached.connection
    }

    /// Returns the connection attempt identity for diagnostics.
    #[must_use]
    pub const fn connection_generation(&self) -> u64 {
        self.cached.generation
    }

    /// Records a failed attempt against the catalog and connection it used.
    ///
    /// Invalidation completes without yielding. Connector retirement is owned
    /// by the lifecycle and cannot extend the caller's request deadline.
    #[allow(
        clippy::unused_async,
        reason = "Retain the async reporting API while committing failure state without yielding."
    )]
    pub async fn note_failure(&self) {
        drop(self.observe_failure());
    }

    /// Completes a recovery trial after a successful real request.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "Retain the async reporting API while committing success state without yielding."
    )]
    pub async fn note_success(&self) {
        let Some(permit) = &self.recovery_permit else {
            return;
        };
        let state = self.client.catalog.endpoints[self.index].operation(self.operation);
        let cache = state
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.cached.generation != state.connection_generation.load(Ordering::Acquire) {
            return;
        }
        if cache
            .as_ref()
            .is_none_or(|cached| cached.generation != self.cached.generation)
        {
            return;
        }
        if !permit.succeed() {
            return;
        }
        let route = self.client.catalog.route(self.operation);
        if let Some(position) = route.indices.iter().position(|index| *index == self.index) {
            *route
                .active_position
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = position;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use async_trait::async_trait;
    use tokio::sync::Notify;

    use crate::{ConnectOptions, PreparedEndpoint};
    use super::*;

    #[derive(Default)]
    struct ControlledConnector {
        attempts: AtomicUsize,
        retired: AtomicUsize,
        entered: Notify,
        release: Notify,
        block_first: bool,
        fail_first: bool,
    }

    #[async_trait]
    impl EndpointConnector for ControlledConnector {
        type Connection = usize;

        async fn connect(
            &self,
            _endpoint: PreparedEndpoint,
            _operation: OperationKind,
        ) -> anyhow::Result<Arc<usize>> {
            let attempt = self.attempts.fetch_add(1, Ordering::AcqRel) + 1;
            if attempt == 1 {
                if self.block_first {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                if self.fail_first {
                    bail!("injected connection failure");
                }
            }
            Ok(Arc::new(attempt))
        }

        async fn retire(&self, _connection: &usize) {
            self.retired.fetch_add(1, Ordering::AcqRel);
        }

        fn close(&self, _connection: &usize) {}

        async fn close_and_join(
            &self,
            _connection: &usize,
            _deadline: crate::RequestDeadline,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn controlled_client(connector: ControlledConnector) -> RoutedClient<ControlledConnector> {
        RoutedClient::with_connector(
            vec![Endpoint::new(
                "primary",
                PreparedEndpoint::tcp("127.0.0.1:49", false, None, ConnectOptions::default()),
                OperationKind::ALL,
            )],
            connector,
        )
    }

    #[tokio::test]
    async fn stale_failure_guard_cannot_invalidate_recovered_connection() {
        let client = controlled_client(ControlledConnector::default());
        let first = client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        let delayed = first.observe_failure();
        drop(first.observe_failure());
        let recovered = client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        assert_ne!(first.connection_generation(), recovered.connection_generation());
        recovered.note_success().await;
        drop(delayed);
        let next = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(next.connection_generation(), recovered.connection_generation());
        assert!(Arc::ptr_eq(next.connection(), recovered.connection()));
    }

    #[test]
    fn failure_guard_can_be_dropped_outside_runtime_context() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = controlled_client(ControlledConnector::default());
        let bound = runtime
            .block_on(client.bind(OperationKind::Accounting, Duration::ZERO))
            .unwrap();
        drop(bound.observe_failure());
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(1), async {
                while client.connector.retired.load(Ordering::Acquire) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        });
        assert!(client.catalog.endpoints[0]
            .operation(OperationKind::Accounting)
            .circuit
            .is_open());
    }

    #[tokio::test]
    async fn removed_endpoint_closes_at_cutoff_without_closing_replacement() {
        use tokio::io::AsyncReadExt;
        use crate::RequestDeadline;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Endpoint::new(
            "server",
            PreparedEndpoint::tcp(
                listener.local_addr().unwrap().to_string(),
                false,
                None,
                ConnectOptions::default(),
            ),
            OperationKind::ALL,
        );
        let client = RoutedClient::new(vec![endpoint.clone()]);
        let old = client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        let _old_session = old.connection().open_conversation().await.unwrap();
        let (mut old_peer, _) = listener.accept().await.unwrap();
        let replacement = client
            .with_endpoints(vec![Endpoint::new(
                "replacement",
                endpoint.prepared().clone(),
                OperationKind::ALL,
            )])
            .await;
        let current = replacement
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        let _current_session = current.connection().open_conversation().await.unwrap();
        let (mut current_peer, _) = listener.accept().await.unwrap();
        client.retire_replaced_until(
            &replacement,
            RequestDeadline::after(Duration::from_millis(25)).unwrap(),
        );
        client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), old_peer.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .is_err());
        replacement
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        replacement
            .close_and_join(RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        assert_eq!(current_peer.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(client
            .bind(OperationKind::Authorization, Duration::ZERO)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn shutdown_joins_connections_retained_across_multiple_catalogs() {
        use crate::RequestDeadline;
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = || {
            Endpoint::new(
                "server",
                PreparedEndpoint::tcp(
                    listener.local_addr().unwrap().to_string(),
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                OperationKind::ALL,
            )
        };
        let mut client = RoutedClient::new(vec![endpoint()]);
        let mut held = Vec::new();
        let mut peers = Vec::new();
        for _generation in 0..4 {
            let bound = client
                .bind(OperationKind::Accounting, Duration::ZERO)
                .await
                .unwrap();
            let session = bound.connection().open_conversation().await.unwrap();
            peers.push(listener.accept().await.unwrap().0);
            held.push((bound, session));
            let replacement = client.with_endpoints(vec![endpoint()]).await;
            client.retire_replaced_until(
                &replacement,
                RequestDeadline::after(Duration::from_secs(30)).unwrap(),
            );
            client = replacement;
        }
        client
            .close_and_join(RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        for mut peer in peers {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0; 1]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
        for (bound, _session) in held {
            assert!(bound.connection().open_conversation().await.is_err());
        }
    }

    #[tokio::test]
    async fn terminal_close_cancels_parked_bind_and_rejects_replacement_catalogs() {
        use crate::RequestDeadline;

        let client = controlled_client(ControlledConnector {
            block_first: true,
            ..Default::default()
        });
        let pending = client.bind(OperationKind::Accounting, Duration::ZERO);
        tokio::pin!(pending);
        assert!(futures::poll!(&mut pending).is_pending());
        client.connector.entered.notified().await;
        client
            .close_and_join(RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        assert!(pending.await.is_err());
        let replacement = client
            .with_endpoints(vec![client.catalog.endpoints[0].endpoint.clone()])
            .await;
        assert!(replacement
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .is_err());
        assert_eq!(client.connector.attempts.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn concurrent_bindings_share_one_connection_attempt() {
        let client = controlled_client(ControlledConnector {
            block_first: true,
            ..Default::default()
        });
        let first_client = client.clone();
        let first = tokio::spawn(async move {
            first_client
                .bind(OperationKind::Accounting, Duration::from_secs(30))
                .await
        });
        client.connector.entered.notified().await;
        let second = client.bind(OperationKind::Accounting, Duration::from_secs(30));
        tokio::pin!(second);
        assert!(futures::poll!(&mut second).is_pending());
        client.connector.release.notify_one();
        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap();
        assert!(Arc::ptr_eq(first.connection(), second.connection()));
        assert_eq!(client.connector.attempts.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn cancelling_connect_releases_reconnect_serialization() {
        let client = controlled_client(ControlledConnector {
            block_first: true,
            ..Default::default()
        });
        {
            let pending = client.bind(OperationKind::Accounting, Duration::from_secs(30));
            tokio::pin!(pending);
            assert!(futures::poll!(&mut pending).is_pending());
            tokio::time::timeout(Duration::from_secs(1), client.connector.entered.notified())
                .await
                .unwrap();
        }
        let binding = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(**binding.connection(), 2);
    }

    #[tokio::test]
    async fn late_connection_failure_cannot_evict_a_new_connection() {
        let client = controlled_client(ControlledConnector {
            fail_first: true,
            ..Default::default()
        });
        let slot = &client.catalog.endpoints[0];
        let failure = client
            .ensure_connection(slot, OperationKind::Accounting)
            .await
            .err()
            .unwrap();
        let recovered = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        client
            .note_failure(0, OperationKind::Accounting, failure.generation)
            .await;
        let current = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(current.connection(), recovered.connection()));
        assert_eq!(client.connector.attempts.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn catalog_replacement_reuses_only_retained_endpoint_identities() {
        let client = controlled_client(ControlledConnector::default());
        let original = client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        let retained = client
            .with_endpoints(vec![original.endpoint().clone()])
            .await;
        client.retire_replaced(&retained).await;
        let reused = retained
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(original.connection(), reused.connection()));
        assert_eq!(client.connector.retired.load(Ordering::Acquire), 0);

        let replacement = client
            .with_endpoints(vec![Endpoint::new(
                original.endpoint().name(),
                original.endpoint().prepared().clone(),
                OperationKind::ALL,
            )])
            .await;
        let fresh = replacement
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(original.connection(), fresh.connection()));
        client.retire_replaced(&replacement).await;
        assert_eq!(client.connector.retired.load(Ordering::Acquire), 1);
        let old_request = client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        old_request.note_failure().await;
        let current = replacement
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(fresh.connection(), current.connection()));
        assert_eq!(client.connector.attempts.load(Ordering::Acquire), 3);
    }

    #[tokio::test]
    async fn catalog_retains_order_and_operation_eligibility() {
        let first = Endpoint::new(
            "accounting",
            PreparedEndpoint::tcp("127.0.0.1:49", false, None, ConnectOptions::default()),
            [OperationKind::Accounting],
        );
        let second = Endpoint::new(
            "all",
            PreparedEndpoint::tcp("127.0.0.2:49", false, None, ConnectOptions::default()),
            OperationKind::ALL,
        );
        let client = RoutedClient::new(vec![first, second]);
        assert_eq!(client.eligible_count(OperationKind::Accounting), 2);
        assert_eq!(client.eligible_count(OperationKind::Authentication), 1);
        assert_eq!(
            client
                .active_endpoint(OperationKind::Accounting)
                .await
                .unwrap()
                .name(),
            "accounting"
        );
        assert_eq!(
            client
                .active_endpoint(OperationKind::Authentication)
                .await
                .unwrap()
                .name(),
            "all"
        );
    }
}
