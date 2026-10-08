//! Endpoint selection, reconnect serialization, and binding outcomes.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::bail;

use super::{Endpoint, EndpointConnector, NativeConnector, OperationKind};
use super::catalog::{CachedConnection, Catalog, EndpointSlot};
use super::circuit::RecoveryPermit;

struct ConnectFailure {
    generation: u64,
    source: anyhow::Error,
}

/// A routed client with one immutable catalog and shared operation state.
///
/// Clones retain the catalog. [`Self::with_endpoints`] creates a replacement
/// without changing existing requests. No agent, listener, or schema is required.
pub struct RoutedClient<Connector: EndpointConnector = NativeConnector> {
    catalog: Arc<Catalog<Connector::Connection>>,
    connector: Arc<Connector>,
}

impl<Connector: EndpointConnector> Clone for RoutedClient<Connector> {
    fn clone(&self) -> Self {
        Self {
            catalog: Arc::clone(&self.catalog),
            connector: Arc::clone(&self.connector),
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
        Self {
            catalog: Arc::new(Catalog::new(
                endpoints
                    .into_iter()
                    .map(|endpoint| Arc::new(EndpointSlot::new(endpoint)))
                    .collect(),
            )),
            connector: Arc::new(connector),
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
                    .unwrap_or_else(|| Arc::new(EndpointSlot::new(endpoint)))
            })
            .collect();
        let replacement = Self {
            catalog: Arc::new(Catalog::new(slots)),
            connector: Arc::clone(&self.connector),
        };
        for operation in OperationKind::ALL {
            if let Some(previous) = self.active_endpoint(operation).await {
                let route = replacement.catalog.route(operation);
                if let Some(position) = route.indices.iter().position(|index| {
                    replacement.catalog.endpoints[*index].endpoint.name() == previous.name()
                }) {
                    *route.active_position.write().await = position;
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
    pub async fn active_endpoint(&self, operation: OperationKind) -> Option<&Endpoint> {
        let route = self.catalog.route(operation);
        let position = *route.active_position.read().await;
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
                let cached = operation.connection.write().await.take();
                if let Some(cached) = cached {
                    self.connector.retire(&cached.connection).await;
                }
            }
        }
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
        let route = self.catalog.route(operation);
        if route.indices.is_empty() {
            bail!("No configured TACACS+ server supports {}", operation.name());
        }
        let start = *route.active_position.read().await;
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
                    *route.active_position.write().await = position;
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
        slot: &EndpointSlot<Connector::Connection>,
        operation: OperationKind,
    ) -> Result<CachedConnection<Connector::Connection>, ConnectFailure> {
        let state = slot.operation(operation);
        if let Some(cached) = state.connection.read().await.as_ref() {
            return Ok(CachedConnection {
                generation: cached.generation,
                connection: Arc::clone(&cached.connection),
            });
        }
        let previous = state.completed_connect_attempts.load(Ordering::Acquire);
        let _guard = state.connect_lock.lock().await;
        if let Some(cached) = state.connection.read().await.as_ref() {
            return Ok(CachedConnection {
                generation: cached.generation,
                connection: Arc::clone(&cached.connection),
            });
        }
        let completed = state.completed_connect_attempts.load(Ordering::Acquire);
        if completed != previous {
            return Err(ConnectFailure {
                generation: completed,
                source: anyhow::anyhow!(
                    "Another {} connection attempt to {} completed for this request",
                    operation.name(),
                    slot.endpoint.prepared().address()
                ),
            });
        }
        let result = self
            .connector
            .connect(slot.endpoint.prepared().clone(), operation)
            .await;
        let generation = state
            .completed_connect_attempts
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        let connection = result.map_err(|source| ConnectFailure { generation, source })?;
        *state.connection.write().await = Some(CachedConnection {
            generation,
            connection: Arc::clone(&connection),
        });
        Ok(CachedConnection {
            generation,
            connection,
        })
    }

    async fn note_failure(&self, index: usize, operation: OperationKind, failed_generation: u64) {
        let state = self.catalog.endpoints[index].operation(operation);
        let guard = state.connect_lock.lock().await;
        if failed_generation != state.completed_connect_attempts.load(Ordering::Acquire) {
            return;
        }
        let cached = state.connection.write().await.take();
        state.circuit.open();
        self.catalog.route(operation).advance_if_active(index).await;
        drop(guard);
        if let Some(cached) = cached {
            self.connector.retire(&cached.connection).await;
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
    pub async fn note_failure(&self) {
        self.client
            .note_failure(self.index, self.operation, self.cached.generation)
            .await;
    }

    /// Completes a recovery trial after a successful real request.
    pub async fn note_success(&self) {
        let Some(permit) = &self.recovery_permit else {
            return;
        };
        let state = self.client.catalog.endpoints[self.index].operation(self.operation);
        let _guard = state.connect_lock.lock().await;
        if self.cached.generation != state.completed_connect_attempts.load(Ordering::Acquire) {
            return;
        }
        if !permit.succeed() {
            return;
        }
        let route = self.client.catalog.route(self.operation);
        if let Some(position) = route.indices.iter().position(|index| *index == self.index) {
            *route.active_position.write().await = position;
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
