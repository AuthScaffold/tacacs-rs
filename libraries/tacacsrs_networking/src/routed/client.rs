//! Endpoint selection, reconnect serialization, and binding outcomes.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::bail;

use super::{Endpoint, EndpointConnector, NativeConnector, OperationKind};
use super::binding::{BoundEndpoint, RecoveryClaim};
use super::catalog::{CachedConnection, Catalog, EndpointSlot};
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
    pub(super) catalog: Arc<Catalog<Connector>>,
    connector: Arc<Connector>,
    runtime: Arc<RoutingRuntime<Connector>>,
    #[cfg(test)]
    drop_checkpoint: Option<Arc<std::sync::Barrier>>,
}

impl<Connector: EndpointConnector> Clone for RoutedClient<Connector> {
    fn clone(&self) -> Self {
        Self {
            catalog: Arc::clone(&self.catalog),
            connector: Arc::clone(&self.connector),
            runtime: Arc::clone(&self.runtime),
            #[cfg(test)]
            drop_checkpoint: self.drop_checkpoint.clone(),
        }
    }
}

#[cfg(test)]
impl<Connector: EndpointConnector> Drop for RoutedClient<Connector> {
    fn drop(&mut self) {
        if let Some(checkpoint) = &self.drop_checkpoint {
            checkpoint.wait();
            checkpoint.wait();
        }
    }
}

impl RoutedClient {
    /// Creates a native routed client without opening connections.
    #[must_use]
    pub fn new(endpoints: Vec<Endpoint>) -> Self {
        Self::with_connector(endpoints, NativeConnector::new())
    }
}

impl<Connector: EndpointConnector> RoutedClient<Connector> {
    /// Reads the circuit state without connecting or changing endpoint selection.
    #[must_use]
    pub fn circuit_open(&self, name: &str, operation: OperationKind) -> Option<bool> {
        self.catalog
            .endpoints
            .iter()
            .find(|slot| slot.endpoint.name() == name && slot.endpoint.supports(operation))
            .map(|slot| slot.operation(operation).circuit.is_open())
    }

    /// Creates a routed client with a host-supplied connection factory.
    pub fn with_connector(endpoints: Vec<Endpoint>, connector: Connector) -> Self {
        let connector = Arc::new(connector);
        let runtime = Arc::new(RoutingRuntime::default());
        let slots = endpoints
            .into_iter()
            .map(|endpoint| {
                let lifecycle =
                    Arc::new(EndpointLifecycle::for_endpoint(connector.clone(), &endpoint));
                runtime.register(lifecycle.clone());
                Arc::new(EndpointSlot::new(endpoint, lifecycle, Arc::downgrade(&runtime)))
            })
            .collect();
        Self {
            catalog: Arc::new(Catalog::new(slots)),
            connector,
            runtime,
            #[cfg(test)]
            drop_checkpoint: None,
        }
    }

    /// Builds a replacement catalog, retaining state for cloned endpoint identities.
    ///
    /// Each operation starts at the first endpoint in the new order whose
    /// circuit is closed. The previous active endpoint stays active only while
    /// every endpoint before it has an open circuit, so a reload that adds or
    /// moves a healthy server ahead of the current one uses that server.
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
                        let lifecycle = Arc::new(EndpointLifecycle::for_endpoint(
                            self.connector.clone(),
                            &endpoint,
                        ));
                        self.runtime.register(lifecycle.clone());
                        Arc::new(EndpointSlot::new(
                            endpoint,
                            lifecycle,
                            Arc::downgrade(&self.runtime),
                        ))
                    })
            })
            .collect();
        let replacement = Self {
            catalog: Arc::new(Catalog::new(slots)),
            connector: Arc::clone(&self.connector),
            runtime: Arc::clone(&self.runtime),
            #[cfg(test)]
            drop_checkpoint: None,
        };
        for operation in OperationKind::ALL {
            if let Some(previous) = self.active_endpoint(operation).await {
                let route = replacement.catalog.route(operation);
                // Keep the previous active endpoint only while every endpoint before it has an
                // open circuit. A new or healthy endpoint earlier in the order becomes active.
                if let Some(position) = route.indices.iter().position(|index| {
                    let slot = &replacement.catalog.endpoints[*index];
                    slot.endpoint.same_identity(previous)
                        || !slot.operation(operation).circuit.is_open()
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
    /// Retained endpoints that no operation routes to in the replacement also
    /// retire their idle connection, either now or when their last binding ends.
    pub async fn retire_replaced(&self, replacement: &Self) {
        self.catalog.supersede(&replacement.catalog);
        for index in 0..replacement.catalog.endpoints.len() {
            replacement.retire_if_unused(index);
        }
        for slot in self.catalog.endpoints.iter().filter(|old| {
            !replacement
                .catalog
                .endpoints
                .iter()
                .any(|new| Arc::ptr_eq(old, new))
        }) {
            let cached = slot
                .connection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(cached) = cached {
                self.connector.retire(&cached.connection).await;
            }
        }
    }

    /// Reports whether an endpoint has an active or unfinished retirement lifecycle.
    #[must_use]
    pub fn retains_endpoint(&self, endpoint: &Endpoint) -> bool {
        self.runtime.retains_endpoint(endpoint)
    }

    /// Schedules terminal retirement of removed endpoints without delaying publication.
    /// Existing captured catalogs can use them only until the supplied deadline.
    pub fn retire_replaced_until(&self, replacement: &Self, deadline: crate::RequestDeadline) {
        self.retire_replaced_with_deadlines(replacement, |_| deadline);
    }

    /// Selects a terminal retirement deadline from each removed endpoint's name.
    ///
    /// Already-retiring historical endpoints are also considered. Retained endpoint
    /// identities and unpublished candidates are excluded. The selector runs synchronously
    /// and must not block. Earlier cutoffs cannot be extended by a later call.
    pub fn retire_replaced_with_deadlines(
        &self,
        replacement: &Self,
        mut deadline: impl FnMut(&str) -> crate::RequestDeadline,
    ) {
        let historical = self.runtime.retiring_endpoints();
        for slot in self.catalog.endpoints.iter().filter(|old| {
            !replacement
                .catalog
                .endpoints
                .iter()
                .any(|new| Arc::ptr_eq(old, new))
        }) {
            slot.lifecycle.retire(deadline(slot.endpoint.name()));
        }
        for lifecycle in historical.into_iter().filter(|historical| {
            !self
                .catalog
                .endpoints
                .iter()
                .chain(&replacement.catalog.endpoints)
                .any(|slot| Arc::ptr_eq(&slot.lifecycle, historical))
        }) {
            lifecycle.retire(deadline(&lifecycle.endpoint_name));
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

    /// Selects an eligible endpoint and obtains its shared connection.
    ///
    /// Each call tries eligible endpoints in three passes. It makes at most one connection attempt per endpoint:
    ///
    /// 1. Try open circuits due for recovery in configuration order. Each endpoint allows one trial at a time for this operation.
    /// 2. Try closed circuits in route order from the active position. The first endpoint that connects becomes active.
    /// 3. Try remaining open circuits in the same route order without waiting for `recovery_interval`.
    ///
    /// All operations that select one endpoint share its cached connection. Circuits and the active position are kept for each operation.
    ///
    /// After a successful recovery or last-resort exchange, [`BoundEndpoint::note_success`] closes the circuit. The endpoint becomes active if it precedes the active endpoint or the active endpoint's circuit is open.
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
        let mut attempted = Vec::with_capacity(route.indices.len());
        for index in &route.indices {
            let slot = &self.catalog.endpoints[*index];
            let circuit = &slot.operation(operation).circuit;
            let Some(permit) = circuit.try_begin_recovery(recovery_interval) else {
                continue;
            };
            let revision = circuit.revision();
            attempted.push(*index);
            match self.ensure_connection(slot, operation).await {
                Ok(cached) => {
                    return Ok(self.binding(
                        *index,
                        operation,
                        cached,
                        Some(RecoveryClaim::Trial(permit)),
                        revision,
                    ))
                }
                Err(error) => {
                    log::warn!(
                        "{} recovery connection to {} failed: {:#}",
                        operation.name(),
                        slot.endpoint.prepared().address(),
                        error.source
                    );
                    self.note_connect_failure(*index, operation, error.generation, revision);
                }
            }
        }
        for offset in 0..route.indices.len() {
            let position = (start + offset) % route.indices.len();
            let index = route.indices[position];
            let slot = &self.catalog.endpoints[index];
            let circuit = &slot.operation(operation).circuit;
            if attempted.contains(&index) || circuit.is_open() {
                continue;
            }
            let revision = circuit.revision();
            attempted.push(index);
            match self.ensure_connection(slot, operation).await {
                Ok(cached) => {
                    *route
                        .active_position
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = position;
                    return Ok(self.binding(index, operation, cached, None, revision));
                }
                Err(error) => {
                    log::warn!(
                        "{} connection to {} failed: {:#}",
                        operation.name(),
                        slot.endpoint.prepared().address(),
                        error.source
                    );
                    self.note_connect_failure(index, operation, error.generation, revision);
                }
            }
        }
        for offset in 0..route.indices.len() {
            let position = (start + offset) % route.indices.len();
            let index = route.indices[position];
            if attempted.contains(&index) {
                continue;
            }
            let slot = &self.catalog.endpoints[index];
            let Some(revision) = slot.operation(operation).circuit.open_revision() else {
                continue;
            };
            attempted.push(index);
            log::debug!(
                "Using {} for {} although its circuit is open because no other server is available",
                slot.endpoint.prepared().address(),
                operation.name()
            );
            match self.ensure_connection(slot, operation).await {
                Ok(cached) => {
                    return Ok(self.binding(
                        index,
                        operation,
                        cached,
                        Some(RecoveryClaim::LastResort(revision)),
                        revision,
                    ));
                }
                Err(error) => {
                    log::warn!(
                        "{} last-resort connection to {} failed: {:#}",
                        operation.name(),
                        slot.endpoint.prepared().address(),
                        error.source
                    );
                    self.note_connect_failure(index, operation, error.generation, revision);
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
        recovery: Option<RecoveryClaim>,
        revision: u64,
    ) -> BoundEndpoint<Connector> {
        BoundEndpoint::new(self.clone(), index, operation, cached, recovery, revision)
    }

    /// Returns the endpoint's cached connection, or connects once for all waiters.
    ///
    /// A successful result counts as a binding until the caller drops the
    /// [`BoundEndpoint`] that owns it.
    async fn ensure_connection(
        &self,
        slot: &EndpointSlot<Connector>,
        operation: OperationKind,
    ) -> Result<CachedConnection<Connector::Connection>, ConnectFailure> {
        slot.lifecycle
            .ensure_open()
            .map_err(|source| ConnectFailure {
                generation: slot.connection_generation.load(Ordering::Acquire),
                source,
            })?;
        if let Some(cached) = lease_cached(slot) {
            return Ok(cached);
        }
        let previous = slot.completed_connect_attempts.load(Ordering::Acquire);
        let _guard = slot.connect_lock.lock().await;
        slot.lifecycle
            .ensure_open()
            .map_err(|source| ConnectFailure {
                generation: slot.connection_generation.load(Ordering::Acquire),
                source,
            })?;
        if let Some(cached) = lease_cached(slot) {
            return Ok(cached);
        }
        let completed = slot.completed_connect_attempts.load(Ordering::Acquire);
        if completed != previous {
            return Err(ConnectFailure {
                generation: slot.connection_generation.load(Ordering::Acquire),
                source: anyhow::anyhow!(
                    "Another connection attempt to {} completed for this request",
                    slot.endpoint.prepared().address()
                ),
            });
        }
        let generation = {
            let _cache = slot
                .connection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slot.connection_generation
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1)
        };
        let result = slot
            .lifecycle
            .connect(slot.endpoint.prepared().clone(), operation)
            .await;
        let mut cache = slot
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.completed_connect_attempts
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
        slot.bindings.fetch_add(1, Ordering::AcqRel);
        Ok(CachedConnection {
            generation,
            connection,
        })
    }

    fn note_connect_failure(
        &self,
        index: usize,
        operation: OperationKind,
        failed_generation: u64,
        revision: u64,
    ) {
        if let Some(connection) = self.invalidate_failure(
            index,
            operation,
            failed_generation,
            FailureKind::Server,
            revision,
        ) {
            self.catalog.endpoints[index]
                .lifecycle
                .retire_detached(connection);
        }
    }

    /// Applies one failure report to the operation circuit and the shared connection.
    ///
    /// A server failure opens the operation's circuit and advances its route,
    /// but keeps the shared connection for other operations. A transport
    /// failure detaches the shared connection. If that connection completed a
    /// valid exchange, the circuit stays closed, so the next binding
    /// reconnects to the same endpoint. Otherwise, the transport failure also
    /// opens the operation's circuit.
    ///
    /// A report for a connection generation that was already replaced never
    /// detaches the newer connection. A stale server failure changes nothing.
    /// A stale transport failure still opens the operation's circuit if no
    /// connection from the failed generation onward completed a valid
    /// exchange, because no connection to the endpoint has worked since that
    /// attempt.
    ///
    /// The circuit changes only if no other outcome changed it after
    /// `revision`, so a stale report cannot undo a newer recovery.
    pub(super) fn invalidate_failure(
        &self,
        index: usize,
        operation: OperationKind,
        failed_generation: u64,
        kind: FailureKind,
        revision: u64,
    ) -> Option<Arc<Connector::Connection>> {
        let slot = &self.catalog.endpoints[index];
        let (detached, open_circuit) = {
            let mut cache = slot
                .connection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let proven_generation = slot.proven_generation.load(Ordering::Acquire);
            if failed_generation != slot.connection_generation.load(Ordering::Acquire) {
                // A newer connection replaced the failed one. An unproven
                // failure still shows that this operation could not use the
                // endpoint, unless the failed or a newer connection completed
                // a valid exchange. Without this rule, concurrent reconnects
                // by other operations hide the failure, and a retry selects
                // the same failing endpoint again.
                let disproved =
                    proven_generation != u64::MAX && proven_generation >= failed_generation;
                (None, kind == FailureKind::Transport && !disproved)
            } else {
                match kind {
                    FailureKind::Server => (None, true),
                    FailureKind::Transport => {
                        let proven = proven_generation == failed_generation;
                        if proven {
                            log::info!(
                                "The connection to {} failed after valid exchanges; the next request reconnects",
                                slot.endpoint.prepared().address()
                            );
                        }
                        (cache.take().map(|cached| cached.connection), !proven)
                    }
                }
            }
        };
        if open_circuit
            && slot
                .operation(operation)
                .circuit
                .open_if_unchanged(revision)
        {
            self.catalog.route(operation).advance_if_active(index);
            self.retire_if_unused(index);
        }
        detached
    }

    /// Makes a recovered endpoint active when it is preferred, then retires unused alternatives.
    ///
    /// The active endpoint changes only when the recovered endpoint precedes
    /// it in configuration order or the active endpoint has an open circuit.
    /// Other endpoints in this operation's route keep their shared connection
    /// only while another operation still routes to them.
    pub(super) fn promote_recovered(&self, index: usize, operation: OperationKind) {
        let route = self.catalog.route(operation);
        let Some(position) = route
            .indices
            .iter()
            .position(|candidate| *candidate == index)
        else {
            return;
        };
        let active_index = {
            let mut active = route
                .active_position
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let current_index = route.indices[*active];
            let current_open = self.catalog.endpoints[current_index]
                .operation(operation)
                .circuit
                .is_open();
            if position < *active || current_open {
                *active = position;
            }
            route.indices[*active]
        };
        for other in route.indices.iter().filter(|other| **other != active_index) {
            self.retire_if_unused(*other);
        }
    }

    /// Retires an endpoint's shared connection when nothing can use it.
    ///
    /// The connection stays while any operation route prefers the endpoint or
    /// any binding still holds a connection from it. After a reload, the check
    /// uses the routes of the newest catalog that retains the endpoint. The
    /// last binding to drop repeats this check.
    pub(super) fn retire_if_unused(&self, index: usize) {
        let slot = &self.catalog.endpoints[index];
        if self.catalog.routes_to(slot) {
            return;
        }
        let detached = {
            let mut cache = slot
                .connection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot.bindings.load(Ordering::Acquire) != 0 {
                return;
            }
            cache.take()
        };
        if let Some(detached) = detached {
            log::info!(
                "Retiring the idle connection to {} because no operation routes to it",
                slot.endpoint.prepared().address()
            );
            slot.lifecycle.retire_detached(detached.connection);
        }
    }
}

/// Clones the cached connection and counts the new binding under the cache lock.
fn lease_cached<Connector: EndpointConnector>(
    slot: &EndpointSlot<Connector>,
) -> Option<CachedConnection<Connector::Connection>> {
    let cache = slot
        .connection
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cached = cache.as_ref()?;
    slot.bindings.fetch_add(1, Ordering::AcqRel);
    Some(CachedConnection {
        generation: cached.generation,
        connection: Arc::clone(&cached.connection),
    })
}

/// How an upstream failure affects routing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FailureKind {
    /// The server failed to connect, timed out, or returned `ERROR`.
    Server,
    /// An established connection failed during I/O.
    Transport,
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
        refused_host: std::sync::Mutex<Option<String>>,
    }

    #[async_trait]
    impl EndpointConnector for ControlledConnector {
        type Connection = usize;

        async fn connect(
            &self,
            endpoint: PreparedEndpoint,
            _operation: OperationKind,
        ) -> anyhow::Result<Arc<usize>> {
            let attempt = self.attempts.fetch_add(1, Ordering::AcqRel) + 1;
            if self.refused_host.lock().unwrap().as_deref() == Some(&*endpoint.address().host()) {
                bail!("injected connection refusal");
            }
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
                PreparedEndpoint::new(
                    crate::ServerAddress::parse("127.0.0.1:49", 49).unwrap(),
                    crate::PreparedTransport::Tcp,
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                OperationKind::ALL,
            )],
            connector,
        )
    }

    #[tokio::test]
    async fn discarded_replacement_releases_speculative_lifecycle() {
        let client = controlled_client(ControlledConnector::default());
        let endpoint = Endpoint::new(
            "discarded",
            PreparedEndpoint::new(
                crate::ServerAddress::new("127.0.0.1", 49).unwrap(),
                crate::PreparedTransport::Tcp,
                false,
                None,
                ConnectOptions::default(),
            ),
            OperationKind::ALL,
        );
        let replacement = client.with_endpoints(vec![endpoint.clone()]).await;
        assert!(client.retains_endpoint(&endpoint));
        drop(replacement);
        assert!(!client.retains_endpoint(&endpoint));
    }

    #[derive(Debug)]
    struct DisposalLedger {
        bytes: Arc<std::sync::atomic::AtomicU64>,
    }

    impl crate::PreparationPayloadLedger for DisposalLedger {
        fn reserve(&self, bytes: u64) -> anyhow::Result<()> {
            self.bytes.fetch_add(bytes, Ordering::SeqCst);
            Ok(())
        }

        fn release(&self, bytes: u64) {
            self.bytes.fetch_sub(bytes, Ordering::SeqCst);
        }
    }

    async fn assert_concurrent_disposal(shared_catalog: bool) {
        let bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let ledger = Arc::new(DisposalLedger {
            bytes: bytes.clone(),
        });
        let weak_ledger = Arc::downgrade(&ledger);
        let payload = crate::PreparationPayload::new(ledger);
        let name = "discarded";
        payload.retain(name.len() * 2).unwrap();
        let mut prepared = PreparedEndpoint::new(
            crate::ServerAddress::new("127.0.0.1", 49).unwrap(),
            crate::PreparedTransport::Tcp,
            false,
            None,
            ConnectOptions::default(),
        );
        prepared.preparation_payload = payload;
        let endpoint = Endpoint::new(name, prepared, OperationKind::ALL);
        let observer = RoutedClient::with_connector(Vec::new(), ControlledConnector::default());
        let mut first = observer.with_endpoints(vec![endpoint.clone()]).await;
        let mut second = if shared_catalog {
            first.clone()
        } else {
            first.with_endpoints(vec![endpoint.clone()]).await
        };
        assert_eq!(Arc::ptr_eq(&first.catalog, &second.catalog), shared_catalog);
        assert!(Arc::ptr_eq(&first.catalog.endpoints[0], &second.catalog.endpoints[0]));
        let lifecycle = Arc::downgrade(&first.catalog.endpoints[0].lifecycle);
        let slot = Arc::downgrade(&first.catalog.endpoints[0]);
        let checkpoint = Arc::new(std::sync::Barrier::new(3));
        first.drop_checkpoint = Some(checkpoint.clone());
        second.drop_checkpoint = Some(checkpoint.clone());

        let (retained_during_drop, charged_during_drop) = std::thread::scope(|scope| {
            scope.spawn(move || drop(first));
            scope.spawn(move || drop(second));
            checkpoint.wait();
            let retained = observer.retains_endpoint(&endpoint)
                && lifecycle.upgrade().is_some()
                && slot.upgrade().is_some()
                && weak_ledger.upgrade().is_some();
            let charged = bytes.load(Ordering::SeqCst);
            checkpoint.wait();
            (retained, charged)
        });

        assert!(retained_during_drop);
        assert_eq!(charged_during_drop, u64::try_from(name.len() * 2).unwrap());
        assert!(slot.upgrade().is_none());
        assert!(
            !observer.retains_endpoint(&endpoint),
            "the final slot owner must unregister its unused lifecycle"
        );
        assert!(lifecycle.upgrade().is_none(), "the lifecycle name owner must drop");
        assert!(weak_ledger.upgrade().is_some());
        assert_eq!(bytes.load(Ordering::SeqCst), charged_during_drop);
        drop(endpoint);
        assert_eq!(bytes.load(Ordering::SeqCst), 0);
        assert!(weak_ledger.upgrade().is_none());
    }

    /// Both old catalog-count checks finish before either client releases its catalog.
    #[tokio::test]
    async fn concurrent_disposal_of_final_client_clones() {
        assert_concurrent_disposal(true).await;
    }

    /// Both old slot-count scans finish before either catalog releases the shared slot.
    #[tokio::test]
    async fn concurrent_disposal_of_catalogs_sharing_slot() {
        assert_concurrent_disposal(false).await;
    }

    #[tokio::test]
    async fn disposal_of_one_catalog_preserves_reused_slot_and_connection() {
        let first = controlled_client(ControlledConnector::default());
        let endpoint = first.catalog.endpoints[0].endpoint.clone();
        let replacement = first.with_endpoints(vec![endpoint.clone()]).await;
        let observer = first.with_endpoints(Vec::new()).await;
        drop(first);
        assert!(observer.retains_endpoint(&endpoint));

        let binding = replacement
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        let remaining = replacement.clone();
        drop(replacement);
        assert!(observer.retains_endpoint(&endpoint));
        let reused = remaining
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(binding.connection(), reused.connection()));
        assert_eq!(observer.connector.attempts.load(Ordering::SeqCst), 1);
        drop(binding);
        drop(reused);
        drop(remaining);
        assert!(observer.retains_endpoint(&endpoint));
        observer
            .close_and_join(crate::RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
    }

    #[test]
    fn disposal_of_slot_after_runtime_releases_lifecycle() {
        let client = controlled_client(ControlledConnector::default());
        let slot = client.catalog.endpoints[0].clone();
        let runtime = Arc::downgrade(&client.runtime);
        let lifecycle = Arc::downgrade(&slot.lifecycle);
        drop(client);
        assert!(runtime.upgrade().is_none());
        assert!(lifecycle.upgrade().is_some());
        drop(slot);
        assert!(lifecycle.upgrade().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn per_endpoint_retirement_preserves_unrelated_grace_and_retained_identity() {
        use crate::RequestDeadline;
        let endpoint = |name, operation| {
            Endpoint::new(
                name,
                PreparedEndpoint::new(
                    crate::ServerAddress::parse("127.0.0.1:49", 49).unwrap(),
                    crate::PreparedTransport::Tcp,
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                [operation],
            )
        };
        let retained = endpoint("retained", OperationKind::Authorization);
        let client = RoutedClient::with_connector(
            vec![
                endpoint("urgent", OperationKind::Authentication),
                endpoint("grace", OperationKind::Accounting),
                retained.clone(),
            ],
            ControlledConnector::default(),
        );
        let original = client
            .bind(OperationKind::Authorization, Duration::ZERO)
            .await
            .unwrap();
        let replacement = client
            .with_endpoints(vec![
                endpoint("urgent", OperationKind::Authentication),
                endpoint("grace", OperationKind::Accounting),
                retained,
            ])
            .await;
        let now = tokio::time::Instant::now();
        let mut selected = Vec::new();
        client.retire_replaced_with_deadlines(&replacement, |name| {
            selected.push(name.to_owned());
            RequestDeadline::at(if name == "urgent" {
                now
            } else {
                now + Duration::from_secs(5)
            })
        });
        assert_eq!(selected, ["urgent", "grace"]);
        client.retire_replaced_until(
            &replacement,
            RequestDeadline::after(Duration::from_secs(60)).unwrap(),
        );
        assert!(client
            .bind(OperationKind::Authentication, Duration::ZERO)
            .await
            .is_err());
        client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .is_err());
        let unchanged = client
            .bind(OperationKind::Authorization, Duration::ZERO)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(original.connection(), unchanged.connection()));
        for operation in OperationKind::ALL {
            replacement.bind(operation, Duration::ZERO).await.unwrap();
        }
        replacement
            .close_and_join(RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_prefers_an_earlier_endpoint_with_a_closed_circuit() {
        let endpoint = |name: &str, port: u16| {
            Endpoint::new(
                name,
                PreparedEndpoint::new(
                    crate::ServerAddress::parse(&format!("127.0.0.1:{port}"), port).unwrap(),
                    crate::PreparedTransport::Tcp,
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                OperationKind::ALL,
            )
        };
        let (a, b) = (endpoint("a", 49), endpoint("b", 50));
        let client = RoutedClient::with_connector(
            vec![a.clone(), b.clone()],
            ControlledConnector::default(),
        );
        let operation = OperationKind::Authorization;
        client.catalog.endpoints[0]
            .operation(operation)
            .circuit
            .open();
        client.catalog.route(operation).advance_if_active(0);
        let active = |client: &RoutedClient<ControlledConnector>, operation| {
            let route = client.catalog.route(operation);
            route
                .active_index()
                .map(|index| client.catalog.endpoints[index].endpoint.name().to_owned())
        };

        let kept = client.with_endpoints(vec![a.clone(), b.clone()]).await;
        assert_eq!(active(&kept, operation).as_deref(), Some("b"));
        assert_eq!(active(&kept, OperationKind::Authentication).as_deref(), Some("a"));

        let inserted = kept.with_endpoints(vec![endpoint("c", 51), a, b]).await;
        assert_eq!(active(&inserted, operation).as_deref(), Some("c"));
        assert_eq!(active(&inserted, OperationKind::Authentication).as_deref(), Some("c"));
    }

    #[tokio::test(start_paused = true)]
    async fn selective_retirement_reaches_older_generations_but_not_unpublished_candidates() {
        use crate::RequestDeadline;
        let endpoint = || {
            Endpoint::new(
                "primary",
                PreparedEndpoint::new(
                    crate::ServerAddress::parse("127.0.0.1:49", 49).unwrap(),
                    crate::PreparedTransport::Tcp,
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                OperationKind::ALL,
            )
        };
        let first = RoutedClient::with_connector(vec![endpoint()], ControlledConnector::default());
        let second = first.with_endpoints(vec![endpoint()]).await;
        first.retire_replaced_until(
            &second,
            RequestDeadline::after(Duration::from_secs(60)).unwrap(),
        );
        let third = second.with_endpoints(vec![endpoint()]).await;
        let candidate = third.with_endpoints(vec![endpoint()]).await;
        first
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        second
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        second.retire_replaced_with_deadlines(&third, |_| {
            RequestDeadline::at(tokio::time::Instant::now())
        });
        assert!(first
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .is_err());
        assert!(second
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .is_err());
        third
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        candidate
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        third
            .close_and_join(RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stale_failure_guard_cannot_invalidate_recovered_connection() {
        let client = controlled_client(ControlledConnector::default());
        let circuit = || {
            client.catalog.endpoints[0]
                .operation(OperationKind::Accounting)
                .circuit
                .is_open()
        };
        let stale = client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        let first = client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        let expired = crate::RequestDeadline::after(Duration::ZERO).unwrap();
        let delayed = stale.observe_failure(expired);
        drop(first.observe_failure(expired));
        assert!(circuit());
        let recovered = client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        // A timeout keeps the shared connection for other packet types.
        assert_eq!(first.connection_generation(), recovered.connection_generation());
        recovered.note_success().await;
        assert!(!circuit());
        drop(delayed);
        assert!(!circuit());
        let next = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(next.connection_generation(), recovered.connection_generation());
        assert!(Arc::ptr_eq(next.connection(), recovered.connection()));
        assert_eq!(client.connector.attempts.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn cancelled_failure_guard_keeps_circuit_closed() {
        let client = controlled_client(ControlledConnector::default());
        let bound = client
            .bind(OperationKind::Accounting, Duration::ZERO)
            .await
            .unwrap();
        drop(
            bound.observe_failure(crate::RequestDeadline::after(Duration::from_secs(60)).unwrap()),
        );
        assert!(!client.catalog.endpoints[0]
            .operation(OperationKind::Accounting)
            .circuit
            .is_open());
        assert_eq!(client.connector.retired.load(Ordering::Acquire), 0);

        bound
            .observe_failure(crate::RequestDeadline::after(Duration::from_secs(60)).unwrap())
            .fail();
        assert!(client.catalog.endpoints[0]
            .operation(OperationKind::Accounting)
            .circuit
            .is_open());
    }

    #[tokio::test]
    async fn only_server_is_used_as_last_resort_and_success_closes_circuit() {
        let client = controlled_client(ControlledConnector::default());
        let circuit = || {
            client.catalog.endpoints[0]
                .operation(OperationKind::Accounting)
                .circuit
                .is_open()
        };
        let first = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        first.note_server_failure().await;
        assert!(circuit());

        let last_resort = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(first.connection(), last_resort.connection()));
        assert!(circuit());
        last_resort.note_success().await;
        assert!(!circuit());
    }

    #[tokio::test]
    async fn last_resort_success_does_not_close_newer_failure() {
        let client = controlled_client(ControlledConnector::default());
        let first = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        first.note_server_failure().await;
        let stale = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        stale.note_server_failure().await;
        let current = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        stale.note_success().await;
        let state = client.catalog.endpoints[0].operation(OperationKind::Accounting);
        assert!(state.circuit.is_open());
        current.note_success().await;
        assert!(!state.circuit.is_open());
    }

    #[tokio::test]
    async fn healthy_alternative_is_preferred_over_open_circuit() {
        let endpoint = |name| {
            Endpoint::new(
                name,
                PreparedEndpoint::new(
                    crate::ServerAddress::parse("127.0.0.1:49", 49).unwrap(),
                    crate::PreparedTransport::Tcp,
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                OperationKind::ALL,
            )
        };
        let client = RoutedClient::with_connector(
            vec![endpoint("primary"), endpoint("secondary")],
            ControlledConnector::default(),
        );
        let primary = client
            .bind(OperationKind::Accounting, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(primary.endpoint().name(), "primary");
        primary.note_server_failure().await;
        for _ in 0..3 {
            let next = client
                .bind(OperationKind::Accounting, Duration::from_secs(30))
                .await
                .unwrap();
            assert_eq!(next.endpoint().name(), "secondary");
            next.note_success().await;
        }
    }

    fn failover_pair() -> RoutedClient<ControlledConnector> {
        let endpoint = |name| {
            Endpoint::new(
                name,
                PreparedEndpoint::new(
                    crate::ServerAddress::parse("127.0.0.1:49", 49).unwrap(),
                    crate::PreparedTransport::Tcp,
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                OperationKind::ALL,
            )
        };
        RoutedClient::with_connector(
            vec![endpoint("primary"), endpoint("secondary")],
            ControlledConnector::default(),
        )
    }

    const HOLD: Duration = Duration::from_secs(30);

    fn distinct_pair() -> RoutedClient<ControlledConnector> {
        let endpoint = |name, host| {
            Endpoint::new(
                name,
                PreparedEndpoint::new(
                    crate::ServerAddress::new(host, 49).unwrap(),
                    crate::PreparedTransport::Tcp,
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                OperationKind::ALL,
            )
        };
        RoutedClient::with_connector(
            vec![
                endpoint("primary", "127.0.0.1"),
                endpoint("secondary", "127.0.0.2"),
            ],
            ControlledConnector::default(),
        )
    }

    #[tokio::test]
    async fn operations_share_one_connection_per_endpoint() {
        let client = distinct_pair();
        let mut bindings = Vec::new();
        for operation in OperationKind::ALL {
            bindings.push(client.bind(operation, HOLD).await.unwrap());
        }
        for binding in &bindings {
            assert_eq!(binding.endpoint().name(), "primary");
            assert!(Arc::ptr_eq(binding.connection(), bindings[0].connection()));
        }
        assert_eq!(client.connector.attempts.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn error_moves_only_failing_operation_and_reuses_backup_connection() {
        let client = distinct_pair();
        let authorization = client
            .bind(OperationKind::Authorization, HOLD)
            .await
            .unwrap();
        let accounting = client.bind(OperationKind::Accounting, HOLD).await.unwrap();
        authorization.note_server_failure().await;

        let moved = client
            .bind(OperationKind::Authorization, HOLD)
            .await
            .unwrap();
        assert_eq!(moved.endpoint().name(), "secondary");
        let stayed = client.bind(OperationKind::Accounting, HOLD).await.unwrap();
        assert_eq!(stayed.endpoint().name(), "primary");
        assert!(Arc::ptr_eq(stayed.connection(), accounting.connection()));

        stayed.note_server_failure().await;
        let joined = client.bind(OperationKind::Accounting, HOLD).await.unwrap();
        assert_eq!(joined.endpoint().name(), "secondary");
        assert!(Arc::ptr_eq(joined.connection(), moved.connection()));
        assert_eq!(client.connector.attempts.load(Ordering::Acquire), 2);

        // Authentication still prefers the primary, so its connection stays open.
        drop((authorization, accounting, stayed));
        let authentication = client
            .bind(OperationKind::Authentication, HOLD)
            .await
            .unwrap();
        assert_eq!(authentication.endpoint().name(), "primary");
        assert_eq!(client.connector.retired.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn proven_transport_failure_reconnects_every_operation_once() {
        let client = distinct_pair();
        let authorization = client
            .bind(OperationKind::Authorization, HOLD)
            .await
            .unwrap();
        let accounting = client.bind(OperationKind::Accounting, HOLD).await.unwrap();
        authorization.note_success().await;
        authorization
            .observe_failure(crate::RequestDeadline::after(Duration::from_secs(60)).unwrap())
            .fail();
        // The other operation sees the same broken stream. Its report is stale.
        accounting
            .observe_failure(crate::RequestDeadline::after(Duration::from_secs(60)).unwrap())
            .fail();

        let mut next = Vec::new();
        for operation in OperationKind::ALL {
            let binding = client.bind(operation, HOLD).await.unwrap();
            assert_eq!(binding.endpoint().name(), "primary");
            assert!(!client.catalog.endpoints[0]
                .operation(operation)
                .circuit
                .is_open());
            next.push(binding);
        }
        assert!(!Arc::ptr_eq(next[0].connection(), authorization.connection()));
        assert!(Arc::ptr_eq(next[0].connection(), next[2].connection()));
        assert_eq!(client.connector.attempts.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn stale_unproven_transport_failure_still_moves_the_operation() {
        let client = distinct_pair();
        let deadline = || crate::RequestDeadline::after(Duration::from_secs(60)).unwrap();
        let authentication = client
            .bind(OperationKind::Authentication, HOLD)
            .await
            .unwrap();
        let accounting = client.bind(OperationKind::Accounting, HOLD).await.unwrap();
        // The first connection never works. Accounting fails first, and
        // authorization reconnects before the authentication report arrives.
        accounting.observe_failure(deadline()).fail();
        let reconnected = client
            .bind(OperationKind::Authorization, HOLD)
            .await
            .unwrap();
        assert_eq!(reconnected.endpoint().name(), "primary");
        authentication.observe_failure(deadline()).fail();

        let retried = client
            .bind(OperationKind::Authentication, HOLD)
            .await
            .unwrap();
        assert_eq!(retried.endpoint().name(), "secondary");
        let current = client
            .bind(OperationKind::Authorization, HOLD)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(current.connection(), reconnected.connection()));

        // A stale failure does not move an operation after a newer
        // connection to the endpoint has worked.
        let stale = client
            .bind(OperationKind::Authorization, HOLD)
            .await
            .unwrap();
        current.note_success().await;
        current.observe_failure(deadline()).fail();
        let replacement = client
            .bind(OperationKind::Authorization, HOLD)
            .await
            .unwrap();
        assert_eq!(replacement.endpoint().name(), "primary");
        stale.observe_failure(deadline()).fail();
        let after_stale = client
            .bind(OperationKind::Authorization, HOLD)
            .await
            .unwrap();
        assert_eq!(after_stale.endpoint().name(), "primary");
    }

    #[tokio::test]
    async fn primary_outage_converges_every_operation_on_one_backup_connection() {
        let client = distinct_pair();
        let mut old = Vec::new();
        for operation in OperationKind::ALL {
            let binding = client.bind(operation, HOLD).await.unwrap();
            binding.note_success().await;
            old.push(binding);
        }
        *client.connector.refused_host.lock().unwrap() = Some("127.0.0.1".to_owned());
        for binding in &old {
            binding
                .observe_failure(crate::RequestDeadline::after(Duration::from_secs(60)).unwrap())
                .fail();
        }

        let mut moved = Vec::new();
        for operation in OperationKind::ALL {
            let binding = client.bind(operation, HOLD).await.unwrap();
            assert_eq!(binding.endpoint().name(), "secondary");
            moved.push(binding);
        }
        for binding in &moved {
            assert!(Arc::ptr_eq(binding.connection(), moved[0].connection()));
        }
    }

    async fn wait_for_retired(client: &RoutedClient<ControlledConnector>, expected: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while client.connector.retired.load(Ordering::Acquire) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retirement did not run");
    }

    #[tokio::test]
    async fn transport_failure_on_proven_connection_reconnects_to_same_endpoint() {
        let client = failover_pair();
        let operation = OperationKind::Authorization;
        let first = client
            .bind(operation, Duration::from_secs(30))
            .await
            .unwrap();
        first.note_success().await;
        first
            .observe_failure(crate::RequestDeadline::after(Duration::from_secs(60)).unwrap())
            .fail();
        // The proxy also reports the same attempt as failed. The first report wins.
        first.note_server_failure().await;

        assert!(!client.catalog.endpoints[0]
            .operation(operation)
            .circuit
            .is_open());
        let next = client
            .bind(operation, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(next.endpoint().name(), "primary");
        assert_ne!(next.connection_generation(), first.connection_generation());
        wait_for_retired(&client, 1).await;
    }

    #[tokio::test]
    async fn transport_failure_on_unproven_connection_opens_circuit() {
        let client = failover_pair();
        let operation = OperationKind::Authorization;
        let first = client
            .bind(operation, Duration::from_secs(30))
            .await
            .unwrap();
        first
            .observe_failure(crate::RequestDeadline::after(Duration::from_secs(60)).unwrap())
            .fail();

        assert!(client.catalog.endpoints[0]
            .operation(operation)
            .circuit
            .is_open());
        let next = client
            .bind(operation, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(next.endpoint().name(), "secondary");
    }

    #[tokio::test]
    async fn recovered_preferred_endpoint_retires_backup_connection() {
        let client = failover_pair();
        let operation = OperationKind::Accounting;
        let primary = client.bind(operation, HOLD).await.unwrap();
        primary.note_server_failure().await;
        let backup = client.bind(operation, HOLD).await.unwrap();
        assert_eq!(backup.endpoint().name(), "secondary");
        backup.note_success().await;
        // The other operations still use the primary connection.
        assert!(client.catalog.endpoints[0]
            .connection
            .lock()
            .unwrap()
            .is_some());

        let trial = client.bind(operation, Duration::ZERO).await.unwrap();
        assert_eq!(trial.endpoint().name(), "primary");
        assert!(Arc::ptr_eq(trial.connection(), primary.connection()));
        trial.note_success().await;
        // The backup stays cached while a binding still holds it.
        tokio::task::yield_now().await;
        assert_eq!(client.connector.retired.load(Ordering::Acquire), 0);
        assert!(client.catalog.endpoints[1]
            .connection
            .lock()
            .unwrap()
            .is_some());
        drop(backup);
        wait_for_retired(&client, 1).await;

        assert!(client.catalog.endpoints[1]
            .connection
            .lock()
            .unwrap()
            .is_none());
        let next = client.bind(operation, HOLD).await.unwrap();
        assert_eq!(next.endpoint().name(), "primary");
        assert!(Arc::ptr_eq(next.connection(), trial.connection()));
    }

    #[tokio::test]
    async fn reload_retires_the_connection_of_an_endpoint_that_no_operation_routes_to() {
        let endpoint = |name: &str, port: u16| {
            Endpoint::new(
                name,
                PreparedEndpoint::new(
                    crate::ServerAddress::parse(&format!("127.0.0.1:{port}"), port).unwrap(),
                    crate::PreparedTransport::Tcp,
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                OperationKind::ALL,
            )
        };
        let retained = endpoint("b", 50);
        let client =
            RoutedClient::with_connector(vec![retained.clone()], ControlledConnector::default());
        let held = client.bind(OperationKind::Accounting, HOLD).await.unwrap();
        for operation in OperationKind::ALL {
            let binding = client.bind(operation, HOLD).await.unwrap();
            assert!(Arc::ptr_eq(binding.connection(), held.connection()));
        }

        let replacement = client
            .with_endpoints(vec![endpoint("a", 49), retained])
            .await;
        client.retire_replaced(&replacement).await;
        // The old catalog still routes to "b", but its binding must not keep the connection.
        tokio::task::yield_now().await;
        assert_eq!(client.connector.retired.load(Ordering::Acquire), 0);
        drop(held);
        wait_for_retired(&client, 1).await;
        assert!(replacement.catalog.endpoints[1]
            .connection
            .lock()
            .unwrap()
            .is_none());
        let next = replacement
            .bind(OperationKind::Accounting, HOLD)
            .await
            .unwrap();
        assert_eq!(next.endpoint().name(), "a");
    }

    #[tokio::test]
    async fn backup_recovery_does_not_displace_healthy_preferred_endpoint() {
        let client = failover_pair();
        let operation = OperationKind::Accounting;
        let primary = client.bind(operation, HOLD).await.unwrap();
        primary.note_server_failure().await;
        let backup = client.bind(operation, HOLD).await.unwrap();
        backup.note_server_failure().await;
        // Both circuits are open. The primary recovers through its trial first.
        let primary_trial = client.bind(operation, Duration::ZERO).await.unwrap();
        assert_eq!(primary_trial.endpoint().name(), "primary");
        primary_trial.note_success().await;
        let backup_trial = client.bind(operation, Duration::ZERO).await.unwrap();
        assert_eq!(backup_trial.endpoint().name(), "secondary");
        backup_trial.note_success().await;

        let next = client.bind(operation, HOLD).await.unwrap();
        assert_eq!(next.endpoint().name(), "primary");
        assert!(Arc::ptr_eq(next.connection(), primary.connection()));
        drop(backup);
        drop(backup_trial);
        wait_for_retired(&client, 1).await;
        assert!(client.catalog.endpoints[1]
            .connection
            .lock()
            .unwrap()
            .is_none());
    }

    #[test]
    fn failure_guard_can_be_dropped_outside_runtime_context() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let endpoint = |name| {
            Endpoint::new(
                name,
                PreparedEndpoint::new(
                    crate::ServerAddress::parse("127.0.0.1:49", 49).unwrap(),
                    crate::PreparedTransport::Tcp,
                    false,
                    None,
                    ConnectOptions::default(),
                ),
                [OperationKind::Accounting],
            )
        };
        let client = runtime.block_on(async {
            RoutedClient::with_connector(
                vec![endpoint("primary"), endpoint("secondary")],
                ControlledConnector::default(),
            )
        });
        let bound = runtime
            .block_on(client.bind(OperationKind::Accounting, Duration::ZERO))
            .unwrap();
        drop(bound.observe_failure(crate::RequestDeadline::after(Duration::ZERO).unwrap()));
        // No route prefers the primary now, so dropping its last binding retires it.
        drop(bound);
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
            PreparedEndpoint::new(
                listener.local_addr().unwrap().try_into().unwrap(),
                crate::PreparedTransport::Tcp,
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
                PreparedEndpoint::new(
                    listener.local_addr().unwrap().try_into().unwrap(),
                    crate::PreparedTransport::Tcp,
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
        let revision = slot.operation(OperationKind::Accounting).circuit.revision();
        client.note_connect_failure(0, OperationKind::Accounting, failure.generation, revision);
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
        old_request.note_server_failure().await;
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
            PreparedEndpoint::new(
                crate::ServerAddress::parse("127.0.0.1:49", 49).unwrap(),
                crate::PreparedTransport::Tcp,
                false,
                None,
                ConnectOptions::default(),
            ),
            [OperationKind::Accounting],
        );
        let second = Endpoint::new(
            "all",
            PreparedEndpoint::new(
                crate::ServerAddress::parse("127.0.0.2:49", 49).unwrap(),
                crate::PreparedTransport::Tcp,
                false,
                None,
                ConnectOptions::default(),
            ),
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
