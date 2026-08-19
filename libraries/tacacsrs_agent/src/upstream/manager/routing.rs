//! Operation-aware route selection and connection invalidation.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::bail;

use super::server_set::ServerSet;
use super::server_slot::ServerSlot;
use super::{BoundServer, UpstreamManager};
#[cfg(test)]
use crate::config::ProxyDownstreamObfuscation;
use crate::upstream::{OperationKind, UpstreamConnection};

impl UpstreamManager {
    #[cfg(test)]
    pub(crate) async fn bind_server_for_new_session(&self) -> anyhow::Result<BoundServer> {
        self.bind_server_for_operation(OperationKind::Authentication)
            .await
    }

    /// Selects an eligible server and operation-scoped connection.
    ///
    /// Services reach this through [`crate::upstream::OperationRouter`].
    pub(in crate::upstream) async fn bind_server_for_operation(
        &self,
        operation: OperationKind,
    ) -> anyhow::Result<BoundServer> {
        let server_set = self.current_server_set();
        self.bind_server_from_set(server_set, operation).await
    }

    #[cfg(test)]
    pub(crate) async fn bind_proxy_server_for_new_session(
        &self,
        operation: OperationKind,
    ) -> anyhow::Result<(BoundServer, ProxyDownstreamObfuscation)> {
        let runtime = self.current_runtime();
        let bound_server = self
            .bind_server_from_set(Arc::clone(&runtime.server_set), operation)
            .await?;
        Ok((bound_server, runtime.proxy_downstream_obfuscation.clone()))
    }

    async fn bind_server_from_set(
        &self,
        server_set: Arc<ServerSet>,
        operation: OperationKind,
    ) -> anyhow::Result<BoundServer> {
        let route = server_set.route(operation);
        if route.server_count() == 0 {
            bail!(
                "No configured TACACS+ server supports {}; waiting for initial configuration",
                operation.name()
            );
        }
        let availability_attempt = self.availability.begin_attempt();
        let start_position = route.active_position().await;
        let recovery_interval = self.runtime_policy().failover_recovery_interval();

        for position in 0..route.server_count() {
            let index = route.server_index(position);
            let operation_slot = server_set.servers[index].operation(operation);
            let Some(recovery_permit) =
                operation_slot.circuit.try_begin_recovery(recovery_interval)
            else {
                continue;
            };
            log::info!(
                "Starting an {} recovery trial on {}",
                operation.name(),
                server_set.servers[index].socket_address()
            );
            match self
                .ensure_connection(&server_set.servers[index], operation)
                .await
            {
                Ok((connection, connection_generation)) => {
                    self.availability.available(availability_attempt);
                    return Ok(BoundServer {
                        server_set,
                        index,
                        operation,
                        connection_generation,
                        recovery_permit: Some(recovery_permit),
                        connection,
                    });
                }
                Err(error) => {
                    recovery_permit.fail();
                    log::warn!(
                        "TACACS+ server {} did not accept an {} recovery connection: {error}",
                        server_set.servers[index].socket_address(),
                        operation.name(),
                    );
                    self.note_failure(&server_set, index, operation, None).await;
                }
            }
        }

        for offset in 0..route.server_count() {
            let position = (start_position + offset) % route.server_count();
            let index = route.server_index(position);
            if server_set.servers[index]
                .operation(operation)
                .circuit
                .is_open()
            {
                continue;
            }
            match self
                .ensure_connection(&server_set.servers[index], operation)
                .await
            {
                Ok((connection, connection_generation)) => {
                    route.set_active_position(position).await;
                    self.availability.available(availability_attempt);
                    return Ok(BoundServer {
                        server_set,
                        index,
                        operation,
                        connection_generation,
                        recovery_permit: None,
                        connection,
                    });
                }
                Err(error) => {
                    log::warn!(
                        "TACACS+ server {} did not accept an {} connection: {error}",
                        server_set.servers[index].socket_address(),
                        operation.name(),
                    );
                    self.note_failure(&server_set, index, operation, None).await;
                }
            }
        }

        log::error!("No configured TACACS+ server accepted an {} connection", operation.name());
        self.availability.unavailable(availability_attempt);
        bail!("No TACACS+ server is available for {}", operation.name());
    }

    async fn ensure_connection(
        &self,
        server_slot: &Arc<ServerSlot>,
        operation: OperationKind,
    ) -> anyhow::Result<(Arc<dyn UpstreamConnection>, u64)> {
        let operation_slot = server_slot.operation(operation);
        let existing_conn = operation_slot.connection.read().await.clone();
        if let Some(existing) = existing_conn {
            let generation = operation_slot
                .completed_connect_attempts
                .load(Ordering::Acquire);
            log::debug!(
                "Reusing the cached {} connection to {}",
                operation.name(),
                server_slot.socket_address()
            );
            return Ok((existing, generation));
        }

        let reconnect_generation = operation_slot
            .completed_connect_attempts
            .load(Ordering::Acquire);
        let _connect_guard = operation_slot.connect_lock.lock().await;

        let existing_conn = operation_slot.connection.read().await.clone();
        if let Some(existing) = existing_conn {
            let generation = operation_slot
                .completed_connect_attempts
                .load(Ordering::Acquire);
            log::debug!(
                "Reusing the cached {} connection to {} after another reconnect",
                operation.name(),
                server_slot.socket_address()
            );
            return Ok((existing, generation));
        }

        if operation_slot
            .completed_connect_attempts
            .load(Ordering::Acquire)
            != reconnect_generation
        {
            log::debug!(
                "Not reconnecting the {} route to {} because another attempt completed",
                operation.name(),
                server_slot.socket_address(),
            );
            bail!(
                "Another {} connection attempt to TACACS+ server {} completed for this request",
                operation.name(),
                server_slot.socket_address()
            );
        }

        log::debug!(
            "Opening an {} connection to TACACS+ server {}",
            operation.name(),
            server_slot.socket_address()
        );
        match self
            .connector
            .connect(Arc::clone(&server_slot.server), operation)
            .await
        {
            Ok(connection) => {
                let generation = operation_slot
                    .completed_connect_attempts
                    .fetch_add(1, Ordering::AcqRel)
                    .saturating_add(1);
                log::info!(
                    "Opened an {} connection to TACACS+ server {}",
                    operation.name(),
                    server_slot.socket_address(),
                );
                *operation_slot.connection.write().await = Some(Arc::clone(&connection));
                Ok((connection, generation))
            }
            Err(error) => {
                log::warn!(
                    "Failed to connect to upstream TACACS+ server {}: {error:#}",
                    server_slot.socket_address(),
                );
                *operation_slot.connection.write().await = None;
                operation_slot
                    .completed_connect_attempts
                    .fetch_add(1, Ordering::AcqRel);
                Err(error)
            }
        }
    }

    async fn note_failure(
        &self,
        server_set: &Arc<ServerSet>,
        index: usize,
        operation: OperationKind,
        failed_generation: Option<u64>,
    ) {
        let operation_slot = server_set.servers[index].operation(operation);
        let connect_guard = operation_slot.connect_lock.lock().await;
        let current_generation = operation_slot
            .completed_connect_attempts
            .load(Ordering::Acquire);
        let connection = if failed_generation.is_none_or(|failed| failed == current_generation) {
            operation_slot.connection.write().await.take()
        } else {
            log::debug!(
                "Ignoring a stale {} connection failure for {}",
                operation.name(),
                server_set.servers[index].socket_address()
            );
            return;
        };
        operation_slot.circuit.open();
        let route_change = server_set.route(operation).advance_if_active(index).await;
        drop(connect_guard);

        if let Some(connection) = connection {
            connection.stop_accepting_new_sessions().await;
        }
        if let Some((previous, next)) = route_change {
            log::info!(
                "Failing over {} requests from {} to {}",
                operation.name(),
                server_set.servers[previous].socket_address(),
                server_set.servers[next].socket_address()
            );
        }
    }

    /// Records a request failure in the server set that the request used.
    ///
    /// Services reach this through [`crate::upstream::OperationRouter`].
    pub(in crate::upstream) async fn note_bound_server_failure(&self, bound_server: &BoundServer) {
        if let Some(permit) = &bound_server.recovery_permit {
            permit.fail();
        }
        self.note_failure(
            &bound_server.server_set,
            bound_server.index,
            bound_server.operation,
            Some(bound_server.connection_generation),
        )
        .await;
    }

    /// Records a successful request and completes a recovery trial when present.
    ///
    /// Services reach this through [`crate::upstream::OperationRouter`].
    pub(in crate::upstream) async fn note_bound_server_success(&self, bound_server: &BoundServer) {
        let Some(permit) = &bound_server.recovery_permit else {
            return;
        };
        permit.succeed();
        let route = bound_server.server_set.route(bound_server.operation);
        if let Some(position) = route.position_of(bound_server.index) {
            route.set_active_position(position).await;
            log::info!(
                "Recovered the {} route through {}",
                bound_server.operation.name(),
                bound_server.connection.server_address()
            );
        }
    }
}
