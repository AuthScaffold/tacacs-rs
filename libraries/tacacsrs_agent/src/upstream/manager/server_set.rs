//! Immutable configured server snapshots used by routing decisions.

use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use async_trait::async_trait;

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt};
use tacacsrs_networking::routed::{BoundEndpoint, EndpointConnector, RoutedClient};
use tacacsrs_networking::retry::FailoverPlan;
use tacacsrs_networking::RequestDeadline;

use super::prepared_server::PreparedServer;
use crate::config::{PolicyService, PreparedProxyPolicy, RuntimePolicy};
use crate::upstream::admission::AdmissionRegistry;
use crate::upstream::admission::AdmissionError;
use crate::upstream::OperationKind;
#[cfg(test)]
use crate::upstream::{UpstreamConnection, UpstreamConnector};

/// Immutable routing inputs published as one generation.
pub(super) struct RuntimeRoutingSnapshot<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    pub(super) generation: u64,
    pub(super) availability_generation: u64,
    pub(super) server_set: Arc<ServerSet<Connector>>,
    pub(super) proxy_downstream_obfuscation: PreparedProxyPolicy,
    pub(super) runtime_policy: Arc<RuntimePolicy>,
    pub(super) admission: Arc<AdmissionRegistry>,
    pub(super) credential_lifetime: crate::runtime::CredentialLifetime,
}

/// One request's immutable routing and retry-policy inputs.
pub(crate) struct RoutingLease<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    pub(super) runtime: Arc<RuntimeRoutingSnapshot<Connector>>,
    pub(super) operation: OperationKind,
    plan: FailoverPlan,
    deadline: RequestDeadline,
}

impl<Connector: EndpointConnector> RoutingLease<Connector> {
    pub(super) fn new(
        runtime: Arc<RuntimeRoutingSnapshot<Connector>>,
        service: PolicyService,
        operation: OperationKind,
    ) -> Self {
        let plan = runtime
            .runtime_policy
            .failover_plan(service, runtime.server_set.client.eligible_count(operation));
        let deadline =
            RequestDeadline::after(runtime.runtime_policy.limits(operation).request_timeout())
                .unwrap_or_else(|_| RequestDeadline::at(tokio::time::Instant::now()));
        let deadline = runtime
            .credential_lifetime
            .deadline
            .map_or(deadline, |expiry| RequestDeadline::at(deadline.expires_at().min(expiry)));
        Self {
            runtime,
            operation,
            plan,
            deadline,
        }
    }

    pub(crate) const fn failover_plan(&self) -> FailoverPlan {
        self.plan
    }

    pub(crate) const fn deadline(&self) -> RequestDeadline {
        self.deadline
    }

    pub(crate) fn generation(&self) -> u64 {
        self.runtime.generation
    }

    pub(crate) fn validate_body_length(&self, body_length: usize) -> Result<(), AdmissionError> {
        let maximum = self
            .runtime
            .runtime_policy
            .limits(self.operation)
            .max_body_length();
        if body_length > maximum {
            return Err(AdmissionError::BodyTooLarge {
                actual: body_length,
                maximum,
            });
        }
        Ok(())
    }
}

/// Source metadata and the networking-owned catalog published with it.
pub(super) struct ServerSet<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    pub(super) servers: Vec<Arc<PreparedServer>>,
    pub(super) client: RoutedClient<Connector>,
}

#[cfg(test)]
pub(crate) struct ServiceConnector(pub(crate) Arc<UpstreamConnector>);

#[cfg(test)]
#[async_trait]
impl EndpointConnector for ServiceConnector {
    type Connection = dyn UpstreamConnection;

    async fn connect(
        &self,
        endpoint: tacacsrs_networking::PreparedEndpoint,
        operation: OperationKind,
    ) -> anyhow::Result<Arc<Self::Connection>> {
        self.0.connect(endpoint, operation).await
    }

    async fn retire(&self, connection: &Self::Connection) {
        connection.stop_accepting_new_sessions().await;
    }

    fn close(&self, connection: &Self::Connection) {
        connection.close();
    }

    async fn close_and_join(
        &self,
        connection: &Self::Connection,
        deadline: RequestDeadline,
    ) -> anyhow::Result<()> {
        connection.close_and_join(deadline).await
    }
}

/// Result of binding an IPC request to a TACACS+ server.
///
/// Contains the server index for failover records and the request connection.
pub(crate) struct BoundServer<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    pub(super) server: Arc<TacacsPlusServer>,
    pub(super) binding: BoundEndpoint<Connector>,
    /// Index in the service server list.
    pub(crate) index: usize,
    /// Server connection for this request.
    pub(crate) connection: Arc<Connector::Connection>,
}

impl<Connector: EndpointConnector> BoundServer<Connector> {
    /// Returns the configured upstream server selected for this request.
    pub(crate) fn server(&self) -> &TacacsPlusServer {
        &self.server
    }

    /// Returns the timeout configured on the selected upstream server.
    pub(crate) fn timeout_duration(&self) -> Duration {
        self.server().timeout_duration()
    }
}

impl<Connector: EndpointConnector> ServerSet<Connector> {
    pub(super) fn new(servers: Vec<Arc<PreparedServer>>, connector: Connector) -> Self {
        let client = RoutedClient::with_connector(
            servers
                .iter()
                .map(|server| server.endpoint.clone())
                .collect(),
            connector,
        );
        Self { servers, client }
    }

    pub(super) fn server_count(&self) -> usize {
        self.servers.len()
    }
}
