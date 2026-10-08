//! Adapts networking bindings to source metadata and service health.

use std::sync::Arc;

use super::{BoundServer, RoutingLease, UpstreamManager};
#[cfg(test)]
use crate::config::{PolicyService, PreparedProxyPolicy};
#[cfg(test)]
use crate::upstream::OperationKind;

impl UpstreamManager {
    #[cfg(test)]
    pub(crate) async fn bind_server_for_new_session(&self) -> anyhow::Result<BoundServer> {
        self.bind_server_for_operation(OperationKind::Authentication)
            .await
    }

    #[cfg(test)]
    pub(in crate::upstream) async fn bind_server_for_operation(
        &self,
        operation: OperationKind,
    ) -> anyhow::Result<BoundServer> {
        self.bind_request(&self.capture_request(PolicyService::ClientApi, operation))
            .await
    }

    #[cfg(test)]
    pub(crate) async fn bind_proxy_server_for_new_session(
        &self,
        operation: OperationKind,
    ) -> anyhow::Result<(BoundServer, PreparedProxyPolicy)> {
        let lease = self.capture_request(PolicyService::TacacsProxy, operation);
        let bound = self.bind_request(&lease).await?;
        Ok((bound, lease.runtime.proxy_downstream_obfuscation.clone()))
    }

    pub(in crate::upstream) async fn bind_request(
        &self,
        lease: &RoutingLease,
    ) -> anyhow::Result<BoundServer> {
        let runtime = &lease.runtime;
        let client = &runtime.server_set.client;
        if client.eligible_count(lease.operation) == 0 {
            anyhow::bail!(
                "No configured TACACS+ server supports {}; waiting for initial configuration",
                lease.operation.name()
            );
        }
        let observation = self
            .availability
            .begin_attempt(runtime.availability_generation);
        match lease
            .deadline()
            .run(client.bind(lease.operation, runtime.runtime_policy.failover_recovery_interval()))
            .await
            .map_err(anyhow::Error::from)
            .and_then(std::convert::identity)
        {
            Ok(binding) => {
                self.availability.available(observation);
                Ok(BoundServer {
                    server: Arc::clone(&runtime.server_set.servers[binding.index()].server),
                    index: binding.index(),
                    connection: Arc::clone(binding.connection()),
                    binding,
                })
            }
            Err(error) => {
                if !error.is::<tacacsrs_networking::DeadlineElapsed>() {
                    self.availability.unavailable(observation);
                }
                Err(error)
            }
        }
    }

    pub(in crate::upstream) async fn note_bound_server_failure(&self, bound_server: &BoundServer) {
        bound_server.binding.note_failure().await;
    }

    pub(in crate::upstream) async fn note_bound_server_success(&self, bound_server: &BoundServer) {
        bound_server.binding.note_success().await;
    }
}
