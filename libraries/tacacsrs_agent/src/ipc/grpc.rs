//! Tonic gRPC service adapter for local TACACS+ agent IPC.

use std::sync::Arc;

use tacacsrs_agent_client::ipc;
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgent;
use tacacsrs_agent_client::{AccountingOperation, AuthorizationOperation};
use tonic::{Request, Response, Status};

use crate::routing::RoutingState;

/// Thin gRPC service adapter that delegates every RPC into the shared routing
/// state.
///
/// Each [`tonic`] handler registers itself as an active client and forwards the
/// decoded request into the routing/failover machinery.
#[derive(Clone)]
pub(crate) struct GrpcService {
    state: Arc<RoutingState>,
}

impl GrpcService {
    /// Creates a gRPC adapter over the shared routing state.
    pub(crate) fn new(state: Arc<RoutingState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl TacacsAgent for GrpcService {
    /// Handles one unary accounting RPC from a local IPC client.
    ///
    /// Decodes the protobuf request, delegates to [`RoutingState`] for server
    /// selection and upstream execution, and encodes the result into the oneof
    /// `AccountingReply` envelope. Transport-level gRPC errors are returned as
    /// [`Status`]; application-level errors are returned inside the
    /// `ServiceError` variant of the reply.
    async fn accounting(
        &self,
        request: Request<ipc::AccountingRequest>,
    ) -> Result<Response<ipc::AccountingReply>, Status> {
        let request = AccountingOperation::try_from(request.into_inner()).map_err(|error| {
            log::warn!("Invalid IPC accounting request: {error}");
            Status::invalid_argument(error.to_string())
        })?;
        log::debug!(
            "Received IPC accounting request: user={}, cmd={}",
            request.user,
            request.command,
        );
        let result = match self.state.execute_accounting_request(request).await {
            Ok(response) => {
                log::debug!(
                    "IPC accounting request completed: server={}, status={:?}",
                    response.server,
                    response.status,
                );
                ipc::AccountingReply {
                    result: Some(ipc::accounting_reply::Result::Response(response.into_proto())),
                }
            }
            Err(error) => {
                log::warn!("IPC accounting request failed: {error:?}");
                ipc::AccountingReply {
                    result: Some(ipc::accounting_reply::Result::Error(error.into_proto())),
                }
            }
        };
        Ok(Response::new(result))
    }

    /// Handles one unary authorization RPC from a local IPC client.
    ///
    /// Decodes the protobuf request, delegates to [`RoutingState`] for server
    /// selection and upstream execution, and encodes the result into the oneof
    /// `AuthorizationReply` envelope.
    async fn authorization(
        &self,
        request: Request<ipc::AuthorizationRequest>,
    ) -> Result<Response<ipc::AuthorizationReply>, Status> {
        let request = AuthorizationOperation::try_from(request.into_inner()).map_err(|error| {
            log::warn!("Invalid IPC authorization request: {error}");
            Status::invalid_argument(error.to_string())
        })?;
        log::debug!(
            "Received IPC authorization request: user={}, service={}, cmd={}",
            request.user,
            request.service().unwrap_or("<missing>"),
            request.command().unwrap_or("<missing>"),
        );

        let result = match self.state.execute_authorization_request(request).await {
            Ok(response) => {
                log::debug!(
                    "IPC authorization request completed: server={}, status={:?}",
                    response.server,
                    response.status,
                );
                ipc::AuthorizationReply {
                    result: Some(ipc::authorization_reply::Result::Response(response.into_proto())),
                }
            }
            Err(error) => {
                log::warn!("IPC authorization request failed: {error:?}");
                ipc::AuthorizationReply {
                    result: Some(ipc::authorization_reply::Result::Error(error.into_proto())),
                }
            }
        };
        Ok(Response::new(result))
    }
}
