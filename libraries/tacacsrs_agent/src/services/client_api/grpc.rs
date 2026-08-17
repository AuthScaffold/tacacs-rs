//! Tonic gRPC service adapter for the local client API.

use std::sync::Arc;

use tacacsrs_agent_client::ipc;
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgent;
use tacacsrs_agent_client::{AccountingOperation, AuthorizationOperation, PapAuthenticationOperation};
use tonic::{Request, Response, Status};

use crate::runtime::RequestTracker;
use crate::services::client_api::upstream_bridge::UpstreamBridge;
use crate::upstream::manager::UpstreamManager;

/// Delegates each gRPC request to the client API upstream bridge.
///
/// Each [`tonic`] handler registers an active request. It then sends the decoded
/// request to the upstream bridge.
#[derive(Clone)]
pub(crate) struct GrpcService {
    upstream_bridge: UpstreamBridge,
    request_tracker: Arc<RequestTracker>,
}

impl GrpcService {
    /// Creates a gRPC adapter for the shared upstream manager.
    pub(crate) fn new(
        upstream_manager: Arc<UpstreamManager>,
        request_tracker: Arc<RequestTracker>,
    ) -> Self {
        Self {
            upstream_bridge: UpstreamBridge::new(upstream_manager),
            request_tracker,
        }
    }
}

#[tonic::async_trait]
impl TacacsAgent for GrpcService {
    async fn authenticate_pap(
        &self,
        request: Request<ipc::PapAuthenticationRequest>,
    ) -> Result<Response<ipc::PapAuthenticationReply>, Status> {
        let request =
            PapAuthenticationOperation::try_from(request.into_inner()).map_err(|error| {
                log::warn!("Invalid IPC PAP authentication request: {error}");
                Status::invalid_argument(error.to_string())
            })?;
        let _request_guard = self.request_tracker.start_request();
        log::debug!("Received an IPC PAP authentication request for user={}", request.user);

        let result = match self
            .upstream_bridge
            .execute_pap_authentication_request(request)
            .await
        {
            Ok(response) => ipc::PapAuthenticationReply {
                result: Some(ipc::pap_authentication_reply::Result::Response(
                    response.into_proto(),
                )),
            },
            Err(error) => {
                log::warn!("IPC PAP authentication request failed: {error:?}");
                ipc::PapAuthenticationReply {
                    result: Some(ipc::pap_authentication_reply::Result::Error(error.into_proto())),
                }
            }
        };
        Ok(Response::new(result))
    }

    /// Handles one accounting RPC from a local IPC client.
    ///
    /// This method decodes the protobuf request and sends it to the upstream
    /// bridge. It puts the result in the `AccountingReply` oneof envelope. It
    /// returns gRPC transport errors as [`Status`]. It puts operation errors in
    /// the `ServiceError` reply variant.
    async fn accounting(
        &self,
        request: Request<ipc::AccountingRequest>,
    ) -> Result<Response<ipc::AccountingReply>, Status> {
        let request = AccountingOperation::try_from(request.into_inner()).map_err(|error| {
            log::warn!("Invalid IPC accounting request: {error}");
            Status::invalid_argument(error.to_string())
        })?;
        let _request_guard = self.request_tracker.start_request();
        log::debug!(
            "Received an IPC accounting request: user={}, cmd={}",
            request.user,
            request.command,
        );
        let result = match self
            .upstream_bridge
            .execute_accounting_request(request)
            .await
        {
            Ok(response) => {
                log::debug!(
                    "IPC accounting request is complete: server={}, status={:?}",
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

    /// Handles one authorization RPC from a local IPC client.
    ///
    /// This method decodes the protobuf request and sends it to the upstream
    /// bridge. It puts the result in the `AuthorizationReply` oneof envelope.
    async fn authorization(
        &self,
        request: Request<ipc::AuthorizationRequest>,
    ) -> Result<Response<ipc::AuthorizationReply>, Status> {
        let request = AuthorizationOperation::try_from(request.into_inner()).map_err(|error| {
            log::warn!("Invalid IPC authorization request: {error}");
            Status::invalid_argument(error.to_string())
        })?;
        let _request_guard = self.request_tracker.start_request();
        log::debug!(
            "Received an IPC authorization request: user={}, service={}, cmd={}",
            request.user,
            request.service().unwrap_or("<missing>"),
            request.command().unwrap_or("<missing>"),
        );

        let result = match self
            .upstream_bridge
            .execute_authorization_request(request)
            .await
        {
            Ok(response) => {
                log::debug!(
                    "IPC authorization request is complete: server={}, status={:?}",
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
