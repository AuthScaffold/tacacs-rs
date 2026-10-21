//! Tonic gRPC service adapter over an operation [`Handler`].
//!
//! Each [`tonic`] handler registers an active request and sends the decoded
//! operation to the handler. This adapter owns the protobuf decoding and
//! encoding and the active-request tracking. It does not own routing, failover,
//! or configuration.

use std::sync::Arc;

use tacacsrs_protocol::operations::{
    AccountingOperation, AuthorizationOperation, PapAuthenticationOperation,
};
use tonic::{Request, Response, Status};

use super::Handler;
use super::request_tracker::RequestTracker;
use crate::proto;
use crate::proto::tacacs_agent_server::TacacsAgent;

/// Delegates each gRPC request to the operation [`Handler`].
pub(super) struct GrpcService<H: Handler> {
    handler: Arc<H>,
    request_tracker: Arc<RequestTracker>,
}

impl<H: Handler> GrpcService<H> {
    /// Creates a gRPC adapter over the handler and shared request tracker.
    pub(super) fn new(handler: Arc<H>, request_tracker: Arc<RequestTracker>) -> Self {
        Self {
            handler,
            request_tracker,
        }
    }
}

impl<H: Handler> Clone for GrpcService<H> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            request_tracker: self.request_tracker.clone(),
        }
    }
}

#[tonic::async_trait]
impl<H: Handler> TacacsAgent for GrpcService<H> {
    async fn authenticate_pap(
        &self,
        request: Request<proto::PapAuthenticationRequest>,
    ) -> Result<Response<proto::PapAuthenticationReply>, Status> {
        let request =
            PapAuthenticationOperation::try_from(request.into_inner()).map_err(|error| {
                log::warn!("Invalid IPC PAP authentication request: {error}");
                Status::invalid_argument(error.to_string())
            })?;
        let _request_guard = self.request_tracker.start_request();
        log::debug!("Received an IPC PAP authentication request for user={}", request.user);

        let result = match self.handler.authenticate_pap(request).await {
            Ok(response) => proto::PapAuthenticationReply {
                result: Some(proto::pap_authentication_reply::Result::Response(response.into())),
            },
            Err(error) => {
                log::warn!("IPC PAP authentication request failed: {error:?}");
                proto::PapAuthenticationReply {
                    result: Some(proto::pap_authentication_reply::Result::Error(error.into())),
                }
            }
        };
        Ok(Response::new(result))
    }

    /// Handles one accounting RPC from a local IPC client.
    ///
    /// This method decodes the protobuf request and sends it to the handler. It
    /// puts the result in the `AccountingReply` oneof envelope. It returns gRPC
    /// transport errors as [`Status`]. It puts operation errors in the
    /// `ServiceError` reply variant.
    async fn accounting(
        &self,
        request: Request<proto::AccountingRequest>,
    ) -> Result<Response<proto::AccountingReply>, Status> {
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
        let result = match self.handler.accounting(request).await {
            Ok(response) => {
                log::debug!(
                    "IPC accounting request is complete: server={}, status={:?}",
                    response.server,
                    response.status,
                );
                proto::AccountingReply {
                    result: Some(proto::accounting_reply::Result::Response(response.into())),
                }
            }
            Err(error) => {
                log::warn!("IPC accounting request failed: {error:?}");
                proto::AccountingReply {
                    result: Some(proto::accounting_reply::Result::Error(error.into())),
                }
            }
        };
        Ok(Response::new(result))
    }

    /// Handles one authorization RPC from a local IPC client.
    ///
    /// This method decodes the protobuf request and sends it to the handler. It
    /// puts the result in the `AuthorizationReply` oneof envelope.
    async fn authorization(
        &self,
        request: Request<proto::AuthorizationRequest>,
    ) -> Result<Response<proto::AuthorizationReply>, Status> {
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

        let result = match self.handler.authorization(request).await {
            Ok(response) => {
                log::debug!(
                    "IPC authorization request is complete: server={}, status={:?}",
                    response.server,
                    response.status,
                );
                proto::AuthorizationReply {
                    result: Some(proto::authorization_reply::Result::Response(response.into())),
                }
            }
            Err(error) => {
                log::warn!("IPC authorization request failed: {error:?}");
                proto::AuthorizationReply {
                    result: Some(proto::authorization_reply::Result::Error(error.into())),
                }
            }
        };
        Ok(Response::new(result))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tacacsrs_protocol::failure::{
        DeliveryState, FailureCategory, FailureFacts, FailurePhase, ServiceError,
    };
    use tacacsrs_protocol::operations::{
        AccountingOperation, AccountingOperationResponse, AuthorizationAuthenticationContext,
        AuthorizationOperation, AuthorizationOperationResponse, PapAuthenticationOperation,
        PapAuthenticationOperationResponse,
    };
    use tonic::Request;

    use super::{GrpcService, Handler};
    use crate::proto;
    use crate::proto::tacacs_agent_server::TacacsAgent;
    use crate::server::request_tracker::RequestTracker;

    /// A handler that returns one conservative authorization failure.
    struct FailingHandler;

    #[async_trait::async_trait]
    impl Handler for FailingHandler {
        async fn authenticate_pap(
            &self,
            _request: PapAuthenticationOperation,
        ) -> Result<PapAuthenticationOperationResponse, ServiceError> {
            unreachable!("the test only exercises authorization")
        }

        async fn accounting(
            &self,
            _request: AccountingOperation,
        ) -> Result<AccountingOperationResponse, ServiceError> {
            unreachable!("the test only exercises authorization")
        }

        async fn authorization(
            &self,
            _request: AuthorizationOperation,
        ) -> Result<AuthorizationOperationResponse, ServiceError> {
            Err(ServiceError::new(
                "Simulated failure",
                FailureFacts::new(
                    FailureCategory::Internal,
                    FailurePhase::Upstream,
                    DeliveryState::OutcomeUnknown,
                ),
            )
            .with_server("primary:49"))
        }
    }

    #[tokio::test]
    async fn authorization_failure_maps_to_the_service_error_oneof() {
        let service =
            GrpcService::new(Arc::new(FailingHandler), Arc::new(RequestTracker::default()));
        let request = AuthorizationOperation::builder(
            "admin",
            0,
            AuthorizationAuthenticationContext::TacacsAscii,
        )
        .port("pts/1")
        .remote_address("127.0.0.1")
        .service("shell")
        .command("/bin/echo")
        .command_arg("hello")
        .build()
        .unwrap();

        let reply = service
            .authorization(Request::new((&request).into()))
            .await
            .unwrap()
            .into_inner();

        let Some(proto::authorization_reply::Result::Error(error)) = reply.result else {
            panic!("the ServiceError oneof must contain the authorization error");
        };
        assert_eq!(error.server, "primary:49");
        assert_eq!(error.retry_advice, proto::RetryAdvice::Never as i32);
        assert!(error.message.contains("Simulated failure"));
    }
}
