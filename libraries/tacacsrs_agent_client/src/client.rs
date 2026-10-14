//! Local gRPC client helpers for communication with the central TACACS+ service.
//!
//! Callers give the client a local IPC endpoint. The client sends each request
//! through the protobuf/gRPC contract. It does not expose TACACS+ wire details.
//!
//! # Transport behavior
//!
//! The production service uses a Unix domain socket at
//! `/run/tacacs/tacacs.sock`. The client also supports loopback TCP endpoints
//! for the Linux IPC emulator.
//!
//! [`ServiceClient`] holds a persistent gRPC [`tonic::transport::Channel`] that
//! is established during construction and reused for all requests. gRPC over
//! HTTP/2 multiplexes concurrent RPCs on one connection. Thus, callers can send
//! requests in parallel without a new connection for each request.

use tonic::Status;
use tonic::transport::Channel;

use crate::convert::{ipc_protocol_failure, ipc_transport_failure};
use crate::ipc;
use crate::ipc::tacacs_agent_client::TacacsAgentClient;
use tacacsrs_protocol::operations::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse, PapAuthenticationOperation, PapAuthenticationOperationResponse,
    ServiceError,
};
use crate::endpoint::connect_channel;
use crate::IpcEndpoint;

/// Convenience wrapper for making local IPC calls to the central service.
///
/// `ServiceClient` holds a persistent gRPC [`Channel`] that is established once
/// during construction and reuses it for all requests. gRPC over HTTP/2
/// multiplexes concurrent RPCs on one connection. Thus, callers can send
/// requests in parallel without a new connection for each request.
///
/// The type is [`Clone`] and [`Send`]; cloning is cheap because [`Channel`] is
/// reference-counted internally.
///
/// # Connection flow
///
/// ```text
/// Caller           ServiceClient        IpcEndpoint       Central Service
///   |                   |                   |                   |
///   | send_accounting() |                   |                   |
///   |------------------>|                   |                   |
///   |                   | gRPC Accounting(request)              |
///   |                   |-------------------------------------->|
///   |                   |                                       |
///   |                   |              AccountingReply          |
///   |                   |<--------------------------------------|
///   |                   |                                       |
///   |   Ok(response)    |                                       |
///   |   or Err(error)   |                                       |
///   |<------------------|                                       |
/// ```
///
/// # Examples
///
/// ```rust,no_run
/// # use tacacsrs_agent_client::{IpcEndpoint, ServiceClient};
/// # use tacacsrs_protocol::operations::AccountingOperation;
/// # async fn example() -> anyhow::Result<()> {
/// let client = ServiceClient::connect(IpcEndpoint::default_local()).await?;
///
/// let response = client
///     .send_accounting(AccountingOperation {
///         user: "admin".into(),
///         port: "tty0".into(),
///         remote_address: "10.0.0.1".into(),
///         command: "show".into(),
///         command_arguments: vec!["users".into()],
///     })
///     .await?;
///
/// println!("Handled by {} → {:?}", response.server, response.status);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ServiceClient {
    /// The persistent gRPC channel shared across all requests.
    channel: Channel,
}

impl ServiceClient {
    /// Establishes a gRPC channel to the local IPC endpoint.
    ///
    /// The returned [`ServiceClient`] reuses the channel for all requests.
    ///
    /// This connects over a Unix domain socket using `tonic`'s
    /// `connect_with_connector` to bridge `tokio::net::UnixStream` into the
    /// HTTP/2 transport. On other platforms it connects over loopback TCP.
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot establish the IPC connection.
    pub async fn connect(endpoint: IpcEndpoint) -> anyhow::Result<Self> {
        let channel = connect_channel(&endpoint).await?;
        Ok(Self { channel })
    }

    /// Sends a single accounting request to the local TACACS+ client service.
    ///
    /// Converts the domain [`AccountingOperation`] into a protobuf request. It
    /// sends the unary RPC over the persistent channel and converts the reply
    /// into the domain response type. Concurrent calls use the same HTTP/2
    /// connection.
    ///
    /// # Errors
    ///
    /// Returns a [`ServiceError`] when:
    /// - The service returns a structured error, for example, when all upstream
    ///   TACACS+ servers are unavailable. The remote failure facts are preserved.
    /// - The IPC RPC fails at the transport level. The delivery outcome is
    ///   unknown, so the error never recommends an automatic replay.
    /// - The reply is missing or malformed. The error is conservative for the
    ///   same reason.
    pub async fn send_accounting(
        &self,
        request: AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        let mut client = TacacsAgentClient::new(self.channel.clone());
        let rpc_request: ipc::AccountingRequest = (&request).into();
        let reply = client
            .accounting(rpc_request)
            .await
            .map_err(|status| rpc_status_failure("Accounting", &status))?
            .into_inner();

        match reply.result {
            None => Err(malformed_reply("Accounting", "returned no result")),
            Some(ipc::accounting_reply::Result::Response(response)) => {
                AccountingOperationResponse::try_from(response).map_err(|error| {
                    malformed_reply(
                        "Accounting",
                        &format!("returned a malformed response: {error}"),
                    )
                })
            }
            Some(ipc::accounting_reply::Result::Error(error)) => {
                Err(remote_service_error("Accounting", error))
            }
        }
    }

    /// Authenticates one user name and password with PAP.
    ///
    /// # Errors
    ///
    /// Returns a [`ServiceError`] when the service returns a structured error,
    /// when the IPC RPC fails at the transport level, or when the reply is
    /// missing or malformed. A transport or malformed-reply failure has an
    /// unknown delivery outcome and never recommends an automatic replay.
    pub async fn authenticate_pap(
        &self,
        request: PapAuthenticationOperation,
    ) -> Result<PapAuthenticationOperationResponse, ServiceError> {
        let mut client = TacacsAgentClient::new(self.channel.clone());
        let reply = client
            .authenticate_pap(ipc::PapAuthenticationRequest::from(request))
            .await
            .map_err(|status| rpc_status_failure("PAP authentication", &status))?
            .into_inner();

        match reply.result {
            None => Err(malformed_reply("PAP authentication", "returned no result")),
            Some(ipc::pap_authentication_reply::Result::Response(response)) => {
                PapAuthenticationOperationResponse::try_from(response).map_err(|error| {
                    malformed_reply(
                        "PAP authentication",
                        &format!("returned a malformed response: {error}"),
                    )
                })
            }
            Some(ipc::pap_authentication_reply::Result::Error(error)) => {
                Err(remote_service_error("PAP authentication", error))
            }
        }
    }

    /// Sends a single authorization request to the local TACACS+ client service.
    ///
    /// Converts the domain [`AuthorizationOperation`] into a protobuf request.
    /// It sends the unary RPC over the persistent channel and converts the reply
    /// into the domain response type.
    ///
    /// # Errors
    ///
    /// Returns a [`ServiceError`] when the service returns a structured error,
    /// when the IPC RPC fails at the transport level, or when the reply is
    /// missing or malformed. A transport or malformed-reply failure has an
    /// unknown delivery outcome and never recommends an automatic replay.
    pub async fn send_authorization(
        &self,
        request: AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        let mut client = TacacsAgentClient::new(self.channel.clone());
        let rpc_request: ipc::AuthorizationRequest = (&request).into();
        let reply = client
            .authorization(rpc_request)
            .await
            .map_err(|status| rpc_status_failure("Authorization", &status))?
            .into_inner();

        match reply.result {
            None => Err(malformed_reply("Authorization", "returned no result")),
            Some(ipc::authorization_reply::Result::Response(response)) => {
                AuthorizationOperationResponse::try_from(response).map_err(|error| {
                    malformed_reply(
                        "Authorization",
                        &format!("returned a malformed response: {error}"),
                    )
                })
            }
            Some(ipc::authorization_reply::Result::Error(error)) => {
                Err(remote_service_error("Authorization", error))
            }
        }
    }
}

/// Builds a conservative error for an in-flight IPC RPC status failure.
///
/// The RPC was sent, so the operation can have reached a server. The delivery
/// outcome is unknown, so the error does not recommend a replay even when gRPC
/// reports a temporary status such as `Unavailable`.
fn rpc_status_failure(rpc: &str, status: &Status) -> ServiceError {
    ipc_transport_failure(format!(
        "{rpc} RPC failed at the IPC transport ({:?}): {}",
        status.code(),
        status.message()
    ))
}

/// Builds a conservative error for a missing or malformed IPC reply.
fn malformed_reply(rpc: &str, detail: &str) -> ServiceError {
    ipc_protocol_failure(format!("{rpc} RPC {detail}"))
}

/// Converts a structured remote error and preserves its failure facts.
///
/// A payload that fails validation is treated as a malformed reply so a buggy
/// or hostile peer cannot assert an unsafe retry outcome.
fn remote_service_error(rpc: &str, error: ipc::ServiceError) -> ServiceError {
    ServiceError::try_from(error).unwrap_or_else(|decode_error| {
        malformed_reply(rpc, &format!("returned a malformed service error: {decode_error}"))
    })
}

#[cfg(test)]
mod sdk_tests {
    use super::*;

    use std::net::{Ipv4Addr, SocketAddr};
    use std::num::NonZeroU32;

    use tacacsrs_protocol::failure::{
        DeliveryState, FailureCategory, FailureFacts, FailurePhase, RetryAdvice,
    };
    use tacacsrs_protocol::privilege::PrivilegeLevel;
    use tacacsrs_secrets::SecretBytes;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};

    use crate::ipc::tacacs_agent_server::{TacacsAgent, TacacsAgentServer};

    /// Scripted agent that selects a reply from the request discriminator.
    ///
    /// Accounting uses the command, PAP uses the user name. A `status-failure`
    /// discriminator returns a gRPC status instead of a reply.
    #[derive(Clone, Default)]
    struct ScriptedAgent;

    #[tonic::async_trait]
    impl TacacsAgent for ScriptedAgent {
        async fn authenticate_pap(
            &self,
            request: Request<ipc::PapAuthenticationRequest>,
        ) -> Result<Response<ipc::PapAuthenticationReply>, Status> {
            let result = match request.into_inner().user.as_str() {
                "status-failure" => return Err(Status::unavailable("upstream IPC dropped")),
                "structured-error" => {
                    Some(ipc::pap_authentication_reply::Result::Error(structured_wire_error()))
                }
                "missing-result" => None,
                _ => Some(ipc::pap_authentication_reply::Result::Response(
                    ipc::PapAuthenticationResponse {
                        server: "primary".to_owned(),
                        status: ipc::AuthenticationStatus::Pass as i32,
                        server_message: String::new(),
                        data: Vec::new(),
                    },
                )),
            };
            Ok(Response::new(ipc::PapAuthenticationReply { result }))
        }

        async fn accounting(
            &self,
            request: Request<ipc::AccountingRequest>,
        ) -> Result<Response<ipc::AccountingReply>, Status> {
            let result = match request.into_inner().command.as_str() {
                "status-failure" => return Err(Status::unavailable("upstream IPC dropped")),
                "structured-error" => {
                    Some(ipc::accounting_reply::Result::Error(structured_wire_error()))
                }
                "invalid-error" => Some(ipc::accounting_reply::Result::Error(ipc::ServiceError {
                    message: "unvalidated error payload".to_owned(),
                    ..Default::default()
                })),
                "missing-result" => None,
                _ => Some(ipc::accounting_reply::Result::Response(ipc::AccountingResponse {
                    server: "primary".to_owned(),
                    status: ipc::AccountingStatus::Success as i32,
                    server_message: String::new(),
                    data: String::new(),
                })),
            };
            Ok(Response::new(ipc::AccountingReply { result }))
        }

        async fn authorization(
            &self,
            _request: Request<ipc::AuthorizationRequest>,
        ) -> Result<Response<ipc::AuthorizationReply>, Status> {
            Ok(Response::new(ipc::AuthorizationReply {
                result: Some(ipc::authorization_reply::Result::Response(
                    ipc::AuthorizationResponse {
                        server: "primary".to_owned(),
                        status: ipc::AuthorizationStatus::PassAdd as i32,
                        server_message: String::new(),
                        args: Vec::new(),
                        data: String::new(),
                    },
                )),
            }))
        }
    }

    /// Builds a wire error whose derived advice is `AfterRecovery` (unsent).
    fn structured_wire_error() -> ipc::ServiceError {
        let facts = FailureFacts::new(
            FailureCategory::Unavailable,
            FailurePhase::Routing,
            DeliveryState::NotSent,
        );
        ipc::ServiceError::from(
            ServiceError::new("no responsive TACACS+ servers are currently available", facts)
                .with_server("tacacs-a:49")
                .with_runtime_generation(11)
                .with_attempt(NonZeroU32::new(2).unwrap()),
        )
    }

    async fn connected_client() -> (ServiceClient, JoinHandle<()>) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind a loopback port");
        let address = listener.local_addr().expect("read the bound address");
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(TacacsAgentServer::new(ScriptedAgent))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .expect("the scripted test server runs");
        });
        let client = ServiceClient::connect(IpcEndpoint::Tcp(address))
            .await
            .expect("connect to the scripted server");
        (client, server)
    }

    fn accounting(command: &str) -> AccountingOperation {
        AccountingOperation {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            command: command.to_owned(),
            command_arguments: Vec::new(),
        }
    }

    fn pap(user: &str) -> PapAuthenticationOperation {
        PapAuthenticationOperation {
            user: user.to_owned(),
            password: SecretBytes::new(b"secret".to_vec()),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            privilege_level: PrivilegeLevel::MAX,
        }
    }

    #[tokio::test]
    async fn structured_remote_error_survives_public_method() {
        let (client, server) = connected_client().await;
        let error = client
            .send_accounting(accounting("structured-error"))
            .await
            .expect_err("the service returns a structured error");
        assert_eq!(error.facts.category(), FailureCategory::Unavailable);
        assert_eq!(error.facts.phase(), FailurePhase::Routing);
        assert_eq!(error.facts.delivery(), DeliveryState::NotSent);
        assert_eq!(error.facts.retry_advice(), RetryAdvice::AfterRecovery);
        assert_eq!(error.server.as_deref(), Some("tacacs-a:49"));
        assert_eq!(error.runtime_generation, Some(11));
        assert_eq!(error.attempt, NonZeroU32::new(2));
        server.abort();
    }

    #[tokio::test]
    async fn pap_structured_remote_error_survives_public_method() {
        let (client, server) = connected_client().await;
        let error = client
            .authenticate_pap(pap("structured-error"))
            .await
            .expect_err("the service returns a structured error");
        assert_eq!(error.facts.category(), FailureCategory::Unavailable);
        assert_eq!(error.facts.retry_advice(), RetryAdvice::AfterRecovery);
        assert_eq!(error.server.as_deref(), Some("tacacs-a:49"));
        server.abort();
    }

    #[tokio::test]
    async fn grpc_status_failure_is_never_a_safe_replay() {
        let (client, server) = connected_client().await;
        let error = client
            .send_accounting(accounting("status-failure"))
            .await
            .expect_err("the IPC RPC fails at the transport level");
        assert_eq!(error.facts.category(), FailureCategory::Transport);
        assert_eq!(error.facts.phase(), FailurePhase::Ipc);
        assert_eq!(error.facts.delivery(), DeliveryState::OutcomeUnknown);
        assert_eq!(error.facts.retry_advice(), RetryAdvice::Never);
        assert!(error.message.contains("upstream IPC dropped"));
        server.abort();
    }

    #[tokio::test]
    async fn missing_result_is_conservative() {
        let (client, server) = connected_client().await;
        let error = client
            .send_accounting(accounting("missing-result"))
            .await
            .expect_err("a reply without a result is malformed");
        assert_eq!(error.facts.category(), FailureCategory::Protocol);
        assert_eq!(error.facts.phase(), FailurePhase::Ipc);
        assert_eq!(error.facts.delivery(), DeliveryState::OutcomeUnknown);
        assert_eq!(error.facts.retry_advice(), RetryAdvice::Never);
        server.abort();
    }

    #[tokio::test]
    async fn invalid_error_payload_is_conservative() {
        let (client, server) = connected_client().await;
        let error = client
            .send_accounting(accounting("invalid-error"))
            .await
            .expect_err("an unvalidated error payload is malformed");
        assert_eq!(error.facts.category(), FailureCategory::Protocol);
        assert_eq!(error.facts.phase(), FailurePhase::Ipc);
        assert_eq!(error.facts.delivery(), DeliveryState::OutcomeUnknown);
        assert_eq!(error.facts.retry_advice(), RetryAdvice::Never);
        server.abort();
    }

    #[tokio::test]
    async fn successful_accounting_returns_a_response() {
        let (client, server) = connected_client().await;
        let response = client
            .send_accounting(accounting("show"))
            .await
            .expect("a valid reply becomes a domain response");
        assert_eq!(response.server, "primary");
        server.abort();
    }
}
