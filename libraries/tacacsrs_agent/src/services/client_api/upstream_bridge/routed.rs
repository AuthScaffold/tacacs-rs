//! Shared operation helpers for [`UpstreamBridge`].

use std::num::NonZeroU32;

use async_trait::async_trait;
use tacacsrs_networking::routed::EndpointConnector;
use tacacsrs_protocol::failure::{DeliveryState, FailureCategory, FailureFacts, FailurePhase};
use tacacsrs_protocol::failure::ServiceError;
use tacacsrs_networking::retry::{
    Attempt, AttemptDisposition, FailoverAttempt, FailoverOutcome, run_with_failover,
};

use super::UpstreamBridge;
use crate::upstream::{
    AttemptFailureKind, OperationKind, OperationRouter, RequestRouting, UpstreamConnection,
    UpstreamRequestError,
};

/// Operation-specific hooks used by the client API upstream bridge.
///
/// Accounting and authorization have different request, reply, and send types.
/// They use the same server selection, failure recording, and failover behavior.
/// This trait keeps the operation-specific implementations small and typed.
#[async_trait]
pub(super) trait RoutedOperation: Send + Sync + 'static {
    /// Client API request type for the operation.
    type Request: Clone + Send + Sync;
    /// Client API response type for the operation.
    type Response: Send;

    /// Lowercase operation name for log messages.
    const NAME: &'static str;
    /// Operation name with display capitalization for log messages.
    const DISPLAY_NAME: &'static str;
    /// TACACS+ operation used for routing and connection isolation.
    const OPERATION: OperationKind;
    /// Sends the operation through the selected server connection.
    async fn send<Connection: UpstreamConnection + ?Sized>(
        connection: &Connection,
        request: &Self::Request,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> Result<Self::Response, UpstreamRequestError>;

    /// Returns whether a valid response reports an operational server error.
    fn is_server_error(response: &Self::Response) -> bool;

    /// Returns the encoded TACACS+ request body length.
    fn request_body_length(request: &Self::Request) -> Result<usize, UpstreamRequestError>;
}

/// One client API request that the failover executor can retry.
struct RoutedAttempt<'request, Operation, Connector: EndpointConnector>
where
    Operation: RoutedOperation,
{
    router: &'request OperationRouter<Connector>,
    routing: RequestRouting<Connector>,
    request: &'request Operation::Request,
}

impl<Operation: RoutedOperation, Connector: EndpointConnector>
    RoutedAttempt<'_, Operation, Connector>
{
    fn with_attempt_context(&self, mut error: ServiceError, attempt_index: usize) -> ServiceError {
        error.runtime_generation = Some(self.routing.generation());
        error.attempt = u32::try_from(attempt_index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .and_then(NonZeroU32::new);
        error
    }
}

#[async_trait]
impl<Operation, Connector: EndpointConnector> FailoverAttempt
    for RoutedAttempt<'_, Operation, Connector>
where
    Operation: RoutedOperation,
    Connector::Connection: UpstreamConnection,
{
    type Value = Operation::Response;
    type Error = ServiceError;

    async fn attempt(&mut self, attempt_index: usize) -> Attempt<Self::Value, Self::Error> {
        let bound_server = match self.routing.bind().await {
            Ok(bound_server) => bound_server,
            Err(error) => {
                log::warn!("Failed to bind a client API request to a TACACS+ server: {error:#}");
                let category = if error.is::<tacacsrs_networking::DeadlineElapsed>() {
                    FailureCategory::Deadline
                } else {
                    FailureCategory::Unavailable
                };
                let error = ServiceError::new(
                    error.to_string(),
                    FailureFacts::new(category, FailurePhase::Routing, DeliveryState::NotSent),
                );
                return Attempt::Aborted(self.with_attempt_context(error, attempt_index));
            }
        };

        log::debug!(
            "Sending an {} request to {} (server index {}, attempt {})",
            Operation::NAME,
            bound_server.connection.server_address(),
            bound_server.index,
            attempt_index + 1,
        );

        let deadline = self.routing.deadline();
        if let Err(error) = deadline.check() {
            let error = ServiceError::new(
                error.to_string(),
                FailureFacts::new(
                    FailureCategory::Deadline,
                    FailurePhase::Upstream,
                    DeliveryState::NotSent,
                ),
            )
            .with_server(bound_server.connection.server_address());
            return Attempt::Aborted(self.with_attempt_context(error, attempt_index));
        }
        let attempt_deadline = deadline.capped(bound_server.timeout_duration());
        let response = attempt_deadline
            .run(async {
                let mut observation = bound_server.observe_failure();
                let response = Operation::send(&*bound_server.connection, self.request, attempt_deadline).await;
                if response.is_ok() || matches!(&response, Err(error) if error.kind() == AttemptFailureKind::InvalidRequest) {
                    observation.disarm();
                }
                response
            })
            .await
            .map_err(UpstreamRequestError::outcome_unknown)
            .and_then(std::convert::identity);
        match response {
            Ok(response) if Operation::is_server_error(&response) => {
                self.router.note_failure(&bound_server).await;
                Attempt::Rejected(response)
            }
            Ok(response) => {
                self.router.note_success(&bound_server).await;
                Attempt::Accepted(response)
            }
            Err(error) if error.kind() == AttemptFailureKind::InvalidRequest => Attempt::Aborted(
                self.with_attempt_context(
                    error
                        .into_service_error()
                        .with_server(bound_server.connection.server_address()),
                    attempt_index,
                ),
            ),
            Err(error) => {
                log::warn!(
                    "{} request failed on {}: {error:#}",
                    Operation::DISPLAY_NAME,
                    bound_server.connection.server_address(),
                );
                let disposition = match error.kind() {
                    AttemptFailureKind::NotSent => AttemptDisposition::NotSent,
                    AttemptFailureKind::OutcomeUnknown => AttemptDisposition::OutcomeUnknown,
                    AttemptFailureKind::InvalidRequest => {
                        unreachable!("invalid requests return before failure recording")
                    }
                };
                let service_error = self.with_attempt_context(
                    error
                        .into_service_error()
                        .with_server(bound_server.connection.server_address()),
                    attempt_index,
                );
                self.router.note_failure(&bound_server).await;
                Attempt::Failed {
                    error: service_error,
                    disposition,
                }
            }
        }
    }
}

impl<Connector: EndpointConnector> UpstreamBridge<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    /// Runs one client API operation against the selected TACACS+ server.
    ///
    /// The networking layer selects dedicated or single-connection behavior.
    /// [`OperationRouter`] selects a server and records the outcome. The shared
    /// failover executor decides whether another server receives the request.
    pub(super) async fn execute_operation<Operation>(
        &self,
        request: Operation::Request,
    ) -> Result<Operation::Response, ServiceError>
    where
        Operation: RoutedOperation,
    {
        let body_length = Operation::request_body_length(&request)
            .map_err(UpstreamRequestError::into_service_error)?;
        let routing = self.router.capture_request(Operation::OPERATION);
        let _admission_permit = routing.admit(body_length).await.map_err(|error| {
            error
                .into_service_error()
                .with_runtime_generation(routing.generation())
        })?;

        let plan = routing.failover_plan();
        let generation = routing.generation();
        let mut attempt = RoutedAttempt::<Operation, Connector> {
            router: &self.router,
            routing,
            request: &request,
        };

        match run_with_failover(plan, &mut attempt).await {
            FailoverOutcome::Accepted(response) | FailoverOutcome::Rejected(response) => {
                Ok(response)
            }
            FailoverOutcome::Failed(error) | FailoverOutcome::Aborted(error) => Err(error),
            FailoverOutcome::NoAttempt => Err(ServiceError::new(
                format!("No TACACS+ server completed the {} request", Operation::NAME),
                FailureFacts::new(
                    FailureCategory::Unavailable,
                    FailurePhase::Routing,
                    DeliveryState::NotSent,
                ),
            )
            .with_runtime_generation(generation)),
        }
    }
}
