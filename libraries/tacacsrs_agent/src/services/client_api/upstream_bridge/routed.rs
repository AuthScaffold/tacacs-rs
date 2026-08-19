//! Shared operation helpers for [`UpstreamBridge`].

use async_trait::async_trait;
use tacacsrs_agent_client::ServiceError;

use super::UpstreamBridge;
use crate::upstream::{
    Attempt, AttemptDisposition, AttemptFailureKind, FailoverAttempt, FailoverOutcome,
    OperationKind, OperationRouter, UpstreamConnection, UpstreamRequestError, run_with_failover,
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
    async fn send(
        connection: &dyn UpstreamConnection,
        request: &Self::Request,
    ) -> Result<Self::Response, UpstreamRequestError>;

    /// Returns whether a valid response reports an operational server error.
    fn is_server_error(response: &Self::Response) -> bool;

    /// Returns the encoded TACACS+ request body length.
    fn request_body_length(request: &Self::Request) -> Result<usize, UpstreamRequestError>;
}

/// One client API request that the failover executor can retry.
struct RoutedAttempt<'request, Operation>
where
    Operation: RoutedOperation,
{
    router: &'request OperationRouter,
    request: &'request Operation::Request,
}

#[async_trait]
impl<Operation> FailoverAttempt for RoutedAttempt<'_, Operation>
where
    Operation: RoutedOperation,
{
    type Value = Operation::Response;
    type Error = ServiceError;

    async fn attempt(&mut self, attempt_index: usize) -> Attempt<Self::Value, Self::Error> {
        let bound_server = match self.router.bind(Operation::OPERATION).await {
            Ok(bound_server) => bound_server,
            Err(error) => {
                log::warn!("Failed to bind a client API request to a TACACS+ server: {error:#}");
                return Attempt::Aborted(ServiceError::new(error.to_string()).retriable(true));
            }
        };

        log::debug!(
            "Sending an {} request to {} (server index {}, attempt {})",
            Operation::NAME,
            bound_server.connection.server_address(),
            bound_server.index,
            attempt_index + 1,
        );

        match Operation::send(&*bound_server.connection, self.request).await {
            Ok(response) if Operation::is_server_error(&response) => {
                self.router.note_failure(&bound_server).await;
                Attempt::Rejected(response)
            }
            Ok(response) => {
                self.router.note_success(&bound_server).await;
                Attempt::Accepted(response)
            }
            Err(error) if error.kind() == AttemptFailureKind::InvalidRequest => {
                Attempt::Aborted(ServiceError::new(error.to_string()).retriable(false))
            }
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
                let service_error = ServiceError::new(error.to_string())
                    .with_server(bound_server.connection.server_address())
                    .retriable(true);
                self.router.note_failure(&bound_server).await;
                Attempt::Failed {
                    error: service_error,
                    disposition,
                }
            }
        }
    }
}

impl UpstreamBridge {
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
            .map_err(|error| ServiceError::new(error.to_string()).retriable(false))?;
        let _admission_permit = self
            .router
            .admit(Operation::OPERATION, body_length)
            .await
            .map_err(|error| {
                let retriable = error.is_retriable();
                ServiceError::new(error.to_string()).retriable(retriable)
            })?;

        let plan = self.router.failover_plan(Operation::OPERATION);
        let mut attempt = RoutedAttempt::<Operation> {
            router: &self.router,
            request: &request,
        };

        match run_with_failover(plan, &mut attempt).await {
            FailoverOutcome::Accepted(response) | FailoverOutcome::Rejected(response) => {
                Ok(response)
            }
            FailoverOutcome::Failed(error) | FailoverOutcome::Aborted(error) => Err(error),
            FailoverOutcome::NoAttempt => Err(ServiceError::new(format!(
                "No TACACS+ server completed the {} request",
                Operation::NAME
            ))
            .retriable(true)),
        }
    }
}
