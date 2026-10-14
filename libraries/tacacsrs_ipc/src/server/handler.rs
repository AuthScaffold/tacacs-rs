//! Operation handler interface for the IPC server adapter.

use tacacsrs_protocol::operations::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse, PapAuthenticationOperation, PapAuthenticationOperationResponse,
    ServiceError,
};

/// Executes decoded client API operations for the IPC server.
///
/// The IPC server decodes each protobuf request into a protocol operation, calls
/// this handler, and encodes the typed result back into a protobuf reply. The
/// handler works only with protocol-domain types. It does not depend on the
/// protobuf schema, the transport, or any routing or networking abstraction.
///
/// A host supplies one handler implementation, usually a thin adapter over its
/// client runtime. A test can supply a deterministic handler without a runtime.
#[async_trait::async_trait]
pub trait Handler: Send + Sync + 'static {
    /// Runs one PAP authentication operation.
    ///
    /// # Errors
    /// Returns a structured [`ServiceError`] with conservative delivery facts.
    async fn authenticate_pap(
        &self,
        request: PapAuthenticationOperation,
    ) -> Result<PapAuthenticationOperationResponse, ServiceError>;

    /// Runs one accounting operation.
    ///
    /// # Errors
    /// Returns a structured [`ServiceError`] with conservative delivery facts.
    async fn accounting(
        &self,
        request: AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError>;

    /// Runs one authorization operation.
    ///
    /// # Errors
    /// Returns a structured [`ServiceError`] with conservative delivery facts.
    async fn authorization(
        &self,
        request: AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError>;
}
