//! Public client API operation handle over the shared upstream manager.

use tacacsrs_protocol::operations::{
    AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
    AuthorizationOperationResponse, PapAuthenticationOperation, PapAuthenticationOperationResponse,
    ServiceError,
};

use super::upstream_bridge::UpstreamBridge;
use crate::upstream::NetworkUpstreamConnector;

/// Cloneable entry point for local client API operations.
///
/// The handle executes PAP authentication, accounting, and authorization
/// operations against the shared upstream manager using the production native
/// connector. Each method returns a typed protocol response or a structured
/// [`ServiceError`]. A host adapts this handle to its IPC server. The handle
/// does not depend on the IPC transport or the protobuf schema.
#[derive(Clone)]
pub struct ClientApiHandle {
    bridge: UpstreamBridge<NetworkUpstreamConnector>,
}

impl ClientApiHandle {
    /// Creates a handle over the shared client API bridge.
    pub(crate) fn new(bridge: UpstreamBridge<NetworkUpstreamConnector>) -> Self {
        Self { bridge }
    }

    /// Runs one PAP authentication operation.
    ///
    /// # Errors
    /// Returns a structured [`ServiceError`] with conservative delivery facts.
    pub async fn authenticate_pap(
        &self,
        request: PapAuthenticationOperation,
    ) -> Result<PapAuthenticationOperationResponse, ServiceError> {
        self.bridge
            .execute_pap_authentication_request(request)
            .await
    }

    /// Runs one accounting operation.
    ///
    /// # Errors
    /// Returns a structured [`ServiceError`] with conservative delivery facts.
    pub async fn accounting(
        &self,
        request: AccountingOperation,
    ) -> Result<AccountingOperationResponse, ServiceError> {
        self.bridge.execute_accounting_request(request).await
    }

    /// Runs one authorization operation.
    ///
    /// # Errors
    /// Returns a structured [`ServiceError`] with conservative delivery facts.
    pub async fn authorization(
        &self,
        request: AuthorizationOperation,
    ) -> Result<AuthorizationOperationResponse, ServiceError> {
        self.bridge.execute_authorization_request(request).await
    }
}
