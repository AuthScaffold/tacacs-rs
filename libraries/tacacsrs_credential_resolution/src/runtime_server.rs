//! Closed non-serializable runtime server configuration.

use std::fmt;

use tacacsrs_config::TacacsPlusServer;

use crate::{
    CredentialResolver, ResolutionError, ResolutionPlan, ResolvedCredential, ResolvedCredentialSet,
    SecretBytes, resolve_plan,
};

/// Validated runtime server with optional resolved central credential material.
///
/// The generated configuration retains opaque central references. Resolved
/// material remains in the non-cloneable, non-serializable result set.
pub struct RuntimeServer {
    config: TacacsPlusServer,
    credentials: ResolvedCredentialSet,
}

impl RuntimeServer {
    /// Creates a runtime server that has no central credential requests.
    ///
    /// # Errors
    ///
    /// Returns an error when the server contains a central reference and must
    /// be constructed through [`resolve`](Self::resolve).
    pub fn inline(config: TacacsPlusServer) -> Result<Self, ResolutionError> {
        let plan = ResolutionPlan::from_server(&config)?;
        if let Some(request) = plan.requests().first() {
            return Err(ResolutionError::resolution_required(
                request.context().clone(),
                request.kind(),
            ));
        }
        let credentials = ResolvedCredentialSet::from_responses(&plan, [])?;
        Ok(Self {
            config,
            credentials,
        })
    }

    /// Resolves every central request and constructs one closed runtime server.
    ///
    /// # Errors
    ///
    /// Returns a typed resolution error if planning, provider resolution, or
    /// request/result matching fails.
    pub async fn resolve(
        config: TacacsPlusServer,
        resolver: &dyn CredentialResolver,
    ) -> Result<Self, ResolutionError> {
        let plan = ResolutionPlan::from_server(&config)?;
        let credentials = resolve_plan(&plan, resolver).await?;
        debug_assert!(credentials.matches_plan(&plan));
        Ok(Self {
            config,
            credentials,
        })
    }

    /// Returns the generated server configuration containing references only.
    #[must_use]
    pub const fn config(&self) -> &TacacsPlusServer {
        &self.config
    }

    /// Returns the resolved TLS 1.3 EPSK bytes when centrally configured.
    #[must_use]
    pub fn tls13_epsk_secret(&self) -> Option<&SecretBytes> {
        match self
            .credentials
            .credential_for_field("client-identity/tls13-epsk")
        {
            Some(ResolvedCredential::SymmetricKey(material)) => Some(&material.key),
            Some(
                ResolvedCredential::CertificateWithKey(_)
                | ResolvedCredential::CaCertificateBag(_)
                | ResolvedCredential::EeCertificateBag(_),
            )
            | None => None,
        }
    }

    /// Returns whether this runtime owns provider-resolved credential material.
    #[must_use]
    pub fn has_resolved_credentials(&self) -> bool {
        !self.credentials.is_empty()
    }
}

impl fmt::Debug for RuntimeServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeServer")
            .field("credential_count", &self.credentials.len())
            .finish_non_exhaustive()
    }
}
