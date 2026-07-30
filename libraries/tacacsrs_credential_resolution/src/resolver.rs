//! Async provider interface and plan execution.

use async_trait::async_trait;

use crate::{
    CredentialRequest, ResolutionError, ResolutionPlan, ResolvedCredential, ResolvedCredentialSet,
    ResolvedResponse,
};

/// Provider-neutral asynchronous credential resolver.
#[async_trait]
pub trait CredentialResolver: Send + Sync {
    /// Resolves one typed request.
    ///
    /// # Errors
    ///
    /// Returns a sanitized typed [`ResolutionError`] without raw references,
    /// provider paths, or source errors.
    async fn resolve(
        &self,
        request: &CredentialRequest,
    ) -> Result<ResolvedCredential, ResolutionError>;
}

/// Resolves every request in deterministic plan order and validates the closed result set.
///
/// # Errors
///
/// Returns the first sanitized provider error or a request/result mismatch.
pub async fn resolve_plan(
    plan: &ResolutionPlan,
    resolver: &dyn CredentialResolver,
) -> Result<ResolvedCredentialSet, ResolutionError> {
    let mut responses = Vec::with_capacity(plan.len());
    for request in plan.requests() {
        let credential = resolver.resolve(request).await?;
        responses.push(ResolvedResponse::new(request.slot(), credential));
    }
    ResolvedCredentialSet::from_responses(plan, responses)
}
