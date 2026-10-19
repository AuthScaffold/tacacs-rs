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
    /// Providers must register owned work before it can outlive this future.
    /// Queued workers and unconsumed results must retain their registered lease.
    async fn resolve(
        &self,
        request: &CredentialRequest,
        scope: &crate::WorkScope,
    ) -> Result<ResolvedCredential, ResolutionError>;
}

/// Resolves each request in deterministic plan order.
///
/// This function also makes sure that the closed result set is valid.
///
/// # Errors
///
/// Returns the first sanitized provider error or a request/result mismatch.
pub async fn resolve_plan(
    plan: &ResolutionPlan,
    resolver: &dyn CredentialResolver,
    scope: &crate::WorkScope,
) -> Result<ResolvedCredentialSet, ResolutionError> {
    let mut responses = Vec::with_capacity(plan.len());
    for request in plan.requests() {
        let credential = resolver.resolve(request, scope).await?;
        responses.push(ResolvedResponse::new(request.slot(), credential));
    }
    ResolvedCredentialSet::from_responses(plan, responses)
}
