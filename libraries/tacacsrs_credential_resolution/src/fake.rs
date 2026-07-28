//! Deterministic fake resolver for tests and provider integration examples.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::{CredentialRequest, ProviderErrorKind, ResolutionError, ResolvedCredential, RequestSlot};

/// In-memory slot-indexed resolver that consumes configured responses once.
#[derive(Default)]
pub struct FakeCredentialResolver {
    responses: Mutex<BTreeMap<RequestSlot, Result<ResolvedCredential, ProviderErrorKind>>>,
}

impl FakeCredentialResolver {
    /// Creates an empty fake resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures resolved material for one request slot.
    #[must_use]
    pub fn with_response(self, slot: RequestSlot, credential: ResolvedCredential) -> Self {
        self.responses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(slot, Ok(credential));
        self
    }

    /// Configures a sanitized provider failure for one request slot.
    #[must_use]
    pub fn with_error(self, slot: RequestSlot, kind: ProviderErrorKind) -> Self {
        self.responses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(slot, Err(kind));
        self
    }
}

#[async_trait]
impl crate::CredentialResolver for FakeCredentialResolver {
    async fn resolve(
        &self,
        request: &CredentialRequest,
    ) -> Result<ResolvedCredential, ResolutionError> {
        let response = self
            .responses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&request.slot())
            .ok_or_else(|| {
                ResolutionError::provider(ProviderErrorKind::NotFound, request.context())
            })?;
        response.map_err(|kind| ResolutionError::provider(kind, request.context()))
    }
}
