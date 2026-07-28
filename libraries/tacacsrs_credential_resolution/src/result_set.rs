//! Closed request/result association and variant validation.

use std::fmt;

use crate::{
    CredentialKind, ResolutionError, ResolutionPlan, ResolvedCredential, RequestContext,
    RequestSlot,
};

/// One provider response associated with a request slot.
pub struct ResolvedResponse {
    slot: RequestSlot,
    credential: ResolvedCredential,
}

impl ResolvedResponse {
    /// Creates a response for one plan slot.
    #[must_use]
    pub const fn new(slot: RequestSlot, credential: ResolvedCredential) -> Self {
        Self { slot, credential }
    }
}

impl fmt::Debug for ResolvedResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedResponse")
            .field("slot", &self.slot)
            .field("kind", &self.credential.kind())
            .finish()
    }
}

struct ResolvedEntry {
    context: RequestContext,
    kind: CredentialKind,
    credential: ResolvedCredential,
}

/// Complete validated result set for one resolution plan.
pub struct ResolvedCredentialSet {
    entries: Vec<ResolvedEntry>,
}

impl ResolvedCredentialSet {
    /// Validates provider responses against a closed request plan.
    ///
    /// # Errors
    ///
    /// Returns typed errors for missing, duplicate, unexpected, or wrong-variant responses.
    pub fn from_responses(
        plan: &ResolutionPlan,
        responses: impl IntoIterator<Item = ResolvedResponse>,
    ) -> Result<Self, ResolutionError> {
        let mut by_slot: Vec<Option<ResolvedCredential>> =
            std::iter::repeat_with(|| None).take(plan.len()).collect();
        for response in responses {
            let index = response.slot.index();
            let Some(target) = by_slot.get_mut(index) else {
                return Err(ResolutionError::unexpected_response(response.slot));
            };
            if target.is_some() {
                return Err(ResolutionError::duplicate_response(response.slot));
            }
            *target = Some(response.credential);
        }

        let mut entries = Vec::with_capacity(plan.len());
        for request in plan.requests() {
            let Some(credential) = by_slot[request.slot().index()].take() else {
                return Err(ResolutionError::missing_response(
                    request.slot(),
                    request.context().clone(),
                    request.kind(),
                ));
            };
            let actual = credential.kind();
            if actual != request.kind() {
                return Err(ResolutionError::response_mismatch(
                    request.slot(),
                    request.context().clone(),
                    request.kind(),
                    actual,
                ));
            }
            entries.push(ResolvedEntry {
                context: request.context().clone(),
                kind: request.kind(),
                credential,
            });
        }
        Ok(Self { entries })
    }

    /// Returns the number of resolved entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no credentials were required.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns resolved material by request slot.
    #[must_use]
    pub fn credential(&self, slot: RequestSlot) -> Option<&ResolvedCredential> {
        self.entries
            .get(slot.index())
            .map(|entry| &entry.credential)
    }

    /// Returns the stable secret-free context for a request slot.
    #[must_use]
    pub fn context(&self, slot: RequestSlot) -> Option<&RequestContext> {
        self.entries.get(slot.index()).map(|entry| &entry.context)
    }
}

impl fmt::Debug for ResolvedCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self
            .entries
            .iter()
            .enumerate()
            .map(|(slot, entry)| (slot, &entry.context, entry.kind))
            .collect::<Vec<_>>();
        formatter
            .debug_struct("ResolvedCredentialSet")
            .field("entries", &entries)
            .finish()
    }
}
