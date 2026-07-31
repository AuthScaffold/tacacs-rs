//! Closed request/result association and variant validation.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fmt;
use std::sync::Arc;

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
    entries: BTreeMap<RequestSlot, ResolvedEntry>,
    plan_identity: Arc<()>,
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
        let expected_slots = plan
            .requests()
            .iter()
            .map(crate::CredentialRequest::slot)
            .collect::<BTreeSet<_>>();
        let mut responses_by_slot = BTreeMap::new();
        for response in responses {
            if !expected_slots.contains(&response.slot) {
                return Err(ResolutionError::unexpected_response(response.slot));
            }
            match responses_by_slot.entry(response.slot) {
                Entry::Vacant(entry) => {
                    entry.insert(response.credential);
                }
                Entry::Occupied(_) => {
                    return Err(ResolutionError::duplicate_response(response.slot));
                }
            }
        }

        let mut entries = BTreeMap::new();
        for request in plan.requests() {
            let Some(credential) = responses_by_slot.remove(&request.slot()) else {
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
            entries.insert(
                request.slot(),
                ResolvedEntry {
                    context: request.context().clone(),
                    kind: request.kind(),
                    credential,
                },
            );
        }
        Ok(Self {
            entries,
            plan_identity: Arc::clone(plan.identity()),
        })
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
        self.entries.get(&slot).map(|entry| &entry.credential)
    }

    /// Returns the stable secret-free context for a request slot.
    #[must_use]
    pub fn context(&self, slot: RequestSlot) -> Option<&RequestContext> {
        self.entries.get(&slot).map(|entry| &entry.context)
    }

    pub(crate) fn matches_plan(&self, plan: &ResolutionPlan) -> bool {
        Arc::ptr_eq(&self.plan_identity, plan.identity())
    }

    pub(crate) fn credential_for_field(&self, field_path: &str) -> Option<&ResolvedCredential> {
        self.entries
            .values()
            .find(|entry| entry.context.field_path() == field_path)
            .map(|entry| &entry.credential)
    }
}

impl fmt::Debug for ResolvedCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self
            .entries
            .iter()
            .map(|(slot, entry)| (*slot, &entry.context, entry.kind))
            .collect::<Vec<_>>();
        formatter
            .debug_struct("ResolvedCredentialSet")
            .field("entries", &entries)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_config::parse_yang_json;

    use super::*;
    use crate::{CertificateBagMaterial, CertificateWithKeyMaterial, PublicBytes, SecretBytes};

    #[test]
    fn lookup_uses_request_slot_when_plan_iteration_order_changes() {
        let config = parse_yang_json(
            r#"{
                "ietf-system-tacacs-plus:tacacs-plus": {
                    "server": [{
                        "name": "reordered-plan",
                        "server-type": "accounting",
                        "address": "192.0.2.40",
                        "port": 49,
                        "client-identity": {
                            "certificate": {
                                "central-keystore-reference": {
                                    "asymmetric-key": "key-reference",
                                    "certificate": "certificate-reference"
                                }
                            }
                        },
                        "server-authentication": {
                            "ca-certs": {"central-truststore-reference": "ca-reference"},
                            "ee-certs": {"central-truststore-reference": "ee-reference"}
                        }
                    }]
                }
            }"#,
        )
        .expect("central credential config");
        let mut plan = ResolutionPlan::from_server(&config.server[0]).expect("resolution plan");
        plan.reverse_requests_for_test();

        let responses = plan.requests().iter().map(|request| {
            let credential = match request.kind() {
                CredentialKind::CertificateWithKey => {
                    ResolvedCredential::CertificateWithKey(CertificateWithKeyMaterial {
                        certificate: PublicBytes::new(b"certificate".to_vec()),
                        private_key: SecretBytes::new(b"private-key".to_vec()),
                    })
                }
                CredentialKind::CaCertificateBag => {
                    ResolvedCredential::CaCertificateBag(CertificateBagMaterial {
                        certificates: vec![PublicBytes::new(b"ca".to_vec())],
                    })
                }
                CredentialKind::EeCertificateBag => {
                    ResolvedCredential::EeCertificateBag(CertificateBagMaterial {
                        certificates: vec![PublicBytes::new(b"ee".to_vec())],
                    })
                }
                CredentialKind::SymmetricKey => unreachable!("test plan has no symmetric key"),
            };
            ResolvedResponse::new(request.slot(), credential)
        });

        let result = ResolvedCredentialSet::from_responses(&plan, responses)
            .expect("responses should match reordered plan");

        assert_eq!(
            result
                .credential(RequestSlot::from_index(0))
                .expect("slot 0")
                .kind(),
            CredentialKind::CertificateWithKey,
        );
        assert_eq!(
            result
                .credential(RequestSlot::from_index(1))
                .expect("slot 1")
                .kind(),
            CredentialKind::CaCertificateBag,
        );
        assert_eq!(
            result
                .credential(RequestSlot::from_index(2))
                .expect("slot 2")
                .kind(),
            CredentialKind::EeCertificateBag,
        );
        assert_eq!(
            result
                .context(RequestSlot::from_index(0))
                .expect("slot 0 context")
                .field_path(),
            "client-identity/certificate",
        );
    }
}
