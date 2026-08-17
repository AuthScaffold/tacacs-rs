//! Closed request-result association and credential variant validation.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
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
    entries: BTreeMap<RequestSlot, ResolvedEntry>,
}

impl ResolvedCredentialSet {
    /// Makes sure that provider responses match a closed request plan.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a missing, duplicate, unexpected, or
    /// wrong-variant response.
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
        Ok(Self { entries })
    }

    /// Returns the number of resolved entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the plan required no credentials.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a resolved credential by request slot.
    #[must_use]
    pub fn credential(&self, slot: RequestSlot) -> Option<&ResolvedCredential> {
        self.entries.get(&slot).map(|entry| &entry.credential)
    }

    /// Returns the stable secret-free context for a request slot.
    #[must_use]
    pub fn context(&self, slot: RequestSlot) -> Option<&RequestContext> {
        self.entries.get(&slot).map(|entry| &entry.context)
    }

    /// Consumes the closed result set into slot-associated credentials.
    #[must_use]
    pub fn into_credentials(
        self,
    ) -> impl ExactSizeIterator<Item = (RequestSlot, RequestContext, ResolvedCredential)> {
        self.entries
            .into_iter()
            .map(|(slot, entry)| (slot, entry.context, entry.credential))
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
    use crate::{
        CertificateBagMaterial, CertificateWithKeyMaterial, NamedCertificateMaterial, PublicBytes,
        SecretBytes,
    };

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
        .expect("central credential configuration must parse");
        let mut plan =
            ResolutionPlan::from_server(&config.server[0]).expect("resolution plan must build");
        plan.reverse_requests_for_test();

        let responses = plan.requests().iter().map(|request| {
            let credential = match request.kind() {
                CredentialKind::CertificateWithKey => {
                    ResolvedCredential::CertificateWithKey(CertificateWithKeyMaterial {
                        public_key_format: None,
                        public_key: None,
                        private_key_format:
                            tacacsrs_config::crypto_types::PrivateKeyFormat::OneAsymmetricKeyFormat,
                        certificate: PublicBytes::new(b"certificate".to_vec()),
                        private_key: SecretBytes::new(b"private-key".to_vec()),
                    })
                }
                CredentialKind::CaCertificateBag => {
                    ResolvedCredential::CaCertificateBag(CertificateBagMaterial {
                        certificates: vec![NamedCertificateMaterial {
                            name: "ca".to_owned(),
                            certificate: PublicBytes::new(b"ca".to_vec()),
                        }],
                    })
                }
                CredentialKind::EeCertificateBag => {
                    ResolvedCredential::EeCertificateBag(CertificateBagMaterial {
                        certificates: vec![NamedCertificateMaterial {
                            name: "ee".to_owned(),
                            certificate: PublicBytes::new(b"ee".to_vec()),
                        }],
                    })
                }
                CredentialKind::SymmetricKey => {
                    unreachable!("the test plan must not contain a symmetric key")
                }
            };
            ResolvedResponse::new(request.slot(), credential)
        });

        let result = ResolvedCredentialSet::from_responses(&plan, responses)
            .expect("responses must match the reordered plan");

        assert_eq!(
            result
                .credential(RequestSlot::from_index(0))
                .expect("slot 0 credential must exist")
                .kind(),
            CredentialKind::CertificateWithKey,
        );
        assert_eq!(
            result
                .credential(RequestSlot::from_index(1))
                .expect("slot 1 credential must exist")
                .kind(),
            CredentialKind::CaCertificateBag,
        );
        assert_eq!(
            result
                .credential(RequestSlot::from_index(2))
                .expect("slot 2 credential must exist")
                .kind(),
            CredentialKind::EeCertificateBag,
        );
        assert_eq!(
            result
                .context(RequestSlot::from_index(0))
                .expect("slot 0 context must exist")
                .field_path(),
            "client-identity/certificate",
        );
    }
}
