//! Projects inspected YANG credential slots into provider requests.

use std::collections::BTreeMap;

use tacacsrs_credential_resolution::{
    CredentialKind, CredentialReference, RequestContext, RequestSlot, ResolutionError,
    ResolutionPlan,
};

use crate::{
    inspect_central_references, CentralCredentialReference, CentralCredentialUsage,
    TacacsPlusServer,
};

/// Provider requests and their configuration-owned installation targets.
#[derive(Debug)]
pub struct ServerResolutionPlan {
    neutral: ResolutionPlan,
    usages: BTreeMap<RequestSlot, CentralCredentialUsage>,
}

impl ServerResolutionPlan {
    /// Borrows the provider-neutral plan for resolution or dependency inspection.
    #[must_use]
    pub const fn neutral_plan(&self) -> &ResolutionPlan {
        &self.neutral
    }

    pub(super) fn usage(&self, slot: RequestSlot) -> Option<CentralCredentialUsage> {
        self.usages.get(&slot).copied()
    }
}

/// Builds a deterministic provider request plan from one enumerated server.
///
/// # Errors
///
/// Returns a sanitized error if a local bundle reference remains or a central
/// reference cannot form a typed request.
pub fn resolution_plan(server: &TacacsPlusServer) -> Result<ServerResolutionPlan, ResolutionError> {
    let slots = inspect_central_references(server).map_err(|error| {
        ResolutionError::enumeration_required(RequestContext::new(
            error.server_name(),
            error.field().field_path(),
        ))
    })?;
    let neutral = ResolutionPlan::new(slots.iter().map(|slot| {
        let kind = match slot.usage() {
            CentralCredentialUsage::ServerOcspResponse => CredentialKind::OcspResponse,
            CentralCredentialUsage::ClientCertificateWithKey => CredentialKind::CertificateWithKey,
            CentralCredentialUsage::ClientTls13Epsk => CredentialKind::SymmetricKey,
            CentralCredentialUsage::ServerCaCertificateBag => CredentialKind::CaCertificateBag,
            CentralCredentialUsage::ServerEeCertificateBag => CredentialKind::EeCertificateBag,
            CentralCredentialUsage::ServerCertificateRevocationLists => {
                CredentialKind::CertificateRevocationLists
            }
        };
        let reference = match slot.reference() {
            CentralCredentialReference::OcspResponse(reference) => {
                CredentialReference::OcspResponse(reference.to_owned())
            }
            CentralCredentialReference::CertificateRevocationLists(reference) => {
                CredentialReference::CertificateRevocationLists(reference.to_owned())
            }
            CentralCredentialReference::CertificateWithKey {
                asymmetric_key,
                certificate,
            } => CredentialReference::CertificateWithKey {
                asymmetric_key: asymmetric_key.map(str::to_owned),
                certificate: certificate.map(str::to_owned),
            },
            CentralCredentialReference::SymmetricKey(reference) => {
                CredentialReference::SymmetricKey(reference.to_owned())
            }
            CentralCredentialReference::CertificateBag(reference) => {
                CredentialReference::CertificateBag(reference.to_owned())
            }
        };
        (RequestContext::new(slot.server_name(), slot.usage().field_path()), kind, reference)
    }))?;
    let usages = neutral
        .requests()
        .iter()
        .zip(slots)
        .map(|(request, slot)| (request.slot(), slot.usage()))
        .collect();
    Ok(ServerResolutionPlan { neutral, usages })
}
