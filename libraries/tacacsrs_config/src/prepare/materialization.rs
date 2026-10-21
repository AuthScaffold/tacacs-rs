//! Conversion of provider results into generated inline server fields.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::SystemTime;

use tacacsrs_credential_resolution::{
    CertificateBagMaterial, CertificateWithKeyMaterial, CredentialResolver, ResolutionError,
    ResolvedCredential, SymmetricKeyMaterial, resolve_plan, RequestContext, PublicBytes,
    CredentialValidity,
};

use crate::keystore::{EndEntityCertWithKeyInlineDefinition, SymmetricKeyInlineDefinition};
use crate::truststore::{CertsCertificate, CertsInlineDefinition};
use crate::{
    TacacsPlus, TacacsPlusServer, ValidationOptions, enumerate_servers, inspect_central_references,
    validation, CentralCredentialUsage,
};

/// Stable materialization error category.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MaterializationErrorKind {
    /// Configuration-local bundle expansion failed.
    Enumeration,
    /// Provider resolution or closed-result validation failed.
    Resolution,
    /// A resolved credential did not populate its generated target field.
    InvalidMaterial,
    /// One or more references remained after materialization.
    UnresolvedReference,
    /// Final generated-model validation failed.
    Validation,
    /// Provider validity windows conflict or exclude the current time.
    Validity,
    /// The caller's admission fence rejected typed installation.
    Admission,
}

/// Sanitized materialization error without reference or credential values.
pub struct MaterializationError {
    kind: MaterializationErrorKind,
    server_name: Option<String>,
    field_path: Option<&'static str>,
    resolution: Option<ResolutionError>,
}

impl MaterializationError {
    fn new(
        kind: MaterializationErrorKind,
        server_name: Option<String>,
        field_path: Option<&'static str>,
    ) -> Self {
        Self {
            kind,
            server_name,
            field_path,
            resolution: None,
        }
    }

    fn resolution(error: ResolutionError) -> Self {
        Self {
            kind: MaterializationErrorKind::Resolution,
            server_name: error
                .context()
                .map(|context| context.server_name().to_owned()),
            field_path: error.context().map(RequestContext::field_path),
            resolution: Some(error),
        }
    }

    /// Creates a sanitized configuration-local enumeration error.
    #[must_use]
    pub fn enumeration() -> Self {
        Self::new(MaterializationErrorKind::Enumeration, None, None)
    }

    /// Returns the stable error category.
    #[must_use]
    pub const fn kind(&self) -> MaterializationErrorKind {
        self.kind
    }

    /// Returns the affected server name when known.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Returns the stable generated field path when known.
    #[must_use]
    pub const fn field_path(&self) -> Option<&'static str> {
        self.field_path
    }

    /// Returns the sanitized resolution error, if resolution failed.
    #[must_use]
    pub const fn resolution_error(&self) -> Option<&ResolutionError> {
        self.resolution.as_ref()
    }
}

impl fmt::Display for MaterializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "credential materialization failed: {:?}", self.kind)?;
        if let Some(server_name) = &self.server_name {
            write!(formatter, " for server '{server_name}'")?;
        }
        if let Some(field_path) = self.field_path {
            write!(formatter, " field '{field_path}'")?;
        }
        Ok(())
    }
}

impl fmt::Debug for MaterializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for MaterializationError {}

/// Derived server data and provider validity constraints, separate from canonical configuration.
#[derive(Debug, Clone)]
pub struct MaterializedServer {
    server: TacacsPlusServer,
    validity: CredentialValidity,
}

impl MaterializedServer {
    /// Wraps inline configuration with no provider-supplied validity bounds.
    #[must_use]
    pub fn unbounded(server: TacacsPlusServer) -> Self {
        Self {
            server,
            validity: CredentialValidity::unbounded(),
        }
    }

    /// Borrows the derived server configuration.
    #[must_use]
    pub const fn server(&self) -> &TacacsPlusServer {
        &self.server
    }

    /// Returns the intersection of all provider validity bounds for this server.
    #[must_use]
    pub const fn validity(&self) -> CredentialValidity {
        self.validity
    }

    /// Transfers both server data and validity to a runtime owner.
    #[must_use]
    pub fn into_parts(self) -> (TacacsPlusServer, CredentialValidity) {
        (self.server, self.validity)
    }
}

impl std::ops::Deref for MaterializedServer {
    type Target = TacacsPlusServer;
    fn deref(&self) -> &Self::Target {
        &self.server
    }
}

/// Adds resolved credentials to one enumerated server.
///
/// This function makes sure that the generated inline result is valid.
///
/// # Errors
///
/// Returns a sanitized error if provider resolution, insertion, reference
/// clearing, or final validation fails.
pub async fn materialize_server(
    server: TacacsPlusServer,
    resolver: &dyn CredentialResolver,
    validation_options: &ValidationOptions,
) -> Result<MaterializedServer, MaterializationError> {
    let candidate = materialize_server_unvalidated(server, resolver).await?;
    let mut candidates = validate_candidates(vec![candidate], validation_options)?;
    Ok(candidates.remove(0))
}

/// Adds resolved credentials to a server set in one all-or-nothing transaction.
///
/// # Errors
///
/// Returns the first sanitized error and drops every staged candidate.
pub async fn materialize_servers(
    servers: Vec<TacacsPlusServer>,
    resolver: &dyn CredentialResolver,
    validation_options: &ValidationOptions,
) -> Result<Vec<MaterializedServer>, MaterializationError> {
    let plans = servers
        .into_iter()
        .map(|server| {
            let plan = super::resolution_plan(&server).map_err(MaterializationError::resolution)?;
            Ok((server, plan))
        })
        .collect::<Result<Vec<_>, MaterializationError>>()?;
    materialize_planned_servers(
        plans,
        resolver,
        &tacacsrs_credential_resolution::WorkScope::unowned(),
        validation_options,
        &|| true,
    )
    .await
}

/// Consumes preflighted typed plans under one caller-owned work scope.
///
/// The caller must reserve configuration payload before cloning enumerated
/// servers. A resolver adapter can charge each return before result buffering.
/// `check_installation` must read admission state without blocking. A false
/// result rejects the candidate before the next typed target changes.
/// # Errors
/// Returns the first sanitized resolution, installation, or validation error.
pub async fn materialize_planned_servers(
    plans: Vec<(TacacsPlusServer, super::ServerResolutionPlan)>,
    resolver: &dyn CredentialResolver,
    scope: &tacacsrs_credential_resolution::WorkScope,
    validation_options: &ValidationOptions,
    check_installation: &(dyn Fn() -> bool + Send + Sync),
) -> Result<Vec<MaterializedServer>, MaterializationError> {
    let mut candidates = Vec::with_capacity(plans.len());
    for (server, plan) in plans {
        candidates.push(
            materialize_server_with_plan(server, plan, resolver, scope, check_installation).await?,
        );
    }
    validate_candidates(candidates, validation_options)
}

/// Enumerates configuration-local bundles and adds credentials to all servers.
///
/// All servers come from one source snapshot.
///
/// # Errors
///
/// Returns a sanitized enumeration or materialization error. The source
/// configuration is borrowed and remains unchanged.
pub async fn enumerate_materialized_servers(
    config: &TacacsPlus,
    resolver: &dyn CredentialResolver,
    validation_options: &ValidationOptions,
) -> Result<Vec<MaterializedServer>, MaterializationError> {
    let servers = enumerate_servers(config).map_err(|_| MaterializationError::enumeration())?;
    materialize_servers(servers, resolver, validation_options).await
}

async fn materialize_server_unvalidated(
    server: TacacsPlusServer,
    resolver: &dyn CredentialResolver,
) -> Result<MaterializedServer, MaterializationError> {
    let plan = super::resolution_plan(&server).map_err(MaterializationError::resolution)?;
    materialize_server_with_plan(
        server,
        plan,
        resolver,
        &tacacsrs_credential_resolution::WorkScope::unowned(),
        &|| true,
    )
    .await
}

async fn materialize_server_with_plan(
    mut server: TacacsPlusServer,
    plan: super::ServerResolutionPlan,
    resolver: &dyn CredentialResolver,
    scope: &tacacsrs_credential_resolution::WorkScope,
    check_installation: &(dyn Fn() -> bool + Send + Sync),
) -> Result<MaterializedServer, MaterializationError> {
    let result_set = resolve_plan(plan.neutral_plan(), resolver, scope)
        .await
        .map_err(MaterializationError::resolution)?;
    let mut credentials = result_set
        .into_credentials()
        .map(|(slot, _, credential)| (slot, credential))
        .collect::<BTreeMap<_, _>>();

    let mut validity = CredentialValidity::unbounded();
    for request in plan.neutral_plan().requests() {
        if !check_installation() {
            return Err(MaterializationError::new(
                MaterializationErrorKind::Admission,
                Some(server.name.clone()),
                Some(request.context().field_path()),
            ));
        }
        let usage = plan.usage(request.slot()).ok_or_else(|| {
            MaterializationError::new(
                MaterializationErrorKind::InvalidMaterial,
                Some(server.name.clone()),
                None,
            )
        })?;
        let credential = credentials.remove(&request.slot()).ok_or_else(|| {
            MaterializationError::new(
                MaterializationErrorKind::InvalidMaterial,
                Some(request.context().server_name().to_owned()),
                Some(request.context().field_path()),
            )
        })?;
        validity = validity.intersect(credential.validity()).map_err(|_| {
            MaterializationError::new(
                MaterializationErrorKind::Validity,
                Some(server.name.clone()),
                None,
            )
        })?;
        install_credential(&mut server, usage, credential)?;
    }

    let references = inspect_central_references(&server).map_err(|_| {
        MaterializationError::new(
            MaterializationErrorKind::UnresolvedReference,
            Some(server.name.clone()),
            None,
        )
    })?;
    if let Some(reference) = references.first() {
        return Err(MaterializationError::new(
            MaterializationErrorKind::UnresolvedReference,
            Some(server.name.clone()),
            Some(reference.usage().field_path()),
        ));
    }

    Ok(MaterializedServer { server, validity })
}

fn install_credential(
    server: &mut TacacsPlusServer,
    usage: CentralCredentialUsage,
    credential: ResolvedCredential,
) -> Result<(), MaterializationError> {
    let server_name = server.name.clone();
    match (usage, credential) {
        (
            CentralCredentialUsage::ServerOcspResponse,
            ResolvedCredential::OcspResponse(material),
        ) => server
            .server_authentication
            .as_mut()
            .and_then(|auth| auth.require_ocsp.as_mut())
            .map(|policy| {
                policy.response = Some(material.response.into_bytes());
                policy.evidence_reference = None;
            }),
        (
            CentralCredentialUsage::ServerCertificateRevocationLists,
            ResolvedCredential::CertificateRevocationLists(material),
        ) => install_revocation_lists(server, material),
        (
            CentralCredentialUsage::ClientCertificateWithKey,
            ResolvedCredential::CertificateWithKey(material),
        ) => install_certificate_with_key(server, material),
        (CentralCredentialUsage::ClientTls13Epsk, ResolvedCredential::SymmetricKey(material)) => {
            install_symmetric_key(server, material)
        }
        (
            CentralCredentialUsage::ServerCaCertificateBag,
            ResolvedCredential::CaCertificateBag(material),
        )
        | (
            CentralCredentialUsage::ServerEeCertificateBag,
            ResolvedCredential::EeCertificateBag(material),
        ) => {
            let target = server
                .server_authentication
                .as_mut()
                .and_then(|auth| match usage {
                    CentralCredentialUsage::ServerCaCertificateBag => auth.ca_certs.as_mut(),
                    CentralCredentialUsage::ServerEeCertificateBag => auth.ee_certs.as_mut(),
                    _ => None,
                });
            target.and_then(|target| {
                let inline = certificate_bag(material)?;
                target.inline_definition = Some(inline);
                target.central_truststore_reference = None;
                Some(())
            })
        }
        _ => None,
    }
    .ok_or_else(|| {
        MaterializationError::new(
            MaterializationErrorKind::InvalidMaterial,
            Some(server_name),
            Some(usage.field_path()),
        )
    })
}

fn install_revocation_lists(
    server: &mut TacacsPlusServer,
    material: tacacsrs_credential_resolution::CertificateRevocationListsMaterial,
) -> Option<()> {
    let policy = server
        .server_authentication
        .as_mut()?
        .require_crls
        .as_mut()?;
    policy.crl = Some(
        material
            .lists
            .into_iter()
            .map(PublicBytes::into_bytes)
            .collect(),
    );
    policy.evidence_reference = None;
    Some(())
}

fn install_certificate_with_key(
    server: &mut TacacsPlusServer,
    material: CertificateWithKeyMaterial,
) -> Option<()> {
    if material.public_key_format.is_some() != material.public_key.is_some() {
        return None;
    }
    let certificate = server.client_identity.as_mut()?.certificate.as_mut()?;
    certificate.inline_definition = Some(EndEntityCertWithKeyInlineDefinition {
        public_key_format: material.public_key_format.map(Into::into),
        public_key: material.public_key.map(PublicBytes::into_bytes),
        private_key_format: Some(material.private_key_format.into()),
        cleartext_private_key: Some(material.private_key),
        cert_data: Some(material.certificate.into_bytes()),
        intermediate_certificate: material
            .intermediates
            .into_iter()
            .map(PublicBytes::into_bytes)
            .collect(),
    });
    certificate.central_keystore_reference = None;
    Some(())
}

fn install_symmetric_key(
    server: &mut TacacsPlusServer,
    material: SymmetricKeyMaterial,
) -> Option<()> {
    let epsk = server.client_identity.as_mut()?.tls13_epsk.as_mut()?;
    epsk.inline_definition = Some(SymmetricKeyInlineDefinition {
        key_format: material.key_format.map(Into::into),
        cleartext_symmetric_key: Some(material.key),
    });
    epsk.central_keystore_reference = None;
    Some(())
}

fn certificate_bag(material: CertificateBagMaterial) -> Option<CertsInlineDefinition> {
    let mut names = BTreeSet::new();
    let mut certificates = Vec::with_capacity(material.certificates.len());
    if material.certificates.is_empty() {
        return None;
    }
    for certificate in material.certificates {
        if certificate.name.is_empty() || !names.insert(certificate.name.clone()) {
            return None;
        }
        certificates.push(CertsCertificate {
            name: certificate.name,
            cert_data: certificate.certificate.into_bytes(),
        });
    }

    Some(CertsInlineDefinition {
        certificate: certificates,
    })
}

fn validate_candidates(
    candidates: Vec<MaterializedServer>,
    validation_options: &ValidationOptions,
) -> Result<Vec<MaterializedServer>, MaterializationError> {
    let now = SystemTime::now();
    for candidate in &candidates {
        if !candidate.validity.is_valid_at(now) {
            return Err(MaterializationError::new(
                MaterializationErrorKind::Validity,
                Some(candidate.name.clone()),
                None,
            ));
        }
    }
    let (servers, validities): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .map(MaterializedServer::into_parts)
        .unzip();
    let mut config = TacacsPlus {
        client_credentials: Vec::new(),
        server_credentials: Vec::new(),
        server: servers,
    };
    validation::validate_config_with_options(&config, validation_options)
        .map_err(|_| MaterializationError::new(MaterializationErrorKind::Validation, None, None))?;
    Ok(std::mem::take(&mut config.server)
        .into_iter()
        .zip(validities)
        .map(|(server, validity)| MaterializedServer { server, validity })
        .collect())
}

#[cfg(test)]
mod tests {
    use tacacsrs_credential_resolution::NamedCertificateMaterial;

    use crate::CentralCredentialUsage;

    use super::*;

    fn trust_server() -> TacacsPlusServer {
        crate::parse_yang_json(
            r#"{"ietf-system-tacacs-plus:tacacs-plus":{"server":[{
                "name":"trust","server-type":"accounting","address":"192.0.2.1","port":300,
                "server-authentication":{
                    "ca-certs":{"central-truststore-reference":"opaque-ca"},
                    "ee-certs":{"central-truststore-reference":"opaque-ee"}
                }
            }]}}"#,
        )
        .unwrap()
        .server
        .remove(0)
    }

    fn bag() -> CertificateBagMaterial {
        CertificateBagMaterial {
            validity: CredentialValidity::unbounded(),
            certificates: vec![NamedCertificateMaterial {
                name: "fixture".to_owned(),
                certificate: PublicBytes::new(vec![1, 2, 3]),
            }],
        }
    }

    #[tokio::test]
    async fn caller_fence_runs_before_each_typed_installation() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tacacsrs_credential_resolution::{RequestSlot, FakeCredentialResolver, WorkScope};
        let source = trust_server();
        let original = source.clone();
        let plan = crate::prepare::resolution_plan(&source).unwrap();
        let resolver = FakeCredentialResolver::new()
            .with_response(RequestSlot::from_index(0), ResolvedCredential::CaCertificateBag(bag()))
            .with_response(RequestSlot::from_index(1), ResolvedCredential::EeCertificateBag(bag()));
        let checks = AtomicUsize::new(0);
        let fence = || checks.fetch_add(1, Ordering::SeqCst) == 0;
        let error = materialize_planned_servers(
            vec![(source, plan)],
            &resolver,
            &WorkScope::unowned(),
            &ValidationOptions::default(),
            &fence,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), MaterializationErrorKind::Admission);
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert_eq!(trust_server(), original);
    }

    #[test]
    fn typed_bag_installation_selects_only_the_matching_destination() {
        for usage in [
            CentralCredentialUsage::ServerCaCertificateBag,
            CentralCredentialUsage::ServerEeCertificateBag,
        ] {
            let mut server = trust_server();
            let original = server.server_authentication.clone().unwrap();
            let credential = match usage {
                CentralCredentialUsage::ServerCaCertificateBag => {
                    ResolvedCredential::CaCertificateBag(bag())
                }
                _ => ResolvedCredential::EeCertificateBag(bag()),
            };
            install_credential(&mut server, usage, credential).unwrap();
            let auth = server.server_authentication.unwrap();
            let target = match usage {
                CentralCredentialUsage::ServerCaCertificateBag => {
                    assert!(auth.ee_certs == original.ee_certs);
                    auth.ca_certs.unwrap()
                }
                _ => {
                    assert!(auth.ca_certs == original.ca_certs);
                    auth.ee_certs.unwrap()
                }
            };
            assert!(target.central_truststore_reference.is_none());
            assert!(target.inline_definition.unwrap().certificate[0].cert_data == [1, 2, 3]);
        }
    }

    #[test]
    fn typed_bag_installation_rejects_swapped_variants_without_mutation() {
        for (usage, credential) in [
            (
                CentralCredentialUsage::ServerCaCertificateBag,
                ResolvedCredential::EeCertificateBag(bag()),
            ),
            (
                CentralCredentialUsage::ServerEeCertificateBag,
                ResolvedCredential::CaCertificateBag(bag()),
            ),
        ] {
            let mut server = trust_server();
            let original = server.clone();
            let error = install_credential(&mut server, usage, credential).unwrap_err();
            assert_eq!(error.kind(), MaterializationErrorKind::InvalidMaterial);
            assert_eq!(error.field_path(), Some(usage.field_path()));
            assert!(server == original);
        }
    }
}
