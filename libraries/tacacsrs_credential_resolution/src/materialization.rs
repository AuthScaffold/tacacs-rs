//! Conversion of provider results into generated inline server fields.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use tacacsrs_config::keystore::{EndEntityCertWithKeyInlineDefinition, SymmetricKeyInlineDefinition};
use tacacsrs_config::truststore::{CertsCertificate, CertsInlineDefinition};
use tacacsrs_config::{
    TacacsPlus, TacacsPlusServer, ValidationOptions, enumerate_servers, inspect_central_references,
    validation,
};

use crate::{
    CertificateBagMaterial, CertificateWithKeyMaterial, CredentialResolver, ResolutionError,
    ResolvedCredential, SymmetricKeyMaterial, resolve_plan,
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
            field_path: error.context().map(crate::RequestContext::field_path),
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
) -> Result<TacacsPlusServer, MaterializationError> {
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
) -> Result<Vec<TacacsPlusServer>, MaterializationError> {
    let mut candidates = Vec::with_capacity(servers.len());
    for server in servers {
        candidates.push(materialize_server_unvalidated(server, resolver).await?);
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
) -> Result<Vec<TacacsPlusServer>, MaterializationError> {
    let servers = enumerate_servers(config).map_err(|_| MaterializationError::enumeration())?;
    materialize_servers(servers, resolver, validation_options).await
}

async fn materialize_server_unvalidated(
    mut server: TacacsPlusServer,
    resolver: &dyn CredentialResolver,
) -> Result<TacacsPlusServer, MaterializationError> {
    let plan =
        crate::ResolutionPlan::from_server(&server).map_err(MaterializationError::resolution)?;
    let result_set = resolve_plan(&plan, resolver)
        .await
        .map_err(MaterializationError::resolution)?;
    let mut credentials = result_set
        .into_credentials()
        .map(|(slot, _, credential)| (slot, credential))
        .collect::<BTreeMap<_, _>>();

    for request in plan.requests() {
        let credential = credentials.remove(&request.slot()).ok_or_else(|| {
            MaterializationError::new(
                MaterializationErrorKind::InvalidMaterial,
                Some(request.context().server_name().to_owned()),
                Some(request.context().field_path()),
            )
        })?;
        install_credential(&mut server, request.context().field_path(), credential)?;
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

    Ok(server)
}

fn install_credential(
    server: &mut TacacsPlusServer,
    field_path: &'static str,
    credential: ResolvedCredential,
) -> Result<(), MaterializationError> {
    let server_name = server.name.clone();
    match credential {
        ResolvedCredential::CertificateWithKey(material) => {
            install_certificate_with_key(server, field_path, material)
        }
        ResolvedCredential::SymmetricKey(material) => {
            install_symmetric_key(server, field_path, material)
        }
        ResolvedCredential::CaCertificateBag(material) => {
            install_certificate_bag(server, field_path, material, true)
        }
        ResolvedCredential::EeCertificateBag(material) => {
            install_certificate_bag(server, field_path, material, false)
        }
    }
    .ok_or_else(|| {
        MaterializationError::new(
            MaterializationErrorKind::InvalidMaterial,
            Some(server_name),
            Some(field_path),
        )
    })
}

fn install_certificate_with_key(
    server: &mut TacacsPlusServer,
    field_path: &'static str,
    material: CertificateWithKeyMaterial,
) -> Option<()> {
    if field_path != "client-identity/certificate" {
        return None;
    }
    if material.public_key_format.is_some() != material.public_key.is_some() {
        return None;
    }
    let certificate = server.client_identity.as_mut()?.certificate.as_mut()?;
    certificate.inline_definition = Some(EndEntityCertWithKeyInlineDefinition {
        public_key_format: material.public_key_format,
        public_key: material.public_key.map(crate::PublicBytes::into_bytes),
        private_key_format: Some(material.private_key_format),
        cleartext_private_key: Some(material.private_key),
        cert_data: Some(material.certificate.into_bytes()),
    });
    certificate.central_keystore_reference = None;
    Some(())
}

fn install_symmetric_key(
    server: &mut TacacsPlusServer,
    field_path: &'static str,
    material: SymmetricKeyMaterial,
) -> Option<()> {
    if field_path != "client-identity/tls13-epsk" {
        return None;
    }
    let epsk = server.client_identity.as_mut()?.tls13_epsk.as_mut()?;
    epsk.inline_definition = Some(SymmetricKeyInlineDefinition {
        key_format: material.key_format,
        cleartext_symmetric_key: Some(material.key),
    });
    epsk.central_keystore_reference = None;
    Some(())
}

fn install_certificate_bag(
    server: &mut TacacsPlusServer,
    field_path: &'static str,
    material: CertificateBagMaterial,
    is_ca: bool,
) -> Option<()> {
    let expected_path = if is_ca {
        "server-authentication/ca-certs"
    } else {
        "server-authentication/ee-certs"
    };
    if field_path != expected_path {
        return None;
    }

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

    let authentication = server.server_authentication.as_mut()?;
    let target = if is_ca {
        authentication.ca_certs.as_mut()?
    } else {
        authentication.ee_certs.as_mut()?
    };
    target.inline_definition = Some(CertsInlineDefinition {
        certificate: certificates,
    });
    target.central_truststore_reference = None;
    Some(())
}

fn validate_candidates(
    candidates: Vec<TacacsPlusServer>,
    validation_options: &ValidationOptions,
) -> Result<Vec<TacacsPlusServer>, MaterializationError> {
    let mut config = TacacsPlus {
        client_credentials: Vec::new(),
        server_credentials: Vec::new(),
        server: candidates,
    };
    validation::validate_config_with_options(&config, validation_options)
        .map_err(|_| MaterializationError::new(MaterializationErrorKind::Validation, None, None))?;
    Ok(std::mem::take(&mut config.server))
}
