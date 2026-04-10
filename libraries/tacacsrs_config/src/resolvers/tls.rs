//! TLS certificate resolution and validation.
//!
//! Handles `central-keystore-reference` for certificate client identity and
//! `central-truststore-reference` for CA/EE certificate bags in server
//! authentication.

use anyhow::{Context, Result};

use crate::generated::tacacs_plus::{ClientIdentityCertificate, ServerAuthenticationCaCerts};

use super::CredentialResolver;

/// Resolves a certificate keystore reference to inline material.
///
/// Calls [`CredentialResolver::resolve_keystore_certificate`] to fetch the
/// X.509 end-entity certificate and its associated asymmetric key pair.
pub(crate) fn resolve_certificate_keystore_ref(
    cert: &mut ClientIdentityCertificate,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ks_ref) = cert.central_keystore_reference {
        let cert_ref = ks_ref.certificate.as_deref().unwrap_or_default();
        let material = resolver
            .resolve_keystore_certificate(cert_ref)
            .with_context(|| {
                format!("failed to resolve central-keystore-reference for certificate '{cert_ref}'")
            })?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "credential resolver did not resolve keystore certificate '{cert_ref}'"
                )
            })?;

        cert.inline_definition =
            Some(crate::generated::keystore::EndEntityCertWithKeyInlineDefinition {
                public_key_format: material
                    .key_material
                    .public_key_format
                    .map(|f| f.as_rfc7951_str().to_owned()),
                public_key: material.key_material.public_key,
                private_key_format: material
                    .key_material
                    .private_key_format
                    .map(|f| f.as_rfc7951_str().to_owned()),
                cleartext_private_key: Some(material.key_material.cleartext_private_key),
                hidden_private_key: None,
                encrypted_private_key: None,
                cert_data: Some(material.cert_data),
            });
        cert.central_keystore_reference = None;
    }
    Ok(())
}

/// Resolves a CA/EE certificate truststore reference to inline material.
///
/// Calls [`CredentialResolver::resolve_certificate_bag`] to fetch all
/// certificates from the referenced certificate bag.
pub(crate) fn resolve_certs_truststore_ref(
    certs: &mut ServerAuthenticationCaCerts,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ts_ref) = certs.central_truststore_reference {
        let entries = resolver
            .resolve_certificate_bag(ts_ref)
            .context("failed to resolve central-truststore-reference for certs")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "credential resolver did not resolve truststore certificate bag '{ts_ref}'"
                )
            })?;

        certs.inline_definition = Some(crate::generated::truststore::CertsInlineDefinition {
            certificate: entries
                .into_iter()
                .map(|entry| crate::generated::truststore::CertsCertificate {
                    name: entry.name,
                    cert_data: entry.cert_data,
                })
                .collect(),
        });
        certs.central_truststore_reference = None;
    }
    Ok(())
}

/// Validates TLS certificate external references in the client-identity subtree.
pub(crate) fn validate_certificate_refs(
    ci: &crate::generated::tacacs_plus::TlsClientClientIdentity,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref cert) = ci.certificate {
        if let Some(ref ks_ref) = cert.central_keystore_reference {
            let cert_ref = ks_ref.certificate.as_deref().unwrap_or_default();
            if let Err(e) = resolver.validate_keystore_certificate(cert_ref) {
                errors.push(format!(
                    "server '{server_name}': certificate central-keystore-reference: {e}",
                ));
            }
        }
    }
}

/// Validates CA/EE certificate truststore references in the server-authentication subtree.
pub(crate) fn validate_server_auth_cert_refs(
    sa: &crate::generated::tacacs_plus::TlsClientServerAuthentication,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref ca) = sa.ca_certs {
        if let Some(ref ts_ref) = ca.central_truststore_reference {
            if let Err(e) = resolver.validate_certificate_bag(ts_ref) {
                errors.push(format!(
                    "server '{server_name}': ca-certs central-truststore-reference: {e}",
                ));
            }
        }
    }
    if let Some(ref ee) = sa.ee_certs {
        if let Some(ref ts_ref) = ee.central_truststore_reference {
            if let Err(e) = resolver.validate_certificate_bag(ts_ref) {
                errors.push(format!(
                    "server '{server_name}': ee-certs central-truststore-reference: {e}",
                ));
            }
        }
    }
}
