use anyhow::{Context, Result};
use tacacsrs_config::{ClientIdentityCertificate, ServerAuthenticationCaCerts};

use crate::CredentialResolver;

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
            Some(tacacsrs_config::keystore::EndEntityCertWithKeyInlineDefinition {
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

        certs.inline_definition = Some(tacacsrs_config::truststore::CertsInlineDefinition {
            certificate: entries
                .into_iter()
                .map(|entry| tacacsrs_config::truststore::CertsCertificate {
                    name: entry.name,
                    cert_data: entry.cert_data,
                })
                .collect(),
        });
        certs.central_truststore_reference = None;
    }
    Ok(())
}

pub(crate) fn validate_certificate_refs(
    ci: &tacacsrs_config::TlsClientClientIdentity,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref cert) = ci.certificate {
        if let Some(ref ks_ref) = cert.central_keystore_reference {
            let cert_ref = ks_ref.certificate.as_deref().unwrap_or_default();
            if let Err(error) = resolver.validate_keystore_certificate(cert_ref) {
                errors.push(format!(
                    "server '{server_name}': certificate central-keystore-reference: {error}",
                ));
            }
        }
    }
}

pub(crate) fn validate_server_auth_cert_refs(
    sa: &tacacsrs_config::TlsClientServerAuthentication,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref ca) = sa.ca_certs {
        if let Some(ref ts_ref) = ca.central_truststore_reference {
            if let Err(error) = resolver.validate_certificate_bag(ts_ref) {
                errors.push(format!(
                    "server '{server_name}': ca-certs central-truststore-reference: {error}",
                ));
            }
        }
    }
    if let Some(ref ee) = sa.ee_certs {
        if let Some(ref ts_ref) = ee.central_truststore_reference {
            if let Err(error) = resolver.validate_certificate_bag(ts_ref) {
                errors.push(format!(
                    "server '{server_name}': ee-certs central-truststore-reference: {error}",
                ));
            }
        }
    }
}
