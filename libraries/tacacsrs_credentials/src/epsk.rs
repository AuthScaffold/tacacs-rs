use anyhow::{Context, Result};
use tacacsrs_config::Tls13Epsk;

use crate::CredentialResolver;

pub(crate) fn resolve_epsk_keystore_ref(
    epsk: &mut Tls13Epsk,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ks_ref) = epsk.central_keystore_reference {
        let material = resolver
            .resolve_symmetric_key(ks_ref)
            .context("failed to resolve central-keystore-reference for tls13-epsk")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "credential resolver did not resolve keystore reference '{ks_ref}' for tls13-epsk"
                )
            })?;

        epsk.inline_definition = Some(tacacsrs_config::keystore::SymmetricKeyInlineDefinition {
            key_format: material.key_format.map(|f| f.as_rfc7951_str().to_owned()),
            cleartext_symmetric_key: Some(material.cleartext_symmetric_key),
            hidden_symmetric_key: None,
            encrypted_symmetric_key: None,
        });
        epsk.central_keystore_reference = None;
    }
    Ok(())
}

pub(crate) fn validate_epsk_keystore_refs(
    ci: &tacacsrs_config::TlsClientClientIdentity,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref epsk) = ci.tls13_epsk {
        if let Some(ref ks_ref) = epsk.central_keystore_reference {
            if let Err(error) = resolver.validate_symmetric_key(ks_ref) {
                errors.push(format!(
                    "server '{server_name}': tls13-epsk central-keystore-reference: {error}",
                ));
            }
        }
    }
}
