use anyhow::{Context, Result};
use tacacsrs_config::{RawPrivateKey, ServerAuthenticationRawPublicKeys};

use crate::CredentialResolver;

pub(crate) fn resolve_raw_private_key_keystore_ref(
    rpk: &mut RawPrivateKey,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ks_ref) = rpk.central_keystore_reference {
        let material = resolver
            .resolve_asymmetric_key(ks_ref)
            .context("failed to resolve central-keystore-reference for raw-private-key")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "credential resolver did not resolve keystore reference '{ks_ref}' for raw-private-key"
                )
            })?;

        rpk.inline_definition = Some(tacacsrs_config::keystore::AsymmetricKeyInlineDefinition {
            public_key_format: material
                .public_key_format
                .map(|f| f.as_rfc7951_str().to_owned()),
            public_key: material.public_key,
            private_key_format: material
                .private_key_format
                .map(|f| f.as_rfc7951_str().to_owned()),
            cleartext_private_key: Some(material.cleartext_private_key),
            hidden_private_key: None,
            encrypted_private_key: None,
        });
        rpk.central_keystore_reference = None;
    }
    Ok(())
}

pub(crate) fn resolve_raw_public_keys_truststore_ref(
    rpk: &mut ServerAuthenticationRawPublicKeys,
    resolver: &dyn CredentialResolver,
) -> Result<()> {
    if let Some(ref ts_ref) = rpk.central_truststore_reference {
        let entries = resolver
            .resolve_public_key_bag(ts_ref)
            .context("failed to resolve central-truststore-reference for raw-public-keys")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "credential resolver did not resolve truststore public key bag '{ts_ref}'"
                )
            })?;

        rpk.inline_definition = Some(tacacsrs_config::truststore::PublicKeysInlineDefinition {
            public_key: entries
                .into_iter()
                .map(|entry| tacacsrs_config::truststore::PublicKeysPublicKey {
                    name: entry.name,
                    public_key_format: entry.public_key_format.as_rfc7951_str().to_owned(),
                    public_key: entry.public_key,
                })
                .collect(),
        });
        rpk.central_truststore_reference = None;
    }
    Ok(())
}

pub(crate) fn validate_rpk_keystore_refs(
    ci: &tacacsrs_config::TlsClientClientIdentity,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref rpk) = ci.raw_private_key {
        if let Some(ref ks_ref) = rpk.central_keystore_reference {
            if let Err(error) = resolver.validate_asymmetric_key(ks_ref) {
                errors.push(format!(
                    "server '{server_name}': raw-private-key central-keystore-reference: {error}",
                ));
            }
        }
    }
}

pub(crate) fn validate_rpk_truststore_refs(
    sa: &tacacsrs_config::TlsClientServerAuthentication,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref rpk) = sa.raw_public_keys {
        if let Some(ref ts_ref) = rpk.central_truststore_reference {
            if let Err(error) = resolver.validate_public_key_bag(ts_ref) {
                errors.push(format!(
                    "server '{server_name}': raw-public-keys central-truststore-reference: {error}",
                ));
            }
        }
    }
}
