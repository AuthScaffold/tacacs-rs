//! Raw Public Key (RPK) resolution and validation.
//!
//! Handles `central-keystore-reference` for raw-private-key client identity
//! and `central-truststore-reference` for raw-public-keys in server
//! authentication.

use anyhow::{Context, Result};

use crate::generated::tacacs_plus::{RawPrivateKey, ServerAuthenticationRawPublicKeys};

use super::CredentialResolver;

/// Resolves an RPK keystore reference to inline asymmetric key material.
///
/// Calls [`CredentialResolver::resolve_asymmetric_key`] to fetch the full
/// key pair (private key, public key, and format identities).
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

        rpk.inline_definition = Some(crate::generated::keystore::AsymmetricKeyInlineDefinition {
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

/// Resolves a raw-public-keys truststore reference to inline material.
///
/// Calls [`CredentialResolver::resolve_public_key_bag`] to fetch all public
/// keys from the referenced public key bag.
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

        rpk.inline_definition = Some(crate::generated::truststore::PublicKeysInlineDefinition {
            public_key: entries
                .into_iter()
                .map(|entry| crate::generated::truststore::PublicKeysPublicKey {
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

/// Validates RPK keystore references in the client-identity subtree.
pub(crate) fn validate_rpk_keystore_refs(
    ci: &crate::generated::tacacs_plus::TlsClientClientIdentity,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref rpk) = ci.raw_private_key {
        if let Some(ref ks_ref) = rpk.central_keystore_reference {
            if let Err(e) = resolver.validate_asymmetric_key(ks_ref) {
                errors.push(format!(
                    "server '{server_name}': raw-private-key central-keystore-reference: {e}",
                ));
            }
        }
    }
}

/// Validates raw-public-keys truststore references in the server-authentication subtree.
pub(crate) fn validate_rpk_truststore_refs(
    sa: &crate::generated::tacacs_plus::TlsClientServerAuthentication,
    server_name: &str,
    resolver: &dyn CredentialResolver,
    errors: &mut Vec<String>,
) {
    if let Some(ref rpk) = sa.raw_public_keys {
        if let Some(ref ts_ref) = rpk.central_truststore_reference {
            if let Err(e) = resolver.validate_public_key_bag(ts_ref) {
                errors.push(format!(
                    "server '{server_name}': raw-public-keys central-truststore-reference: {e}",
                ));
            }
        }
    }
}
