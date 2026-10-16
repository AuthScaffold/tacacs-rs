//! Derives protected downstream credentials from canonical local-service policy.
//!
//! The adapter supplies the highest-priority row matching its proxy endpoint.
//! Preparation never changes that row or the canonical credential-source selection.

use anyhow::{Context, ensure};

use tacacsrs_secrets::SecretString;

use crate::{
    TacacsPlusServer,
    tacacsrs::{LocalServices, ProxyCredentialSource},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum CredentialState {
    Unavailable,
    Unobfuscated,
    SharedSecret(SecretString),
}

/// Immutable downstream policy with validated, redacted credential material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedProxyPolicy {
    state: CredentialState,
}

impl PreparedProxyPolicy {
    /// Rejects downstream connections until a valid source generation is available.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            state: CredentialState::Unavailable,
        }
    }

    /// Selects unobfuscated traffic explicitly for a native runtime caller.
    #[must_use]
    pub const fn unobfuscated() -> Self {
        Self {
            state: CredentialState::Unobfuscated,
        }
    }

    /// Returns the protected secret, or no secret for explicit unobfuscated mode.
    ///
    /// # Errors
    ///
    /// Returns an error while the required credentials are unavailable.
    pub fn shared_secret(&self) -> anyhow::Result<Option<&SecretString>> {
        match &self.state {
            CredentialState::Unavailable => {
                anyhow::bail!("Downstream proxy credentials are not available")
            }
            CredentialState::Unobfuscated => Ok(None),
            CredentialState::SharedSecret(secret) => Ok(Some(secret)),
        }
    }
}

pub(crate) fn validate_proxy_source(source: &LocalServices) -> anyhow::Result<()> {
    ensure!(
        source.tacacs_proxy_enabled
            || source.proxy_credential_source == ProxyCredentialSource::Unobfuscated,
        "Downstream credentials require an enabled TACACS+ proxy"
    );
    ensure!(
        (source.proxy_credential_source == ProxyCredentialSource::Inline)
            == source.proxy_shared_secret.is_some(),
        "proxy-shared-secret must be present exactly when proxy-credential-source is inline"
    );
    if let Some(secret) = &source.proxy_shared_secret {
        ensure!(!secret.expose_secret().is_empty(), "Downstream shared secret must not be empty");
    }
    if source.proxy_credential_source == ProxyCredentialSource::LocalProxyRow {
        ensure!(
            source
                .tacacs_proxy_endpoint
                .as_deref()
                .is_some_and(|endpoint| endpoint.parse::<std::net::SocketAddr>().is_ok()),
            "local-proxy-row credentials require a numeric TCP proxy endpoint"
        );
    }
    Ok(())
}

/// Prepares downstream policy from a source and its selected local proxy row.
///
/// Only `local-proxy-row` mode reads `selected_row`. The adapter selects the first
/// matching row in canonical server order before removing self-looping upstreams.
/// A missing row or secret cannot downgrade the policy to unobfuscated traffic.
///
/// # Errors
///
/// Returns an error for inconsistent source fields or absent or empty credentials.
pub fn prepare_proxy_policy(
    source: &LocalServices,
    selected_row: Option<&TacacsPlusServer>,
) -> anyhow::Result<PreparedProxyPolicy> {
    validate_proxy_source(source)?;
    let secret = match source.proxy_credential_source {
        ProxyCredentialSource::Unobfuscated => return Ok(PreparedProxyPolicy::unobfuscated()),
        ProxyCredentialSource::Inline => source.proxy_shared_secret.as_ref(),
        ProxyCredentialSource::LocalProxyRow => selected_row
            .context("No matching local proxy row is available for downstream credentials")?
            .shared_secret
            .as_ref(),
    }
    .context("The configured downstream credential source has no shared secret")?;
    ensure!(!secret.expose_secret().is_empty(), "Downstream shared secret must not be empty");
    Ok(PreparedProxyPolicy {
        state: CredentialState::SharedSecret(secret.clone()),
    })
}

#[cfg(test)]
mod tests {
    use crate::{TacacsPlusServerBuilder, TacacsPlusServerType};
    use super::*;

    #[test]
    fn inline_preparation_preserves_and_redacts_source() {
        let source = LocalServices {
            tacacs_proxy_enabled: true,
            proxy_credential_source: ProxyCredentialSource::Inline,
            proxy_shared_secret: Some(SecretString::new("private-proxy-key".to_owned())),
            ..LocalServices::default()
        };
        let original = source.clone();
        let prepared = prepare_proxy_policy(&source, None).unwrap();
        assert_eq!(source, original);
        assert_eq!(prepared.shared_secret().unwrap().unwrap().expose_secret(), "private-proxy-key");
        assert!(!format!("{source:?} {prepared:?}").contains("private-proxy-key"));
    }

    #[test]
    fn missing_or_empty_credentials_never_become_unobfuscated() {
        let mut source = LocalServices {
            tacacs_proxy_enabled: true,
            proxy_credential_source: ProxyCredentialSource::Inline,
            ..LocalServices::default()
        };
        assert!(prepare_proxy_policy(&source, None).is_err());
        source.proxy_shared_secret = Some(SecretString::new(String::new()));
        assert!(prepare_proxy_policy(&source, None).is_err());
        source.proxy_shared_secret = None;
        source.proxy_credential_source = ProxyCredentialSource::LocalProxyRow;
        source.tacacs_proxy_endpoint = Some("127.0.0.1:49".to_owned());
        assert!(prepare_proxy_policy(&source, None).is_err());
        let row = TacacsPlusServerBuilder::new(
            "private-row",
            TacacsPlusServerType::all(),
            "127.0.0.1",
            49,
        )
        .build();
        let error = prepare_proxy_policy(&source, Some(&row)).unwrap_err();
        assert!(!format!("{error:#}").contains("private-row"));
        assert!(PreparedProxyPolicy::unavailable().shared_secret().is_err());
    }

    #[test]
    fn row_rotation_keeps_source_and_previous_preparation_unchanged() {
        let source = LocalServices {
            tacacs_proxy_enabled: true,
            tacacs_proxy_endpoint: Some("127.0.0.1:49".to_owned()),
            proxy_credential_source: ProxyCredentialSource::LocalProxyRow,
            ..LocalServices::default()
        };
        let original = source.clone();
        let row =
            TacacsPlusServerBuilder::new("local", TacacsPlusServerType::all(), "127.0.0.1", 49)
                .with_shared_secret("old-key")
                .build();
        let original_row = row.clone();
        let old = prepare_proxy_policy(&source, Some(&row)).unwrap();
        let mut rotated = row.clone();
        rotated.shared_secret = Some(SecretString::new("new-key".to_owned()));
        let new = prepare_proxy_policy(&source, Some(&rotated)).unwrap();
        assert_ne!(old, new);
        assert_eq!(old.shared_secret().unwrap(), row.shared_secret.as_ref());
        assert_eq!(source, original);
        assert_eq!(row, original_row);
    }
}
