//! Accessors and validation for YANG TLS 1.3 EPSK configuration.

use anyhow::{Result, bail};
use tacacsrs_config::generated::tacacs_plus::Tls13Epsk;

/// The minimum required TLS 1.3 EPSK key length in bytes.
///
/// Per RFC 9257 section 6, PSKs must be at least 128 bits.
pub(crate) const MIN_PSK_KEY_LENGTH: usize = 16;

/// Returns the inline symmetric key configured for a TLS 1.3 EPSK.
pub(crate) fn symmetric_key(epsk: &Tls13Epsk) -> Result<&[u8]> {
    epsk.inline_definition
        .as_ref()
        .and_then(|definition| definition.cleartext_symmetric_key.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "TLS 1.3 EPSK inline-definition.cleartext-symmetric-key must be configured"
            )
        })
}

/// Validates the TLS 1.3 EPSK fields required by the OpenSSL PSK callback.
pub(crate) fn validate(epsk: &Tls13Epsk) -> Result<()> {
    if epsk.external_identity.is_empty() {
        bail!("PSK identity must not be empty");
    }

    if epsk.external_identity.contains('\0') {
        bail!(
            "PSK identity must not contain NUL bytes (identity is passed to OpenSSL as a byte string)"
        );
    }

    let key = symmetric_key(epsk)?;
    if key.len() < MIN_PSK_KEY_LENGTH {
        bail!(
            "PSK key must be at least {} bytes (128 bits), per RFC 9257 section 6; got {} bytes",
            MIN_PSK_KEY_LENGTH,
            key.len()
        );
    }

    Ok(())
}
