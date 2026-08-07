//! Secret value ownership with redacted formatting and zeroization on drop.

use std::fmt;

use zeroize::Zeroizing;

/// Secret byte ownership that zeroizes its allocation on drop.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Adopts an already-zeroizing allocation without copying the secret.
    ///
    /// Use this when the secret was read into a [`Zeroizing<Vec<u8>>`] so the
    /// bytes stay protected on every path from the initial read through
    /// ownership by [`SecretBytes`], with no intervening unprotected buffer.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// Explicitly borrows the secret value.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Transfers the existing allocation into a non-zeroizing byte vector.
    ///
    /// This avoids copying secret bytes when ownership must cross into an
    /// external type that requires `Vec<u8>`, such as a generated protobuf
    /// request. The returned vector no longer zeroizes on drop, so callers
    /// should keep its lifetime short and must not log or persist it.
    #[must_use]
    pub fn into_unprotected_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.0)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretBytes;

    #[test]
    fn debug_redacts_secret_bytes() {
        let secret = SecretBytes::new(b"not-in-secret-debug".to_vec());
        let debug = format!("{secret:?}");

        assert_eq!(debug, "SecretBytes(<redacted>)");
        assert!(!debug.contains("not-in-secret-debug"));
        assert_eq!(secret.expose_secret(), b"not-in-secret-debug");
    }

    #[test]
    fn ownership_handoff_reuses_the_secret_allocation() {
        let secret = SecretBytes::new(b"handoff-secret".to_vec());
        let original_allocation = secret.expose_secret().as_ptr();

        let bytes = secret.into_unprotected_vec();

        assert_eq!(bytes, b"handoff-secret");
        assert_eq!(bytes.as_ptr(), original_allocation);
    }

    #[test]
    fn zeroizing_handoff_reuses_the_secret_allocation() {
        let protected = zeroize::Zeroizing::new(b"zeroizing-handoff-secret".to_vec());
        let original_allocation = protected.as_ptr();

        let secret = SecretBytes::from_zeroizing(protected);

        assert_eq!(secret.expose_secret(), b"zeroizing-handoff-secret");
        assert_eq!(secret.expose_secret().as_ptr(), original_allocation);
    }
}
