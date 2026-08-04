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

    /// Explicitly borrows the secret value.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
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
}
