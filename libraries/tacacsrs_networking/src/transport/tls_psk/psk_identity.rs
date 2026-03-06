/// Represents a TLS 1.3 Pre-Shared Key identity and secret.
///
/// This holds the PSK identity string (sent to the server during handshake)
/// and the corresponding shared secret key. Both values must match what the
/// server expects.
///
/// # Security
///
/// The PSK key material is sensitive. Avoid logging or displaying it.
/// Use strong, randomly generated keys of sufficient length (at least 32 bytes
/// is recommended for TLS 1.3).
#[derive(Clone)]
pub struct PskIdentity {
    /// The identity string sent to the server during the TLS handshake.
    /// This allows the server to look up the correct pre-shared key.
    identity: String,

    /// The shared secret key bytes. Must match the server's configured key
    /// for the given identity.
    key: Vec<u8>,
}

impl PskIdentity {
    /// The minimum required key length in bytes.
    ///
    /// TLS 1.3 PSK requires keys of sufficient entropy. 16 bytes (128 bits) is
    /// the minimum recommended length.
    pub const MIN_KEY_LENGTH: usize = 16;

    /// Creates a new PSK identity with the given identity string and key.
    ///
    /// # Arguments
    ///
    /// * `identity` - A string identifying this client to the server (e.g., "tacacs-client-1").
    ///   Must not contain NUL (`\0`) bytes, as the identity is sent as a null-terminated
    ///   C string during the TLS handshake.
    /// * `key` - The shared secret key bytes. Must be at least [`Self::MIN_KEY_LENGTH`] bytes
    ///   (16 bytes / 128 bits).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `identity` contains a NUL byte (`\0`)
    /// - `identity` is empty
    /// - `key` is shorter than [`Self::MIN_KEY_LENGTH`] bytes
    ///
    /// # Example
    ///
    /// ```
    /// use tacacsrs_networking::transport::tls_psk::PskIdentity;
    ///
    /// let psk = PskIdentity::new("my-client", b"super_secret_key!").unwrap();
    ///
    /// // NUL bytes in identity are rejected
    /// assert!(PskIdentity::new("bad\0id", b"super_secret_key!").is_err());
    ///
    /// // Keys shorter than 16 bytes are rejected
    /// assert!(PskIdentity::new("my-client", b"too_short").is_err());
    /// ```
    pub fn new(identity: impl Into<String>, key: impl Into<Vec<u8>>) -> anyhow::Result<Self> {
        let identity = identity.into();
        let key = key.into();

        if identity.is_empty() {
            anyhow::bail!("PSK identity must not be empty");
        }

        if identity.contains('\0') {
            anyhow::bail!(
                "PSK identity must not contain NUL bytes (identity is sent as a null-terminated C string)"
            );
        }

        if key.len() < Self::MIN_KEY_LENGTH {
            anyhow::bail!(
                "PSK key must be at least {} bytes, got {} bytes",
                Self::MIN_KEY_LENGTH,
                key.len()
            );
        }

        Ok(Self { identity, key })
    }

    /// Returns the PSK identity string.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Returns the PSK key bytes.
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl std::fmt::Debug for PskIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PskIdentity")
            .field("identity", &self.identity)
            .field("key", &"[REDACTED]")
            .finish()
    }
}
