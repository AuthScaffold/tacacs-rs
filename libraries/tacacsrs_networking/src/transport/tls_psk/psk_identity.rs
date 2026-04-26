/// Represents a TLS 1.3 Pre-Shared Key identity and secret.
///
/// This holds the PSK identity string (sent to the server during handshake)
/// and the corresponding shared secret key. Both values must match what the
/// server expects.
///
/// This type is internal to the crate; PSK material is supplied through the
/// YANG configuration model and consumed by
/// [`super::establish_from_server`].
///
/// # Security
///
/// The PSK key material is sensitive. Avoid logging or displaying it.
/// Per [RFC 9257 §6], a PSK MUST be at least 128 bits (16 bytes) and SHOULD
/// be derived from at least 128 bits of entropy.
///
/// [RFC 9257 §6]: https://www.rfc-editor.org/rfc/rfc9257.html#section-6
#[derive(Clone)]
pub(crate) struct PskIdentity {
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
    /// Per RFC 9257 §6, PSKs MUST be at least 128 bits (16 bytes).
    pub(crate) const MIN_KEY_LENGTH: usize = 16;

    /// Creates a new PSK identity with the given identity string and key.
    ///
    /// # Errors
    ///
    /// Returns an error if `identity` is empty, contains a NUL byte, or `key`
    /// is shorter than [`Self::MIN_KEY_LENGTH`] bytes.
    pub(crate) fn new(
        identity: impl Into<String>,
        key: impl Into<Vec<u8>>,
    ) -> anyhow::Result<Self> {
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
                "PSK key must be at least {} bytes (128 bits), per RFC 9257 §6; got {} bytes",
                Self::MIN_KEY_LENGTH,
                key.len()
            );
        }

        Ok(Self { identity, key })
    }

    /// Returns the PSK identity string.
    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    /// Returns the PSK key bytes.
    pub(crate) fn key(&self) -> &[u8] {
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
