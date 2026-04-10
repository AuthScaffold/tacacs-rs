/// Represents a TLS client identity using a raw public/private key pair.
///
/// In raw public key (RPK) authentication, the client proves possession of
/// a private key corresponding to a known public key, without needing an
/// X.509 certificate chain.
///
/// # Implementation
///
/// Uses OpenSSL 3.2+ native RPK support.  The private key is loaded into
/// OpenSSL, which derives the `SubjectPublicKeyInfo` and sends it as the
/// raw public key during the TLS handshake via the `client_certificate_type`
/// extension (RFC 7250).
///
/// # Security
///
/// The private key material is sensitive.  Avoid logging or displaying it.
/// The [`Debug`] implementation redacts the key bytes.
#[derive(Clone)]
pub struct RpkIdentity {
    /// The client's private key (DER-encoded).
    private_key_der: Vec<u8>,
    /// The private key format.
    private_key_format: KeyFormat,
    /// DER-encoded `SubjectPublicKeyInfo` (SPKI) blobs pinned for server
    /// verification.  When non-empty, the server's certificate public key
    /// must match one of these to be accepted.
    pinned_server_keys: Vec<PinnedPublicKey>,
}

/// A public key pinned for server verification.
#[derive(Clone, Debug)]
pub struct PinnedPublicKey {
    /// Human-readable name from the YANG configuration.
    pub name: String,
    /// DER-encoded `SubjectPublicKeyInfo`.
    pub spki_der: Vec<u8>,
}

/// Supported DER private key encodings.
#[derive(Clone, Debug, Copy)]
pub enum KeyFormat {
    /// PKCS#1 `RSAPrivateKey` (corresponds to `rsa-private-key-format`).
    Pkcs1,
    /// SEC1 `ECPrivateKey` (corresponds to `ec-private-key-format`).
    Sec1,
    /// PKCS#8 `OneAsymmetricKey` (corresponds to `one-asymmetric-key-format`).
    Pkcs8,
}

impl RpkIdentity {
    /// Creates a new RPK identity from raw DER key material.
    ///
    /// # Errors
    ///
    /// Returns an error if the key material cannot be parsed as the
    /// specified format.
    pub fn new(private_key_der: Vec<u8>, private_key_format: KeyFormat) -> anyhow::Result<Self> {
        if private_key_der.is_empty() {
            anyhow::bail!("RPK private key must not be empty");
        }

        // Validate that the key can be parsed.
        Self::parse_private_key(&private_key_der, private_key_format)?;

        Ok(Self {
            private_key_der,
            private_key_format,
            pinned_server_keys: Vec::new(),
        })
    }

    /// Adds pinned server public keys for server verification.
    #[must_use]
    pub fn with_pinned_server_keys(mut self, keys: Vec<PinnedPublicKey>) -> Self {
        self.pinned_server_keys = keys;
        self
    }

    /// Parses the stored key material into an OpenSSL `PKey`.
    pub(crate) fn to_openssl_pkey(
        &self,
    ) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
        Self::parse_private_key(&self.private_key_der, self.private_key_format)
    }

    /// Returns the pinned server public keys.
    pub(crate) fn pinned_server_keys(&self) -> &[PinnedPublicKey] {
        &self.pinned_server_keys
    }

    fn parse_private_key(
        der: &[u8],
        format: KeyFormat,
    ) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
        use openssl::pkey::PKey;

        match format {
            KeyFormat::Pkcs1 => {
                let rsa = openssl::rsa::Rsa::private_key_from_der(der)
                    .map_err(|e| anyhow::anyhow!("failed to parse PKCS#1 RSA private key: {e}"))?;
                PKey::from_rsa(rsa)
                    .map_err(|e| anyhow::anyhow!("failed to wrap RSA key in PKey: {e}"))
            }
            KeyFormat::Sec1 => {
                let ec = openssl::ec::EcKey::private_key_from_der(der)
                    .map_err(|e| anyhow::anyhow!("failed to parse SEC1 EC private key: {e}"))?;
                PKey::from_ec_key(ec)
                    .map_err(|e| anyhow::anyhow!("failed to wrap EC key in PKey: {e}"))
            }
            KeyFormat::Pkcs8 => PKey::private_key_from_der(der)
                .map_err(|e| anyhow::anyhow!("failed to parse PKCS#8 private key: {e}")),
        }
    }
}

impl std::fmt::Debug for RpkIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpkIdentity")
            .field("private_key_format", &self.private_key_format)
            .field("private_key", &"[REDACTED]")
            .field("pinned_server_keys", &self.pinned_server_keys.len())
            .finish_non_exhaustive()
    }
}
