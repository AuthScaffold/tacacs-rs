//! Connection-ready values derived from authoritative configuration.
//!
//! Prepared endpoints own native TLS contexts and protected credential bytes.
//! They are not a configuration schema and do not retain the source snapshot.

use std::fmt;

use tacacsrs_secrets::SecretBytes;

use crate::establish::{ConnectOptions, PreparedTransport};
use crate::transport::tls::{CertificateIdentity, TlsClientConfig};
use crate::transport::tls_psk::{PskClientConfig, PskHash, PskDheGroup};

/// An immutable endpoint with validated native transport material.
///
/// Callers supply explicit runtime values and borrowed transport credentials.
/// Clones share native contexts but not connection or session state.
#[derive(Clone)]
pub struct PreparedEndpoint {
    pub(crate) address: String,
    pub(crate) single_connection: bool,
    pub(crate) obfuscation_key: Option<SecretBytes>,
    pub(crate) transport: PreparedTransport,
    pub(crate) options: ConnectOptions,
}

impl PreparedEndpoint {
    /// Selects TLS 1.3 PSK with explicit hash and ordered key-exchange groups.
    ///
    /// An empty group list selects PSK-only key exchange. The prepared context
    /// owns protected key bytes and does not retain the borrowed inputs.
    /// Connections must authenticate with the PSK and negotiate the selected
    /// mode before the client sends TACACS+ data. Certificate fallback is rejected.
    /// This PSK path requires OpenSSL 3.0 or newer for negotiated-group inspection.
    ///
    /// # Errors
    ///
    /// Returns an error if the identity, key, groups, or native context is invalid.
    pub fn with_psk(
        mut self,
        identity: &str,
        key: &[u8],
        hash: PskHash,
        groups: &[PskDheGroup],
        server_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        self.transport = PreparedTransport::Psk(
            PskClientConfig::prepare(identity, key, hash, groups)?,
            server_name.map(str::to_owned),
        );
        Ok(self)
    }

    /// Selects certificate TLS and validates borrowed DER credentials.
    ///
    /// Empty roots select the platform trust store. The endpoint options control
    /// certificate verification. No network I/O occurs during preparation.
    ///
    /// # Errors
    ///
    /// Returns an error if the DER material or native context is invalid.
    pub fn with_certificate_tls<'a>(
        mut self,
        server_name: &str,
        roots: impl IntoIterator<Item = &'a [u8]>,
        identity: Option<CertificateIdentity<'_>>,
    ) -> anyhow::Result<Self> {
        self.transport = PreparedTransport::Tls(TlsClientConfig::prepare(
            server_name,
            roots,
            identity,
            self.options.certificate_verification_disabled(),
        )?);
        Ok(self)
    }

    /// Creates a plain TCP endpoint from explicit runtime values.
    ///
    /// The packet layer applies `obfuscation_key` when present. This constructor
    /// does not resolve the address or open a connection.
    #[must_use]
    pub fn tcp(
        address: impl Into<String>,
        single_connection: bool,
        obfuscation_key: Option<SecretBytes>,
        options: ConnectOptions,
    ) -> Self {
        Self {
            address: address.into(),
            single_connection,
            obfuscation_key,
            transport: PreparedTransport::Tcp,
            options,
        }
    }

    /// Returns the prepared host and port without resolving DNS.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns whether this endpoint requests TACACS+ single-connection mode.
    #[must_use]
    pub const fn single_connection(&self) -> bool {
        self.single_connection
    }

    pub(crate) const fn security_label(&self) -> &'static str {
        match self.transport {
            PreparedTransport::Tls(_) | PreparedTransport::Psk(_, _) => "tls",
            PreparedTransport::Tcp if self.obfuscation_key.is_some() => "obfuscation",
            PreparedTransport::Tcp => "plain-tcp",
        }
    }
}

impl fmt::Debug for PreparedEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedEndpoint")
            .field("address", &self.address)
            .field("single_connection", &self.single_connection)
            .field("security", &self.security_label())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_endpoint_needs_no_source_model_or_network_io() {
        let endpoint = PreparedEndpoint::tcp(
            "127.0.0.1:1",
            false,
            Some(SecretBytes::new(b"private-key".to_vec())),
            ConnectOptions::default(),
        );
        assert_eq!(endpoint.address(), "127.0.0.1:1");
        assert!(!endpoint.single_connection());
        assert!(!format!("{endpoint:?}").contains("private-key"));
        crate::TacacsClient::connect_prepared(endpoint)
            .await
            .unwrap();
    }
}
