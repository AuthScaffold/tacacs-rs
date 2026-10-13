//! Connection-ready values derived from authoritative configuration.
//!
//! Prepared endpoints own native TLS contexts and protected credential bytes.
//! They are not a configuration schema and do not retain the source snapshot.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tacacsrs_secrets::SecretBytes;

use crate::establish::{ConnectOptions, PreparedTransport};
use crate::transport::tls::{CertificateIdentity, CertificateTrust, TlsClientConfig};
use crate::transport::tls_psk::{PskClientConfig, PskHash, PskDheGroup};

/// Host-owned checks for resolved and connected TCP destinations.
///
/// Guards must be thread-safe and must not perform network I/O. Endpoint clones
/// share the guard so listener state can change without rewriting configuration.
pub trait ConnectionGuard: Send + Sync {
    /// Checks one resolved destination immediately before a connection attempt.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination or current host state is not permitted.
    fn check_destination(&self, destination: SocketAddr) -> anyhow::Result<()>;

    /// Checks the connected socket before TLS or TACACS+ I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket or current host state is not permitted.
    fn check_connected(&self, peer: SocketAddr, local: SocketAddr) -> anyhow::Result<()>;
}

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
    pub(crate) connection_guard: Option<Arc<dyn ConnectionGuard>>,
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
    /// Trust roles and platform trust are explicit. The endpoint options control
    /// certificate verification. Empty explicit trust is rejected before I/O.
    /// `peer_identity` is the expected DNS/IP SAN. `sni_name` independently selects
    /// an optional DNS name for the `ClientHello`. IP addresses are not sent as SNI.
    ///
    /// # Errors
    ///
    /// Returns an error if the DER material or native context is invalid.
    pub fn with_certificate_tls(
        mut self,
        peer_identity: &str,
        sni_name: Option<&str>,
        trust: CertificateTrust<'_>,
        identity: Option<CertificateIdentity<'_>>,
    ) -> anyhow::Result<Self> {
        self.transport = PreparedTransport::Tls(TlsClientConfig::prepare(
            peer_identity,
            sni_name,
            trust,
            identity,
            self.options.certificate_verification_disabled(),
        )?);
        Ok(self)
    }

    /// Applies stapled OCSP requirements to this certificate TLS endpoint.
    ///
    /// # Errors
    /// Returns an error if required evidence is combined with another transport or disabled verification.
    pub fn with_certificate_revocation(
        mut self,
        policy: crate::CertificateRevocationPolicy,
    ) -> anyhow::Result<Self> {
        self.transport = match self.transport {
            PreparedTransport::Tls(config) => {
                PreparedTransport::Tls(config.with_revocation_policy(policy)?)
            }
            transport => {
                anyhow::ensure!(
                    policy.maximum_response_age().is_none(),
                    "Required OCSP evidence needs certificate TLS"
                );
                transport
            }
        };
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
            connection_guard: None,
        }
    }

    /// Attaches execution-time host checks without changing the source configuration.
    #[must_use]
    pub fn with_connection_guard(mut self, guard: impl ConnectionGuard + 'static) -> Self {
        self.connection_guard = Some(Arc::new(guard));
        self
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

    /// Returns the TCP connection timeout, if one was prepared.
    #[must_use]
    pub const fn connection_timeout(&self) -> Option<Duration> {
        self.options.timeout()
    }

    /// Returns intrinsic validity for the configured client certificate, when present.
    ///
    /// These bounds do not describe provider metadata or negotiated peer certificates.
    #[must_use]
    pub fn client_certificate_validity(&self) -> Option<crate::CertificateValidity> {
        self.client_identity_lifetime()
            .map(|lifetime| lifetime.validity)
    }

    pub(crate) fn client_identity_lifetime(
        &self,
    ) -> Option<crate::transport::tls::CertificateLifetime> {
        match &self.transport {
            PreparedTransport::Tls(config) => config.lifetime,
            PreparedTransport::Tcp | PreparedTransport::Psk(_, _) => None,
        }
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

    struct DenyConnection;

    impl ConnectionGuard for DenyConnection {
        fn check_destination(&self, _: SocketAddr) -> anyhow::Result<()> {
            anyhow::bail!("blocked test destination")
        }

        fn check_connected(&self, _: SocketAddr, _: SocketAddr) -> anyhow::Result<()> {
            anyhow::bail!("blocked test connection")
        }
    }

    #[tokio::test]
    async fn rejected_destination_never_connects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = PreparedEndpoint::tcp(
            listener.local_addr().unwrap().to_string(),
            false,
            None,
            ConnectOptions::default(),
        )
        .with_connection_guard(DenyConnection);
        let result = crate::establish::establish_stream(&endpoint).await;
        assert!(result.is_err(), "execution must enforce the destination guard");
        assert!(tokio::time::timeout(Duration::from_millis(25), listener.accept())
            .await
            .is_err());
    }

    struct RejectConnected;

    impl ConnectionGuard for RejectConnected {
        fn check_destination(&self, _: SocketAddr) -> anyhow::Result<()> {
            Ok(())
        }
        fn check_connected(&self, _: SocketAddr, _: SocketAddr) -> anyhow::Result<()> {
            anyhow::bail!("host state changed before the connection completed")
        }
    }

    #[tokio::test]
    async fn post_connect_rejection_sends_no_plain_tls_or_psk_bytes() {
        use tokio::io::AsyncReadExt;

        for security in ["plain", "tls", "psk"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = PreparedEndpoint::tcp(
                listener.local_addr().unwrap().to_string(),
                false,
                None,
                ConnectOptions::default(),
            )
            .with_connection_guard(RejectConnected);
            let endpoint = match security {
                "tls" => endpoint
                    .with_certificate_tls("localhost", None, CertificateTrust::Platform, None)
                    .unwrap(),
                "psk" => endpoint
                    .with_psk("client", b"valid-test-psk-material", PskHash::Sha256, &[], None)
                    .unwrap(),
                _ => endpoint,
            };
            tokio::time::timeout(Duration::from_secs(2), async {
                let (accepted, opened) =
                    tokio::join!(listener.accept(), crate::establish::establish_stream(&endpoint));
                assert!(opened.is_err(), "guard must reject {security}");
                let (mut stream, _) = accepted.unwrap();
                let mut byte = [0];
                assert_eq!(
                    stream.read(&mut byte).await.unwrap(),
                    0,
                    "{security} must send no bytes"
                );
            })
            .await
            .unwrap();
        }
    }

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
        assert_eq!(endpoint.connection_timeout(), None);
        assert!(!format!("{endpoint:?}").contains("private-key"));
        crate::TacacsClient::connect_prepared(endpoint)
            .await
            .unwrap();
    }
}
