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
/// Callers supply a structured address, prepared transport, and protected packet key.
/// Clones share native contexts but not connection or session state.
#[derive(Clone)]
pub struct PreparedEndpoint {
    pub(crate) address: crate::ServerAddress,
    pub(crate) single_connection: bool,
    pub(crate) obfuscation_key: Option<SecretBytes>,
    pub(crate) transport: PreparedTransport,
    pub(crate) options: ConnectOptions,
    pub(crate) connection_guard: Option<Arc<dyn ConnectionGuard>>,
    pub(crate) counters: crate::ServerCounters,
}

impl PreparedEndpoint {
    /// Finalizes an endpoint from one fully prepared transport.
    ///
    /// The packet layer applies `obfuscation_key` when present. This constructor
    /// does not resolve the address or open a connection. Security cannot be replaced.
    ///
    /// ```compile_fail
    /// use tacacsrs_networking::{ConnectOptions, PreparedEndpoint};
    /// let endpoint = PreparedEndpoint::tcp("localhost:49", false, None, ConnectOptions::default());
    /// ```
    ///
    /// ```compile_fail
    /// use tacacsrs_networking::PreparedEndpoint;
    /// fn reselect(endpoint: PreparedEndpoint) {
    ///     endpoint.with_certificate_tls("localhost", None, tacacsrs_networking::CertificateTrust::Platform, None);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use tacacsrs_networking::{PreparedEndpoint, PskHash};
    /// fn reselect(endpoint: PreparedEndpoint) {
    ///     endpoint.with_psk("client", b"valid-test-psk-material", PskHash::Sha256, &[], None);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use tacacsrs_networking::{PreparedEndpoint, CertificateRevocationPolicy};
    /// fn attach(endpoint: PreparedEndpoint) {
    ///     endpoint.with_certificate_revocation(CertificateRevocationPolicy::disabled());
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use tacacsrs_networking::PreparedEndpoint;
    /// fn attach(endpoint: PreparedEndpoint) {
    ///     endpoint.with_certificate_crls(&[], std::time::Duration::from_secs(300));
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use tacacsrs_networking::PreparedEndpoint;
    /// fn attach(endpoint: PreparedEndpoint) {
    ///     endpoint.with_certificate_ocsp_response(&[], std::time::Duration::from_secs(300));
    /// }
    /// ```
    #[must_use]
    pub fn new(
        address: crate::ServerAddress,
        transport: PreparedTransport,
        single_connection: bool,
        obfuscation_key: Option<SecretBytes>,
        options: ConnectOptions,
    ) -> Self {
        Self {
            address,
            single_connection,
            obfuscation_key,
            transport,
            options,
            connection_guard: None,
            counters: crate::ServerCounters::default(),
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
    pub fn address(&self) -> &crate::ServerAddress {
        &self.address
    }

    /// Returns the counter owner shared by this endpoint's clones and connections.
    #[must_use]
    pub fn counters(&self) -> crate::ServerCounters {
        self.counters.clone()
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

    /// Returns the validity interval for prepared fetched OCSP and CRL evidence.
    #[must_use]
    pub fn revocation_evidence_validity(&self) -> Option<crate::RevocationEvidenceValidity> {
        match &self.transport {
            PreparedTransport::Tls(config) => {
                config.evidence_lifetime.map(|lifetime| lifetime.validity)
            }
            _ => None,
        }
    }

    pub(crate) fn validate_client_certificate_dates(&self) -> anyhow::Result<()> {
        match &self.transport {
            PreparedTransport::Tls(config) => config.validate_client_certificate_dates(),
            PreparedTransport::Tcp | PreparedTransport::Psk(_) => Ok(()),
        }
    }

    pub(crate) fn revocation_evidence_lifetime(
        &self,
    ) -> Option<crate::transport::tls::RevocationEvidenceLifetime> {
        match &self.transport {
            PreparedTransport::Tls(config) => config.evidence_lifetime,
            PreparedTransport::Tcp | PreparedTransport::Psk(_) => None,
        }
    }

    pub(crate) const fn security_label(&self) -> &'static str {
        match self.transport {
            PreparedTransport::Tls(_) | PreparedTransport::Psk(_) => "tls",
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
    use crate::{CertificateTrust, TlsClientConfig, PskClientConfig, PskHash};

    #[test]
    fn finalized_tls_retains_mandatory_staple_policy() {
        let policy =
            crate::CertificateRevocationPolicy::require_stapled_ocsp(Duration::from_secs(300))
                .unwrap();
        let endpoint = PreparedEndpoint::new(
            crate::ServerAddress::parse("localhost:300", 49).unwrap(),
            PreparedTransport::Tls(
                TlsClientConfig::prepare(
                    "localhost",
                    None,
                    CertificateTrust::Platform,
                    None,
                    crate::CertificateVerification::Required,
                )
                .unwrap()
                .with_revocation_policy(policy)
                .unwrap(),
            ),
            false,
            None,
            ConnectOptions::default(),
        );
        let PreparedTransport::Tls(config) = endpoint.transport else {
            panic!("certificate TLS must remain selected");
        };
        assert_eq!(config.revocation, policy);
    }

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
        let endpoint = PreparedEndpoint::new(
            listener.local_addr().unwrap().try_into().unwrap(),
            crate::PreparedTransport::Tcp,
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
            let transport = match security {
                "tls" => PreparedTransport::Tls(
                    TlsClientConfig::prepare(
                        "localhost",
                        None,
                        CertificateTrust::Platform,
                        None,
                        crate::CertificateVerification::Required,
                    )
                    .unwrap(),
                ),
                "psk" => PreparedTransport::Psk(
                    PskClientConfig::prepare(
                        "client",
                        b"valid-test-psk-material",
                        PskHash::Sha256,
                        &[],
                        None,
                    )
                    .unwrap(),
                ),
                _ => PreparedTransport::Tcp,
            };
            let endpoint = PreparedEndpoint::new(
                listener.local_addr().unwrap().try_into().unwrap(),
                transport,
                false,
                None,
                ConnectOptions::default(),
            )
            .with_connection_guard(RejectConnected);
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
        let endpoint = PreparedEndpoint::new(
            crate::ServerAddress::parse("127.0.0.1:1", 49).unwrap(),
            crate::PreparedTransport::Tcp,
            false,
            Some(SecretBytes::new(b"private-key".to_vec())),
            ConnectOptions::default(),
        );
        assert_eq!(endpoint.address().to_string(), "127.0.0.1:1");
        assert!(!endpoint.single_connection());
        assert_eq!(endpoint.connection_timeout(), None);
        assert!(!format!("{endpoint:?}").contains("private-key"));
        crate::TacacsClient::connect_prepared(endpoint)
            .await
            .unwrap();
    }
}
