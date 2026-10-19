//! Establishes connections from prepared endpoint values.
//!
//! The dispatcher uses prepared transport values without interpreting configuration.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::destination::connect_tcp;
use crate::endpoint::{ConnectionGuard, PreparedEndpoint};
use crate::transport::BoxedTransport;
use crate::transport::{tls, tls_psk};

/// One fully prepared transport, selected before endpoint construction.
#[derive(Clone, Debug)]
pub enum PreparedTransport {
    /// Plain TCP, with optional packet obfuscation supplied by the endpoint.
    Tcp,
    /// Certificate TLS with all required evidence attached.
    Tls(tls::TlsClientConfig),
    /// TLS 1.3 PSK with validated optional SNI in the prepared configuration.
    ///
    /// ```compile_fail
    /// use tacacsrs_networking::{PreparedTransport, PskClientConfig};
    /// fn replace_sni(config: PskClientConfig) {
    ///     let transport = PreparedTransport::Psk(config, Some("other.example".to_owned()));
    /// }
    /// ```
    Psk(tls_psk::PskClientConfig),
}

/// Optional readiness check before a prepared client is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectPreflight {
    /// Do not run a connection preflight when constructing a client.
    #[default]
    Disabled,
    /// Send a TACACS+ accounting WATCHDOG request before returning the client.
    ///
    /// When the server configuration enables single-connection mode, this also
    /// discovers support and promotes the preflight connection if the server echoes
    /// the single-connect flag.
    AccountingWatchdog,
}

/// TCP connection timeout and optional TACACS+ preflight.
///
/// Certificate verification belongs to TLS preparation, not execution controls.
///
/// ```compile_fail
/// use tacacsrs_networking::ConnectOptions;
/// let options = ConnectOptions::default().with_certificate_verification_disabled(true);
/// ```
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// Connection timeout. When `None`, no timeout is applied to the TCP
    /// connection phase. Callers must apply other timeouts.
    timeout: Option<Duration>,
    /// Optional preflight operation performed by `TacacsClient::connect_prepared`.
    preflight: ConnectPreflight,
}

impl ConnectOptions {
    pub(crate) const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Returns options with the TCP connect timeout set to `timeout`.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Returns options with the connection preflight mode set to `preflight`.
    #[must_use]
    pub const fn with_preflight(mut self, preflight: ConnectPreflight) -> Self {
        self.preflight = preflight;
        self
    }

    pub(crate) const fn preflight(&self) -> ConnectPreflight {
        self.preflight
    }
}

/// Opens the prepared transport without interpreting source configuration.
///
/// # Errors
///
/// Returns an error if:
/// - TCP connection fails or times out
/// - the prepared backend fails to complete its handshake
#[cfg(test)]
pub(crate) async fn establish_stream(endpoint: &PreparedEndpoint) -> Result<BoxedTransport> {
    establish_stream_until(endpoint, None).await
}

pub(crate) async fn establish_stream_until(
    endpoint: &PreparedEndpoint,
    deadline: Option<crate::RequestDeadline>,
) -> Result<BoxedTransport> {
    let mut attempt =
        crate::statistics::ConnectionAttempt::new(endpoint.counters()).with_deadline(deadline);
    let result = establish_transport(endpoint, &mut attempt).await;
    match result {
        Ok(transport) => {
            attempt.succeeded();
            let counters = endpoint
                .counters()
                .for_connection(attempt.peer_address(), transport.tls_details());
            Ok(transport.with_counters(counters))
        }
        Err(error) => {
            attempt.failed_error(&error);
            Err(error)
        }
    }
}

struct CertificateTlsConnectionGuard<'a> {
    endpoint: &'a PreparedEndpoint,
    host_guard: Option<&'a dyn ConnectionGuard>,
}

impl ConnectionGuard for CertificateTlsConnectionGuard<'_> {
    fn check_destination(&self, destination: SocketAddr) -> Result<()> {
        if let Some(host_guard) = self.host_guard {
            host_guard.check_destination(destination)?;
        }
        self.endpoint
            .validate_client_certificate_dates()
            .context(crate::statistics::CertificateFailure)
    }

    fn check_connected(&self, peer: SocketAddr, local: SocketAddr) -> Result<()> {
        match self.host_guard {
            Some(host_guard) => host_guard.check_connected(peer, local),
            None => Ok(()),
        }
    }
}

async fn establish_transport(
    endpoint: &PreparedEndpoint,
    attempt: &mut crate::statistics::ConnectionAttempt,
) -> Result<BoxedTransport> {
    endpoint
        .validate_client_certificate_dates()
        .context(crate::statistics::CertificateFailure)?;
    let operation = establish_transport_inner(endpoint, attempt);
    match endpoint.revocation_evidence_lifetime() {
        Some(lifetime) => lifetime.run(operation).await,
        None => operation.await,
    }
}

async fn establish_transport_inner(
    endpoint: &PreparedEndpoint,
    attempt: &mut crate::statistics::ConnectionAttempt,
) -> Result<BoxedTransport> {
    let address = endpoint.address();
    let options = &endpoint.options;

    let security_label = endpoint.security_label();
    log::debug!(
        "Connecting to TACACS+ server {address} (security: {security_label}, timeout: {:?})",
        options.timeout,
    );

    let certificate_tls_guard =
        matches!(&endpoint.transport, PreparedTransport::Tls(_)).then(|| {
            CertificateTlsConnectionGuard {
                endpoint,
                host_guard: endpoint.connection_guard.as_deref(),
            }
        });
    let connection_guard = certificate_tls_guard
        .as_ref()
        .map(|guard| guard as &dyn ConnectionGuard)
        .or(endpoint.connection_guard.as_deref());
    let tcp_stream = match options.timeout {
        Some(dur) => tokio::time::timeout(dur, connect_tcp(address, connection_guard))
            .await
            .with_context(|| format!("Connection to TACACS+ server {address} timed out"))?
            .with_context(|| format!("Failed to establish TCP connection to {address}"))?,
        None => connect_tcp(address, connection_guard)
            .await
            .with_context(|| format!("Failed to establish TCP connection to {address}"))?,
    };

    log::debug!("TCP connection to {address} established");
    attempt.connected();
    attempt.peer(tcp_stream.peer_addr().ok());

    match &endpoint.transport {
        PreparedTransport::Tcp => Ok(BoxedTransport::new(tcp_stream)),
        PreparedTransport::Tls(config) => {
            attempt.handshake();
            config.connect(tcp_stream).await
        }
        PreparedTransport::Psk(config) => {
            attempt.handshake();
            let stream = config.connect(address, tcp_stream).await?;
            let details = crate::TlsDetails::from_ssl(stream.ssl());
            Ok(BoxedTransport::new(stream).with_tls_details(details))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn evidence_deadline_bounds_stalled_handshake_before_transport_registration() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut endpoint = PreparedEndpoint::new(
            listener.local_addr().unwrap().try_into().unwrap(),
            PreparedTransport::Tls(
                crate::TlsClientConfig::prepare(
                    "localhost",
                    None,
                    crate::CertificateTrust::Platform,
                    None,
                    crate::CertificateVerification::DisabledForDevelopment,
                )
                .unwrap(),
            ),
            false,
            None,
            ConnectOptions::default(),
        );
        let now = SystemTime::now();
        let validity = crate::transport::tls::RevocationEvidenceValidity::from_bounds(
            now - Duration::from_secs(1),
            now + Duration::from_secs(60),
        )
        .unwrap();
        let PreparedTransport::Tls(config) = &mut endpoint.transport else {
            panic!("test endpoint must use certificate TLS");
        };
        config.evidence_lifetime = Some(crate::transport::tls::RevocationEvidenceLifetime {
            validity,
            deadline: crate::RequestDeadline::after(Duration::from_secs(1)).unwrap(),
        });
        let (connected, observed) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = connected.send(());
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            received
        });
        let setup = establish_stream(&endpoint);
        tokio::pin!(setup);
        tokio::select! {
            result = &mut setup => match result {
                Ok(_) => panic!("setup completed before TCP connected"),
                Err(error) => panic!("setup failed before TCP connected: {error:#}"),
            },
            result = observed => result.unwrap(),
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = match setup.await {
            Ok(_) => panic!("setup completed after evidence expired"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("request deadline expired"),
            "unexpected setup error: {error:#}"
        );
        assert!(!peer.await.unwrap().is_empty(), "TLS must start before evidence expiry");
    }
}
