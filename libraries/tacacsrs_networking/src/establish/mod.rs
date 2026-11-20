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

#[cfg(all(test, target_os = "linux"))]
mod tests_binding;

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

/// Connection timeout, local binding, and optional TACACS+ preflight.
///
/// Certificate verification belongs to TLS preparation, not execution controls.
///
/// ```compile_fail
/// use tacacsrs_networking::ConnectOptions;
/// let options = ConnectOptions::default().with_certificate_verification_disabled(true);
/// ```
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    binding: crate::LocalBinding,
    /// Connection timeout. It bounds the TCP connect and the TLS or PSK
    /// handshake together. When `None`, no timeout is applied to connection
    /// setup. Callers must apply other timeouts.
    timeout: Option<Duration>,
    /// Optional preflight operation performed by `TacacsClient::connect_prepared`.
    preflight: ConnectPreflight,
}

impl ConnectOptions {
    pub(crate) fn local_binding(&self) -> &crate::LocalBinding {
        &self.binding
    }

    /// Sets the derived local source, egress, VRF, and fallback policy.
    #[must_use]
    pub fn with_local_binding(mut self, binding: crate::LocalBinding) -> Self {
        self.binding = binding;
        self
    }

    pub(crate) const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Returns options with the connection timeout set to `timeout`.
    ///
    /// The timeout bounds the TCP connect and the TLS or PSK handshake
    /// together. A server that accepts TCP and then stalls the handshake
    /// therefore fails within `timeout`, and failover can try another server.
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
/// - TCP connection fails
/// - the prepared backend fails to complete its handshake
/// - the TCP connect and handshake together exceed the connection timeout
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
    establish_transport_inner(endpoint, attempt).await
}

async fn establish_transport_inner(
    endpoint: &PreparedEndpoint,
    attempt: &mut crate::statistics::ConnectionAttempt,
) -> Result<BoxedTransport> {
    let address = endpoint.address();
    let timeout = endpoint.options.timeout;
    log::debug!(
        "Connecting to TACACS+ server {address} (security: {}, timeout: {timeout:?})",
        endpoint.security_label(),
    );
    let deadline = timeout.map(|duration| tokio::time::Instant::now() + duration);
    let connection = connect_and_handshake(endpoint, attempt, deadline);
    match timeout {
        Some(duration) => tokio::time::timeout(duration, connection)
            .await
            .with_context(|| {
                format!(
                    "Connection to TACACS+ server {address} did not complete within {duration:?}"
                )
            })?,
        None => connection.await,
    }
}

/// Opens TCP and completes the prepared handshake, without a timeout.
///
/// `deadline` is the end of the caller's connection timeout. A revocation
/// verifier receives it so that an evidence fetch can stop in time.
async fn connect_and_handshake(
    endpoint: &PreparedEndpoint,
    attempt: &mut crate::statistics::ConnectionAttempt,
    deadline: Option<tokio::time::Instant>,
) -> Result<BoxedTransport> {
    let address = endpoint.address();
    let options = &endpoint.options;

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
    let tcp_stream = connect_tcp(address, connection_guard, &options.binding)
        .await
        .with_context(|| format!("Failed to establish TCP connection to {address}"))?;

    log::debug!("TCP connection to {address} established");
    attempt.connected();
    attempt.peer(tcp_stream.peer_addr().ok());

    match &endpoint.transport {
        PreparedTransport::Tcp => Ok(BoxedTransport::new(tcp_stream)),
        PreparedTransport::Tls(config) => {
            attempt.handshake();
            let revocation =
                endpoint
                    .revocation_verifier
                    .as_ref()
                    .map(|verifier| tls::RevocationCheck {
                        verifier: std::sync::Arc::clone(verifier),
                        network: crate::RevocationNetwork::new(
                            options.binding.clone(),
                            endpoint.connection_guard.clone(),
                        ),
                        deadline,
                        counters: endpoint.counters(),
                    });
            config.connect(tcp_stream, revocation.as_ref()).await
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
    use std::time::Duration;

    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn connect_timeout_bounds_a_stalled_tls_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = PreparedEndpoint::new(
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
            ConnectOptions::default().with_timeout(Duration::from_secs(1)),
        );
        // The peer accepts TCP and never answers the ClientHello.
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            received
        });
        let started = tokio::time::Instant::now();
        let error = match establish_stream(&endpoint).await {
            Ok(_) => panic!("setup completed without a TLS handshake"),
            Err(error) => error,
        };
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        assert!(error.is::<tokio::time::error::Elapsed>(), "unexpected setup error: {error:#}");
        assert_eq!(endpoint.counters().snapshot().connection_timeouts, 1);
        assert!(!peer.await.unwrap().is_empty(), "TLS must start before the timeout");
    }
}
