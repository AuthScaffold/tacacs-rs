//! TLS transport for TACACS+ connections.
//!
//! Native contexts use borrowed DER material and explicit verification settings.
//! Each context supports repeated handshakes without reparsing credentials.

mod config_builder;
mod config;
mod validity;
mod revocation;
#[allow(clippy::module_inception)]
mod tls;

pub(crate) use config_builder::TlsConfigurationBuilder;
pub(crate) use config::TlsClientConfig;
pub use config::{CertificateIdentity, CertificateTrust, PrivateKeyEncoding};
pub use validity::CertificateValidity;
pub use revocation::CertificateRevocationPolicy;
pub(crate) use validity::CertificateLifetime;

use anyhow::Context;
use openssl::ssl::Ssl;
use openssl::ssl::SslContext;
use openssl::x509::verify::X509CheckFlags;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

/// Establishes a TLS connection over an existing TCP connection.
///
/// `peer_identity` is the expected DNS or IP subject alternative name.
/// `sni_name` independently selects a DNS name for the `ClientHello`.
///
/// # Errors
///
/// Returns an error if:
/// - the server name is not a valid domain name or IP address, or
/// - the TLS handshake fails.
async fn connect_tls(
    context: &SslContext,
    stream: TcpStream,
    peer_identity: &str,
    sni_name: Option<&str>,
    peer_validity_index: config_builder::PeerValidityIndex,
    revocation: Option<revocation::ConnectionRevocation>,
) -> anyhow::Result<SslStream<TcpStream>> {
    let mut ssl = Ssl::new(context).context("OpenSSL failed to allocate TLS SSL object")?;
    ssl.set_ex_data(peer_validity_index, std::sync::Mutex::new(None));
    revocation::request(&mut ssl, revocation)?;
    ssl.param_mut()
        .set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS | X509CheckFlags::NEVER_CHECK_SUBJECT);
    match peer_identity.parse::<std::net::IpAddr>() {
        Ok(address) => ssl
            .param_mut()
            .set_ip(address)
            .context("OpenSSL failed to set TLS peer IP verification")?,
        Err(_) => ssl
            .param_mut()
            .set_host(peer_identity)
            .context("OpenSSL failed to set TLS peer DNS verification")?,
    }
    if let Some(name) = sni_name {
        ssl.set_hostname(name)
            .context("OpenSSL failed to set TLS SNI")?;
    }

    let mut stream = SslStream::new(ssl, stream)
        .context("OpenSSL failed to attach the TLS SSL object to the TCP connection")?;

    let handshake = SslStream::connect(std::pin::Pin::new(&mut stream)).await;
    revocation::verified_validity(stream.ssl())?;
    handshake.context("OpenSSL TLS handshake failed")?;

    Ok(stream)
}
