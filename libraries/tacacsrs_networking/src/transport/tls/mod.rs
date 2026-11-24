//! TLS transport for TACACS+ connections.
//!
//! Native contexts use borrowed DER material and explicit verification settings.
//! Each context supports repeated handshakes without reparsing credentials.
//! Client certificate dates are checked before each connection and again before
//! its handshake. Established connections retain no certificate-date cutoff.

mod config_builder;
mod config;
mod revocation_hook;
mod validity;
#[allow(clippy::module_inception)]
mod tls;

pub(crate) use config_builder::TlsConfigurationBuilder;
pub use config::TlsClientConfig;
pub use config::{CertificateIdentity, CertificateTrust, CertificateVerification, PrivateKeyEncoding};
pub(crate) use revocation_hook::RevocationCheck;
pub use validity::asn1_system_time;

use anyhow::Context;
use openssl::ssl::{ErrorCode, Ssl, SslContext};
use openssl::x509::verify::X509CheckFlags;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

/// Establishes a TLS connection over an existing TCP connection.
///
/// `peer_identity` is the expected DNS or IP subject alternative name.
/// `sni_name` independently selects a DNS name for the `ClientHello`. When
/// `revocation` is present, the handshake pauses while the verifier obtains
/// evidence and then resumes on the same socket.
///
/// # Errors
///
/// Returns an error if:
/// - the server name is not a valid domain name or IP address,
/// - the certificate or revocation check rejects the server, or
/// - the TLS handshake fails.
async fn connect_tls(
    context: &SslContext,
    stream: TcpStream,
    peer_identity: &str,
    sni_name: Option<&str>,
    revocation: Option<&RevocationCheck>,
) -> anyhow::Result<SslStream<TcpStream>> {
    let mut ssl = Ssl::new(context).context("OpenSSL failed to allocate TLS SSL object")?;
    let hook = revocation
        .map(|check| revocation_hook::HandshakeRevocation::attach(&mut ssl, check, peer_identity))
        .transpose()?;
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

    let handshake = loop {
        let result = SslStream::connect(std::pin::Pin::new(&mut stream)).await;
        let retry = matches!(&result, Err(error) if error.code() == ErrorCode::from_raw(revocation_hook::SSL_ERROR_WANT_RETRY_VERIFY));
        let (Some(hook), Some(check), true) = (&hook, revocation, retry) else {
            break result;
        };
        let Some(path) = hook.take_pending() else {
            break result;
        };
        hook.record_wait();
        hook.verifier()
            .obtain(&path, &check.network, check.deadline)
            .await;
    };
    let rejection = hook.as_ref().and_then(|hook| hook.rejection());
    let verify_result = stream.ssl().verify_result();
    let certificate_failed = verify_result != openssl::x509::X509VerifyResult::OK;
    let error = match (handshake, rejection) {
        (_, Some(rejection)) => anyhow::anyhow!(
            "Certificate revocation check rejected the server: {}",
            rejection.reason()
        ),
        (Err(error), None) if certificate_failed => {
            anyhow::Error::new(error).context("OpenSSL TLS handshake failed")
        }
        (Err(error), None) => {
            return Err(anyhow::Error::new(error).context("OpenSSL TLS handshake failed"));
        }
        (Ok(()), None) => return Ok(stream),
    };
    Err(error
        .context(crate::statistics::CertificateVerificationCode(verify_result.as_raw()))
        .context(crate::statistics::CertificateFailure))
}
