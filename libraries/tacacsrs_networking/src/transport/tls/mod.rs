//! TLS transport for TACACS+ connections.
//!
//! Native contexts use borrowed DER material and explicit verification settings.
//! Each context supports repeated handshakes without reparsing credentials.
//! Client certificate dates are checked before each connection and again before
//! its handshake. Established connections retain no certificate-date cutoff.

mod config_builder;
mod config;
mod validity;
mod revocation;
#[allow(clippy::module_inception)]
mod tls;

pub(crate) use config_builder::TlsConfigurationBuilder;
pub use config::TlsClientConfig;
pub use config::{CertificateIdentity, CertificateTrust, CertificateVerification, PrivateKeyEncoding};
pub use validity::RevocationEvidenceValidity;
pub use revocation::CertificateRevocationPolicy;
pub(crate) use validity::RevocationEvidenceLifetime;

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
    revocation: Option<revocation::ConnectionRevocation>,
    crls: Option<std::sync::Arc<revocation::crls::CrlEvidence>>,
) -> anyhow::Result<(SslStream<TcpStream>, Option<RevocationEvidenceValidity>)> {
    let mut ssl = Ssl::new(context).context("OpenSSL failed to allocate TLS SSL object")?;
    revocation::request(&mut ssl, revocation)?;
    revocation::crls::attach(&mut ssl, crls)?;
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
    let crl_failed = revocation::crls::verification_failed(stream.ssl());
    let ocsp_failed = revocation::verification_failed(stream.ssl());
    let certificate_failed = stream.ssl().verify_result() != openssl::x509::X509VerifyResult::OK
        || crl_failed
        || ocsp_failed;
    let result = (|| -> anyhow::Result<Option<RevocationEvidenceValidity>> {
        if crl_failed {
            return revocation::crls::require_verified(stream.ssl()).map(|()| None);
        }
        if ocsp_failed {
            return revocation::verified_validity(stream.ssl());
        }
        handshake.context("OpenSSL TLS handshake failed")?;
        revocation::crls::require_verified(stream.ssl())?;
        revocation::verified_validity(stream.ssl())
    })();
    let evidence_validity = if certificate_failed {
        result
            .map_err(|error| {
                if error.is::<crate::statistics::CertificateVerificationCode>() {
                    error
                } else {
                    error.context(crate::statistics::CertificateVerificationCode(
                        stream.ssl().verify_result().as_raw(),
                    ))
                }
            })
            .context(crate::statistics::CertificateFailure)?
    } else {
        result?
    };

    Ok((stream, evidence_validity))
}
