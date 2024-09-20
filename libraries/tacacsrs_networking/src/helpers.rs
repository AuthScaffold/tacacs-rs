use std::{net::{SocketAddr, ToSocketAddrs}, sync::Arc};

use tokio_rustls::{rustls, TlsConnector};


pub fn get_server_addresses(hostname : &str) -> anyhow::Result<Vec::<SocketAddr>>
{
    let address = if hostname.contains(':') {
        hostname.to_string()
    } else {
        format!("{}:{}", hostname, 49)
    };

    let server_address_list : Vec::<SocketAddr> = address.to_socket_addrs()?.collect();
    Ok(server_address_list)
}

pub async fn connect_tcp(hostname : &str) -> anyhow::Result<tokio::net::TcpStream>
{
    for server_address in get_server_addresses(hostname)?
    {
        match tokio::net::TcpStream::connect(server_address).await
        {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                log::error!("Failed to connect to server: {}", e);
                continue;
            }
        };
    };

    Err(anyhow::Error::msg("Failed to connect to any server"))
}



pub async fn connect_tls(stream : tokio::net::TcpStream, domain : &str) -> anyhow::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    // Only support TLS 1.3
    let supported_tls_versions = vec![&rustls::version::TLS13];

    // Empty certificate store
    let root_cert_store = rustls::RootCertStore::empty();

    // Default client config
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(supported_tls_versions.as_slice())
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    // Disable resumption
    config.resumption = config.resumption.tls12_resumption(rustls::client::Tls12Resumption::Disabled);

    // Disable ssl verification
    config.dangerous().set_certificate_verifier(Arc::new(danger::NoCertificateVerification::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    )));

    let connector = TlsConnector::from(Arc::new(config));

    let domain = rustls::pki_types::ServerName::try_from(domain)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dnsname"))?
        .to_owned();

    let stream : tokio_rustls::client::TlsStream<tokio::net::TcpStream> = connector.connect(domain, stream).await?;
    Ok(stream)
}


mod danger {
    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::{verify_tls13_signature, CryptoProvider};
    use rustls::DigitallySignedStruct;

    #[derive(Debug)]
    pub struct NoCertificateVerification(CryptoProvider);

    impl NoCertificateVerification {
        pub fn new(provider: CryptoProvider) -> Self {
            Self(provider)
        }
    }

    impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            println!("verify_server_cert");
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("TLS 1.2 not supported".to_string()))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}