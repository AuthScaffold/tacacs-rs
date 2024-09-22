use std::{net::{SocketAddr, ToSocketAddrs}, path::PathBuf, sync::Arc};

use rustls_cert_file_reader::{FileReader, Format, ReadCerts, ReadKey};
use tokio_rustls::{rustls::{self}, TlsConnector};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};



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
            Ok(stream) => {
                log::info!(
                    target: "tacacsrs_networking::helpers::connect_tcp",
                    "Connected to server: {}", server_address);
                return Ok(stream)
            },
            Err(e) => {
                log::error!(
                    target: "tacacsrs_networking::helpers::connect_tcp",
                    "Failed to connect to server {}: {}", server_address, e);
                continue;
            }
        };
    };

    Err(anyhow::Error::msg("Failed to connect to any server"))
}

pub struct TlsConfigurationBuilder
{
    root_cert_store : rustls::RootCertStore,
    resumption_enabled : bool,
    certificate_chain : Option<Vec<CertificateDer<'static>>>,
    private_key : Option<PrivateKeyDer<'static>>,
    disable_certificate_verification : bool
}

impl Default for TlsConfigurationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfigurationBuilder {
    pub fn new() -> Self {
        Self {
            root_cert_store : rustls::RootCertStore::empty(),
            resumption_enabled : false,
            certificate_chain : Option::None,
            private_key : Option::None,
            disable_certificate_verification : false
        }
    }

    pub fn with_root_certificates(mut self, root_cert_store : rustls::RootCertStore) -> Self {
        self.root_cert_store = root_cert_store;
        self
    }

    pub fn with_resumption(mut self, enabled : bool) -> Self {
        self.resumption_enabled = enabled;
        self
    }

    // pub fn with_client_auth_cert(mut self, certificate_chain : Vec<CertificateDer<'_>>, private_key : PrivateKeyDer<'_>) -> Self {
    //     self.certificate_chain = Some(certificate_chain);
    //     self.private_key = Some(private_key);
    //     self
    // }

    pub async fn with_client_auth_cert_files(mut self, certificate_chain_file : impl Into<PathBuf>, private_key_file : impl Into<PathBuf>) -> anyhow::Result<Self> {
        let cert_file_reader  : FileReader<Vec<CertificateDer<'_>>> = FileReader::new(
            certificate_chain_file, Format::PEM);
        let cert_chain = cert_file_reader.read_certs().await?;

        let key_file_reader : FileReader<PrivateKeyDer<'_>> = FileReader::new(
            private_key_file, Format::PEM);
        let key_der = key_file_reader.read_key().await?;

        self.certificate_chain = cert_chain.into();
        self.private_key = key_der.into();
        Ok(self)
    }

    pub fn with_certificate_verification_disabled(mut self, disabled : bool) -> Self {
        self.disable_certificate_verification = disabled;
        self
    }


    pub fn build(self) -> anyhow::Result<rustls::ClientConfig> {
        let supported_tls_versions = vec![&rustls::version::TLS13];

        let config = rustls::ClientConfig::builder_with_protocol_versions(supported_tls_versions.as_slice())
            .with_root_certificates(self.root_cert_store);

        let mut config = match self.certificate_chain {
            Some(cert_chain) => {
                match self.private_key {
                    Some(key_der) => {
                        config.with_client_auth_cert(cert_chain, key_der)?
                    },
                    None => {
                        return Err(anyhow::Error::msg("Private key not provided"));
                    }
                }
            },
            None => {
                config.with_no_client_auth()
            }
        };

        if !self.resumption_enabled
        {
            config.resumption = config.resumption.tls12_resumption(rustls::client::Tls12Resumption::Disabled);
        }

        if self.disable_certificate_verification
        {
            config.dangerous().set_certificate_verifier(Arc::new(danger::NoCertificateVerification::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
            )));
        }

        Ok(config)
    }
    
}


pub async fn connect_tls(config : &Arc<rustls::ClientConfig>, stream : tokio::net::TcpStream, domain : &str) -> anyhow::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let connector = TlsConnector::from(config.clone());

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
