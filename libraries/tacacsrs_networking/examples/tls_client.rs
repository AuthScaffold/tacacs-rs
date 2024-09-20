use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use argh::FromArgs;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::*;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types;
use tokio_rustls::{rustls, TlsConnector};

use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;


use rustls::crypto::aws_lc_rs as provider;

/// Tokio Rustls client example
#[derive(FromArgs)]
struct Options {
    /// host
    #[argh(positional)]
    host: String,

    /// port
    #[argh(option, short = 'p', default = "443")]
    port: u16,

    /// domain
    #[argh(option, short = 'd')]
    domain: Option<String>
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let domain = options.domain.unwrap_or(options.host);

    let root_cert_store = rustls::RootCertStore::empty();
    let supported_tls_versions = vec![&rustls::version::TLS13];
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(supported_tls_versions.as_slice())
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    println!("resumption: {:?}", config.resumption);
    config.resumption = config.resumption.tls12_resumption(rustls::client::Tls12Resumption::Disabled);
    config.enable_sni = false;

    config.dangerous().set_certificate_verifier(Arc::new(danger::NoCertificateVerification::new(
        provider::default_provider(),
    )));

    println!("Config: {:#?}", config);


    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(&addr).await.unwrap();

    let domain = pki_types::ServerName::try_from(domain.as_str())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))
        .unwrap()
        .to_owned();

    let stream = connector.connect(domain, stream).await?;

    let connection = Arc::new(tacacsrs_networking::tls_connection::TlsConnection::new());
    connection.clone().connect(stream).await?;

    let session = connection.create_session().await?;

    let response = match session.send_accounting_request(AccountingRequest
        {
            flags: TacacsAccountingFlags::STOP,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "admin".to_string(),
            port: "test".to_string(),
            rem_address: "1.1.1.1".to_string(),
            args: vec![
                "service=shell".to_string(),
                "task_id=123".to_string(),
                "cmd=test".to_string()
            ],
        }
    ).await {
        Ok(response) => response,
        Err(e) => {
            println!("Failed to send accounting request: {}", e);
            return Err(e);
        }
    };

    println!("Received accounting response: {:?}", response);

    Ok(())
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