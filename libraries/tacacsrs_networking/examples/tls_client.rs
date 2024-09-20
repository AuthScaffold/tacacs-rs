use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::*;
use tacacsrs_networking::helpers::connect_tcp;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types;
use tokio_rustls::{rustls, TlsConnector};

use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;
use tacacsrs_networking::traits::SessionCreationTrait;
use tacacsrs_networking::tls_connection::{TlsConnection, TLSConnectionTrait};


use rustls::crypto::aws_lc_rs as provider;

use tacacsrs_networking::helpers::*;



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let hostname = "tacacsserver.local";
    let obfuscation_key = Some(b"tac_plus_key".to_vec());

    let tcp_stream = connect_tcp(hostname).await?;
    let tls_stream = connect_tls(tcp_stream, hostname).await?;

    let connection = Arc::new(tacacsrs_networking::tls_connection::TlsConnection::new());
    connection.run(tls_stream).await?;

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

    println!("Received accounting response: {:#?}", response);

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