use std::sync::Arc;

use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::*;
use tacacsrs_networking::helpers::connect_tcp;

use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;
use tacacsrs_networking::traits::SessionCreationTrait;
use tacacsrs_networking::tls_connection::TLSConnectionTrait;



use tacacsrs_networking::helpers::*;



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = init_logging();

    let hostname = "tacacsserver.local:449";
    let obfuscation_key = Some(b"tac_plus_key".to_vec());

    let tcp_stream = connect_tcp(hostname).await?;
    let tls_stream = connect_tls(tcp_stream, "tacacsserver.local").await?;

    let connection = Arc::new(
        tacacsrs_networking::tls_connection::TlsConnection::new(obfuscation_key.as_deref())
    );
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



use log::{Record, Level, Metadata};
use log::{SetLoggerError, LevelFilter};
static LOGGER: SimpleLogger = SimpleLogger;

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{} ({}): {}", record.target(), record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

pub fn init_logging() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Info))
}