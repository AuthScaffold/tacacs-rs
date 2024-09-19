
use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};
use std::vec;

use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService, TacacsAuthenticationType};
use tacacsrs_networking::connection;

use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;



#[tokio::main]
async fn main() {
    let _ = init_logging();

    #[cfg(tokio_unstable)]
    {
        console_subscriber::init();
    }

    let mut server_address_list = lookup_host("tacacsserver.local:49").await.unwrap();
    let server_addr = match server_address_list.next() {
        Some(SocketAddr::V4(addr)) => addr.ip().clone(),
        _ => panic!("No valid IPv4 address found for tacacsserver.local"),
    };

    println!("Resolved tacacsserver.local to {}", server_addr);
    
    let connection_info = connection::ConnectionInfo {
        ip_socket: SocketAddr::new(IpAddr::V4(server_addr), 49),
        obfuscation_key: Some(b"tac_plus_key".to_vec()),
    };

    let connection = Arc::new(connection::Connection::new(&connection_info));

    match connection.clone().connect().await {
        Ok(_) => {
            println!("Successfully connected to server at {}", connection_info.ip_socket);
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }

    let session = Arc::new(connection.create_session().await.unwrap());

    let accounting_request = AccountingRequest
    {
        flags: TacacsAccountingFlags::START,
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
    };

    let response = match session.send_accounting_request(accounting_request).await {
        Ok(response) => response,
        Err(e) => {
            println!("Failed to send accounting request: {}", e);
            return;
        }
    };

    println!("Received accounting response: {:?}", response);

    let session = Arc::new(connection.create_session().await.unwrap());

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
            return;
        }
    };

    println!("Received accounting response: {:?}", response);
}



use log::{Record, Level, Metadata};
use log::{SetLoggerError, LevelFilter};
use tokio::net::lookup_host;
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