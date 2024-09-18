
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::vec;

use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService, TacacsAuthenticationType};
use tacacsrs_networking::connection;

use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;



#[tokio::main]
async fn main() {
    let _ = init_logging();
    console_subscriber::init();
    
    let connection_info = connection::ConnectionInfo {
        ip_socket: SocketAddr::new(IpAddr::V4("192.168.1.32".parse::<Ipv4Addr>().unwrap()), 49),
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

    let mut handles = vec![];

    for _ in 0..100000 {
        let connection_clone = Arc::clone(&connection);
        let handle = tokio::spawn(async move {
            send_test_request(connection_clone).await;
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

}

async fn send_test_request(connection : Arc<connection::Connection>) {
    let session = Arc::new(connection.create_session().await.unwrap());

    let accounting_request = AccountingRequest
    {
        flags: TacacsAccountingFlags::START | TacacsAccountingFlags::STOP,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
        priv_lvl: 0,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: "admin".to_string(),
        port: "test".to_string(),
        rem_address: "1.1.1.1".to_string(),
        args: vec!["cmd=test".to_string()],
    };

    let _response = match session.send_accounting_request(accounting_request).await {
        Ok(response) => response,
        Err(e) => {
            println!("Failed to send accounting request: {}", e);
            return;
        }
    };

    //println!("Received accounting response: {:?}", response);
}


use log::{Record, Level, Metadata};
use log::{SetLoggerError, LevelFilter};
static LOGGER: SimpleLogger = SimpleLogger;

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Error
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