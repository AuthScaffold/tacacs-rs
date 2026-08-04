use std::sync::Arc;
use std::vec;

use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerType};
use tacacsrs_flows::accounting::AccountingExchange;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType,
};
use tacacsrs_networking::{ConnectOptions, TacacsClient};
use tokio::task::JoinHandle;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = init_logging();

    #[cfg(tokio_unstable)]
    {
        console_subscriber::init();
    }

    let server = TacacsPlusServerBuilder::new(
        "multiple-transactions-example",
        TacacsPlusServerType::ACCOUNTING,
        "tacacsserver.local",
        49,
    )
    .with_shared_secret("tac_plus_key")
    .build();
    let connection = Arc::new(TacacsClient::connect(server, ConnectOptions::default()).await?);
    let session_count = 100_000;

    let handles: Vec<JoinHandle<anyhow::Result<()>>> = (0..session_count)
        .map(|_| {
            let connection = Arc::clone(&connection);
            tokio::spawn(async move { send_test_request(&connection).await })
        })
        .collect();

    for handle in handles {
        handle.await??;
    }

    Ok(())
}

async fn send_test_request(connection: &TacacsClient) -> anyhow::Result<()> {
    let accounting_request = AccountingRequest {
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

    connection
        .execute(AccountingExchange::new(accounting_request))
        .await?;
    Ok(())
}

use log::{Level, Metadata, Record};
use log::{LevelFilter, SetLoggerError};

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

/// # Errors
/// Returns an error if the logger has already been set.
pub fn init_logging() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info))
}
