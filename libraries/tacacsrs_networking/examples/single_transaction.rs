use std::vec;

use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerType};
use tacacsrs_flows::accounting::AccountingExchange;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType,
};
use tacacsrs_networking::{ConnectOptions, TacacsClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = init_logging();

    #[cfg(tokio_unstable)]
    {
        console_subscriber::init();
    }

    let server = TacacsPlusServerBuilder::new(
        "single-transaction-example",
        TacacsPlusServerType::ACCOUNTING,
        "tacacsserver.local",
        49,
    )
    .with_shared_secret("tac_plus_key")
    .build();
    let connection = TacacsClient::connect(server, ConnectOptions::default()).await?;

    for flags in [TacacsAccountingFlags::START, TacacsAccountingFlags::STOP] {
        let response = connection
            .execute(AccountingExchange::new(AccountingRequest {
                flags,
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
                    "cmd=test".to_string(),
                ],
            }))
            .await?;

        println!("Received accounting response: {response:#?}");
    }

    Ok(())
}

use log::{Level, Metadata, Record};
use log::{LevelFilter, SetLoggerError};
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

/// # Errors
/// Returns an error if the logger has already been set.
pub fn init_logging() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info))
}
