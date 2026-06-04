use std::vec;

use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerType};
use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType, TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;
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
        let session = connection.create_session().await?;
        let response = send_accounting_request(
            &session,
            AccountingRequest {
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
            },
        )
        .await?;

        println!("Received accounting response: {response:#?}");
    }

    Ok(())
}

async fn send_accounting_request(
    session: &(impl ClientSessionFlowIoTrait + Sync),
    request: AccountingRequest,
) -> anyhow::Result<AccountingReply> {
    if session.is_complete().await {
        return Err(anyhow::Error::msg(
            "Cannot send accounting request: session is already complete",
        ));
    }

    let sequence_number = session.next_sequence_number().await;
    let data = request.to_bytes()?;
    let length = u32::try_from(data.len())
        .map_err(|_| anyhow::Error::msg("Accounting request payload exceeds u32 length"))?;

    let packet = Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: sequence_number,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id: session.session_id(),
            length,
        },
        data,
    )?;

    session.send_packet(packet).await?;
    let response = session.receive_packet().await?;
    let reply = AccountingReply::from_bytes(response.body())?;
    session.complete().await;
    Ok(reply)
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
