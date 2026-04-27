use std::sync::Arc;
use std::vec;

use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType, TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;

use tacacsrs_networking::helpers::connect_tcp;
use tacacsrs_networking::session::Session;
use tacacsrs_networking::traits::SessionManagementTrait;
use tacacsrs_networking::TacacsConnection;
use tokio::task::JoinHandle;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = init_logging();
    let hostname = "tacacsserver.local";
    let obfuscation_key = Some(b"tac_plus_key".to_vec());

    #[cfg(tokio_unstable)]
    {
        console_subscriber::init();
    }

    let tcp_stream = connect_tcp(hostname).await?;
    let connection = Arc::new(TacacsConnection::new(obfuscation_key.as_deref()));
    connection.run(tcp_stream).await?;

    // For TLS or TLS-PSK, build a TacacsPlusServer via TacacsPlusServerBuilder
    // and call tacacsrs_networking::config_connect::establish_stream — see the
    // tls_client.rs and tls_psk_client.rs examples in this directory.

    let session_count = 100_000;

    let session_creation = (0..session_count).map(|_| {
        let conn = connection.clone();
        tokio::spawn(async move { conn.create_session().await })
    });

    let mut sessions = Vec::<Session>::with_capacity(session_count);
    for session in session_creation {
        let session = match session.await? {
            Ok(session) => session,
            Err(e) => {
                println!("Failed to create session: {e}");
                return Err(e);
            }
        };

        sessions.push(session);
    }

    let handles: Vec<JoinHandle<anyhow::Result<()>>> = sessions
        .into_iter()
        .map(|session| tokio::spawn(async move { send_test_request(session).await }))
        .collect();

    for handle in handles {
        let _ = handle.await?;
    }

    Ok(())
}

async fn send_test_request(session: Session) -> anyhow::Result<()> {
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

    let _response = match send_accounting_request(&session, accounting_request).await {
        Ok(response) => response,
        Err(e) => {
            println!("Failed to send accounting request: {e}");
            return Err(e);
        }
    };

    Ok(())
}

async fn send_accounting_request(
    session: &Session,
    request: AccountingRequest,
) -> anyhow::Result<AccountingReply> {
    let sequence_number = session.next_sequence_number().await;
    let data = request.to_bytes();
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

    session.duplex_channel.sender.send(packet).await?;
    let mut reader_lock = session.duplex_channel.receiver.write().await;
    let response = reader_lock
        .recv()
        .await
        .ok_or_else(|| anyhow::Error::msg("Failed to receive response"))?;
    let reply = AccountingReply::from_bytes(response.body())?;
    session.complete().await;
    Ok(reply)
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

/// # Errors
/// Returns an error if the logger has already been set.
pub fn init_logging() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info))
}
