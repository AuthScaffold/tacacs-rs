//! Demonstrates establishing a TLS 1.3 PSK connection by constructing a
//! [`TacacsPlusServer`] with [`TacacsPlusServerBuilder`] and letting the
//! dispatcher in [`tacacsrs_networking::config_connect`] pick the correct
//! transport.
//!
//! This is the only supported entry point for PSK connection construction —
//! the lower-level builders inside `transport::tls_psk` are crate-internal.

use std::sync::Arc;

use env_logger::Env;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerExt, TacacsPlusServerType};
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType, TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_networking::TacacsConnection;
use tacacsrs_networking::config_connect::{ConnectOptions, establish_stream};
use tacacsrs_networking::session::Session;
use tacacsrs_networking::traits::SessionManagementTrait;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();

    // Configure a TACACS+ server that uses a TLS 1.3 externally provisioned PSK.
    let server = TacacsPlusServerBuilder::new(
        "tacacs-psk-example",
        TacacsPlusServerType::all(),
        "tacacsserver.local",
        449,
    )
    .with_tls13_epsk("tacacs-client-01", b"my-pre-shared-key-material".to_vec())
    .build();

    let options = ConnectOptions::default();

    let stream = establish_stream(&server, &options).await?;
    let obfuscation_key = server.obfuscation_key();
    let connection = Arc::new(TacacsConnection::new(obfuscation_key.as_deref()));
    connection.run(stream).await?;

    let session = connection.create_session().await?;

    let response = match send_accounting_request(
        &session,
        AccountingRequest {
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
                "cmd=test".to_string(),
            ],
        },
    )
    .await
    {
        Ok(response) => response,
        Err(e) => {
            println!("Failed to send accounting request: {e}");
            return Err(e);
        }
    };

    println!("Received accounting response: {response:#?}");

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
