//! Demonstrates establishing a TLS 1.3 PSK connection through the public client
//! session API.

use env_logger::Env;
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
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();

    let server = TacacsPlusServerBuilder::new(
        "tacacs-psk-example",
        TacacsPlusServerType::all(),
        "tacacsserver.local",
        449,
    )
    .with_tls13_epsk("tacacs-client-01", b"my-pre-shared-key-material".to_vec())
    .build();

    let connection = TacacsClient::connect(server, ConnectOptions::default()).await?;
    let session = connection.create_session().await?;

    let response = send_accounting_request(
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
    .await?;

    println!("Received accounting response: {response:#?}");

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
