//! Demonstrates establishing a certificate-based TLS connection through the
//! public client session API.

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

    let binary_path = std::env::current_exe()?;
    let Some(parent_folder) = binary_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
    else {
        println!("Failed to get parent folder of binary path.");
        return Err(anyhow::Error::msg("Failed to get parent folder of binary path."));
    };

    let examples_folder = parent_folder
        .join("libraries")
        .join("tacacsrs_networking")
        .join("examples");

    let client_certificate_path = examples_folder.join("samples").join("client.crt.der");
    let client_key_path = examples_folder.join("samples").join("client.key.der");

    if !client_certificate_path.exists() || !client_key_path.exists() {
        println!(
            "Client certificate {} or key {} does not exist.",
            client_certificate_path.display(),
            client_key_path.display()
        );
        return Err(anyhow::Error::msg("Client certificate or key does not exist."));
    }

    let cert_data = tokio::fs::read(&client_certificate_path).await?;
    let key_data = tokio::fs::read(&client_key_path).await?;

    let server = TacacsPlusServerBuilder::new(
        "tacacs-tls-example",
        TacacsPlusServerType::all(),
        "tacacsserver.local",
        449,
    )
    .with_tls_client_certificate(Some(cert_data), Some(key_data))
    .build();

    let connection = TacacsClient::connect(
        server,
        ConnectOptions::default().with_certificate_verification_disabled(true),
    )
    .await?;
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
        return Err(anyhow::Error::msg("Cannot send accounting request on a completed session"));
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
