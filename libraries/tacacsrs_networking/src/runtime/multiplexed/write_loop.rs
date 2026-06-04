use std::sync::Arc;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use tacacsrs_messages::packet::{Packet, PacketTrait};

use crate::codec::{PacketWriteResult, PacketWriterTrait};

use crate::session::SessionManager;

pub(super) async fn run_write_loop(
    packet_writer: &dyn PacketWriterTrait,
    mut receiver: mpsc::Receiver<Packet>,
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    connection: Arc<SessionManager>,
) -> anyhow::Result<()> {
    loop {
        let packet = tokio::select! {
            () = connection.wait_for_close() => {
                log::info!(
                    target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                    "Received close signal. Shutting down write handler."
                );
                let _ = writer.shutdown().await;
                return Ok(());
            }

            packet = receiver.recv() => {
                if let Some(packet) = packet { packet } else {
                    log::info!(
                        target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                        "Channel closed. Shutting down write handler."
                    );
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
            }
        };

        let session_id = packet.header().session_id;

        log::info!(
            target: "tacacsrs_networking::runtime::multiplexed::write_loop",
            "Received packet for session id {session_id} to send to network"
        );

        match packet_writer.write_packet(writer, packet).await {
            PacketWriteResult::Success => {
                log::info!(
                    target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                    "Sent packet for session id {session_id} to network"
                );
            }
            PacketWriteResult::WriteError(error) => {
                log::error!(
                    target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                    "Failed to write packet for session id {session_id} due to error: {error}"
                );
                return Err(anyhow::Error::msg(error.to_string()));
            }
        }
    }
}
