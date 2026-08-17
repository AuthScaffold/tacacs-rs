use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use tacacsrs_messages::packet::{Packet, PacketTrait};

use crate::codec::{PacketWriteResult, PacketWriter};

use crate::session::SessionManager;

pub(super) async fn run_write_loop(
    packet_writer: &PacketWriter,
    mut receiver: mpsc::Receiver<Packet>,
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    connection: Arc<SessionManager>,
) -> anyhow::Result<()> {
    loop {
        let packet = tokio::select! {
            () = connection.wait_for_close() => {
                log::info!(
                    target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                    "Received close signal. Stopping the write handler."
                );
                let _ = writer.shutdown().await;
                return Ok(());
            }

            packet = receiver.recv() => {
                if let Some(packet) = packet { packet } else {
                    log::info!(
                        target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                        "Channel closed. Stopping the write handler."
                    );
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
            }
        };

        let session_id = packet.header().session_id;

        log::trace!(
            target: "tacacsrs_networking::runtime::multiplexed::write_loop",
            "Received packet for session ID {session_id} to send on the connection"
        );

        match packet_writer.write_packet(writer, packet).await {
            PacketWriteResult::Success => {
                log::trace!(
                    target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                    "Sent packet for session ID {session_id}"
                );
            }
            PacketWriteResult::WriteError(error) => {
                log::error!(
                    target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                    "Failed to write packet for session ID {session_id}: {error}"
                );
                return Err(error).context("failed to write TACACS+ packet");
            }
        }
    }
}
