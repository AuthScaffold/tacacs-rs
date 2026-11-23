use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use tacacsrs_protocol::packet::{Packet, PacketTrait};

use crate::codec::{PacketWriteResult, PacketWriter};

use crate::session::SessionManager;

pub(super) async fn run_write_loop(
    packet_writer: &PacketWriter,
    mut receiver: mpsc::Receiver<Packet>,
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    connection: Arc<SessionManager>,
    mut send_single_connect_on_first_packet: bool,
) -> anyhow::Result<()> {
    loop {
        let packet = tokio::select! {
            () = connection.wait_for_close() => {
                log::info!(
                    target: "tacacsrs_networking::connection::multiplexed::write_loop",
                    "Received close signal. Stopping the write handler."
                );
                let _ = writer.shutdown().await;
                return Ok(());
            }

            packet = receiver.recv() => {
                if let Some(packet) = packet { packet } else {
                    log::info!(
                        target: "tacacsrs_networking::connection::multiplexed::write_loop",
                        "Channel closed. Stopping the write handler."
                    );
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
            }
        };

        let packet = if std::mem::take(&mut send_single_connect_on_first_packet) {
            let mut header = packet.header().clone();
            header.flags |=
                tacacsrs_protocol::enumerations::TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG;
            Packet::new(header, packet.body().to_vec())
                .context("failed to set single-connect flag on initial packet")?
        } else {
            packet
        };

        let correlation = tacacsrs_protocol::header::wire_correlation(packet.header().session_id);

        log::trace!(
            target: "tacacsrs_networking::connection::multiplexed::write_loop",
            "Received packet for correlation {correlation} to send on the connection"
        );

        match packet_writer.write_packet(writer, packet).await {
            PacketWriteResult::Success => {
                log::trace!(
                    target: "tacacsrs_networking::connection::multiplexed::write_loop",
                    "Sent packet for correlation {correlation}"
                );
            }
            PacketWriteResult::WriteError(error) => {
                log::error!(
                    target: "tacacsrs_networking::connection::multiplexed::write_loop",
                    "Failed to write packet for correlation {correlation}: {error}"
                );
                return Err(error).context("failed to write TACACS+ packet");
            }
        }
    }
}
