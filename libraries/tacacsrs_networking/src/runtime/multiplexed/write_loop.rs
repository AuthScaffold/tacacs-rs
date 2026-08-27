use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use tacacsrs_messages::packet::{Packet, PacketTrait};

use crate::codec::{PacketWriteResult, PacketWriter};

use crate::session::SessionManager;

/// Upper bound on packets coalesced into one write.
///
/// Matches the connection queue capacity so a single drain can empty a full queue.
const MAX_WRITE_BATCH: usize = 64;

pub(super) async fn run_write_loop(
    packet_writer: &PacketWriter,
    mut receiver: mpsc::Receiver<Packet>,
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    connection: Arc<SessionManager>,
) -> anyhow::Result<()> {
    let mut batch: Vec<Packet> = Vec::with_capacity(MAX_WRITE_BATCH);
    let mut buffer: Vec<u8> = Vec::new();

    loop {
        batch.clear();

        let count = tokio::select! {
            () = connection.wait_for_close() => {
                log::info!(
                    target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                    "Received close signal. Stopping the write handler."
                );
                let _ = writer.shutdown().await;
                return Ok(());
            }

            drained = receiver.recv_many(&mut batch, MAX_WRITE_BATCH) => drained
        };

        if count == 0 {
            log::info!(
                target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                "Channel closed. Stopping the write handler."
            );
            let _ = writer.shutdown().await;
            return Ok(());
        }

        buffer.clear();

        // Drains rather than consumes so the batch allocation is reused, and keeps packets in order.
        #[allow(clippy::iter_with_drain)]
        for packet in batch.drain(..) {
            let session_id = packet.header().session_id;
            packet_writer.encode_into(packet, &mut buffer);

            log::trace!(
                target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                "Queued packet for session ID {session_id} in the pending write batch"
            );
        }

        match PacketWriter::write_encoded(writer, &buffer).await {
            PacketWriteResult::Success => {
                log::trace!(
                    target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                    "Sent {count} packet(s) in one write"
                );
            }
            PacketWriteResult::WriteError(error) => {
                log::error!(
                    target: "tacacsrs_networking::runtime::multiplexed::write_loop",
                    "Failed to write a batch of {count} packet(s): {error}"
                );
                return Err(error).context("failed to write TACACS+ packet");
            }
        }
    }
}
