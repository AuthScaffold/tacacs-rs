use std::sync::Arc;
use async_trait::async_trait;
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::PacketTrait;
use tacacsrs_messages::packet::Packet;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::session_manager::SessionManager;

/// Result of writing a packet to the stream.
#[derive(Debug)]
pub enum PacketWriteResult {
    /// Successfully wrote the packet.
    Success,
    /// The close signal was received.
    CloseSignal,
    /// The channel was closed.
    ChannelClosed,
    /// Failed to write to stream.
    WriteError(std::io::Error),
}

/// Trait for writing TACACS+ packets to a stream.
///
/// This trait abstracts the packet writing logic to allow for dependency injection
/// and easier testing. Implementations can provide custom behavior for obfuscating
/// and writing packets.
#[async_trait]
pub trait PacketWriterTrait: Send + Sync {
    /// Prepares a packet for writing by optionally obfuscating it.
    ///
    /// # Arguments
    /// * `packet` - The packet to prepare
    ///
    /// # Returns
    /// The packet (potentially obfuscated) ready to be written.
    fn prepare_packet(&self, packet: Packet) -> Packet;

    /// Writes a single packet to the provided writer.
    ///
    /// # Arguments
    /// * `writer` - A mutable reference to an async writer
    /// * `packet` - The packet to write
    ///
    /// # Returns
    /// A `PacketWriteResult` indicating success or failure.
    async fn write_packet(
        &self,
        writer: &mut (dyn AsyncWrite + Unpin + Send),
        packet: Packet,
    ) -> PacketWriteResult;

    /// Runs the write handler loop, receiving packets from the channel and writing them.
    ///
    /// This method will:
    /// 1. Wait for packets from the receiver or a close signal
    /// 2. Prepare (potentially obfuscate) each packet
    /// 3. Write the packet to the stream
    /// 4. Continue until close signal or channel closed
    ///
    /// # Arguments
    /// * `receiver` - The channel receiver for outgoing packets
    /// * `writer` - A mutable reference to an async writer
    /// * `connection` - The session manager for close signal coordination
    ///
    /// # Returns
    /// `Ok(())` on graceful shutdown, `Err` on write failure.
    async fn run_write_loop(
        &self,
        mut receiver: tokio::sync::mpsc::Receiver<Packet>,
        writer: &mut (dyn AsyncWrite + Unpin + Send),
        connection: Arc<SessionManager>,
    ) -> anyhow::Result<()> {
        loop {
            let packet = tokio::select! {
                // Wait for close signal
                _ = connection.wait_for_close() => {
                    log::info!(
                        target: "tacacsrs_networking::packet_writer::run_write_loop",
                        "Received close signal. Shutting down write handler."
                    );
                    // Gracefully shutdown the write half
                    let _ = writer.shutdown().await;
                    return Ok(())
                }

                // Wait for packet to send
                packet = receiver.recv() => {
                    match packet {
                        Some(packet) => packet,
                        None => {
                            log::info!(
                                target: "tacacsrs_networking::packet_writer::run_write_loop",
                                "Channel closed. Shutting down write handler."
                            );
                            let _ = writer.shutdown().await;
                            return Ok(())
                        }
                    }
                }
            };

            let session_id = packet.header().session_id;

            log::info!(
                target: "tacacsrs_networking::packet_writer::run_write_loop",
                "Received packet for session id {} to send to network",
                session_id
            );

            match self.write_packet(writer, packet).await {
                PacketWriteResult::Success => {
                    log::info!(
                        target: "tacacsrs_networking::packet_writer::run_write_loop",
                        "Sent packet for session id {} to network",
                        session_id
                    );
                }
                PacketWriteResult::WriteError(e) => {
                    log::error!(
                        target: "tacacsrs_networking::packet_writer::run_write_loop",
                        "Failed to write packet for session id {} due to error: {}",
                        session_id, e
                    );
                    return Err(anyhow::Error::msg(e.to_string()));
                }
                PacketWriteResult::CloseSignal | PacketWriteResult::ChannelClosed => {
                    // These shouldn't happen in write_packet, but handle gracefully
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
            }
        }
    }
}

/// Default implementation of `PacketWriterTrait` for writing TACACS+ packets.
///
/// Handles writing packets to any async writer, including optional obfuscation
/// using the provided key.
pub struct PacketWriter {
    obfuscation_key: Option<Vec<u8>>,
}

impl PacketWriter {
    /// Creates a new `PacketWriter` with an optional obfuscation key.
    ///
    /// # Arguments
    /// * `obfuscation_key` - Optional key used to obfuscate outgoing packets.
    ///   If `None`, packets are sent unencrypted.
    pub fn new(obfuscation_key: Option<Vec<u8>>) -> Self {
        Self { obfuscation_key }
    }
}

#[async_trait]
impl PacketWriterTrait for PacketWriter {
    fn prepare_packet(&self, mut packet: Packet) -> Packet {
        let session_id = packet.header().session_id;
        let is_packet_deobfuscated = packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        if let Some(key) = &self.obfuscation_key {
            if is_packet_deobfuscated {
                packet = packet.to_obfuscated(key);
                log::info!(
                    target: "tacacsrs_networking::packet_writer::prepare_packet",
                    "Obfuscated packet for session id {}",
                    session_id
                );
            }
        }

        packet
    }

    async fn write_packet(
        &self,
        writer: &mut (dyn AsyncWrite + Unpin + Send),
        packet: Packet,
    ) -> PacketWriteResult {
        let packet = self.prepare_packet(packet);
        let bytes = packet.to_bytes();

        match writer.write_all(&bytes).await {
            Ok(_) => PacketWriteResult::Success,
            Err(e) => PacketWriteResult::WriteError(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tacacsrs_messages::enumerations::{
        TacacsFlags, TacacsType, TacacsMajorVersion, TacacsMinorVersion,
    };
    use tacacsrs_messages::header::Header;

    fn create_test_header(session_id: u32, body_length: u32, flags: TacacsFlags) -> Header {
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAuthentication,
            seq_no: 1,
            flags,
            session_id,
            length: body_length,
        }
    }

    fn create_test_packet(session_id: u32, body: Vec<u8>, flags: TacacsFlags) -> Packet {
        let header = create_test_header(session_id, body.len() as u32, flags);
        Packet::new(header, body).unwrap()
    }

    #[tokio::test]
    async fn test_write_packet_success() {
        let packet = create_test_packet(
            12345,
            vec![0x01, 0x02, 0x03, 0x04],
            TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
        );
        let expected_bytes = packet.to_bytes();

        let mut buffer = Cursor::new(Vec::new());
        let packet_writer = PacketWriter::new(None);

        match packet_writer.write_packet(&mut buffer, packet).await {
            PacketWriteResult::Success => {
                assert_eq!(buffer.into_inner(), expected_bytes);
            }
            _ => panic!("Expected Success result"),
        }
    }

    #[tokio::test]
    async fn test_prepare_packet_no_obfuscation_key() {
        let body = vec![0x01, 0x02, 0x03, 0x04];
        let packet =
            create_test_packet(12345, body.clone(), TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let packet_writer = PacketWriter::new(None);

        let prepared = packet_writer.prepare_packet(packet);

        // Without obfuscation key, packet should be unchanged
        assert!(prepared
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_eq!(prepared.body(), &body);
    }

    #[tokio::test]
    async fn test_prepare_packet_with_obfuscation_key() {
        let body = vec![0x01, 0x02, 0x03, 0x04];
        let packet =
            create_test_packet(12345, body.clone(), TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let obfuscation_key = b"test_key".to_vec();
        let packet_writer = PacketWriter::new(Some(obfuscation_key));

        let prepared = packet_writer.prepare_packet(packet);

        // With obfuscation key, packet should be obfuscated (flag removed, body changed)
        assert!(!prepared
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_ne!(prepared.body(), &body); // Body should be different after obfuscation
    }

    #[tokio::test]
    async fn test_prepare_packet_already_obfuscated() {
        let body = vec![0x01, 0x02, 0x03, 0x04];
        // Packet without the unencrypted flag (already obfuscated)
        let packet = create_test_packet(12345, body.clone(), TacacsFlags::empty());
        let obfuscation_key = b"test_key".to_vec();
        let packet_writer = PacketWriter::new(Some(obfuscation_key));

        let prepared = packet_writer.prepare_packet(packet);

        // Already obfuscated packet should not be double-obfuscated
        assert!(!prepared
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_eq!(prepared.body(), &body); // Body should remain unchanged
    }
}
