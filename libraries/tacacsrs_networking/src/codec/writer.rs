use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::Packet;
use tacacsrs_messages::packet::PacketTrait;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Result of writing a packet to a connection.
#[derive(Debug)]
pub enum PacketWriteResult {
    /// The packet was written.
    Success,
    /// Writing the packet failed.
    WriteError(std::io::Error),
}

/// Writes TACACS+ packets, including optional body obfuscation.
pub struct PacketWriter {
    obfuscation_key: Option<Vec<u8>>,
}

impl PacketWriter {
    /// Creates a `PacketWriter` with an optional obfuscation key.
    ///
    /// # Arguments
    /// * `obfuscation_key` - Optional key used to obfuscate outgoing packets.
    ///   If `None`, packets are sent unencrypted.
    #[must_use]
    pub const fn new(obfuscation_key: Option<Vec<u8>>) -> Self {
        Self { obfuscation_key }
    }

    /// Returns the configured packet obfuscation key, if one is present.
    #[must_use]
    pub fn obfuscation_key(&self) -> Option<&[u8]> {
        self.obfuscation_key.as_deref()
    }

    /// Applies configured TACACS+ body obfuscation in place.
    #[must_use]
    pub fn prepare_packet(&self, mut packet: Packet) -> Packet {
        let session_id = packet.header().session_id;
        let is_packet_deobfuscated = packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        if let Some(key) = &self.obfuscation_key {
            if is_packet_deobfuscated {
                packet = packet.to_obfuscated(key);
                log::trace!(
                    target: "tacacsrs_networking::codec::writer::prepare_packet",
                    "Obfuscated packet for session id {session_id}"
                );
            }
        }

        packet
    }

    /// Encodes and writes one TACACS+ packet as one contiguous buffer.
    pub async fn write_packet<Writer>(
        &self,
        writer: &mut Writer,
        packet: Packet,
    ) -> PacketWriteResult
    where
        Writer: AsyncWrite + Unpin + ?Sized,
    {
        let packet = self.prepare_packet(packet);
        let bytes = packet.to_bytes();

        match writer.write_all(&bytes).await {
            Ok(()) => PacketWriteResult::Success,
            Err(error) => PacketWriteResult::WriteError(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tacacsrs_messages::enumerations::{
        TacacsFlags, TacacsType, TacacsMajorVersion, TacacsMinorVersion,
    };
    use tacacsrs_messages::header::Header;
    use tokio::io::AsyncWrite;

    #[derive(Default)]
    struct CountingWriter {
        bytes: Vec<u8>,
        write_count: usize,
    }

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.write_count += 1;
            self.bytes.extend_from_slice(buffer);
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

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

    #[allow(clippy::cast_possible_truncation)] // test data is small
    fn create_test_packet(session_id: u32, body: Vec<u8>, flags: TacacsFlags) -> Packet {
        let header = create_test_header(session_id, body.len() as u32, flags);
        Packet::new(header, body).unwrap()
    }

    #[tokio::test]
    async fn test_write_packet_uses_single_write() {
        let packet = create_test_packet(
            12345,
            vec![0x01, 0x02, 0x03, 0x04],
            TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
        );
        let expected_bytes = packet.to_bytes();

        let mut writer = CountingWriter::default();
        let packet_writer = PacketWriter::new(None);

        match packet_writer.write_packet(&mut writer, packet).await {
            PacketWriteResult::Success => {
                assert_eq!(writer.bytes, expected_bytes);
                assert_eq!(writer.write_count, 1);
            }
            PacketWriteResult::WriteError(error) => panic!("expected success: {error}"),
        }
    }

    #[tokio::test]
    async fn test_prepare_packet_no_obfuscation_key() {
        let body = vec![0x01, 0x02, 0x03, 0x04];
        let packet =
            create_test_packet(12345, body.clone(), TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let packet_writer = PacketWriter::new(None);

        let prepared = packet_writer.prepare_packet(packet);

        // Without an obfuscation key, the packet must not change.
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

        // With an obfuscation key, the flag is removed and the body changes.
        assert!(!prepared
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_ne!(prepared.body(), &body); // Obfuscation changes the body.
    }

    #[tokio::test]
    async fn test_prepare_packet_already_obfuscated() {
        let body = vec![0x01, 0x02, 0x03, 0x04];
        // A packet without the unencrypted flag is already obfuscated.
        let packet = create_test_packet(12345, body.clone(), TacacsFlags::empty());
        let obfuscation_key = b"test_key".to_vec();
        let packet_writer = PacketWriter::new(Some(obfuscation_key));

        let prepared = packet_writer.prepare_packet(packet);

        // Do not obfuscate an obfuscated packet again.
        assert!(!prepared
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_eq!(prepared.body(), &body); // The body must not change.
    }
}
